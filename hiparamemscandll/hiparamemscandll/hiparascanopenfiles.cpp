#include <stdio.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>

#include "hiparahelper.h"
#include "hiparascanopenfiles.h"
#include <strsafe.h>
#include <Psapi.h>

extern FILE *g_pReportFile;
static USHORT iterator = 0;
static WCHAR pwstrPathStack[MAX_NUM_FILES][MAX_PATH];

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

void savePath(LPWSTR path)
{
	if (iterator >= MAX_NUM_FILES)
	{
		_tprintf(_T("Maximum number of files open exceeded. Returning without saving."));
		return;
	}
	wcscpy(pwstrPathStack[iterator++], path);
}

bool checkPath(LPWSTR path)
{
	USHORT i = 0;
	if (iterator <= 0)
	{
		return false;
	}
	while (i <= iterator)
	{
		if (!(wcscmp(pwstrPathStack[i++], path)))
		{
			return true;
		}
	}
	return false;
}


BOOLEAN ScanOpenFilePerProcess(DWORD pid)
{
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
		GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)
		GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
	_NtQueryObject NtQueryObject = (_NtQueryObject)
		GetLibraryProcAddress("ntdll.dll", "NtQueryObject");

	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x1000;
	HANDLE processHandle;
	ULONG i;
	TCHAR Path[BUFSIZE];
	DWORD dwRet;
	bool bScanResult = FALSE;
	WCHAR szMaliciousProcessName[MAX_PATH_LEN];
	CHAR szReportMessage[MAX_PATH_LEN];
	WCHAR szErrorMessage[MAX_PATH_LEN];

	if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, pid)))
	{
		_tprintf(_T("Could not open PID %d! (Don't try to open a system process.)\n"), pid);
		return FALSE;
	}
	
	dwRet = GetProcessImageFileName(processHandle, szMaliciousProcessName, MAX_PATH_LEN);
	if (dwRet == 0)
	{
		dwRet = GetLastError();
		_tprintf(_T("GetProcessImageFileName failed with error = %d\n"), dwRet);
		CloseHandle(processHandle);
		return FALSE;
	}
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

	while ((status = NtQuerySystemInformation(
		SystemHandleInformation,
		handleInfo,
		handleInfoSize,
		NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	if (!NT_SUCCESS(status))
	{
		_tprintf(_T("NtQuerySystemInformation failed with status = %d\n"), status);
		return FALSE;
	}

	for (i = 0; i < handleInfo->HandleCount; i++)
	{
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		
		status = NtDuplicateObject(
			processHandle,
			handle.Handle,
			GetCurrentProcess(),
			&dupHandle,
			0,
			0,
			0);
		if (!NT_SUCCESS(status))
		{
			//	_tprintf(_T("[%#x] Error! = %x\n"), handle.Handle, GetLastError());
			continue;
		}
		
		
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(
			dupHandle,
			ObjectTypeInformation,
			objectTypeInfo,
			0x1000,
			NULL)))
		{
			//_tprintf(_T("[%#x] Error!\n"), handle.Handle);
			CloseHandle(dupHandle);
			continue;
		}
	
		if (handle.GrantedAccess == 0x0012019f)
		{
			_tprintf(_T("[%#x] %.*s: (did not get name)\n"),
				handle.Handle,
				objectTypeInfo->Name.Length / 2,
				objectTypeInfo->Name.Buffer
				);
			free(objectTypeInfo);
			CloseHandle(dupHandle);
			continue;
		}
		dwRet = GetProcessImageFileName(processHandle, szMaliciousProcessName, MAX_PATH_LEN);

		if (!wcscmp(objectTypeInfo->Name.Buffer, _T("File")))
		{
			dwRet = GetFinalPathNameByHandle(dupHandle, Path, BUFSIZE, FILE_NAME_NORMALIZED);

			if (dwRet < BUFSIZE)
			{
				if (!checkPath(&(Path[4])))
				{
					savePath(&(Path[4]));
					bScanResult = scanFile(&(Path[4]));
					if (bScanResult == TRUE)
					{
						if (0 == dwRet)
						{
							dwRet = GetLastError();
							swprintf(szErrorMessage, L"GetProcessImageFileName failed with error(%d)", dwRet);
							OutputDebugString(szErrorMessage);

							continue;
						}

						dwRet = sprintf_s(szReportMessage, MAX_PATH_LEN, "Malicious file (%S) loaded in process (%S)\n", Path, szMaliciousProcessName);
						if (-1 == dwRet)
						{
							swprintf(szErrorMessage, L"Report not generated for(%s)", szMaliciousProcessName);
							OutputDebugString(szErrorMessage);
						}
						else
						{
							fwrite(szReportMessage, sizeof(CHAR), dwRet, g_pReportFile);
						}
					}
					_tprintf(TEXT("\nThe final path is: %s\n"), &(Path[4]));
				}
			}
		}
		free(objectTypeInfo);
		objectTypeInfo = NULL;
		CloseHandle(dupHandle);
	}

	free(handleInfo);
	CloseHandle(processHandle);

	return TRUE;
}
