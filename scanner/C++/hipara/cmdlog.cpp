#include "stdafx.h"
#include<tchar.h>
#include<Windows.h>
#include <ntstatus.h>
#include <psapi.h>
#include <TlHelp32.h>
#include <Strsafe.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>
#include <stdio.h>
#include <time.h>
#include "cmdlog.h"
#include "hipara.h"
#include "libyara\include\yara\libyara.h"
#include "libyara\include\yara\compiler.h"
#include "libyara\include\yara\rules.h"
#include "hiparaDlg.h"

#pragma comment(lib,"ntdll.lib")

WCHAR gszCmdLogFile[MAX_PATH] = _T("C:\\Program Files\\Allsum\\Hipara\\cmd.txt");
extern CHiparaDlg *g_pThis;

BOOLEAN
LogCmdProcess(
	DWORD dwProcessIdToLog,
	HANDLE hStopEvent,
	HANDLE hProcessEvent,
	USHORT *pushCommandCount
	)
{
	HMODULE hMod;
	BOOL boRetVal;
	ULONG ulIndex;
	DWORD dwRetVal;
	HANDLE hProcess;
	BOOLEAN bRetVal;
	DWORD dwProcessId;
	NTSTATUS NTStatus;
	DWORD dwNeededSize;
	char msg[MAX_PATH];
	HANDLE hCurrentProcess;
	WCHAR wszProcessName[MAX_PATH];
	WCHAR wszCmdProcessName[MAX_PATH];
	static DWORD dwParentProcessId = 0;
	PSYSTEM_HANDLE_INFORMATION pSystemHandleInfo;
	PFN_NTQUERYSYSTEMINFORMATION pfnNtQuerySystemInformation;

	if (NULL == pushCommandCount)
	{
		return FALSE;
	}

	hMod = LoadLibraryEx(_T("ntdll.dll"), NULL, 0);
	if (NULL == hMod)
	{
		_tprintf(_T("main: LoadLibraryEx failed.\n"));
		return FALSE;
	}

	pfnNtQuerySystemInformation = (PFN_NTQUERYSYSTEMINFORMATION)GetProcAddress(hMod, "NtQuerySystemInformation");
	if (NULL == pfnNtQuerySystemInformation)
	{
		FreeLibrary(hMod);
		_tprintf(_T("main: GetProcAddress failed for NtQuerySystemInformation.\n"));
		return FALSE;
	}

	dwNeededSize = 0x10000;
	pSystemHandleInfo = (SYSTEM_HANDLE_INFORMATION *)malloc(dwNeededSize);
	if (NULL == pSystemHandleInfo)
	{
		FreeLibrary(hMod);
		_tprintf(_T("main: Memory allocation to system handle information failed.\n"));
		getchar();
		return FALSE;
	}

	NTStatus = pfnNtQuerySystemInformation(SystemHandleInformation, pSystemHandleInfo, dwNeededSize, &dwNeededSize);
	if (STATUS_SUCCESS != NTStatus && STATUS_INFO_LENGTH_MISMATCH == NTStatus)
	{
		free(pSystemHandleInfo);
		pSystemHandleInfo = (SYSTEM_HANDLE_INFORMATION *)malloc(dwNeededSize);
		if (NULL == pSystemHandleInfo)
		{
			FreeLibrary(hMod);
			_tprintf(_T("main: NtQuerySystemInformation failed(0x%08X)"), NTStatus);
			getchar();
			return FALSE;
		}
		NTStatus = pfnNtQuerySystemInformation(SystemHandleInformation, pSystemHandleInfo, dwNeededSize, NULL);
	}

	if (STATUS_SUCCESS != NTStatus)
	{
		free(pSystemHandleInfo);
		FreeLibrary(hMod);
		_tprintf(_T("main: NtQuerySystemInformation failed(0x%08X)"), NTStatus);
		getchar();
		return FALSE;
	}

	for (ulIndex = 0; ulIndex < pSystemHandleInfo->NumberOfHandles; ulIndex++)
	{
		if (0x07 != pSystemHandleInfo->Handles[ulIndex].ObjectTypeNumber)
		{
			continue;
		}

		sprintf_s(msg, sizeof(msg), "Process Id 1(%u) Process Id 2(%u)\n", dwProcessIdToLog, pSystemHandleInfo->Handles[ulIndex].ProcessId);
		OutputDebugStringA(msg);

		if (dwProcessIdToLog != pSystemHandleInfo->Handles[ulIndex].ProcessId)
		{
			continue;
		}

		bRetVal = GetProcessName(pSystemHandleInfo->Handles[ulIndex].ProcessId, wszProcessName, sizeof(wszProcessName));
		if (FALSE == bRetVal)
		{
			continue;
		}

		if (0 != _wcsicmp(wszProcessName, L"conhost.exe"))
		{
			continue;
		}

		OutputDebugString(_T("==== Found conhost.exe process ====\n"));

		hCurrentProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pSystemHandleInfo->Handles[ulIndex].ProcessId);
		if (NULL == hCurrentProcess)
		{
			continue;
		}

		boRetVal = DuplicateHandle(hCurrentProcess, (HANDLE)pSystemHandleInfo->Handles[ulIndex].Handle, GetCurrentProcess(), &hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, 0);
		if (0 == boRetVal)
		{
			_tprintf(_T("Duplicate handle failed(%d)\n"), GetLastError());
			CloseHandle(hCurrentProcess);
			continue;
		}

		dwProcessId = GetProcessId(hProcess);

		dwRetVal = GetProcessImageFileName(hProcess, wszCmdProcessName, sizeof(wszCmdProcessName) / sizeof(WCHAR));
		if (0 == dwRetVal)
		{
			_tprintf(_T("GetProcessImageFileName failed.\n"));
			continue;
		}

		if (NULL == wcsstr(wszCmdProcessName, L"cmd.exe"))
		{
			continue;
		}

		if (0 == dwParentProcessId)
		{
			bRetVal = GetParentProcessID(dwProcessId, &dwParentProcessId);
		}

		/*sprintf_s(msg, sizeof(msg), "Found cmd.exe process: (%s) with Process id:(%u) Parent(%u)\n", wszCmdProcessName, dwProcessId, dwParentProcessId);
		OutputDebugStringA(msg);*/

		bRetVal = WriteProcessMemoryToFile(hCurrentProcess, (HANDLE)pSystemHandleInfo->Handles[ulIndex].Handle, hStopEvent, hProcessEvent, pushCommandCount, dwParentProcessId);
		if (FALSE == bRetVal)
		{
			_tprintf(_T("WriteProcessMemoryToFile failed.\n"));
		}

		CloseHandle(hCurrentProcess);
		break;
	}

	free(pSystemHandleInfo);
	FreeLibrary(hMod);

	getchar();
	return TRUE;
}


BOOLEAN WriteProcessMemoryToFile(HANDLE hProcess, HANDLE hHandle, HANDLE hStopEvent, HANDLE hProcessEvent, USHORT *pushCommandCount, DWORD dwParentProcessId)
{
	DWORD dwCnt;
	USHORT ushLen;
	BOOL boRetVal;
	DWORD dwWait;
	DWORD dwIndex;
	DWORD dwError;
	SIZE_T stRetVal;
	LPBYTE lpTempPtr;
	SIZE_T bytesReturn;
	LPBYTE lProcMinAddress;
	LPBYTE lProcMaxAddress;
	SYSTEM_INFO SystemInfo;
	TCHAR errMsg[MAX_PATH];
	ULONG_PTR ulHandelValue;
	USHORT ushLastCommandCount;
	COMMAND_HISTORY *pCommandHistory;
	WCHAR wszCommand[MAX_NAME_LENGTH];
	MEMORY_BASIC_INFORMATION MemBasicInfo;

	USHORT *pushBuffer;
	BYTE	*pbyBuffer1;				// Common buffer required to query process image headers.
	OutputDebugString(_T("WriteProcessMemoryToFile: Entry.\n"));
	//
	//	Parameter validation.
	//
	if (NULL == hProcess || NULL == hProcessEvent || NULL == pushCommandCount)
	{
		OutputDebugString(_T("WriteProcessMemoryToFile: Invalid Parameter.\n"));
		return FALSE;
	}

	GetSystemInfo(&SystemInfo);

	lProcMinAddress = (LPBYTE)SystemInfo.lpMinimumApplicationAddress;
	lProcMaxAddress = (LPBYTE)SystemInfo.lpMaximumApplicationAddress;

	pCommandHistory = NULL;
	ushLastCommandCount = 0;
	while (TRUE)
	{
		OutputDebugString(_T("WriteProcessMemoryToFile: Checking stop event.\n"));
		dwWait = WaitForSingleObject(hStopEvent, 0);
		if (WAIT_OBJECT_0 == dwWait)
		{
			OutputDebugString(_T("WriteProcessMemoryToFile: WaitForSingleObject1 State sinnaled...breaking from loop\n"));
			break;
		}
		dwWait = WaitForSingleObject(hProcessEvent, 0);
		if (WAIT_OBJECT_0 == dwWait)
		{
			OutputDebugString(_T("WriteProcessMemoryToFile: WaitForSingleObject1 State sinnaled...breaking from loop\n"));
			break;
		}
		OutputDebugString(_T("WriteProcessMemoryToFile: Stop event not set..calling virtualQueryEx.\n"));

		stRetVal = VirtualQueryEx(hProcess, lProcMinAddress, &MemBasicInfo, sizeof(MemBasicInfo));
		if (0 == stRetVal)
		{
			//_tprintf(_T("VirtualQueryEx failed.\n"));
			OutputDebugString(_T("VirtualQueryEx failed.\n"));
			break;
		}

		if (MEM_COMMIT != MemBasicInfo.State)
		{
			lProcMinAddress += MemBasicInfo.RegionSize;
			//_tprintf(_T("Memory pages are not committed or reserved.\n"));
			continue;
		}

		if (MEM_PRIVATE != MemBasicInfo.Type)
		{
			//_tprintf(_T("Memory type is not Private.\n"));
			lProcMinAddress += MemBasicInfo.RegionSize;
			continue;
		}

		pbyBuffer1 = (BYTE *)malloc(MemBasicInfo.RegionSize);
		if (NULL == pbyBuffer1)
		{
			_tprintf(_T("Memory allocation to buffer failed.\n"));
			break;
		}

		memset(pbyBuffer1, 0, MemBasicInfo.RegionSize);

		bytesReturn = 0;

		boRetVal = ReadProcessMemory(hProcess, lProcMinAddress, pbyBuffer1, MemBasicInfo.RegionSize, &bytesReturn);
		if (0 == boRetVal)
		{
			dwError = GetLastError();
			//_tprintf(_T("Error: (%d)\n"), dwError);
			free(pbyBuffer1);
			//_tprintf(_T("Failed ReadProcessMemory for(%d)\n"), MemBasicInfo.Type);
			lProcMinAddress += MemBasicInfo.RegionSize;
			continue;
		}

		pushBuffer = (USHORT *)pbyBuffer1;
		for (dwIndex = 0; dwIndex < MemBasicInfo.RegionSize / sizeof(USHORT); dwIndex++)
		{
			dwWait = WaitForSingleObject(hStopEvent, 0);
			if (WAIT_OBJECT_0 == dwWait)
			{
				OutputDebugString(_T("WriteProcessMemoryToFile: WaitForSingleObject 2 State sinnaled...breaking from loop\n"));
				free(pbyBuffer1);
				return TRUE;
			}

			dwWait = WaitForSingleObject(hProcessEvent, 0);
			if (WAIT_OBJECT_0 == dwWait)
			{
				OutputDebugString(_T("WriteProcessMemoryToFile: Process terminated\n"));
				free(pbyBuffer1);
				return TRUE;
			}

			if (pushBuffer[dwIndex] == (USHORT)0x32)
			{
				lpTempPtr = (BYTE *)&pushBuffer[dwIndex];
				
				lpTempPtr = lpTempPtr + sizeof(VOID*);
				
				ulHandelValue = *(ULONG *)lpTempPtr;
				if ((HANDLE)ulHandelValue == hHandle)
				{
					OutputDebugString(_T("Found Command History structure.\n"));
					pCommandHistory = (COMMAND_HISTORY *)((BYTE *)&pushBuffer[dwIndex] - 8);
					ushLastCommandCount = pCommandHistory->ushCommandCount;

					for (dwCnt = *pushCommandCount; dwCnt < pCommandHistory->ushCommandCount; dwCnt++)
					{
						ushLen = 0;
						boRetVal = ReadProcessMemory(hProcess, pCommandHistory->pCommand[dwCnt], &ushLen, sizeof(USHORT), &bytesReturn);
						if (0 == boRetVal)
						{
							_tprintf(_T("ReadProcessMemory failed(%d)\n"), GetLastError());
						}
						else
						{
							//_tprintf(_T("Command length: %d\n"), ushLen);
							memset(wszCommand, 0, sizeof(wszCommand));
							boRetVal = ReadProcessMemory(hProcess, ((BYTE *)pCommandHistory->pCommand[dwCnt] + sizeof(USHORT)), (BYTE *)wszCommand, ushLen, &bytesReturn);
							if (0 == boRetVal)
							{
								_tprintf(_T("ReadProcessMemory while command read failed(%d)\n"), GetLastError());
							}
							else
							{
								/*_stprintf_s(errMsg, sizeof(errMsg), L"wszCommand(%s)", wszCommand);
								OutputDebugString(errMsg);*/
								//_tprintf(_T("Command: %s\n"), wszCommand);
								//LogCmdActivityToFile((BYTE *)wszCommand, wcslen(wszCommand) * sizeof(wszCommand[0]));
								g_pThis->SendAlertMessageToServer(wszCommand, ALERT_CMD, dwParentProcessId);
							}
						}
					}
					break;
				}
			}
		}
		free(pbyBuffer1);
		lProcMinAddress += MemBasicInfo.RegionSize;
		if (NULL != pCommandHistory)
		{
			break;
		}
		OutputDebugString(_T("WriteProcessMemoryToFile: Going to ready next chunk of memory.\n"));
	}
	OutputDebugString(_T("WriteProcessMemoryToFile: Giving back last command count.\n"));
	*pushCommandCount = ushLastCommandCount;
	OutputDebugString(_T("WriteProcessMemoryToFile: Given back command prompt\n"));

	return TRUE;
}


BOOLEAN
GetParentProcessID(
	DWORD dwPID,
	DWORD *pdwPPID
)
{
	int iPID;
	HANDLE hToolhelp32;
	PROCESSENTRY32 ProccessEntry;;

	iPID = -1;
	ProccessEntry.dwSize = sizeof(PROCESSENTRY32);

	if (NULL == pdwPPID)
	{
		return FALSE;
	}

	hToolhelp32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32First(hToolhelp32, &ProccessEntry))
	{
		do
		{
			if (ProccessEntry.th32ProcessID == dwPID)
			{
				*pdwPPID = (DWORD)ProccessEntry.th32ParentProcessID;
				CloseHandle(hToolhelp32);
				return TRUE;
			}

		} while (Process32Next(hToolhelp32, &ProccessEntry));
	}

	CloseHandle(hToolhelp32);
	return FALSE;
}

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
	)
{
	LUID luid;
	BOOL boRetVal;
	TOKEN_PRIVILEGES tp;

	boRetVal = LookupPrivilegeValue(NULL, lpszPrivilege, &luid);   // receives LUID of privilege
	if (0 == boRetVal)
	{
		_tprintf(_T("LookupPrivilegeValue error: %u\n"), GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	boRetVal = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);
	if (0 == boRetVal)
	{
		_tprintf(_T("AdjustTokenPrivileges error: %u\n"), GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		_tprintf(_T("The token does not have the specified privilege. \n"));
		return FALSE;
	}

	return TRUE;
}

BOOLEAN GetProcessName(ULONG ulProcessId, WCHAR *pwszProcessName, ULONG ulcbSize)
{
	//HMODULE hMod;
	//DWORD cbNeeded;

	//// Get a handle to the process.

	//HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ulProcessId);
	//if (NULL == hProcess)
	//{
	//	return FALSE;
	//}

	//// Get the process name.

	//if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
	//	&cbNeeded))
	//{
	//	GetModuleBaseName(hProcess, hMod, pwszProcessName, ulcbSize / sizeof(WCHAR));
	//}
	//// Print the process name and identifier.

	//_tprintf(TEXT("%s  (PID: %u)\n"), pwszProcessName, ulProcessId);

	//// Release the handle to the process.

	//CloseHandle(hProcess);

	BOOLEAN bFound;
	HANDLE hSnapShot;
	PROCESSENTRY32 processEntry;

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (NULL == hSnapShot)
	{
		return FALSE;
	}

	processEntry.dwSize = sizeof(PROCESSENTRY32);
	bFound = FALSE;

	if (Process32First(hSnapShot, &processEntry))
	{
		do 
		{
			if (processEntry.th32ProcessID == ulProcessId)
			{
				wcscpy_s(pwszProcessName, ulcbSize / sizeof(WCHAR), processEntry.szExeFile);
				bFound = TRUE;
				//_tprintf(_T("Process name is:(%s)\n"), pwszProcessName);
				break;
			}
			processEntry.dwSize = sizeof(PROCESSENTRY32);

		} while (Process32Next(hSnapShot, &processEntry));
	}

	if (FALSE == bFound)
	{
		return FALSE;
	}

	return TRUE;
}


BOOLEAN
LogCmdActivityToFile(
	BYTE *pbyCommand,
	DWORD dwcbCommand
	)
{
	HANDLE hFile;
	BOOL boRetVal;
	time_t timer;
	struct tm* tm_info;
	WCHAR wszbuffer[26];
	TCHAR ErrMgg[MAX_PATH];
	DWORD dwNumberOfBytesReturned;
	LARGE_INTEGER liDistanceToMove;

	OutputDebugString(_T("LogCmdActivityToFile() Entry."));

	if (NULL == pbyCommand || 0 == dwcbCommand)
	{
		_stprintf_s(ErrMgg, sizeof(ErrMgg), L"Invalid parameter.");
		OutputDebugString(ErrMgg);

		return FALSE;
	}

	hFile = CreateFileW(gszCmdLogFile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		_stprintf_s(ErrMgg, sizeof(ErrMgg), L"CreateFileW() Failed. Error(%u).", GetLastError());
		OutputDebugString(ErrMgg);

		return FALSE;
	}

	liDistanceToMove.QuadPart = 0;
	boRetVal = SetFilePointerEx(hFile, liDistanceToMove, NULL, FILE_END);
	if (FALSE == boRetVal)
	{
		_stprintf_s(ErrMgg, sizeof(ErrMgg), L"SetFilePointerEx() Failed. Error(%u).", GetLastError());
		OutputDebugString(ErrMgg);

		CloseHandle(hFile);
		return FALSE;
	}

	time(&timer);
	tm_info = localtime(&timer);

	wcsftime(wszbuffer, ARRAY_SIZE(wszbuffer), L"%Y:%m:%d %H:%M:%S ", tm_info);

	boRetVal = WriteFile(hFile, wszbuffer, wcslen(wszbuffer) * sizeof(wszbuffer[0]), &dwNumberOfBytesReturned, NULL);
	if (FALSE == boRetVal)
	{
		_stprintf_s(ErrMgg, sizeof(ErrMgg), L"WriteFile() Failed. Error(%u).", GetLastError());
		OutputDebugString(ErrMgg);

		CloseHandle(hFile);
		return FALSE;
	}

	boRetVal = WriteFile(hFile, pbyCommand, dwcbCommand, &dwNumberOfBytesReturned, NULL);
	if (FALSE == boRetVal)
	{
		_stprintf_s(ErrMgg, sizeof(ErrMgg), L"WriteFile() Failed. Error(%u).", GetLastError());
		OutputDebugString(ErrMgg);

		CloseHandle(hFile);
		return FALSE;
	}

	boRetVal = WriteFile(hFile, L"\r\n", wcslen(L"\r\n") * sizeof(WCHAR), &dwNumberOfBytesReturned, NULL);
	if (FALSE == boRetVal)
	{
		_stprintf_s(ErrMgg, sizeof(ErrMgg), L"WriteFile() Failed. Error(%u).", GetLastError());
		OutputDebugString(ErrMgg);

		CloseHandle(hFile);
		return FALSE;
	}

	OutputDebugString(_T("LogCmdActivityToFile() Exit."));

	CloseHandle(hFile);
	return TRUE;
}
