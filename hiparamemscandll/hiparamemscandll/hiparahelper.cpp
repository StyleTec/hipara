#include <stdio.h>
#include <fcntl.h>
#include <tchar.h>
#include <io.h>
#include <sys/stat.h>
#include <strsafe.h>

#include "hiparahelper.h"
#include "hiparascanopenfiles.h"
#include "libyara\include\yara\rules.h"
#include "libyara\include\yara\libyara.h"
#include "libyara\include\yara\compiler.h"

#include <Psapi.h>

TCHAR gszSignatureFolderPath[MAX_PATH_LEN] = _T("C:\\Program Files\\Allsum\\Hipara\\signatures");
TCHAR gszSignatureFolder64Path[MAX_PATH_LEN] = _T("C:\\Program Files (x86)\\Allsum\\Hipara\\signatures");

CHAR gszReportFilePath[MAX_PATH_LEN] = "C:\\Program Files\\Allsum\\Hipara\\Report_MemoryScan.txt";
CHAR gszReportFileWow64Path[MAX_PATH_LEN] = "C:\\Program Files (x86)\\Allsum\\Hipara\\Report_MemoryScan.txt";

extern YR_RULES *g_pYrRules;
extern YR_COMPILER *g_pYrCompiler;
extern FILE *g_pYarFile;
extern FILE *g_pReportFile;

int initYara()
{
	int iRetVal;
	UINT uiOutLen;
	BOOL boRetVal;
	BOOL boIsWow64;
	HRESULT hrRetVal;
	HANDLE hFileFind;
	CHAR *pszFileName;
	WIN32_FIND_DATA findData;
	TCHAR szSigFilePath[MAX_PATH_LEN] = { '\0' };
	TCHAR szTempFolderPath[MAX_PATH_LEN] = { '\0' };
	CHAR szFileName[MAX_PATH_LEN] = { '\0' };

	char msg[260];	//	For debug logs.

	boRetVal = IsWow64Process(GetCurrentProcess(), &boIsWow64);
	if (0 == boRetVal)
	{
		OutputDebugString(_T("initYara: IsWow64Process failed.\n"));
		return -1;
	}

	if (TRUE == boIsWow64)
	{
		_tcscpy_s(szTempFolderPath, MAX_PATH_LEN, gszSignatureFolder64Path);
	}
	else
	{
		_tcscpy_s(szTempFolderPath, MAX_PATH_LEN, gszSignatureFolderPath);
	}

	hrRetVal = StringCchCat(szTempFolderPath, MAX_PATH_LEN, _T("\\*"));
	if (FAILED(hrRetVal))
	{
		OutputDebugString(_T("initYara:: StringCchCat failed.\n"));
		return -1;
	}

	WCHAR wszPath[260];
	swprintf(wszPath, L"Signature Path: %s", szTempFolderPath);
	OutputDebugString(wszPath);

	hFileFind = FindFirstFile(szTempFolderPath, &findData);
	if (INVALID_HANDLE_VALUE == hFileFind)
	{
		OutputDebugString(_T("initYara:: FindFirstFile failed.\n"));
		return -1;
	}

	do
	{
		if ((0 != _tcscmp(findData.cFileName, _T("."))) && (0 != _tcscmp(findData.cFileName, _T(".."))))
		{
			if (TRUE == boIsWow64)
			{
				hrRetVal = StringCchPrintf(szSigFilePath, MAX_PATH_LEN, _T("%s\\%s"), gszSignatureFolder64Path, findData.cFileName);
				if (FAILED(hrRetVal))
				{
					OutputDebugString(_T("initYara::StringCchPrintf failed"));
					break;
				}
			}
			else
			{
				hrRetVal = StringCchPrintf(szSigFilePath, MAX_PATH_LEN, _T("%s\\%s"), gszSignatureFolderPath, findData.cFileName);
				if (FAILED(hrRetVal))
				{
					OutputDebugString(_T("initYara::StringCchPrintf failed"));
					break;
				}
			}

			iRetVal = yr_initialize();
			if (ERROR_SUCCESS != iRetVal)
			{
				OutputDebugString(_T("initYara: yr_initialize failed.\n"));

				swprintf_s(wszPath, sizeof(wszPath), _T("initYara: yr_initialize failed for(%S)"), szSigFilePath);
				OutputDebugStringW(wszPath);

				FindClose(hFileFind);
				return iRetVal;
			}

			iRetVal = yr_compiler_create(&g_pYrCompiler);
			if (ERROR_SUCCESS != iRetVal)
			{
				yr_finalize();
				FindClose(hFileFind);

				g_pYrCompiler = NULL;
				OutputDebugString(_T("initYara: yr_compiler_create failed.\n"));
				return iRetVal;
			}

			iRetVal = ConvertFromWideCharToMultiByte(szSigFilePath, _tcslen(szSigFilePath), &pszFileName, &uiOutLen);
			if (FALSE == iRetVal)
			{
				yr_compiler_destroy(g_pYrCompiler);
				yr_finalize();
				FindClose(hFileFind);

				g_pYrCompiler = NULL;
				OutputDebugString(_T("initYara: ConvertFromWideCharToMultiByte() failed.\n"));
				return -1;
			}

			g_pYarFile = fopen(pszFileName, "rb");
			if (NULL == g_pYarFile)
			{
				yr_compiler_destroy(g_pYrCompiler);
				yr_finalize();
				FindClose(hFileFind);

				g_pYrCompiler = NULL;
				g_pYarFile = NULL;

				sprintf_s(msg, sizeof(msg), "initYara: fopen failed for(%s)", pszFileName);
				OutputDebugStringA(msg);

				return -1;
			}

			sprintf_s(msg, sizeof(msg), ("initYara: yr_compiler_add_file for(%S)"), pszFileName);
			OutputDebugStringA(msg);

			iRetVal = yr_compiler_add_file(g_pYrCompiler, g_pYarFile, NULL, NULL);
			if (iRetVal > 0)
			{
				fclose(g_pYarFile);
				yr_compiler_destroy(g_pYrCompiler);
				yr_finalize();
				FindClose(hFileFind);

				g_pYrCompiler = NULL;
				g_pYarFile = NULL;

				sprintf_s(msg, sizeof(msg), "initYara: yr_compiler_add_file failed for(%s)", pszFileName);
				OutputDebugStringA(msg);

				return iRetVal;
			}

			iRetVal = yr_compiler_get_rules(g_pYrCompiler, &g_pYrRules);
			if (ERROR_SUCCESS != iRetVal)
			{
				fclose(g_pYarFile);
				yr_compiler_destroy(g_pYrCompiler);
				yr_finalize();
				FindClose(hFileFind);

				g_pYrCompiler = NULL;
				g_pYarFile = NULL;
				g_pYrRules = NULL;
				OutputDebugString(_T("initYara: yr_compiler_get_rules failed.\n"));
				return iRetVal;
			}

			if (TRUE == boIsWow64)
			{
				g_pReportFile = fopen(gszReportFileWow64Path, "w+");
				if (NULL == g_pReportFile)
				{
					yr_rules_destroy(g_pYrRules);
					yr_compiler_destroy(g_pYrCompiler);
					fclose(g_pYarFile);
					yr_finalize();

					g_pYrCompiler = NULL;
					g_pYarFile = NULL;
					g_pYrRules = NULL;
					OutputDebugString(_T("initYara: fopen for log file failed.\n"));
					return -1;
				}
			}
			else
			{
				g_pReportFile = fopen(gszReportFilePath, "w+");
				if (NULL == g_pReportFile)
				{
					yr_rules_destroy(g_pYrRules);
					yr_compiler_destroy(g_pYrCompiler);
					fclose(g_pYarFile);
					yr_finalize();

					g_pYrCompiler = NULL;
					g_pYarFile = NULL;
					g_pYrRules = NULL;
					OutputDebugString(_T("initYara: fopen for log file failed.\n"));
					return -1;
				}
			}

			FindClose(hFileFind);
			break;
		}
	} while (FindNextFile(hFileFind, &findData) != 0);

	return 1;
}

void deinitYara()
{
	OutputDebugString(_T("deinitYara: Entry.\n"));

	if (NULL != g_pYrRules)
	{
		yr_rules_destroy(g_pYrRules);
	}

	if (NULL != g_pYarFile)
	{
		fclose(g_pYarFile);
		g_pYarFile = NULL;
	}

	if (NULL != g_pYrCompiler)
	{
		yr_compiler_destroy(g_pYrCompiler);
	}

	yr_finalize();

	if (NULL != g_pReportFile)
	{
		fclose(g_pReportFile);
		g_pReportFile = NULL;
	}

	OutputDebugString(_T("deinitYara: Exit.\n"));
}


BOOLEAN ScanProcessAndModules()
{
	int iRetVal;
	BOOL bRetVal;
	HANDLE hDevice;
	DWORD dwErrorCode;
	ULONG ulInputData;
	DWORD dwBytesRead;
	int iNumOfStructs;
	HANDLE hOpenProcess;
	ULONG ulReturnedLength;
	WCHAR szErrorMessage[MAX_PATH_LEN];
	SYSTEM_PROCESS_INFORMATION *pSysProcInfo;
	SYSTEM_PROCESS_INFORMATION *pTempSysProc;

	ulInputData = 0;
	dwBytesRead = 0;

	OutputDebugString(_T("ScanProcessAndModules: Entry.\n"));

	hDevice = CreateFile(HIPARA_DEVICE_NAME, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		swprintf(szErrorMessage, L"ScanProcessAndModules: Failed create memory scanner device with error = %d", GetLastError());
		OutputDebugString(szErrorMessage);

		return FALSE;
	}

	bRetVal = DeviceIoControl(
							hDevice,
							IOCTL_GET_LENGTH,
							&ulInputData,
							sizeof(ulInputData),
							(PVOID)&ulReturnedLength,
							sizeof(ulReturnedLength),
							&dwBytesRead,
							NULL);
	if (!bRetVal)
	{
		dwErrorCode = GetLastError();
		swprintf(szErrorMessage, L"ScanProcessAndModules: DeviceIoControl failed for IOCTL_GET_LENGTH with error = %d", dwErrorCode);
		OutputDebugString(szErrorMessage);

		CloseHandle(hDevice);
		return FALSE;
	}

	iNumOfStructs = ulReturnedLength / sizeof(SYSTEM_PROCESS_INFORMATION);
	ulInputData = sizeof(SYSTEM_PROCESS_INFORMATION)* (iNumOfStructs * 5);

	pSysProcInfo = (SYSTEM_PROCESS_INFORMATION*)malloc(ulInputData);
	if (NULL == pSysProcInfo)
	{
		OutputDebugString(_T("ScanProcessAndModules: Memory allocation failed.\n"));

		CloseHandle(hDevice);
		return FALSE;
	}

	ZeroMemory(pSysProcInfo, ulInputData);

	bRetVal = DeviceIoControl(
							hDevice,
							IOCTL_PROC_INFO,
							&ulInputData,
							sizeof(ulInputData),
							(PVOID)pSysProcInfo,
							ulInputData,
							&dwBytesRead,
							NULL);
	if (!bRetVal)
	{
		dwErrorCode = GetLastError();
		swprintf(szErrorMessage, L"ScanProcessAndModules: DeviceIoControl failed for IOCTL_PROC_INFO with error = %d", dwErrorCode);
		OutputDebugString(szErrorMessage);

		free(pSysProcInfo);
		CloseHandle(hDevice);
		return FALSE;
	}

	pTempSysProc = pSysProcInfo;
	while (pTempSysProc->NextEntryOffset)
	{
		pTempSysProc = (SYSTEM_PROCESS_INFORMATION*)((ULONG)pTempSysProc + pTempSysProc->NextEntryOffset);
		hOpenProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pTempSysProc->ProcessId);
		if (NULL == hOpenProcess)
		{
			dwErrorCode = GetLastError();
			if (5 != dwErrorCode)
			{
				swprintf(szErrorMessage, L"ScanProcessAndModules: OpenProcess failed for process id= %d with error = %d", (DWORD)pTempSysProc->ProcessId, dwErrorCode);
				OutputDebugString(szErrorMessage);
			}
			continue;
		}
		else
		{
			//	Scan process memory.
			iRetVal = ScanProcessMemory(hOpenProcess, (DWORD)pTempSysProc->ProcessId);
			if (iRetVal != SUCCESS)
			{
				swprintf(szErrorMessage, L"ScanProcessAndModules: ScanProcessMemory failed with error (%d)", iRetVal);
				OutputDebugString(szErrorMessage);

				CloseHandle(hOpenProcess);
				continue;	//	Try to dump process memory for each possible process.
			}

			//	Scan modules (dlls) loaded into process address space.
			bRetVal = ScanProcessModules(hOpenProcess);
			if (FALSE == bRetVal)
			{
				OutputDebugString(_T("ScanProcessAndModules failed.\n"));
				CloseHandle(hOpenProcess);
				continue;
			}

			// Scan all the open files by the process.
			bRetVal = ScanOpenFilePerProcess((DWORD)pTempSysProc->ProcessId);
			if (FALSE == bRetVal)
			{
				OutputDebugString(_T("ScanOpenFilePerProcess failed.\n"));
				CloseHandle(hOpenProcess);
				continue;
			}

			CloseHandle(hOpenProcess);
		}
	}

	//
	// Cleanup memory.
	//
	free(pSysProcInfo);
	CloseHandle(hDevice);

	OutputDebugString(_T("ScanProcessAndModules: Exit.\n"));
	return TRUE;
}

int ScanProcessMemory(HANDLE hProcess, DWORD dwPid)
{
	int iFile;
	int iRetVal;
	BOOL boRetVal;
	DWORD dwError;
	DWORD dwRetVal;
	SIZE_T stRetVal;
	BYTE *pbyBuffer1;	// Common buffer required to query process image headers.
	SIZE_T bytesReturn;
	BOOLEAN bScanResult;
	WCHAR wcProcessId[50];
	LPBYTE lProcMinAddress;
	LPBYTE lProcMaxAddress;
	SYSTEM_INFO SystemInfo;
	CHAR szReportMessage[MAX_PATH_LEN];
	WCHAR szErrorMessage[MAX_PATH_LEN];
	WCHAR szTempFolderPath[MAX_PATH_LEN];
	MEMORY_BASIC_INFORMATION MemBasicInfo;
	WCHAR szMaliciousProcessName[MAX_PATH_LEN];

	OutputDebugString(_T("ScanProcessMemory: Entry\n"));

	//
	//	Parameter validation.
	//
	if (NULL == hProcess)
	{
		OutputDebugString(_T("ScanProcessMemory: Invalid Parameter.\n"));
		return INVALID_PARAM;
	}

	GetSystemInfo(&SystemInfo);

	lProcMinAddress = (LPBYTE)SystemInfo.lpMinimumApplicationAddress;
	lProcMaxAddress = (LPBYTE)SystemInfo.lpMaximumApplicationAddress;

	dwRetVal = GetTempPath(MAX_PATH_LEN, szTempFolderPath);
	if (0 == dwRetVal)
	{
		swprintf(szErrorMessage, L"ScanProcessMemory: Failed to get the temp folder path with error = %d", GetLastError());
		OutputDebugString(szErrorMessage);

		return GetLastError();
	}

	//
	//	Get Temp folder path and store file over there.
	//	File should get deleted after scanning.
	//
	swprintf(wcProcessId, _T("process_%d"), (DWORD)dwPid);
	lstrcatW(szTempFolderPath, wcProcessId);

	iFile = _topen(szTempFolderPath, _O_WRONLY | _O_CREAT, _S_IREAD | _S_IWRITE);
	if (-1 == iFile)
	{
		swprintf(szErrorMessage, L"ScanProcessMemory: _topen() failed %d", errno);
		OutputDebugString(szErrorMessage);

		return errno;
	}

	//
	//	Write process memory to the file.
	//

	//lProcMinAddress = 0;
	while (TRUE)
	{
		stRetVal = VirtualQueryEx(hProcess, lProcMinAddress, &MemBasicInfo, sizeof(MemBasicInfo));
		if (0 == stRetVal)
		{
			//_tprintf(_T("VirtualQueryEx failed = %d.\n"), GetLastError());
			break;
		}

		if (MEM_COMMIT != MemBasicInfo.State)
		{
			lProcMinAddress += MemBasicInfo.RegionSize;
			//_tprintf(_T("Memory pages are not committed.\n"));
			continue;
		}

		if (MEM_IMAGE != MemBasicInfo.Type /*|| MEM_MAPPED != MemBasicInfo.Type*/)
		{
			//	_tprintf(_T("Memory type is not Image.\n"));
			lProcMinAddress += MemBasicInfo.RegionSize;
			continue;
		}

		pbyBuffer1 = (BYTE *)malloc(MemBasicInfo.RegionSize);
		if (NULL == pbyBuffer1)
		{
			OutputDebugString(_T("ScanProcessMemory(): Memory allocation to buffer failed.\n"));
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

			lProcMinAddress += MemBasicInfo.RegionSize;
			continue;
		}

		dwError = _write(iFile, pbyBuffer1, MemBasicInfo.RegionSize);
		if (dwError == -1)
		{
			swprintf(szErrorMessage, L"ScanProcessMemory: Failed to write to file for process = %d", (DWORD)hProcess);
			OutputDebugString(szErrorMessage);
		}

		free(pbyBuffer1);

		lProcMinAddress += MemBasicInfo.RegionSize;
	}

	_close(iFile);

	//
	//	Scan the file.
	//
	bScanResult = scanFile(szTempFolderPath);
	if (TRUE == bScanResult)
	{
		dwRetVal = GetProcessImageFileName(hProcess, szMaliciousProcessName, MAX_PATH_LEN);
		if (0 == dwRetVal)
		{
			dwError = GetLastError();
			swprintf(szErrorMessage, L"ScanProcessMemory: GetProcessImageFileName failed with error(%d)", dwError);
			OutputDebugString(szErrorMessage);

			return FAILURE;
		}

		iRetVal = sprintf_s(szReportMessage, MAX_PATH_LEN, "Malicious Process(%S)\n", szMaliciousProcessName);
		if (-1 == iRetVal)
		{
			swprintf(szErrorMessage, L"ScanProcessMemory: Report not generated for(%s)", szMaliciousProcessName);
			OutputDebugString(szErrorMessage);
		}
		else
		{
			fwrite(szReportMessage, sizeof(CHAR), iRetVal, g_pReportFile);
		}
	}

	//
	//	Delete file as its not needed now.
	//
	boRetVal = DeleteFile(szTempFolderPath);
	if (0 == boRetVal)
	{
		swprintf(szErrorMessage, L"ScanProcessMemory: Failed to delete file (%s)", szTempFolderPath);
		OutputDebugString(szErrorMessage);
	}

	return SUCCESS;
}


int
yaraScanCallback(
	int iMessage,
	void *pMessageData,
	void *pUserData
	)
{
	P_YARA_CONTEXT pyaraContext;

	//OutputDebugString(_T("yaraScanCalback: Entry.\n"));
	pyaraContext = (YARA_CONTEXT *)pUserData;

	if (CALLBACK_MSG_RULE_MATCHING == iMessage)
	{
		pyaraContext->bScanResult = TRUE;
		OutputDebugString(_T("yaraScanCallback:: CALLBACK_MSG_RULE_MATCHING."));
	}
	else if (CALLBACK_MSG_RULE_NOT_MATCHING == iMessage)
	{
		//printf("yaraScanCallback: CALLBACK_MSG_RULE_NOT_MATCHING.\n");
	}
	else if (CALLBACK_MSG_IMPORT_MODULE == iMessage)
	{
		//OutputDebugString(_T("yaraScanCallback: CALLBACK_MSG_IMPORT_MODULE.\n"));
	}
	else if (CALLBACK_MSG_SCAN_FINISHED == iMessage)
	{
		SetEvent(pyaraContext->hStopEvent);
		//OutputDebugString(_T("yaraScanCallback: CALLBACK_MSG_SCAN_FINISHED.\n"));
	}

	//OutputDebugString(_T("yaraScanCalback: Exit.\n"));
	return ERROR_SUCCESS;
}


BOOLEAN
scanFile(
	PWCHAR pszFilePath
)
{
	int iRetVal;
	errno_t errVal;
	size_t charsConverted;
	YARA_CONTEXT yaraContext;
	CHAR szFileName[MAX_PATH_LEN];

	OutputDebugString(_T("scanFile: Entry.\n"));
	if (NULL == pszFilePath)
	{
		OutputDebugString(_T("scanFile: Invalid parameter.\n"));
		return FALSE;
	}

	yaraContext.bScanResult = FALSE;
	yaraContext.hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (NULL == yaraContext.hStopEvent)
	{
		OutputDebugString(_T("scanFile: CreateEvent failed.\n"));
		return FALSE;
	}

	//printf("ScanFile: File Path is(%S)\n", pszFilePath);
	errVal = wcstombs_s(&charsConverted, szFileName, sizeof(szFileName), pszFilePath, MAX_PATH_LEN);
	if (0 != errVal)
	{
		OutputDebugString(_T("scanFile: wcstombs_s failed.\n"));
		CloseHandle(yaraContext.hStopEvent);
		return FALSE;
	}

	iRetVal = yr_rules_scan_file(g_pYrRules, szFileName, 0, yaraScanCallback, &yaraContext, 0);
	if (ERROR_SUCCESS != iRetVal)
	{
		OutputDebugString(_T("scanFile: yr_rules_scan_file failed.\n"));
		CloseHandle(yaraContext.hStopEvent);
		return FALSE;
	}

	//
	// Wait till scanning is finished.
	// event will be set in yaraScanCallback function once scanning is finished.
	//
	OutputDebugString(_T("scanFile: Waiting for scanning to finish.\n"));
	WaitForSingleObject(yaraContext.hStopEvent, INFINITE);
	OutputDebugString(_T("scanFile: Scanning for file finished.\n"));

	CloseHandle(yaraContext.hStopEvent);

	OutputDebugString(_T("scanFile: Exit.\n"));
	return yaraContext.bScanResult;
}


BOOLEAN
ConvertFromWideCharToMultiByte(
	WCHAR *pwszInput,
	UINT uiInputLen,
	PCHAR *ppszOutput,
	UINT *puiOutputLen
	)
{
	INT iLen;

	if (NULL == pwszInput || NULL == ppszOutput || NULL == puiOutputLen)
	{
		OutputDebugString(_T("ConvertFromWideCharToMultiByte: Invalid Parameter.\n"));
		return FALSE;
	}

	iLen = WideCharToMultiByte(CP_ACP, 0, pwszInput, -1, NULL, 0, NULL, NULL);

	*ppszOutput = (CHAR *)malloc(iLen);
	if (NULL == *ppszOutput)
	{
		OutputDebugString(_T("ConvertFromWideCharToMultiByte: Memory allocation failed to ppszOutput.\n"));
		return FALSE;
	}

	iLen = WideCharToMultiByte(CP_ACP, 0, pwszInput, -1, *ppszOutput, iLen, NULL, NULL);
	if (0 == iLen)
	{
		OutputDebugString(_T("ConvertFromWideCharToMultiByte: WideCharToMultiByte failed(%d)\n", GetLastError()));

		free(*ppszOutput);
		return FALSE;
	}

	*puiOutputLen = iLen;
	return TRUE;
}

BOOLEAN ScanProcessModules(HANDLE hProcess)
{
	int iRetVal;
	ULONG ulIndex;
	BOOL boRetVal;
	DWORD dwRetVal;
	DWORD dwcbNeeded;
	BOOLEAN bScanResult;
	HMODULE hMods[MAX_MODULE_COUNT];
	TCHAR szModuleName[MAX_PATH_LEN];
	CHAR szReportMessage[MAX_PATH_LEN];
	WCHAR szErrorMessage[MAX_PATH_LEN];
	WCHAR szMaliciousProcessName[MAX_PATH_LEN];


	OutputDebugString(_T("ScanProcessModules Entry.\n"));

	boRetVal = EnumProcessModules(hProcess, hMods, sizeof(hMods), &dwcbNeeded);
	if (0 == boRetVal)
	{
		swprintf(szErrorMessage, L"EnumProcessModules function failed(%d)", GetLastError());
		OutputDebugString(szErrorMessage);
		return FALSE;
	}

	for (ulIndex = 0; ulIndex < (dwcbNeeded / sizeof(HMODULE)); ulIndex++)
	{
		dwRetVal = GetModuleFileNameEx(hProcess, hMods[ulIndex], szModuleName, ARRAY_SIZE(szModuleName));
		if (0 == dwRetVal)
		{
			OutputDebugString(_T("GetModuleFileNameEx failed (%d)\n", GetLastError()));
			continue;
		}

		swprintf(szErrorMessage, L"Module Name: %s", szModuleName);
		OutputDebugString(szErrorMessage);

		//
		//	Scan the file.
		//
		bScanResult = scanFile(szModuleName);
		if (TRUE == bScanResult)
		{
			dwRetVal = GetProcessImageFileName(hProcess, szMaliciousProcessName, MAX_PATH_LEN);
			if (0 == dwRetVal)
			{
				dwRetVal = GetLastError();
				swprintf(szErrorMessage, L"GetProcessImageFileName failed with error(%d)", dwRetVal);
				OutputDebugString(szErrorMessage);

				continue;
			}

			iRetVal = sprintf_s(szReportMessage, MAX_PATH_LEN, "Malicious module (%S) loaded in process (%S)\n", szModuleName, szMaliciousProcessName);
			if (-1 == iRetVal)
			{
				swprintf(szErrorMessage, L"Report not generated for(%s)", szMaliciousProcessName);
				OutputDebugString(szErrorMessage);
			}
			else
			{
				fwrite(szReportMessage, sizeof(CHAR), iRetVal, g_pReportFile);
			}
		}
	}

	OutputDebugString(_T("ScanProcessModules Exit.\n"));
	return TRUE;
}

BOOLEAN ScanServices()
{
	int iIndex;
	LONG lRetVal;
	HKEY hRootKey;
	DWORD dwcbData;
	HRESULT hResult;
	BOOLEAN bRetVal;
	HKEY hServiceKey;
	DWORD dwcntSubKeys;
	DWORD dwServiceType;
	DWORD dwKeyNameLength;
	HKEY hServiceParametersKey;
	WCHAR szKeyName[MAX_PATH_LEN];
	WCHAR szServiceName[MAX_PATH_LEN];
	WCHAR szErrorMessage[MAX_PATH_LEN];
	CHAR szReportMessage[MAX_PATH_LEN];
	WCHAR szServiceKeyPath[MAX_PATH_LEN];
	WCHAR szServiceFullPath[MAX_PATH_LEN];
	WCHAR szServiceParametersKey[MAX_PATH_LEN];

	OutputDebugString(_T("ScanServices: Entry.\n"));

	// Open Services key.
	lRetVal = RegOpenKeyEx(HKEY_LOCAL_MACHINE, HIPARA_REG_PATH_SERVICES, 0, KEY_ALL_ACCESS, &hRootKey);
	if (ERROR_SUCCESS != lRetVal)
	{
		swprintf(szErrorMessage, L"RegOpenKeyEx failed (%d)\n", lRetVal);
		OutputDebugString(szErrorMessage);
		return 0;
	}

	//	Query information about Services key.
	//	Like number of sub keys.
	lRetVal = RegQueryInfoKey(
							hRootKey,
							NULL,
							NULL,
							NULL,
							&dwcntSubKeys,
							NULL,
							NULL,
							NULL,
							NULL,
							NULL,
							NULL,
							NULL
							);
	if (ERROR_SUCCESS != lRetVal)
	{
		swprintf(szErrorMessage, L"RegQueryInfokey failed(%d)\n", lRetVal);
		OutputDebugString(szErrorMessage);
		RegCloseKey(hRootKey);
		return 0;
	}

	for (iIndex = 0; iIndex < dwcntSubKeys; iIndex++)
	{
		dwKeyNameLength = MAX_PATH_LEN;
		lRetVal = RegEnumKeyEx(
							hRootKey,
							iIndex,
							szKeyName,
							&dwKeyNameLength,
							NULL,
							NULL,
							NULL,
							NULL
							);
		if (ERROR_SUCCESS != lRetVal)
		{
			swprintf(szErrorMessage, L"RegEnumKeyEx failed(%d)\n", lRetVal);
			OutputDebugString(szErrorMessage);
			continue;
		}

		hResult = StringCchPrintf(szServiceKeyPath, ARRAY_SIZE(szServiceKeyPath), _T("%s\\"), HIPARA_REG_PATH_SERVICES);
		if (FAILED(hResult))
		{
			swprintf(szErrorMessage, L"StringCchPrintf failed (0x%08X)\n", hResult);
			OutputDebugString(szErrorMessage);
			continue;
		}

		hResult = StringCchCat(szServiceKeyPath, ARRAY_SIZE(szServiceKeyPath), szKeyName);
		if (FAILED(hResult))
		{
			swprintf(szErrorMessage, L"StringCchCat failed (0x%08X)\n", hResult);
			OutputDebugString(szErrorMessage);
			continue;
		}

		lRetVal = RegOpenKeyEx(
							HKEY_LOCAL_MACHINE,
							szServiceKeyPath,
							0,
							KEY_ALL_ACCESS,
							&hServiceKey
							);
		if (ERROR_SUCCESS != lRetVal)
		{
			swprintf(szErrorMessage, L"RegOpenKeyEx failed for key (%s) with error (%d)\n", szServiceKeyPath, lRetVal);
			OutputDebugString(szErrorMessage);
			continue;
		}

		//	Get type of service.
		//	Like Kernel mode service, win32 own service, win32 share service.
		dwcbData = sizeof(DWORD);
		lRetVal = RegQueryValueEx(
								hServiceKey,
								L"Type",
								NULL,
								NULL,
								(BYTE*)&dwServiceType,
								&dwcbData
								);
		if (ERROR_SUCCESS != lRetVal)
		{
			RegCloseKey(hServiceKey);
			continue;
		}

		//	We will scan only win32 services.
		if (SERVICE_WIN32_OWN_PROCESS != dwServiceType && SERVICE_WIN32_SHARE_PROCESS != dwServiceType)
		{
			RegCloseKey(hServiceKey);
			continue;
		}

		if (SERVICE_WIN32_SHARE_PROCESS == dwServiceType)
		{
			hResult = StringCchPrintf(szServiceParametersKey, ARRAY_SIZE(szServiceParametersKey), _T("%s\\"), szServiceKeyPath);
			if (FAILED(hResult))
			{
				swprintf(szErrorMessage, L"StringCchPrintf failed (0x%08X)\n", hResult);
				OutputDebugString(szErrorMessage);

				RegCloseKey(hServiceKey);
				continue;
			}

			hResult = StringCchCat(szServiceParametersKey, ARRAY_SIZE(szServiceParametersKey), L"Parameters");
			if (FAILED(hResult))
			{
				swprintf(szErrorMessage, L"StringCchCat failed (0x%08X)\n", hResult);
				OutputDebugString(szErrorMessage);

				RegCloseKey(hServiceKey);
				continue;
			}

			lRetVal = RegOpenKeyEx(
								HKEY_LOCAL_MACHINE,
								szServiceParametersKey,
								0,
								KEY_ALL_ACCESS,
								&hServiceParametersKey
								);
			if (ERROR_SUCCESS != lRetVal)
			{
				swprintf(szErrorMessage, L"RegOpenKeyEx failed for key (%s) with error (%d)\n", szServiceParametersKey, lRetVal);
				OutputDebugString(szErrorMessage);

				RegCloseKey(hServiceKey);
				continue;
			}

			dwcbData = sizeof(szServiceName);
			lRetVal = RegQueryValueEx(
									hServiceParametersKey,
									L"ServiceDll",
									NULL,
									NULL,
									(BYTE*)szServiceName,
									&dwcbData
									);
			if (ERROR_SUCCESS != lRetVal)
			{
				//_tprintf(_T("RegQueryValueEx failed (%d)\n"), lRetVal);
				RegCloseKey(hServiceParametersKey);
				RegCloseKey(hServiceKey);
				continue;
			}

			bRetVal = ConvertServiceDllPath(
										szServiceName,
										MAX_PATH_LEN,
										szServiceFullPath,
										MAX_PATH_LEN
										);
			if (FALSE == bRetVal)
			{
				swprintf(szErrorMessage, L"ConvertServiceDllPath failed for (%s)\n", szServiceName);
				OutputDebugString(szErrorMessage);
			}
			else
			{
				swprintf(szErrorMessage, L"Scanning file (%s)\n", szServiceFullPath);
				OutputDebugString(szErrorMessage);
				//	scan file.
				bRetVal = scanFile(szServiceFullPath);
				if (TRUE == bRetVal)
				{
					lRetVal = sprintf_s(szReportMessage, MAX_PATH_LEN * sizeof(CHAR), "Malicious service (%S)\n", szServiceFullPath);
					if (-1 == lRetVal)
					{
						swprintf(szErrorMessage, L"Report not generated for(%s)", szServiceFullPath);
						OutputDebugString(szErrorMessage);
					}
					else
					{
						fwrite(szReportMessage, sizeof(CHAR), lRetVal, g_pReportFile);
					}
				}
			}

			RegCloseKey(hServiceParametersKey);
		}
		else
		{
			dwcbData = sizeof(szServiceName);
			lRetVal = RegQueryValueEx(
									hServiceKey,
									L"ImagePath",
									NULL,
									NULL,
									(BYTE*)szServiceName,
									&dwcbData
									);
			if (ERROR_SUCCESS != lRetVal)
			{
				swprintf(szErrorMessage, L"RegQueryValueEx failed (%d)\n", lRetVal);
				OutputDebugString(szErrorMessage);

				RegCloseKey(hServiceKey);
				continue;
			}

			bRetVal = ConvertServiceImagePath(
										szServiceName,
										MAX_PATH_LEN,
										szServiceFullPath,
										MAX_PATH_LEN
										);
			if (FALSE == bRetVal)
			{
				swprintf(szErrorMessage, L"ConvertServiceImagePath failed for (%s)\n", szServiceName);
				OutputDebugString(szErrorMessage);
			}
			else
			{
				swprintf(szErrorMessage, L"Scanning file (%s)\n", szServiceFullPath);
				OutputDebugString(szErrorMessage);
				//	scan file.
				bRetVal = scanFile(szServiceFullPath);
				if (TRUE == bRetVal)
				{
					lRetVal = sprintf_s(szReportMessage, MAX_PATH_LEN * sizeof(CHAR), "Malicious service (%S)\n", szServiceFullPath);
					if (-1 == lRetVal)
					{
						swprintf(szErrorMessage, L"Report not generated for(%s)", szServiceFullPath);
						OutputDebugString(szErrorMessage);
					}
					else
					{
						fwrite(szReportMessage, sizeof(CHAR), lRetVal, g_pReportFile);
					}
				}
			}
		}

		RegCloseKey(hServiceKey);
	}
	RegCloseKey(hRootKey);

	OutputDebugString(_T("ScanServices: Exit.\n"));
	return TRUE;
}


BOOLEAN ConvertServiceDllPath(
	WCHAR *pwszServiceDllPath,
	DWORD dwcchServiceDllPathLen,
	WCHAR *pwszServiceDllFullpath,
	DWORD dwcchServiceDllFullPathLen
	)
{
	DWORD dwRetVal;
	HRESULT hResult;
	WCHAR *pwszTempPath;
	WCHAR szErrorMessage[MAX_PATH_LEN];
	WCHAR wszSystemRootPath[MAX_PATH_LEN];

	OutputDebugString(_T("ConvertServiceDllpath: Entry.\n"));

	if (NULL == pwszServiceDllPath || NULL == pwszServiceDllFullpath)
	{
		OutputDebugString(_T("ConvertServiceDllpath: Invalid parameters.\n"));
		return FALSE;
	}

	dwRetVal = GetSystemWindowsDirectory(wszSystemRootPath, MAX_PATH_LEN);
	if (0 == dwRetVal)
	{
		swprintf(szErrorMessage, L"GetSystemWindowsDirectory failed (%d)\n", GetLastError());
		OutputDebugString(szErrorMessage);
		
		return FALSE;
	}

	pwszTempPath = wcsstr(pwszServiceDllPath, L"\\");
	if (NULL == pwszTempPath)
	{
		OutputDebugString(_T("Invalid service dll path.\n"));
		return FALSE;
	}

	hResult = StringCchCopy(pwszServiceDllFullpath, dwcchServiceDllFullPathLen, wszSystemRootPath);
	if (FAILED(hResult))
	{
		swprintf(szErrorMessage, L"StringCchCopy failed (0x%08X)\n", hResult);
		OutputDebugString(szErrorMessage);

		return FALSE;
	}

	hResult = StringCchCat(pwszServiceDllFullpath, dwcchServiceDllFullPathLen, pwszTempPath);
	if (FAILED(hResult))
	{
		swprintf(szErrorMessage, L"StringCchCat failed (0x%08X)\n", hResult);
		OutputDebugString(szErrorMessage);

		return FALSE;
	}

	OutputDebugString(_T("ConvertServiceDllpath: Exit.\n"));
	return TRUE;
}

BOOLEAN ConvertServiceImagePath(
	WCHAR *pwszServiceImagePath,
	DWORD dwcchServiceImagePathLen,
	WCHAR *pwszServiceImageFullpath,
	DWORD dwcchServiceImageFullPathLen
	)
{
	int iRetVal;
	size_t size;
	UINT uiRetVal;
	WCHAR *pszPath;
	DWORD dwRetVal;
	HRESULT hResult;
	WCHAR *pwszTempPath;
	WCHAR wszTempPath[MAX_PATH_LEN];
	WCHAR wszFullPath[MAX_PATH_LEN];
	WCHAR wszWindowsDir[MAX_PATH_LEN];
	WCHAR szErrorMessage[MAX_PATH_LEN];


	OutputDebugString(_T("ConvertServiceImagePath: Entry.\n"));

	if (
		NULL == pwszServiceImagePath ||
		0 == dwcchServiceImagePathLen ||
		NULL == pwszServiceImageFullpath ||
		0 == dwcchServiceImageFullPathLen
		)
	{
		OutputDebugString(_T("Invalid parameters.\n"));
		return FALSE;
	}

	hResult = StringCchCopy(wszFullPath, MAX_PATH_LEN, pwszServiceImagePath);
	if (FAILED(hResult))
	{
		swprintf(szErrorMessage, L"StringCchCopy failed(0x%08X)\n", hResult);
		OutputDebugString(szErrorMessage);

		return FALSE;
	}

	//	Check if path contains ".
	if (wszFullPath[0] == L'\"')
	{
		pszPath = wszFullPath + 1;
		pwszTempPath = wcschr(pszPath, L'\"');
		if (NULL == pwszTempPath)
		{
			OutputDebugString(_T("Path contains starting \" but does not end with \".\n"));
			return FALSE;
		}
		*pwszTempPath = L'\0';
	}
	else
	{
		pszPath = wszFullPath;
	}

	//	Check if path contains %.
	if (pszPath[0] == L'%')
	{
		dwRetVal = ExpandEnvironmentStrings(pszPath, wszTempPath, MAX_PATH_LEN);
		if (0 == dwRetVal)
		{
			swprintf(szErrorMessage, L"ExpandEnvironmentStrings failed(%d)\n", GetLastError());
			OutputDebugString(szErrorMessage);

			return FALSE;
		}

		hResult = StringCchCopy(wszFullPath, MAX_PATH_LEN, wszTempPath);
		if (FAILED(hResult))
		{
			swprintf(szErrorMessage, L"StringCchCopy failed while copying expanded path(0x%08X)\n", hResult);
			OutputDebugString(szErrorMessage);

			return FALSE;
		}

		pszPath = wszFullPath;
	}

	//	Check if file path is followed by any arguments.
	pwszTempPath = wcsstr(pszPath, L".exe");
	if (NULL == pwszTempPath)
	{
		pwszTempPath = wcsstr(pszPath, L".EXE");
		if (NULL == pwszTempPath)
		{
			OutputDebugString(_T("Path is invalid. Does not contains .exe extension.\n"));

			return FALSE;
		}
	}

	size = wcslen(L".exe");
	pwszTempPath = pwszTempPath + size;
	*pwszTempPath = L'\0';

	//	Get windows directory path.
	uiRetVal = GetSystemWindowsDirectory(wszWindowsDir, MAX_PATH_LEN);
	if (0 == uiRetVal)
	{
		swprintf(szErrorMessage, L"GetSystemWindowsDirectory failed(%d)\n", GetLastError());
		OutputDebugString(szErrorMessage);
		
		return FALSE;
	}

	//	Check if path starts with "System32"
	size = wcslen(L"System32");
	iRetVal = _wcsnicmp(pszPath, L"System32", size);
	if (0 == iRetVal)
	{
		hResult = StringCchPrintf(wszTempPath, MAX_PATH_LEN, L"%s\\%s", wszWindowsDir, pszPath);
		if (FAILED(hResult))
		{
			swprintf(szErrorMessage, L"StringCchPrintf failed(0x%08X)\n", hResult);
			OutputDebugString(szErrorMessage);

			return FALSE;
		}

		hResult = StringCchCopy(wszFullPath, MAX_PATH_LEN, wszTempPath);
		if (FAILED(hResult))
		{
			swprintf(szErrorMessage, L"StringCchCopy while copying win dir and path (system32) failed(0x%08X)\n", hResult);
			OutputDebugString(szErrorMessage);

			return FALSE;
		}
		pszPath = wszFullPath;
	}

	//	Check if path starts with \SystemRoot
	size = wcslen(L"\\SystemRoot");
	iRetVal = _wcsnicmp(pszPath, L"\\SystemRoot", size);
	if (0 == iRetVal)
	{
		hResult = StringCchPrintf(wszTempPath, MAX_PATH_LEN, L"%s%s", wszWindowsDir, pszPath + size);
		if (FAILED(hResult))
		{
			swprintf(szErrorMessage, L"StringCchPrintf failed(0x%08X)\n", hResult);
			OutputDebugString(szErrorMessage);
			return FALSE;
		}

		hResult = StringCchCopy(wszFullPath, MAX_PATH_LEN, wszTempPath);
		if (FAILED(hResult))
		{
			swprintf(szErrorMessage, L"StringCchCopy while copying win dir and path (\\SystemRoot) failed(0x%08X)\n", hResult);
			OutputDebugString(szErrorMessage);
			return FALSE;
		}
		pszPath = wszFullPath;
	}

	//	Check if path starts with \Windows
	size = wcslen(L"\\Windows");
	iRetVal = _wcsnicmp(pszPath, L"\\Windows", size);
	if (0 == iRetVal)
	{
		hResult = StringCchPrintf(wszTempPath, MAX_PATH_LEN, L"%s%s", wszWindowsDir, pszPath + size);
		if (FAILED(hResult))
		{
			swprintf(szErrorMessage, L"StringCchPrintf failed(0x%08X)\n", hResult);
			OutputDebugString(szErrorMessage);
			return FALSE;
		}

		hResult = StringCchCopy(wszFullPath, MAX_PATH_LEN, wszTempPath);
		if (FAILED(hResult))
		{
			swprintf(szErrorMessage, L"StringCchCopy while copying win dir and path (\\Windows) failed(0x%08X)\n", hResult);
			OutputDebugString(szErrorMessage);
			return FALSE;
		}
		pszPath = wszFullPath;

	}

	hResult = StringCchCopy(pwszServiceImageFullpath, dwcchServiceImageFullPathLen, pszPath);
	if (FAILED(hResult))
	{
		swprintf(szErrorMessage, L"StringCchCopy failed(0x%08X) while copying path in out buffer.\n", hResult);
		OutputDebugString(szErrorMessage);
		return FALSE;
	}

	OutputDebugString(_T("ConvertServiceImagePath: Exit.\n"));
	return TRUE;
}