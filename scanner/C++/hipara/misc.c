#include <Windows.h>
#include <fltUser.h>
#include <tchar.h>
#include <strsafe.h>
#include "misc.h"
#include "../inc/scanuk.h"

extern TCHAR gszInstallationDir[MAX_LENGTH_PATH];
WCHAR wszHiparaMemScanDriverPath[MAX_PATH];

#define	MEMSCAN_FOLDER_PATH		L"memscan"

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
		//OutputDebugString(_T("ConvertFromWideCharToMultiByte: Invalid Parameter.\n"));
		return FALSE;
	}

	iLen = WideCharToMultiByte(CP_UTF8, 0, pwszInput, -1, NULL, 0, NULL, NULL);

	*ppszOutput = (CHAR *)malloc(iLen);
	if (NULL == *ppszOutput)
	{
		//OutputDebugString(_T("ConvertFromWideCharToMultiByte: Memory allocation failed to ppszOutput.\n"));
		return FALSE;
	}

	iLen = WideCharToMultiByte(CP_UTF8, 0, pwszInput, -1, *ppszOutput, iLen, NULL, NULL);
	if (0 == iLen)
	{
		//OutputDebugString(_T("ConvertFromWideCharToMultiByte: WideCharToMultiByte failed(%d)\n", GetLastError()));

		free(*ppszOutput);
		return FALSE;
	}

	*puiOutputLen = iLen;
	return TRUE;
}

BOOLEAN
InstallMemoryScannerDriver(
	WCHAR *pwszDriverName,
	WCHAR *pwszServiceName
	)
{
	PVOID pVoid;
	BOOL boRetVal;
	UINT uiRetVal;
	DWORD dwRetVal;
	HRESULT hResult;
	WCHAR *pwszTemp;
	SC_HANDLE hService;
	SC_HANDLE hSCManager;
	WCHAR wszErrMsg[MAX_LENGTH_PATH];
	WCHAR wszWindowsDir[MAX_LENGTH_PATH];
	WCHAR wszDriverPath[MAX_LENGTH_PATH];
	WCHAR wszModulePath[MAX_LENGTH_PATH];
	WCHAR wszDriverImagePath[MAX_LENGTH_PATH];

	OutputDebugString(_T("InstallMemoryScannerDriver: Entry.\n"));

	if (NULL == pwszDriverName || NULL == pwszServiceName)
	{
		//OutputDebugString(L"Invalid parameters.");

		return FALSE;
	}

	boRetVal = Wow64DisableWow64FsRedirection(&pVoid);

	uiRetVal = GetSystemWindowsDirectory(wszWindowsDir, MAX_LENGTH_PATH);
	if (0 == uiRetVal)
	{
		swprintf(wszErrMsg, L"GetSystemWindowsDirectory failed(%d).", GetLastError());
		//OutputDebugString(wszErrMsg);

		boRetVal = Wow64RevertWow64FsRedirection(pVoid);
		return FALSE;
	}
	
	hResult = StringCchPrintf(wszDriverPath, ARRAY_SIZE(wszDriverPath), L"%s%s%s", wszWindowsDir, SYSTEM32_DRIVERS_PATH, pwszDriverName);
	if (FAILED(hResult))
	{
		swprintf(wszErrMsg, L"StringCchPrintf(1) failed(0x%08X).\n", hResult);
		OutputDebugString(wszErrMsg);

		boRetVal = Wow64RevertWow64FsRedirection(pVoid);
		return FALSE;
	}

	hResult = StringCchCopy(wszHiparaMemScanDriverPath, ARRAY_SIZE(wszHiparaMemScanDriverPath), wszDriverPath);
	if (FAILED(hResult))
	{
		wszHiparaMemScanDriverPath[0] = '\0';
	}

	swprintf(wszErrMsg, L"Driver Path (%s).", wszDriverPath);
	OutputDebugString(wszErrMsg);

	dwRetVal = GetModuleFileName(NULL, wszModulePath, MAX_LENGTH_PATH);
	if (0 == dwRetVal)
	{
		swprintf(wszErrMsg, L"GetModuleFileName failed(%d).", GetLastError());
		OutputDebugString(wszErrMsg);

		boRetVal = Wow64RevertWow64FsRedirection(pVoid);
		return FALSE;
	}

	pwszTemp = wcsrchr(wszModulePath, L'\\');
	if (NULL == pwszTemp)
	{
		//OutputDebugString(_T("GetModuleFileName returned wrong path.\n"));
		
		boRetVal = Wow64RevertWow64FsRedirection(pVoid);
		return FALSE;
	}

	*pwszTemp = L'\0';

	swprintf(wszErrMsg, L"Module Path (%s).", wszModulePath);
	OutputDebugString(wszErrMsg);

	hResult = StringCchPrintf(wszDriverImagePath, ARRAY_SIZE(wszDriverImagePath), L"%s\\%s\\%s", wszModulePath, MEMSCAN_FOLDER_PATH, pwszDriverName);
	if (FAILED(hResult))
	{
		swprintf(wszErrMsg, L"StringCchPrintf(2) failed(0x%08X).\n", hResult);
		OutputDebugString(wszErrMsg);

		boRetVal = Wow64RevertWow64FsRedirection(pVoid);
		return FALSE;
	}

	swprintf(wszErrMsg, L"Driver image Path (%s).", wszDriverImagePath);
	OutputDebugString(wszErrMsg);

	//
	//	Copy driver file to system32\drivers folder.
	//
	boRetVal = CopyFile(wszDriverImagePath, wszDriverPath, FALSE);
	if (0 == boRetVal)
	{
		swprintf(wszErrMsg, L"CopyFile failed(%d).", GetLastError());
		//OutputDebugString(wszErrMsg);

		boRetVal = Wow64RevertWow64FsRedirection(pVoid);
		return FALSE;
	}

	boRetVal = Wow64RevertWow64FsRedirection(pVoid);

	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == hSCManager)
	{
		swprintf(wszErrMsg, L"OpenSCManager failed(%d).", GetLastError());
		//OutputDebugString(wszErrMsg);

		return FALSE;
	}

	hService = CreateService(
						hSCManager,
						pwszServiceName,
						pwszServiceName,
						SERVICE_ALL_ACCESS,
						SERVICE_KERNEL_DRIVER,
						SERVICE_DEMAND_START,
						SERVICE_ERROR_NORMAL,
						wszDriverPath,
						NULL,
						NULL,
						NULL,
						NULL,
						NULL
						);
	if (NULL == hService)
	{
		dwRetVal = GetLastError();

		//
		//	If service is already present, then just open that service and start it.
		//
		if (1073 == dwRetVal)
		{
			hService = OpenService(hSCManager, pwszServiceName, SERVICE_ALL_ACCESS);
			if (NULL == hService)
			{
				swprintf(wszErrMsg, L"OpenService failed(%d).", GetLastError());
				OutputDebugString(wszErrMsg);

				CloseServiceHandle(hSCManager);
				return FALSE;
			}

			boRetVal = StartService(hService, 0, NULL);
			if (0 == boRetVal)
			{
				swprintf(wszErrMsg, L"StartService failed(%d).", GetLastError());
				OutputDebugString(wszErrMsg);
			}
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCManager);

			OutputDebugString(_T("InstallMemoryScannerDriver: Exit.\n"));
			return TRUE;
		}
		swprintf(wszErrMsg, L"CreateService failed(%d).", GetLastError());
		OutputDebugString(wszErrMsg);
		
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	boRetVal = StartService(hService, 0, NULL);
	if (0 == boRetVal)
	{
		swprintf(wszErrMsg, L"StartService failed(%d).", GetLastError());
		OutputDebugString(wszErrMsg);

		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

	OutputDebugString(_T("InstallMemoryScannerDriver: Exit.\n"));

	return TRUE;
}

BOOLEAN
UnInstallMemoryScannerDriver(
	WCHAR *pwszServiceName
	)
{
	PVOID pVoid;
	DWORD dwError;
	BOOL boRetVal;
	SC_HANDLE hService;
	SC_HANDLE hSCManager;
	SERVICE_STATUS serviceStatus;
	WCHAR wszErrMsg[MAX_LENGTH_PATH];

	//OutputDebugString(_T("UnInstallMemoryScannerDriver: Entry.\n"));

	if (NULL == pwszServiceName)
	{
		//OutputDebugString(L"Invalid parameter.");

		return FALSE;
	}

	boRetVal = Wow64DisableWow64FsRedirection(&pVoid);

	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == hSCManager)
	{
		swprintf(wszErrMsg, L"OpenSCManager failed(%d).", GetLastError());
		//OutputDebugString(wszErrMsg);

		boRetVal = Wow64RevertWow64FsRedirection(pVoid);
		return FALSE;
	}

	hService = OpenService(hSCManager, pwszServiceName, SERVICE_ALL_ACCESS | DELETE);
	if (NULL == hService)
	{
		swprintf(wszErrMsg, L"OpenService failed(%d).", GetLastError());
		//OutputDebugString(wszErrMsg);

		CloseServiceHandle(hSCManager);
		boRetVal = Wow64RevertWow64FsRedirection(pVoid);
		return FALSE;
	}

	boRetVal = ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus);
	if (0 == boRetVal)
	{
		dwError = GetLastError();
		swprintf(wszErrMsg, L"ControlService failed(%d).", GetLastError());
		//OutputDebugString(wszErrMsg);

		//
		//	If ControlService fails due to 'The service has not been started.' then just delete the service.
		//	So that it will not faile next time while installation.
		//
		if (1062 == dwError)
		{
			DeleteService(hService);
		}

		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		boRetVal = Wow64RevertWow64FsRedirection(pVoid);
		return FALSE;
	}

	boRetVal = DeleteService(hService);
	if (0 == boRetVal)
	{
		swprintf(wszErrMsg, L"DeleteService failed(%d).", GetLastError());
		//OutputDebugString(wszErrMsg);

		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		boRetVal = Wow64RevertWow64FsRedirection(pVoid);
		return FALSE;
	}

	if ('\0' != wszHiparaMemScanDriverPath[0])
	{
		DeleteFile(wszHiparaMemScanDriverPath);
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	boRetVal = Wow64RevertWow64FsRedirection(pVoid);

	//OutputDebugString(_T("UnInstallMemoryScannerDriver: Exit.\n"));
	return TRUE;
}

BOOLEAN
GetConfigInfo(
BYTE *pbyLogToServer
)
{
	INT iRetVal;
	HRESULT hrRetVal;
	TCHAR errMsg[MAX_PATH];
	WCHAR wszConfigFilePath[MAX_LENGTH_PATH];

	//OutputDebugString(_T("GetSignatureServerUrl: Entry.\n"));

	if (NULL == pbyLogToServer)
	{
		OutputDebugString(_T("GetConfigInfo: Invalid Parameter.\n"));
		return FALSE;
	}

	*pbyLogToServer = 0;

	hrRetVal = StringCchPrintf(wszConfigFilePath, MAX_LENGTH_PATH, _T("%s\\%s"), gszInstallationDir, HIPARA_CONFIG_FILE_NAME);
	if (FAILED(hrRetVal))
	{
		//OutputDebugString(_T("StringCchPrintf failed while creating ini file path.\n"));
		return FALSE;
	}

	/*_stprintf_s(errMsg, sizeof(errMsg), _T("GetConfigInfo: Config file path(%s)\n."), wszConfigFilePath);
	OutputDebugString(errMsg);*/

	iRetVal = GetPrivateProfileInt(
		HIPARA_CONFIG_INFO_SECTION_NAME,
		HIPARA_ONLY_LOG_TO_SERVER_KEY_NAME,
		-1,
		wszConfigFilePath
		);
	if (-1 == iRetVal)
	{
		/*_stprintf_s(errMsg, sizeof(errMsg), _T("GetPrivateProfileInt failed with error(%d)."), GetLastError());
		OutputDebugString(errMsg);*/
	}
	else
	{
		if (1 == iRetVal)
		{
			*pbyLogToServer = 1;
		}
	}

	_stprintf_s(errMsg, sizeof(errMsg), _T("GetConfigInfo: LogToServer(%d)\n."), iRetVal);
	OutputDebugString(errMsg);

	//OutputDebugString(_T("GetSignatureServerUrl: Exit.\n"));
	return TRUE;
}


BOOLEAN
LoadFilter(
WCHAR *pwszFilterName
)
{
	HRESULT hRes;
	DWORD dwError;
	BOOLEAN bRetVal;

#if DEBUG_LOG_LOADFILTER
	TCHAR errMsg[MAX_PATH];
	OutputDebugString(_T("LoadFilter: Entry.\n"));
#endif

	//
	//	Parameter validation.
	//
	if (NULL == pwszFilterName)
	{
#if DEBUG_LOG_LOADFILTER
		OutputDebugString(_T("LoadFilter: Invalid parameter.\n"));
#endif

		return FALSE;
	}

	bRetVal = SetPrivilege(_T("SeLoadDriverPrivilege"), TRUE, &dwError);
	if (FALSE == bRetVal)
	{
		//	No need to return.
	}

	hRes = FilterLoad(pwszFilterName);
	if (FAILED(hRes))
	{
		if (
			HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) == hRes ||
			HRESULT_FROM_WIN32(ERROR_SERVICE_ALREADY_RUNNING) == hRes
			)
		{
			return TRUE;
		}

		return FALSE;
	}

#if DEBUG_LOG_LOADFILTER
	OutputDebugString(_T("LoadFilter: Exit.\n"));
#endif

	return TRUE;
}


BOOLEAN
UnloadFilter(
WCHAR *pwszFilterName
)
{
	HRESULT hRes;

	hRes = FilterUnload(pwszFilterName);
	if (FAILED(hRes))
	{
		return FALSE;
	}

	return TRUE;
}


BOOLEAN
SetPrivilege(
const TCHAR *pcszPrivilegeStr,
BOOL bEnablePrivilege,
DWORD *pdwError
)
{
	BOOL bRet;
	LUID luid;
	HANDLE hToken;
	HANDLE hProcess;
	TOKEN_PRIVILEGES tokenPrivilege;

	if (NULL == pcszPrivilegeStr || NULL == pdwError)
	{
		return FALSE;
	}

	//
	//	No need to check the return value. As per the documentation, the function does not fail.
	//
	hProcess = GetCurrentProcess();

	bRet = OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	if (FALSE == bRet)
	{
		*pdwError = GetLastError();
		return FALSE;
	}

	bRet = LookupPrivilegeValue(NULL, pcszPrivilegeStr, &luid);
	if (FALSE == bRet)
	{
		*pdwError = GetLastError();
		CloseHandle(hToken);
		return FALSE;
	}

	ZeroMemory(&tokenPrivilege, sizeof(tokenPrivilege));
	tokenPrivilege.PrivilegeCount = 1;
	tokenPrivilege.Privileges[0].Luid = luid;
	if (TRUE == bEnablePrivilege)
	{
		tokenPrivilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else
	{
		tokenPrivilege.Privileges[0].Attributes = 0;
	}

	//
	//	Adjust Token privileges.
	//
	bRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivilege, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (FALSE == bRet)
	{
		*pdwError = GetLastError();
		CloseHandle(hToken);
		return FALSE;
	}

	*pdwError = GetLastError();

	if (ERROR_NOT_ALL_ASSIGNED == *pdwError)
	{
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);

	return TRUE;
}