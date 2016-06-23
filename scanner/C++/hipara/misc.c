#include <tchar.h>
#include <strsafe.h>
#include "misc.h"


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

	//OutputDebugString(_T("InstallMemoryScannerDriver: Entry.\n"));

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
		//OutputDebugString(wszErrMsg);

		boRetVal = Wow64RevertWow64FsRedirection(pVoid);
		return FALSE;
	}

	swprintf(wszErrMsg, L"Driver Path (%s).", wszDriverPath);
	//OutputDebugString(wszErrMsg);

	dwRetVal = GetModuleFileName(NULL, wszModulePath, MAX_LENGTH_PATH);
	if (0 == dwRetVal)
	{
		swprintf(wszErrMsg, L"GetModuleFileName failed(%d).", GetLastError());
		//OutputDebugString(wszErrMsg);

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
	//OutputDebugString(wszErrMsg);

	hResult = StringCchPrintf(wszDriverImagePath, ARRAY_SIZE(wszDriverImagePath), L"%s\\%s", wszModulePath, pwszDriverName);
	if (FAILED(hResult))
	{
		swprintf(wszErrMsg, L"StringCchPrintf(2) failed(0x%08X).\n", hResult);
		//OutputDebugString(wszErrMsg);

		boRetVal = Wow64RevertWow64FsRedirection(pVoid);
		return FALSE;
	}

	swprintf(wszErrMsg, L"Driver image Path (%s).", wszDriverImagePath);
	//OutputDebugString(wszErrMsg);

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
		swprintf(wszErrMsg, L"CreateService failed(%d).", GetLastError());
		//OutputDebugString(wszErrMsg);
		
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	boRetVal = StartService(hService, 0, NULL);
	if (0 == boRetVal)
	{
		swprintf(wszErrMsg, L"StartService failed(%d).", GetLastError());
		//OutputDebugString(wszErrMsg);

		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

	//OutputDebugString(_T("InstallMemoryScannerDriver: Exit.\n"));

	return TRUE;
}

BOOLEAN
UnInstallMemoryScannerDriver(
	WCHAR *pwszServiceName
	)
{
	PVOID pVoid;
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
		swprintf(wszErrMsg, L"ControlService failed(%d).", GetLastError());
		//OutputDebugString(wszErrMsg);

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

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	boRetVal = Wow64RevertWow64FsRedirection(pVoid);

	//OutputDebugString(_T("UnInstallMemoryScannerDriver: Exit.\n"));
	return TRUE;
}