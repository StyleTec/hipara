#ifndef __MISC_H__
#define __MISC_H__

#include <Windows.h>

#define	HIPARA_MEMORY_SCAN_SERVICE			L"HiparaMemScan"
#define	HIPARA_MEMORY_SCAN_DRIVER			L"hiparamemscan.sys"
#define	SYSTEM32_DRIVERS_PATH				L"\\System32\\drivers\\"
#define MAX_LENGTH_PATH						260
#define	ARRAY_SIZE(X)						((sizeof(X)) / (sizeof(X[0])))

#define	HIPARA_UPDATE_SECTION_NAME			L"Update"
#define HIPARA_UPDATE_URL_KEY_NAME			L"URL"
#define	HIPARA_UPDATE_USERNAME_KEY_NAME		L"USERNAME"
#define	HIPARA_UPDATE_PASSWORD_KEY_NAME		L"PWD"

#define	HIPARA_CONFIG_INFO_SECTION_NAME		L"Options"
#define	HIPARA_ONLY_LOG_TO_SERVER_KEY_NAME	L"LOGTOSERVER"

#define	HIPARA_CONFIG_FILE_NAME				L"config.ini"

BOOLEAN
ConvertFromWideCharToMultiByte(
	WCHAR *pwszInput,
	UINT uiInputLen,
	PCHAR *ppszOutput,
	UINT *puiOutputLen
);

BOOLEAN
InstallMemoryScannerDriver(
	WCHAR *pwszDriverName,
	WCHAR *pwszServiceName
	);

BOOLEAN
UnInstallMemoryScannerDriver(
	WCHAR *pwszServiceName
);

BOOLEAN
GetConfigInfo(
BYTE *pbyLogToServer
);


BOOLEAN
LoadFilter(
	WCHAR *pwszFilterName
);


BOOLEAN
UnloadFilter(
	WCHAR *pwszFilterName
);


BOOLEAN
SetPrivilege(
	const TCHAR *pcszPrivilegeStr,
	BOOL bEnablePrivilege,
	DWORD *pdwError
);

#endif		// __MISC_H__