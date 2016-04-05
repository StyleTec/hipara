#ifndef __MISC_H__
#define __MISC_H__

#include <Windows.h>

#define	HIPARA_MEMORY_SCAN_SERVICE			L"HiparaMemScan"
#define	HIPARA_MEMORY_SCAN_DRIVER			L"hiparamemscan.sys"
#define	SYSTEM32_DRIVERS_PATH				L"\\System32\\drivers\\"
#define MAX_LENGTH_PATH						260
#define	ARRAY_SIZE(X)						((sizeof(X)) / (sizeof(X[0])))

BOOLEAN
ConvertFromWideCharToMultiByte(
	WCHAR *pwszInput,
	UINT uiInputLen,
	PCHAR *ppszOutput,
	UINT *puiOutputLen
);

BOOLEAN
InstallMemoryScannerDriver(
	);

BOOLEAN
UnInstallMemoryScannerDriver(
	);
#endif		// __MISC_H__