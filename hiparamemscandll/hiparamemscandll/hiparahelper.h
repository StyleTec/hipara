#ifndef __HIPARAHELPER__
#define __HIPARAHELPER__

#ifdef HIPARAMEMSCANDLL_EXPORTS
#define HIPARAMEMSCANDLL_API __declspec(dllexport)
#else
#define HIPARAMEMSCANDLL_API __declspec(dllimport)
#endif

#include<Windows.h>

#define SIOCTL_TYPE 40000

#define IOCTL_GET_LENGTH\
	CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define IOCTL_PROC_INFO\
	CTL_CODE(SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#define IOCTL_HANDLE_INFO\
	CTL_CODE(SIOCTL_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)


#define MAX_PATH_LEN			512
#define	MAX_MODULE_COUNT		1024

#define ARRAY_SIZE(X)			((sizeof(X)) / (sizeof(X[0])))

#define	HIPARA_DEVICE_NAME		L"\\\\.\\HiparaMemScan"

#define	HIPARA_REG_PATH_SERVICES	L"SYSTEM\\CurrentControlSet\\Services"

typedef enum _ERROR
{
	SUCCESS = 0,
	FAILURE = 1,
	INVALID_PARAM = -1
}_ERROR;

//
//	Structures definitions.
//
typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
}UNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	ULONG PrivatePageCount;
	LARGE_INTEGER Reserver6[6];
}SYSTEM_PROCESS_INFORMATION;

typedef struct _YARA_CONTEXT{

	HANDLE hStopEvent;		// event to wait for finishing scan
	BOOLEAN bScanResult;	// set to TRUE if match found otherwise it returns FALSE.

} YARA_CONTEXT, *P_YARA_CONTEXT;

//
//	Function delcarations.
//
int
initYara(
);

void
deinitYara(
);

BOOLEAN
init(
	);

void 
deinit(
	);

BOOLEAN
ScanProcessAndModules(
	);

int
ScanProcessMemory(
	HANDLE hProcess,
	DWORD dwPid
	);


BOOLEAN
scanFile(
	PWCHAR pszFilePath
	);

BOOLEAN
ConvertFromWideCharToMultiByte(
	WCHAR *pwszInput,
	UINT uiInputLen,
	PCHAR *ppszOutput,
	UINT *puiOutputLen
	);

BOOLEAN
ScanProcessModules(
	HANDLE hProcess
	);

BOOLEAN ScanServices(
	);

BOOLEAN ConvertServiceDllPath(
	WCHAR *pwszServiceDllPath,
	DWORD dwcchServiceDllPathLen,
	WCHAR *pwszServiceDllFullpath,
	DWORD dwcchServiceDllFullPathLen
	);

BOOLEAN ConvertServiceImagePath(
	WCHAR *pwszServiceImagePath,
	DWORD dwcchServiceImagePathLen,
	WCHAR *pwszServiceImageFullpath,
	DWORD dwcchServiceImageFullPathLen
	);

#endif /*__HIPARAHELPER__*/