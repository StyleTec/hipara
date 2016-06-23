//#include<Winternl.h>

#define	SystemHandleInformation		16
#define	MAX_NAME_LENGTH				260
#define	MAX_HISTORY_COUNT			0x32
#define	SEARCH_PATTERN				L"0x320x00"

#define	ARRAY_SIZE(arr)	(sizeof(arr) / sizeof(arr[0]))

typedef NTSTATUS(NTAPI *PFN_NTQUERYSYSTEMINFORMATION)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

/* The following structure is actually called SYSTEM_HANDLE_TABLE_ENTRY_INFO, but SYSTEM_HANDLE is shorter. */
typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

//typedef struct COMMAND_HISTORY
//{
//	/*WCHAR wszProcessName[MAX_NAME_LENGTH];
//	ULONG ulProcessId;
//	PVOID pOffsetToHistory;*/
//	WCHAR wszApplicationName[MAX_NAME_LENGTH];
//	WCHAR wszFlags[MAX_NAME_LENGTH];
//	ULONG ulCommandCount;
//	WCHAR wszLastAdded[MAX_NAME_LENGTH];
//	WCHAR wszLastDisplayed[MAX_NAME_LENGTH];
//	WCHAR wszFirstCommand[MAX_NAME_LENGTH];
//	USHORT ulCommandMaxCount;
//	ULONG ulHandle;
//	ULONG ulCommandNumber;
//	PVOID pCommandOffset;
//	WCHAR wszCommand[MAX_NAME_LENGTH];
//
//}	COMMAND_HISTORY_INGO, *P_COMMAND_HISTORY_INFO;

typedef struct COMMAND
{
	USHORT ushCmdLen;
	WCHAR wszCommand[MAX_NAME_LENGTH];
} COMMAND, *P_COMMAND;

typedef struct COMMAND_HISTORY32
{
	USHORT	ushCommandCount;
	USHORT	ushLastAdded;
	USHORT	ushLastDisaplayed;
	USHORT	ushFirstCommand;
	USHORT	ushCommandMaxCount;
	UINT	uiHandle;
	VOID	*pCommandHistory1;
	VOID	*pCommandHistory2;
	COMMAND *pCommand[50];

} COMMAND_HISTORY32, *P_COMMAND_HISTORY32;

typedef struct COMMAND_HISTORY64
{
	USHORT	ushCommandCount;
	USHORT	ushLastAdded;
	USHORT	ushLastDisaplayed;
	USHORT	ushFirstCommand;
	USHORT	ushCommandMaxCount;
	BYTE	byReserved[6];
	UINT	uiHandle;
	VOID	*pCommandHistory1;
	VOID	*pCommandHistory2;
	COMMAND *pCommand[50];

} COMMAND_HISTORY64, *P_COMMAND_HISTORY64;

#ifdef _WIN32_
#define	COMMAND_HISTORY			COMMAND_HISTORY32
#else
#define COMMAND_HISTORY			COMMAND_HISTORY64
#endif

//typedef struct COMMAND_HISTORY
//{
//	LONGLONG	llListEntry;
//	ULONG		ulFlags;
//	WCHAR		*pwszApplication;
//	USHORT		ushCommandCount;
//	USHORT		ushLastAdded;
//	USHORT		ushLastDisaplayed;
//	USHORT		ushFirstCommand;
//	USHORT		ushCommandCountMax;
//	UINT		uiProcessHandle;
//	LONGLONG	llPopupList;
//	COMMAND		*pCommand[50];
//
//} COMMAND_HISTORY, *P_COMMAND_HISTORY;

typedef struct tagPRC_QUERY_HANDLE
{
	HANDLE						hCurrentProcess;
	HANDLE						hCMDProcess;
	PSYSTEM_HANDLE_INFORMATION	pSystemHandleInfo;

}	PRC_QUERY_HANDLE, *P_PRC_QUERY_HANDLE;


BOOLEAN LogCmdProcess(DWORD dwProcessIdToLog, HANDLE hStopEvent, HANDLE hProcessEvent, USHORT *pushCommandCount);

BOOLEAN GetProcessName(ULONG ulProcessId, WCHAR *pwszProcessName, ULONG ulcbSize);

BOOLEAN WriteProcessMemoryToFile(HANDLE hProcess, HANDLE hHandle, HANDLE hStopEvent, HANDLE hProcessEvent, USHORT *pushCommandCount);

BOOLEAN
LogCmdActivityToFile(
	BYTE *pbyCommand,
	DWORD dwcbCommand
	);


BOOLEAN
QueryCmdHistoryBuffer(
	DWORD dwProcessIdToLog,
	HANDLE *phProcess,
	COMMAND_HISTORY **ppCommandHistory
	);


BOOLEAN
ReleaseCmdHistoryBuffer(
	HANDLE hProcess
	);


BOOLEAN
QueryProcessInfo(
	SYSTEM_HANDLE_INFORMATION *pSystemHandleInfo,
	DWORD dwProcessIdToLog,
	PRC_QUERY_HANDLE *pPrcQueryHandle
	);


BOOLEAN
RealeseProcessInfo(
	PRC_QUERY_HANDLE *pPrcQueryHandle
	);


BOOLEAN
GetCommandHistoryBuffer(
	DWORD dwProcessIdToLog,
	HANDLE *phProcess,
	COMMAND_HISTORY **ppCommandHistory
	);


BOOLEAN
LogCmdActivity(
	HANDLE hProcess,
	COMMAND_HISTORY *pCommandHistory
	);
