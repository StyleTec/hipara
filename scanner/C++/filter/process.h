//
//	process.c
//	Author: Sujay Upasani.
//	Date: 07 May 2016.
//	Created.
//

//////////////////////////////////////////////////////////////////////////
//	I N C L U D E
//////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////
//	M A C R O.
//////////////////////////////////////////////////////////////////////////

#define	TAG_NAME_PROCESS_NOTIFICATION							'corp'

#define	CONHOST_PROCESS_FILE_PATH								L"\\SystemRoot\\System32\\conhost.exe"
#define	CONHOST_PROCESS_FILE_PATH_WOW64							L"\\SystemRoot\\SysWOW64\\conhost.exe"

#define	CMDFLT_RESOLVED_PROCESS_PATH_NONE						0x000000000
#define	CMDFLT_RESOLVED_PROCESS_PATH_CONHOST					0x000000001
#define	CMDFLT_RESOLVED_PROCESS_PATH_CONHOST_WOW64				0x000000002

#define	ARRAY_SIXE(X)											((sizeof(X)) / (sizeof(X[0])))


//////////////////////////////////////////////////////////////////////////
//	STRUCTURES.
//////////////////////////////////////////////////////////////////////////

#pragma pack(push, 1)
typedef struct tagDRIVER_GLOBALS
{
	ULONG	ulFlags;			//	See CMDFLT_RESOLVED_PROCESS_PATH_XXX.
	WCHAR	wszConhostPath[1024];
	WCHAR	wszConhostPathWow64[1024];

}	DRIVER_GLOBALS, *P_DRIVER_GLOBALS;
#pragma pack(pop)


//////////////////////////////////////////////////////////////////////////
//	F U N C T I O N D E F I N A T I O N S.
//////////////////////////////////////////////////////////////////////////


NTSTATUS
InitProcessNotificationRoutine(
	);


NTSTATUS
DeinitProcessNotificationRoutine(
	);


VOID
CreateProcessNotifyRoutine(
	PEPROCESS Process,
	HANDLE hProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
	);


NTSTATUS
NotifyProcessToApp(
	HANDLE hParentId,
	HANDLE hProcessId,
	BOOLEAN bCreate
	);


NTSTATUS
InitProcessPaths(
	);


NTSTATUS
GetProcessPath(
	const WCHAR *pcwszPath,
	WCHAR *pwszProcessPath,
	ULONG ulcchProcessPath
	);


BOOLEAN
IsCMDProcess(
	PFILE_OBJECT pFileObject
	);


//////////////////////////////////////////////////////////////////////////
//	T Y P E D E F S.
//////////////////////////////////////////////////////////////////////////
