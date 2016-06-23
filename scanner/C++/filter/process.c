//
//	process.c
//	Author: Sujay Upasani.
//	Date: 07 May 2016.
//	Created.
//

//////////////////////////////////////////////////////////////////////////
//	I N C L U D E
//////////////////////////////////////////////////////////////////////////

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#include "process.h"
#include "scanner.h"
//#include "cmdflt.h"

#include "procuk.h"


//////////////////////////////////////////////////////////////////////////
//	M A C R O.
//////////////////////////////////////////////////////////////////////////

typedef unsigned char BYTE;


//////////////////////////////////////////////////////////////////////////
//	STRUCTURES.
//////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////
//	E X T E R N   V A R I A B L E S.
//////////////////////////////////////////////////////////////////////////

//
//  Structure that contains all the global data structures
//  used throughout the scanner.
//

extern SCANNER_DATA ScannerData;
DRIVER_GLOBALS DriverGlobals;


//////////////////////////////////////////////////////////////////////////
//	F U N C T I O N D E F I N A T I O N S.
//////////////////////////////////////////////////////////////////////////


NTSTATUS
InitProcessNotificationRoutine(
	)
{
	NTSTATUS NTStatus;

	NTStatus = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)CreateProcessNotifyRoutine, FALSE);
	
	return NTStatus;
}


NTSTATUS
DeinitProcessNotificationRoutine(
	)
{
	NTSTATUS NTStatus;

	NTStatus = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)CreateProcessNotifyRoutine, TRUE);

	return NTStatus;
}


VOID
CreateProcessNotifyRoutine(
	PEPROCESS Process,
	HANDLE hProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
	)
{
	BOOLEAN bRetVal;

	UNREFERENCED_PARAMETER(Process);

	if (NULL != CreateInfo)
	{
		bRetVal = IsCMDProcess(CreateInfo->FileObject);
		if (TRUE == bRetVal)
		{
			NotifyProcessToApp(CreateInfo->ParentProcessId, hProcessId, TRUE);
		}
	}
	else
	{
		NotifyProcessToApp(NULL, hProcessId, FALSE);
	}
}


NTSTATUS
NotifyProcessToApp(
	HANDLE hParentId,
	HANDLE hProcessId,
	BOOLEAN bCreate
	)
{
	NTSTATUS NTStatus;
	PROCESS_NOTIFICATION *pProcessNotifiction;

	UNREFERENCED_PARAMETER(hParentId);

	pProcessNotifiction = ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_NOTIFICATION), TAG_NAME_PROCESS_NOTIFICATION);
	if (NULL == pProcessNotifiction)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//
	//	Fill process information data.
	//
	pProcessNotifiction->bCreate = bCreate;
	pProcessNotifiction->ulProcessId = (ULONG)(ULONG_PTR)hProcessId;

	NTStatus = FltSendMessage(
							ScannerData.Filter,
							&ScannerData.ClientPortCmd,
							pProcessNotifiction,
							sizeof(PROCESS_NOTIFICATION),
							NULL,
							0,
							NULL
							);
	if (STATUS_SUCCESS != NTStatus)
	{
		ExFreePoolWithTag(pProcessNotifiction, TAG_NAME_PROCESS_NOTIFICATION);
		return NTStatus;
	}

	ExFreePoolWithTag(pProcessNotifiction, TAG_NAME_PROCESS_NOTIFICATION);
	return STATUS_SUCCESS;
}


NTSTATUS
InitProcessPaths(
	)
{
	NTSTATUS NTStatus;

	NTStatus = GetProcessPath(CONHOST_PROCESS_FILE_PATH, DriverGlobals.wszConhostPath, ARRAY_SIXE(DriverGlobals.wszConhostPath));
	if (STATUS_SUCCESS == NTStatus)
	{
		DriverGlobals.ulFlags |= CMDFLT_RESOLVED_PROCESS_PATH_CONHOST;
	}

	NTStatus = GetProcessPath(CONHOST_PROCESS_FILE_PATH_WOW64, DriverGlobals.wszConhostPathWow64, ARRAY_SIXE(DriverGlobals.wszConhostPathWow64));
	if (STATUS_SUCCESS == NTStatus)
	{
		DriverGlobals.ulFlags |= CMDFLT_RESOLVED_PROCESS_PATH_CONHOST_WOW64;
	}

	return STATUS_SUCCESS;
}


NTSTATUS
GetProcessPath(
	const WCHAR *pcwszPath,
	WCHAR *pwszProcessPath,
	ULONG ulcchProcessPath
	)
{
	ULONG ulLen;
	HANDLE hFile;
	NTSTATUS NTStatus;
	PVOID pvFileObject;
	IO_STATUS_BLOCK IoSB;
	OBJECT_ATTRIBUTES oa;
	ULONG ulLenghtReturned;
	UNICODE_STRING usLinkPath;
	UNICODE_STRING usPathTempPath;
	POBJECT_NAME_INFORMATION pObjName;

	#undef	__DEBUG_FOR_THIS_FUNCTION_ONLY__
	#define	__DEBUG_FOR_THIS_FUNCTION_ONLY__	DEBUG_GETPROCESSPATH

	#if	__DEBUG_FOR_THIS_FUNCTION_ONLY__
	DoTraceEx(TRACE_LEVEL_INFORMATION, FNS_ANALYSIS, ("==>GetProcessPath."));
	#endif

	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		#if	__DEBUG_FOR_THIS_FUNCTION_ONLY__
		DoTraceEx(TRACE_LEVEL_INFORMATION, FNS_ANALYSIS, ("GetProcessPath: IRQL > PASSIVE_LEVEL."));
		#endif

		return STATUS_UNSUCCESSFUL;
	}

	if (
		NULL == pcwszPath		||
		NULL == pwszProcessPath	||
		0 == ulcchProcessPath
		)
	{
		#if	__DEBUG_FOR_THIS_FUNCTION_ONLY__
		DoTraceEx(TRACE_LEVEL_INFORMATION, FNS_ANALYSIS, ("GetProcessPath: NULL parameter."));
		#endif

		return STATUS_UNSUCCESSFUL;
	}

	RtlInitUnicodeString(&usLinkPath, pcwszPath);

	InitializeObjectAttributes(
							&oa,
							&usLinkPath,
							OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
							NULL,
							NULL
							);

	NTStatus = ZwCreateFile(
						&hFile,
						GENERIC_READ,
						&oa,
						&IoSB,
						0,
						FILE_ATTRIBUTE_NORMAL,
						FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
						FILE_OPEN,
						FILE_SYNCHRONOUS_IO_NONALERT,
						NULL,
						0
						);
	if (!NT_SUCCESS(NTStatus))
	{
		#if __DEBUG_FOR_THIS_FUNCTION_ONLY__
		DoTraceEx(TRACE_LEVEL_INFORMATION, FNS_ANALYSIS, ("GetProcessPath: ZwCreateFile failed 0x%08X."), NTStatus);
		#endif

		return NTStatus;
	}

	NTStatus = ObReferenceObjectByHandle(
										hFile,
										0,
										*IoFileObjectType,
										KernelMode,
										&pvFileObject,
										NULL
										);
	if (!NT_SUCCESS(NTStatus))
	{
		#if __DEBUG_FOR_THIS_FUNCTION_ONLY__
		DoTraceEx(TRACE_LEVEL_INFORMATION, FNS_ANALYSIS, ("GetProcessPath: ObReferenceObjectByHandle failed 0x%08X."), NTStatus);
		#endif

		ZwClose(hFile);
		return NTStatus;
	}

	ulLen = (1024 * sizeof(WCHAR)) + sizeof(OBJECT_NAME_INFORMATION);
	pObjName = (OBJECT_NAME_INFORMATION *)ExAllocatePoolWithTag(PagedPool, ulLen, 'htap');
	if (NULL == pObjName)
	{
		#if __DEBUG_FOR_THIS_FUNCTION_ONLY__
		DoTraceEx(TRACE_LEVEL_INFORMATION, FNS_ANALYSIS, ("GetProcessPath: Inssufficient memory for pObjName"));
		#endif

		ObDereferenceObject(pvFileObject);
		ZwClose(hFile);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	NTStatus = ObQueryNameString(pvFileObject, pObjName, ulLen, &ulLenghtReturned);
	if (!NT_SUCCESS(NTStatus))
	{
		#if __DEBUG_FOR_THIS_FUNCTION_ONLY__
		DoTraceEx(TRACE_LEVEL_INFORMATION, FNS_ANALYSIS, ("GetProcessPath: ObQueryNameString failed 0x%08X."), NTStatus);
		#endif

		ExFreePoolWithTag(pObjName, 'htap');
		ObDereferenceObject(pvFileObject);
		ZwClose(hFile);
		return NTStatus;
	}

	if ((pObjName->Name).Length >= ulcchProcessPath * sizeof(WCHAR))
	{
		#if	__DEBUG_FOR_THIS_FUNCTION_ONLY__
		DoTraceEx(TRACE_LEVEL_ERROR, FNS_STRING, "FnsCopyUnicodeString: pusSourceString->Length >= ulcbBuffer.");
		#endif

		ExFreePoolWithTag(pObjName, 'htap');
		ObDereferenceObject(pvFileObject);
		ZwClose(hFile);
		return STATUS_BUFFER_TOO_SMALL;
	}

	//
	//	Initialize destination string members.
	//
	usPathTempPath.Length = 0;
	usPathTempPath.MaximumLength = (USHORT)((ulcchProcessPath * sizeof(WCHAR)) - sizeof(WCHAR));
	usPathTempPath.Buffer = pwszProcessPath;

	//
	//	Copy string.
	//
	RtlCopyUnicodeString(&usPathTempPath, &pObjName->Name);

	//
	//	Make string NULL terminated.
	//
	usPathTempPath.Buffer[usPathTempPath.Length / sizeof(WCHAR)] = L'\0';

	ExFreePoolWithTag(pObjName, 'htap');
	ObDereferenceObject(pvFileObject);
	ZwClose(hFile);

	#if	__DEBUG_FOR_THIS_FUNCTION_ONLY__
	DoTraceEx(TRACE_LEVEL_INFORMATION, FNS_ANALYSIS, ("<==GetProcessPath."));
	#endif

	return STATUS_SUCCESS;
}


BOOLEAN
IsCMDProcess(
	PFILE_OBJECT pFileObject
	)
{
	LONG lRetVal;
	NTSTATUS NTStatus;
	UNICODE_STRING usFilePath;
	PFLT_FILE_NAME_INFORMATION pFileNameInformation;

	if (NULL == pFileObject)
	{
		return FALSE;
	}

	//
	//	We can use the imagepath, so used FileObject.
	//	This function is used as per Microsoft document for process protection.
	//
	NTStatus = FltGetFileNameInformationUnsafe(
											pFileObject,
											NULL,
											FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
											&pFileNameInformation
											);
	if (!NT_SUCCESS(NTStatus))
	{
		return FALSE;
	}

	lRetVal = -1;
	if (DriverGlobals.ulFlags & CMDFLT_RESOLVED_PROCESS_PATH_CONHOST)
	{
		RtlInitUnicodeString(&usFilePath, DriverGlobals.wszConhostPath);
		lRetVal = RtlCompareUnicodeString(&usFilePath, &pFileNameInformation->Name, TRUE);
	}

	if (0 != lRetVal && (DriverGlobals.ulFlags & CMDFLT_RESOLVED_PROCESS_PATH_CONHOST_WOW64))
	{
		RtlInitUnicodeString(&usFilePath, DriverGlobals.wszConhostPathWow64);
		lRetVal = RtlCompareUnicodeString(&usFilePath, &pFileNameInformation->Name, TRUE);
	}

	FltReleaseFileNameInformation(pFileNameInformation);

	return (0 == lRetVal);
}



//////////////////////////////////////////////////////////////////////////
//	T Y P E D E F S.
//////////////////////////////////////////////////////////////////////////
