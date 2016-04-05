/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

    scrubber.h

Abstract:
    Header file which contains the structures, type definitions,
    constants, global variables and function prototypes that are
    only visible within the kernel.

Environment:

    Kernel mode

--*/
#ifndef __SCANNER_H__
#define __SCANNER_H__


///////////////////////////////////////////////////////////////////////////
//
//  Macros
//
///////////////////////////////////////////////////////////////////////////
#define MAX_FILE_PATH					512
///////////////////////////////////////////////////////////////////////////
//
//  Global variables
//
///////////////////////////////////////////////////////////////////////////


typedef struct _SCANNER_DATA {

    //
    //  The object that identifies this driver.
    //

    PDRIVER_OBJECT DriverObject;

    //
    //  The filter handle that results from a call to
    //  FltRegisterFilter.
    //

    PFLT_FILTER Filter;

    //
    //  Listens for incoming connections
    //

    PFLT_PORT ServerPort;

    //
    //  User process that connected to the port
    //

    PEPROCESS UserProcess;

    //
    //  Client port for a connection to user-mode
    //

    PFLT_PORT ClientPort;

} SCANNER_DATA, *PSCANNER_DATA;

extern SCANNER_DATA ScannerData;

typedef struct _SCANNER_STREAM_HANDLE_CONTEXT {

    BOOLEAN RescanRequired;
    
} SCANNER_STREAM_HANDLE_CONTEXT, *PSCANNER_STREAM_HANDLE_CONTEXT;

typedef struct _SCANNER_INSTANCE_CONTEXT
{
	UNICODE_STRING usDosVolumeName;

} SCANNER_INSTANCE_CONTEXT, *PSCANNER_INSTANCE_CONTEXT;

#pragma warning(push)
#pragma warning(disable:4200) // disable warnings for structures with zero length arrays.

typedef struct _SCANNER_CREATE_PARAMS {

    WCHAR String[0];

} SCANNER_CREATE_PARAMS, *PSCANNER_CREATE_PARAMS;

#pragma warning(pop)


///////////////////////////////////////////////////////////////////////////
//
//  Prototypes for the startup and unload routines used for 
//  this Filter.
//
//  Implementation in scanner.c
//
///////////////////////////////////////////////////////////////////////////
DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
ScannerUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
ScannerQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
ScannerPreCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
ScannerPostCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
ScannerPreCleanup (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
ScannerPreWrite (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

#if (WINVER >= 0x0602)

FLT_PREOP_CALLBACK_STATUS
ScannerPreFileSystemControl (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

#endif

NTSTATUS
ScannerInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );


VOID
ScannerContextCleanup(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
);

NTSTATUS
getDosVolumeName(
	PCFLT_RELATED_OBJECTS pFltObject,
	/*PUNICODE_STRING pusDosName*/
	PSCANNER_INSTANCE_CONTEXT pInstanceContext
);


BOOLEAN
getFilePath(
	PCFLT_RELATED_OBJECTS pFltObject,
	PFLT_FILE_NAME_INFORMATION pFileNameInfo,
	PWCHAR pszFilePath
);


BOOLEAN
IsSubstringPresentInString(
	PUNICODE_STRING pusString,
	PUNICODE_STRING pusSubString
);


#endif /* __SCANNER_H__ */

