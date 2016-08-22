/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

    scanner.c

Abstract:

    This is the main module of the scanner filter.

    This filter scans the data in a file before allowing an open to proceed.  This is similar
    to what virus checkers do.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "scanuk.h"
#include "process.h"
#include "scanner.h"
#include "filecache.h"

#pragma warning(disable : 4995)
#include <ntstrsafe.h>
#include <strsafe.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#define SCANNER_REG_TAG       'Rncs'
#define SCANNER_STRING_TAG    'Sncs'

//
//  Structure that contains all the global data structures
//  used throughout the scanner.
//

SCANNER_DATA ScannerData;

//
//  This is a static list of file name extensions files we are interested in scanning
//

PUNICODE_STRING ScannedExtensions;
ULONG ScannedExtensionCount;

extern FILE_CACHE_MGR	g_s_FileCacheMgr;

//
//  The default extension to scan if not configured in the registry
//

UNICODE_STRING ScannedExtensionDefault = RTL_CONSTANT_STRING( L"doc" );

//
//  Function prototypes
//

NTSTATUS 
ScannerInitializeScannedExtensions(
    _In_ PUNICODE_STRING RegistryPath
    );

VOID
ScannerFreeExtensions(
    );

NTSTATUS
ScannerAllocateUnicodeString (
    _Inout_ PUNICODE_STRING String
    );

VOID
ScannerFreeUnicodeString (
    _Inout_ PUNICODE_STRING String
    );

NTSTATUS
ScannerPortConnect (
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
    );

VOID
ScannerPortDisconnect (
    _In_opt_ PVOID ConnectionCookie
    );


NTSTATUS
CmdFltPortConnect(
	__in PFLT_PORT ClientPort,
	__in_opt PVOID ServerPortCookie,
	__in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID *ConnectionCookie
	);


VOID
CmdFltPortDisconnect(
	__in_opt PVOID ConnectionCookie
	);


NTSTATUS
ScannerpScanFileInUserMode (
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PBOOLEAN SafeToOpen
    );


NTSTATUS
ScannerpScanFileInUserModeEx(
	_In_ PFLT_INSTANCE Instance,
	_In_ PFILE_OBJECT FileObject,
	_In_ PWCHAR pszFilePath,
	_Out_ PBOOLEAN SafeToOpne
	);

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
    #pragma alloc_text(INIT, DriverEntry)
    #pragma alloc_text(INIT, ScannerInitializeScannedExtensions)    
    #pragma alloc_text(PAGE, ScannerInstanceSetup)
    #pragma alloc_text(PAGE, ScannerPreCreate)
    #pragma alloc_text(PAGE, ScannerPortConnect)
    #pragma alloc_text(PAGE, ScannerPortDisconnect)
    #pragma alloc_text(PAGE, ScannerFreeExtensions)    
    #pragma alloc_text(PAGE, ScannerAllocateUnicodeString)
    #pragma alloc_text(PAGE, ScannerFreeUnicodeString)
#endif


//
//  Constant FLT_REGISTRATION structure for our filter.  This
//  initializes the callback routines our filter wants to register
//  for.  This is only used to register with the filter manager
//

const FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      0,
      ScannerPreCreate,
      ScannerPostCreate},

    { IRP_MJ_CLEANUP,
      0,
      ScannerPreCleanup,
      NULL},

    { IRP_MJ_WRITE,
      0,
      ScannerPreWrite,
	  ScannerPostWrite},

#if (WINVER>=0x0602)

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      ScannerPreFileSystemControl,
      NULL
    },

#endif

    { IRP_MJ_OPERATION_END}
};


const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

    { FLT_STREAMHANDLE_CONTEXT,
      0,
	  ScannerContextCleanup,
      sizeof(SCANNER_STREAM_HANDLE_CONTEXT),
      'chBS' },
	{ FLT_INSTANCE_CONTEXT,
	  0,
	  ScannerContextCleanup,
	  sizeof(SCANNER_INSTANCE_CONTEXT),
	  'chBS'},

    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    ContextRegistration,                //  Context Registration.
    Callbacks,                          //  Operation callbacks
    ScannerUnload,                      //  FilterUnload
    ScannerInstanceSetup,               //  InstanceSetup
    ScannerQueryTeardown,               //  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent
};

////////////////////////////////////////////////////////////////////////////
//
//    Filter initialization and unload routines.
//
////////////////////////////////////////////////////////////////////////////

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for the Filter driver.  This
    registers the Filter with the filter manager and initializes all
    its global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Returns STATUS_SUCCESS.
--*/
{
    OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;
	UNICODE_STRING uniStringCmd;
    PSECURITY_DESCRIPTOR sd;
    NTSTATUS status;

    //
    //  Default to NonPagedPoolNx for non paged pool allocations where supported.
    //
    ExInitializeDriverRuntime( DrvRtPoolNxOptIn );

    //
    //  Register with filter manager.
    //
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &ScannerData.Filter );
    if (!NT_SUCCESS( status )) 
	{
        return status;
    }

    //
    // Obtain the extensions to scan from the registry
    //
    status = ScannerInitializeScannedExtensions( RegistryPath );
    if (!NT_SUCCESS( status ))
	{
        status = STATUS_SUCCESS;
        ScannedExtensions = &ScannedExtensionDefault;
        ScannedExtensionCount = 1;    
    }    

	status = InitProcessPaths();
	if (!NT_SUCCESS(status))
	{
		ScannerFreeExtensions();
		FltUnregisterFilter(ScannerData.Filter);

		return status;
	}

	status = InitFileCacheMgr();
	if (!NT_SUCCESS(status))
	{
		ScannerFreeExtensions();
		FltUnregisterFilter(ScannerData.Filter);

		return status;
	}

    //
    //  Create a communication port.
    //
	RtlInitUnicodeString(&uniString, ScannerPortName);
	RtlInitUnicodeString(&uniStringCmd, CmdPortName);

    //
    //  We secure the port so only ADMINs & SYSTEM can acecss it.
    //
    status = FltBuildDefaultSecurityDescriptor( &sd, FLT_PORT_ALL_ACCESS );
	if (!NT_SUCCESS(status))
	{
		DeInitFileCacheMgr();
		ScannerFreeExtensions();
		FltUnregisterFilter(ScannerData.Filter);

		return status;
	}

	InitializeObjectAttributes(&oa, &uniStringCmd, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);

	status = FltCreateCommunicationPort(ScannerData.Filter,
										&ScannerData.ServerPortCmd,
										&oa,
										NULL,
										CmdFltPortConnect,
										CmdFltPortDisconnect,
										NULL,
										1);
	if (!NT_SUCCESS(status))
	{
		FltFreeSecurityDescriptor(sd);
		DeInitFileCacheMgr();
		ScannerFreeExtensions();
		FltUnregisterFilter(ScannerData.Filter);

		return status;
	}

	InitializeObjectAttributes(&oa, &uniString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);
	status = FltCreateCommunicationPort(ScannerData.Filter,
                                            &ScannerData.ServerPort,
                                            &oa,
                                            NULL,
                                            ScannerPortConnect,
                                            ScannerPortDisconnect,
                                            NULL,
                                            1 );  
	if (!NT_SUCCESS(status))
	{
		FltCloseCommunicationPort(ScannerData.ServerPortCmd);
		FltFreeSecurityDescriptor(sd);
		DeInitFileCacheMgr();
		ScannerFreeExtensions();
		FltUnregisterFilter(ScannerData.Filter);

		return status;
	}
			
	//
    //  Free the security descriptor in all cases. It is not needed once
    //  the call to FltCreateCommunicationPort() is made.
    //
    FltFreeSecurityDescriptor( sd );


	status = InitProcessNotificationRoutine();
	if (!NT_SUCCESS(status))
	{
		FltCloseCommunicationPort(ScannerData.ServerPort);
		FltCloseCommunicationPort(ScannerData.ServerPortCmd);
		DeInitFileCacheMgr();
		ScannerFreeExtensions();
		FltUnregisterFilter(ScannerData.Filter);

		return status;
	}

    //
    //  Start filtering I/O.
    //
    status = FltStartFiltering( ScannerData.Filter );
    if (!NT_SUCCESS( status ))
	{
		DeinitProcessNotificationRoutine();
		FltCloseCommunicationPort(ScannerData.ServerPort);
		FltCloseCommunicationPort(ScannerData.ServerPortCmd);
		DeInitFileCacheMgr();
		ScannerFreeExtensions();
		FltUnregisterFilter(ScannerData.Filter);

		return status;
    }
        
    return STATUS_SUCCESS;
}


NTSTATUS 
ScannerInitializeScannedExtensions(
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Descrition:

    This routine sets the the extensions for files to be scanned based
    on the registry.
    
Arguments:

    RegistryPath - The path key passed to the driver during DriverEntry.

Return Value:

    STATUS_SUCCESS if the function completes successfully.  Otherwise a valid
    NTSTATUS code is returned.

--*/
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES attributes;
    HANDLE driverRegKey = NULL;
    UNICODE_STRING valueName;
    PKEY_VALUE_PARTIAL_INFORMATION valueBuffer = NULL;
    ULONG valueLength = 0;
    BOOLEAN closeHandle = FALSE;
    PWCHAR ch;
    SIZE_T length;
    ULONG count;
    PUNICODE_STRING ext;
    
    PAGED_CODE();

    ScannedExtensions = NULL;
    ScannedExtensionCount = 0;

    //
    //  Open the driver registry key.
    //

    InitializeObjectAttributes( &attributes,
                                RegistryPath,
                                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                NULL,
                                NULL );

    status = ZwOpenKey( &driverRegKey,
                        KEY_READ,
                        &attributes );

    if (!NT_SUCCESS( status )) {

        goto ScannerInitializeScannedExtensionsCleanup;
    }

    closeHandle = TRUE;

    //
    //   Query the length of the reg value
    //
    
    RtlInitUnicodeString( &valueName, L"Extensions" );

    status = ZwQueryValueKey( driverRegKey,
                              &valueName,
                              KeyValuePartialInformation,
                              NULL,
                              0,
                              &valueLength );

    if (status!=STATUS_BUFFER_TOO_SMALL && status!=STATUS_BUFFER_OVERFLOW) {

        status = STATUS_INVALID_PARAMETER;
        goto ScannerInitializeScannedExtensionsCleanup;
    }

    //
    //  Extract the path.
    //

    valueBuffer = ExAllocatePoolWithTag( NonPagedPool,
                                         valueLength,
                                         SCANNER_REG_TAG );

    if (valueBuffer == NULL) {

        status = STATUS_INSUFFICIENT_RESOURCES;
        goto ScannerInitializeScannedExtensionsCleanup;
    }

    status = ZwQueryValueKey( driverRegKey,
                              &valueName,
                              KeyValuePartialInformation,
                              valueBuffer,
                              valueLength,
                              &valueLength );

    if (!NT_SUCCESS( status )) {

        goto ScannerInitializeScannedExtensionsCleanup;
    }

    ch = (PWCHAR)(valueBuffer->Data);

    count = 0;

    //
    //  Count how many strings are in the multi string
    //
    
    while (*ch != '\0') {

        ch = ch + wcslen( ch ) + 1;
        count++;
    }

    ScannedExtensions = ExAllocatePoolWithTag( PagedPool, 
                                               count * sizeof(UNICODE_STRING),
                                               SCANNER_STRING_TAG );
    
    if (ScannedExtensions == NULL) {
        goto ScannerInitializeScannedExtensionsCleanup;
    }

    ch = (PWCHAR)((PKEY_VALUE_PARTIAL_INFORMATION)valueBuffer->Data);
    ext = ScannedExtensions;
    
    while (ScannedExtensionCount < count) {

        length = wcslen( ch ) * sizeof(WCHAR);

        ext->MaximumLength = (USHORT) length;
        
        status = ScannerAllocateUnicodeString( ext );
        
        if (!NT_SUCCESS( status )) {
            goto ScannerInitializeScannedExtensionsCleanup;
        }

        ext->Length = (USHORT)length;
 
        RtlCopyMemory( ext->Buffer, ch, length );

        ch = ch + length/sizeof(WCHAR) + 1;

        ScannedExtensionCount++;

        ext++;
        
    }

ScannerInitializeScannedExtensionsCleanup:

    //
    //  Note that this function leaks the global buffers.
    //  On failure DriverEntry will clean up the globals
    //  so we don't have to do that here.
    //

    if (valueBuffer != NULL) {

        ExFreePoolWithTag( valueBuffer, SCANNER_REG_TAG );
        valueBuffer = NULL;
    }

    if (closeHandle) {

        ZwClose( driverRegKey );
    }

    if (!NT_SUCCESS( status )) {

        ScannerFreeExtensions();
    }
    
    return status;
}


VOID
ScannerFreeExtensions(
    )
/*++

Routine Descrition:

    This routine cleans up the global buffers on both
    teardown and initialization failure.

Arguments:

Return Value:

    None.

--*/
{
    PAGED_CODE();

    //
    // Free the strings in the scanned extension array
    //

    while (ScannedExtensionCount > 0) {

        ScannedExtensionCount--;

        if (ScannedExtensions != &ScannedExtensionDefault) {

            ScannerFreeUnicodeString( ScannedExtensions + ScannedExtensionCount );        
        }
    }
    
    if (ScannedExtensions != &ScannedExtensionDefault && ScannedExtensions != NULL) {

        ExFreePoolWithTag( ScannedExtensions, SCANNER_STRING_TAG );
    }

    ScannedExtensions = NULL;    

}


NTSTATUS
ScannerAllocateUnicodeString (
    _Inout_ PUNICODE_STRING String
    )
/*++

Routine Description:

    This routine allocates a unicode string

Arguments:

    String - supplies the size of the string to be allocated in the MaximumLength field 
             return the unicode string

Return Value:

    STATUS_SUCCESS                  - success
    STATUS_INSUFFICIENT_RESOURCES   - failure
  
--*/
{

    PAGED_CODE();

    String->Buffer = ExAllocatePoolWithTag( NonPagedPool,
                                            String->MaximumLength,
                                            SCANNER_STRING_TAG );

    if (String->Buffer == NULL) {

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    String->Length = 0;

    return STATUS_SUCCESS;
}


VOID
ScannerFreeUnicodeString (
    _Inout_ PUNICODE_STRING String
    )
/*++

Routine Description:

    This routine frees a unicode string

Arguments:

    String - supplies the string to be freed 

Return Value:

    None    

--*/
{
    PAGED_CODE();

    if (String->Buffer) {

        ExFreePoolWithTag( String->Buffer,
                           SCANNER_STRING_TAG );
        String->Buffer = NULL;
    }

    String->Length = String->MaximumLength = 0;
    String->Buffer = NULL;
}


NTSTATUS
ScannerPortConnect (
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
    )
/*++

Routine Description

    This is called when user-mode connects to the server port - to establish a
    connection

Arguments

    ClientPort - This is the client connection port that will be used to
        send messages from the filter

    ServerPortCookie - The context associated with this port when the
        minifilter created this port.

    ConnectionContext - Context from entity connecting to this port (most likely
        your user mode service)

    SizeofContext - Size of ConnectionContext in bytes

    ConnectionCookie - Context to be passed to the port disconnect routine.

Return Value

    STATUS_SUCCESS - to accept the connection

--*/
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER( ServerPortCookie );
    UNREFERENCED_PARAMETER( ConnectionContext );
    UNREFERENCED_PARAMETER( SizeOfContext);
    UNREFERENCED_PARAMETER( ConnectionCookie = NULL );

    FLT_ASSERT( ScannerData.ClientPort == NULL );
    FLT_ASSERT( ScannerData.UserProcess == NULL );

    //
    //  Set the user process and port. In a production filter it may
    //  be necessary to synchronize access to such fields with port
    //  lifetime. For instance, while filter manager will synchronize
    //  FltCloseClientPort with FltSendMessage's reading of the port 
    //  handle, synchronizing access to the UserProcess would be up to
    //  the filter.
    //

    ScannerData.UserProcess = PsGetCurrentProcess();
    ScannerData.ClientPort = ClientPort;

    //DbgPrint( "!!! scanner.sys --- connected, port=0x%p\n", ClientPort );

    return STATUS_SUCCESS;
}


VOID
ScannerPortDisconnect(
     _In_opt_ PVOID ConnectionCookie
     )
/*++

Routine Description

    This is called when the connection is torn-down. We use it to close our
    handle to the connection

Arguments

    ConnectionCookie - Context from the port connect routine

Return value

    None

--*/
{
    UNREFERENCED_PARAMETER( ConnectionCookie );

    PAGED_CODE();

    //DbgPrint( "!!! scanner.sys --- disconnected, port=0x%p\n", ScannerData.ClientPort );

    //
    //  Close our handle to the connection: note, since we limited max connections to 1,
    //  another connect will not be allowed until we return from the disconnect routine.
    //

    FltCloseClientPort( ScannerData.Filter, &ScannerData.ClientPort );

    //
    //  Reset the user-process field.
    //

    ScannerData.UserProcess = NULL;
}



NTSTATUS
CmdFltPortConnect(
__in PFLT_PORT ClientPort,
__in_opt PVOID ServerPortCookie,
__in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
__in ULONG SizeOfContext,
__deref_out_opt PVOID *ConnectionCookie
)
/*++

Routine Description

This is called when user-mode connects to the server port - to establish a
connection

Arguments

ClientPort - This is the client connection port that will be used to
send messages from the filter

ServerPortCookie - The context associated with this port when the
minifilter created this port.

ConnectionContext - Context from entity connecting to this port (most likely
your user mode service)

SizeofContext - Size of ConnectionContext in bytes

ConnectionCookie - Context to be passed to the port disconnect routine.

Return Value

STATUS_SUCCESS - to accept the connection

--*/
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie);

	ASSERT(CmdFltData.ClientPort == NULL);
	ASSERT(CmdFltData.UserProcess == NULL);

	//
	//  Set the user process and port.
	//

	ScannerData.ClientPortCmd = ClientPort;

	//DbgPrint("!!! CmdFltPortConnect scanner.sys --- connected, port=0x%p\n", ClientPort);

	return STATUS_SUCCESS;
}


VOID
CmdFltPortDisconnect(
__in_opt PVOID ConnectionCookie
)
/*++

Routine Description

This is called when the connection is torn-down. We use it to close our
handle to the connection

Arguments

ConnectionCookie - Context from the port connect routine

Return value

None

--*/
{
	UNREFERENCED_PARAMETER(ConnectionCookie);

	PAGED_CODE();

	//DbgPrint("!!! CmdFltPortDisconnect scanner.sys --- disconnected, port=0x%p\n", ScannerData.ClientPortCmd);

	//
	//  Close our handle to the connection: note, since we limited max connections to 1,
	//  another connect will not be allowed until we return from the disconnect routine.
	//

	FltCloseClientPort(ScannerData.Filter, &ScannerData.ClientPortCmd);
}


NTSTATUS
ScannerUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for the Filter driver.  This unregisters the
    Filter with the filter manager and frees any allocated global data
    structures.

Arguments:

    None.

Return Value:

    Returns the final status of the deallocation routines.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

	DeinitProcessNotificationRoutine();
    ScannerFreeExtensions();

	DeInitFileCacheMgr();

	//
    //  Close the server port.
    //

	FltCloseCommunicationPort(ScannerData.ServerPortCmd);
	FltCloseCommunicationPort(ScannerData.ServerPort);


    //
    //  Unregister the filter
    //

    FltUnregisterFilter( ScannerData.Filter );

    return STATUS_SUCCESS;
}


NTSTATUS
ScannerInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called by the filter manager when a new instance is created.
    We specified in the registry that we only want for manual attachments,
    so that is all we should receive here.

Arguments:

    FltObjects - Describes the instance and volume which we are being asked to
        setup.

    Flags - Flags describing the type of attachment this is.

    VolumeDeviceType - The DEVICE_TYPE for the volume to which this instance
        will attach.

    VolumeFileSystemType - The file system formatted on this volume.

Return Value:

  STATUS_SUCCESS            - we wish to attach to the volume
  STATUS_FLT_DO_NOT_ATTACH  - no, thank you

--*/
{
	NTSTATUS ntStatus;
	PSCANNER_INSTANCE_CONTEXT pInstanceContext = NULL;
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    FLT_ASSERT( FltObjects->Filter == ScannerData.Filter );
	//DbgPrint("ScannerInstanceSetup: Entry.\n\n");
    //
    //  Don't attach to network volumes.
    //

    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {

       return STATUS_FLT_DO_NOT_ATTACH;
    }

	ntStatus = FltAllocateContext(FltObjects->Filter, FLT_INSTANCE_CONTEXT, sizeof(SCANNER_INSTANCE_CONTEXT), NonPagedPool, &pInstanceContext);
	if (!NT_SUCCESS(ntStatus))
	{
		//DbgPrint("ScannerInstanceSetup: FltAllocateContext failed with error (0x%08X)\n", ntStatus);
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	RtlZeroMemory(pInstanceContext, sizeof(SCANNER_INSTANCE_CONTEXT));

	ntStatus = FltSetInstanceContext(FltObjects->Instance, FLT_SET_CONTEXT_REPLACE_IF_EXISTS, pInstanceContext, NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		// Free usDosVolumeName
		//DbgPrint("ScannerInstanceSetup: FltSetInstanceContext failed(0x%08x)\n", ntStatus);
		FltReleaseContext(pInstanceContext);		// For FltAllocateContext
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	ntStatus = getDosVolumeName(FltObjects, pInstanceContext);
	if (!NT_SUCCESS(ntStatus))
	{
		//DbgPrint("ScannerInstanceSetup: getDosVolumeName failed(0x%08x)\n", ntStatus);
	}

	FltReleaseContext(pInstanceContext);	// For FltAllocateContext
	//DbgPrint("ScannerInstancesetup: Exit.\n");
    return STATUS_SUCCESS;
}

NTSTATUS
ScannerQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is the instance detach routine for the filter. This
    routine is called by filter manager when a user initiates a manual instance
    detach. This is a 'query' routine: if the filter does not want to support
    manual detach, it can return a failure status

Arguments:

    FltObjects - Describes the instance and volume for which we are receiving
        this query teardown request.

    Flags - Unused

Return Value:

    STATUS_SUCCESS - we allow instance detach to happen

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    return STATUS_SUCCESS;
}


FLT_PREOP_CALLBACK_STATUS
ScannerPreCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    Pre create callback.  We need to remember whether this file has been
    opened for write access.  If it has, we'll want to rescan it in cleanup.
    This scheme results in extra scans in at least two cases:
    -- if the create fails (perhaps for access denied)
    -- the file is opened for write access but never actually written to
    The assumption is that writes are more common than creates, and checking
    or setting the context in the write path would be less efficient than
    taking a good guess before the create.

Arguments:

    Data - The structure which describes the operation parameters.

    FltObject - The structure which describes the objects affected by this
        operation.

    CompletionContext - Output parameter which can be used to pass a context
        from this pre-create callback to the post-create callback.

Return Value:

   FLT_PREOP_SUCCESS_WITH_CALLBACK - If this is not our user-mode process.
   FLT_PREOP_SUCCESS_NO_CALLBACK - All other threads.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext = NULL );

    PAGED_CODE();

    //
    //  See if this create is being done by our user process.
    //

    if (IoThreadToProcess( Data->Thread ) == ScannerData.UserProcess) {

        //DbgPrint( "!!! scanner.sys -- allowing create for trusted process \n" );

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


BOOLEAN
ScannerpCheckExtension (
    _In_ PUNICODE_STRING Extension
    )
/*++

Routine Description:

    Checks if this file name extension is something we are interested in

Arguments

    Extension - Pointer to the file name extension

Return Value

    TRUE - Yes we are interested
    FALSE - No
--*/
{
    ULONG count;

    if (Extension->Length == 0) {

        return FALSE;
    }

    //
    //  Check if it matches any one of our static extension list
    //

    for (count = 0; count < ScannedExtensionCount; count++) {
        
        if (RtlCompareUnicodeString( Extension, ScannedExtensions + count, TRUE ) == 0) {

            //
            //  A match. We are interested in this file
            //

            return TRUE;
        }
    }

    return FALSE;
}


FLT_POSTOP_CALLBACK_STATUS
ScannerPostCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    Post create callback.  We can't scan the file until after the create has
    gone to the filesystem, since otherwise the filesystem wouldn't be ready
    to read the file for us.

Arguments:

    Data - The structure which describes the operation parameters.

    FltObject - The structure which describes the objects affected by this
        operation.

    CompletionContext - The operation context passed fron the pre-create
        callback.

    Flags - Flags to say why we are getting this post-operation callback.

Return Value:

    FLT_POSTOP_FINISHED_PROCESSING - ok to open the file or we wish to deny
                                     access to this file, hence undo the open

--*/
{
    PSCANNER_STREAM_HANDLE_CONTEXT scannerContext;
	BOOLEAN bClean;
    NTSTATUS status;
    BOOLEAN safeToOpen;

    UNREFERENCED_PARAMETER( CompletionContext );

	//
	//	Check for draining flags.
	//
	if (FLTFL_POST_OPERATION_DRAINING & Flags)
	{
		//
		//	Post operation draining, do not perform any activity.
		//
		DbgPrint("ScannerPostCreate: Post operation draining.");

		return FLT_POSTOP_FINISHED_PROCESSING;
	}


    //
    //  If this create was failing anyway, don't bother scanning now.
    //

    if (!NT_SUCCESS( Data->IoStatus.Status ) ||
        (STATUS_REPARSE == Data->IoStatus.Status)) {

        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    //  Check if we are interested in this file.
    //

    /*status = FltGetFileNameInformation( Data,
                                        FLT_FILE_NAME_NORMALIZED |
                                            FLT_FILE_NAME_QUERY_DEFAULT,
                                        &nameInfo );

    if (!NT_SUCCESS( status )) {

        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    FltParseFileNameInformation( nameInfo );

    //
    //  Check if the extension matches the list of extensions we are interested in
    //

    scanFile = ScannerpCheckExtension( &nameInfo->Extension );

    //
    //  Release file name info, we're done with it
    //


    if (!scanFile) {

        //
        //  Not an extension we are interested in
        //
		FltReleaseFileNameInformation(nameInfo);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }*/
	
	status = FltAllocateContext(
								ScannerData.Filter,
								FLT_STREAMHANDLE_CONTEXT,
								sizeof(SCANNER_STREAM_HANDLE_CONTEXT),
								PagedPool,
								&scannerContext);
	if (!NT_SUCCESS(status))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	//
	//	Init Unicode string.
	//
	RtlInitEmptyUnicodeString(&scannerContext->usFilePath, scannerContext->wszFilePath, MAX_FILE_PATH * sizeof(WCHAR));

	//
	// Additionaly Check if the extension matches the list of extensions we are interested in
	//
	status = GetFilepath(Data, FltObjects->Instance, &scannerContext->usFilePath);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint("ScannerPostCreate: getFilePath failed.\n");
		FltReleaseContext(scannerContext);	//	FltAllocateContext

		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	else
	{
		DbgPrint("\n ScannerPostCreate: File Path (%wZ)", &scannerContext->usFilePath);
	}

	RtlHashUnicodeString(&scannerContext->usFilePath, TRUE, 0, &scannerContext->ulFilePathHash);

	//
	//	Get cache entry.
	//	Must release reference if entry found.
	//
	bClean = IsFileInCache(scannerContext->usFilePath, scannerContext->ulFilePathHash, NULL);
	if (bClean)
	{
		DbgPrint("\n File is clean(%wZ)", &scannerContext->usFilePath);
	}

	//if (Data->Iopb->Parameters.Create.Options & FILE_COMPLETE_IF_OPLOCKED)
	//{
	//	DbgPrint("\n ScannerPostCreate: FILE_COMPLETE_IF_OPLOCKED flag is set for File(%wZ)", &scannerContext->usFilePath);

	//	FltReleaseContext(scannerContext);	//	FltAllocateContext
	//	return FLT_POSTOP_FINISHED_PROCESSING;
	//}

	if (FALSE == bClean)
	{
		status = ScannerpScanFileInUserModeEx(FltObjects->Instance,
			FltObjects->FileObject,
			scannerContext->wszFilePath,
			&safeToOpen);
		if (!NT_SUCCESS(status))
		{
			FltReleaseContext(scannerContext);	//	FltAllocateContext

			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		if (!safeToOpen) {

			//
			//  Ask the filter manager to undo the create.
			//

			////DbgPrint( "!!! scanner.sys -- foul language detected in postcreate !!!\n" );
			DbgPrint("\n ScannerPostCreate: Malware detected in(%wZ)", &scannerContext->usFilePath);

			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
			Data->IoStatus.Information = 0;

			if (!(FltObjects->FileObject->Flags & FO_HANDLE_CREATED))
			{
				FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
			}

			FltReleaseContext(scannerContext);	//	FltAllocateContext

			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		status = AddToFileCache(scannerContext->usFilePath, scannerContext->ulFilePathHash, NULL);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("\n AddToFileCache Failed.Error(0x%08X)");
		}
	}
	

	if (FltObjects->FileObject->WriteAccess)
	{
        //
        //
        //  The create has requested write access, mark to rescan the file.
        //  Allocate the context.
        //

		//DbgPrint("scanner.sys : yara signature not detected....\n");
		scannerContext->RescanRequired = TRUE;
		scannerContext->bModify = FALSE;

        (VOID) FltSetStreamHandleContext( FltObjects->Instance,
                                            FltObjects->FileObject,
                                            FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
                                            scannerContext,
                                            NULL );

        //
        //  Normally we would check the results of FltSetStreamHandleContext
        //  for a variety of error cases. However, The only error status 
        //  that could be returned, in this case, would tell us that
        //  contexts are not supported.  Even if we got this error,
        //  we just want to release the context now and that will free
        //  this memory if it was not successfully set.
        //

        //
        //  Release our reference on the context (the set adds a reference)
        //
    }

	FltReleaseContext(scannerContext);	//	FltAllocateContext

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
ScannerPreCleanup (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    Pre cleanup callback.  If this file was opened for write access, we want
    to rescan it now.

Arguments:

    Data - The structure which describes the operation parameters.

    FltObject - The structure which describes the objects affected by this
        operation.

    CompletionContext - Output parameter which can be used to pass a context
        from this pre-cleanup callback to the post-cleanup callback.

Return Value:

    Always FLT_PREOP_SUCCESS_NO_CALLBACK.

--*/
{
    NTSTATUS status;
    PSCANNER_STREAM_HANDLE_CONTEXT context;
    BOOLEAN safe;

    UNREFERENCED_PARAMETER( CompletionContext );

    status = FltGetStreamHandleContext( FltObjects->Instance,
                                        FltObjects->FileObject,
                                        &context );

	if (!NT_SUCCESS(status))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

    if (TRUE == context->bModify)
	{

		RemoveFromFileCache(context->usFilePath, context->ulFilePathHash);

		//
		//	fixme: Need to check rename file.
		//	If renamed only then query new path.
		//
		//
		// Additionaly Check if the extension matches the list of extensions we are interested in
		//
		status = GetFilepath(Data, FltObjects->Instance, &context->usFilePath);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("ScannerPreCleanup: getFilePath failed.\n");
			FltReleaseContext(context);

			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		RtlHashUnicodeString(&context->usFilePath, TRUE, 0, &context->ulFilePathHash);

		/*(VOID) ScannerpScanFileInUserMode( FltObjects->Instance,
                                            FltObjects->FileObject,
                                            &safe );*/
		status = ScannerpScanFileInUserModeEx(FltObjects->Instance,
											FltObjects->FileObject,
											context->wszFilePath,
											&safe);
		if (!NT_SUCCESS(status))
		{
			FltReleaseContext(context);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

        if (!safe) {

            //DbgPrint( "!!! scanner.sys -- yara signature detected in precleanup !!!\n" );
        }
		else
		{
			//DbgPrint("ScannerPreCleanup : yara signature not detected....\n");
			status = AddToFileCache(context->usFilePath, context->ulFilePathHash, NULL);
			if (!NT_SUCCESS(status))
			{
				DbgPrint("AddToFileCache Failed.Error(0x%08X)", status);
			}
		}
	}

	FltReleaseContext(context);

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


//FLT_PREOP_CALLBACK_STATUS
//ScannerPreWrite(
//_Inout_ PFLT_CALLBACK_DATA Data,
//_In_ PCFLT_RELATED_OBJECTS FltObjects,
//_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
//)
///*++
//
//Routine Description:
//
//Pre write callback.  We want to scan what's being written now.
//
//Arguments:
//
//Data - The structure which describes the operation parameters.
//
//FltObject - The structure which describes the objects affected by this
//operation.
//
//CompletionContext - Output parameter which can be used to pass a context
//from this pre-write callback to the post-write callback.
//
//Return Value:
//
//Always FLT_PREOP_SUCCESS_NO_CALLBACK.
//
//--*/
//{
//	NTSTATUS status;
//	PSCANNER_STREAM_HANDLE_CONTEXT context = NULL;
//
//	//
//	//  If not client port just ignore this write.
//	//
//
//	if (ScannerData.ClientPort == NULL)
//	{
//		return FLT_PREOP_SUCCESS_NO_CALLBACK;
//	}
//
//	status = FltGetStreamHandleContext(FltObjects->Instance,
//		FltObjects->FileObject,
//		&context);
//	if (!NT_SUCCESS(status))
//	{
//		//
//		//  We are not interested in this file
//		//
//		return FLT_PREOP_SUCCESS_NO_CALLBACK;
//	}
//
//	//
//	//  Pass the contents of the buffer to user mode.
//	//
//
//	if (Data->Iopb->Parameters.Write.Length == 0)
//	{
//		//
//		//  We are not interested in this file
//		//
//		FltReleaseContext(context);
//		return FLT_PREOP_SUCCESS_NO_CALLBACK;
//	}
//
//	if (TRUE == context->bModify)
//	{
//		FltReleaseContext(context);
//		return FLT_PREOP_SUCCESS_NO_CALLBACK;
//	}
//
//	*CompletionContext = context;
//	FltReleaseContext(context);
//
//	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
//}

FLT_PREOP_CALLBACK_STATUS
ScannerPreWrite(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

Pre write callback.  We want to scan what's being written now.

Arguments:

Data - The structure which describes the operation parameters.

FltObject - The structure which describes the objects affected by this
operation.

CompletionContext - Output parameter which can be used to pass a context
from this pre-write callback to the post-write callback.

Return Value:

Always FLT_PREOP_SUCCESS_NO_CALLBACK.

--*/
{
	FLT_PREOP_CALLBACK_STATUS returnStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	NTSTATUS status;
	PSCANNER_NOTIFICATION notification = NULL;
	PSCANNER_STREAM_HANDLE_CONTEXT context = NULL;
	ULONG replyLength;
	BOOLEAN safe = TRUE;
	PUCHAR buffer;

	//
	//  If not client port just ignore this write.
	//

	if (ScannerData.ClientPort == NULL) {

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	status = FltGetStreamHandleContext(FltObjects->Instance,
		FltObjects->FileObject,
		&context);

	if (!NT_SUCCESS(status))
	{
		//
		//  We are not interested in this file
		//
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	//
	//  Use try-finally to cleanup
	//

	try {

		//
		//  Pass the contents of the buffer to user mode.
		//

		if (Data->Iopb->Parameters.Write.Length == 0)
		{
			//
			//  We are not interested in this file
			//
			//FltReleaseContext(context);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		//
		//  Get the users buffer address.  If there is a MDL defined, use
		//  it.  If not use the given buffer address.
		//

		if (Data->Iopb->Parameters.Write.MdlAddress != NULL)
		{

			buffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Write.MdlAddress,
				NormalPagePriority);

			//
			//  If we have a MDL but could not get and address, we ran out
			//  of memory, report the correct error
			//

			if (buffer == NULL)
			{

				Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				Data->IoStatus.Information = 0;
				//FltReleaseContext(context);
				return FLT_PREOP_COMPLETE;
			}

		}
		else
		{

			//
			//  Use the users buffer
			//

			buffer = Data->Iopb->Parameters.Write.WriteBuffer;
		}

		//
		//  In a production-level filter, we would actually let user mode scan the file directly.
		//  Allocating & freeing huge amounts of non-paged pool like this is not very good for system perf.
		//  This is just a sample!
		//

		notification = ExAllocatePoolWithTag(NonPagedPool,
			sizeof(SCANNER_NOTIFICATION),
			'nacS');
		if (notification == NULL)
		{

			Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			Data->IoStatus.Information = 0;
			//FltReleaseContext(context);
			return FLT_PREOP_COMPLETE;
		}

		RtlZeroMemory(notification, sizeof(SCANNER_NOTIFICATION));
		notification->BytesToScan = min(Data->Iopb->Parameters.Write.Length, SCANNER_READ_BUFFER_SIZE);
		notification->ushFlag = notification->ushFlag | FILE_CONTENTS_STORED;

		//
		//  The buffer can be a raw user buffer. Protect access to it
		//

		try  {

			RtlCopyMemory(&notification->Contents,
				buffer,
				notification->BytesToScan);

		} except(EXCEPTION_EXECUTE_HANDLER)
		{
			//
			//  Error accessing buffer. Complete i/o with failure
			//

			Data->IoStatus.Status = GetExceptionCode();
			Data->IoStatus.Information = 0;
			ExFreePoolWithTag(notification, 'nacS');
			notification = NULL;
			//FltReleaseContext(context);
			return FLT_PREOP_COMPLETE;
		}

		//
		//  Send message to user mode to indicate it should scan the buffer.
		//  We don't have to synchronize between the send and close of the handle
		//  as FltSendMessage takes care of that.
		//

		replyLength = sizeof(SCANNER_REPLY);

		status = FltSendMessage(ScannerData.Filter,
			&ScannerData.ClientPort,
			notification,
			sizeof(SCANNER_NOTIFICATION),
			notification,
			&replyLength,
			NULL);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("!!! scanner.sys --- couldn't send message to user-mode to scan file, status 0x%X\n", status);

			ExFreePoolWithTag(notification, 'nacS');
			notification = NULL;
			//FltReleaseContext(context);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		safe = ((PSCANNER_REPLY)notification)->SafeToOpen;
		if (!safe)
		{
			//
			//  Block this write if not paging i/o (as a result of course, this scanner will not prevent memory mapped writes of contaminated
			//  strings to the file, but only regular writes). The effect of getting ERROR_ACCESS_DENIED for many apps to delete the file they
			//  are trying to write usually.
			//  To handle memory mapped writes - we should be scanning at close time (which is when we can really establish that the file object
			//  is not going to be used for any more writes)
			//

			//DbgPrint( "!!! scanner.sys -- foul language detected in write !!!\n" );

			if (!FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO))
			{

				//DbgPrint( "!!! scanner.sys -- blocking the write !!!\n" );

				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				Data->IoStatus.Information = 0;
				ExFreePoolWithTag(notification, 'nacS');
				notification = NULL;
				//FltReleaseContext(context);
				return FLT_PREOP_COMPLETE;
			}
		}

		if (TRUE == context->bModify)
		{
			*CompletionContext = context;
			returnStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		}
		else
		{
			returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
	}
	finally
	{
		if (notification)
		{
			ExFreePoolWithTag(notification, 'nacS');
		}
		if (context)
		{
			FltReleaseContext(context);
		}
	}

	return returnStatus;
}

FLT_POSTOP_CALLBACK_STATUS
ScannerPostWrite(
	PFLT_CALLBACK_DATA pCBData,
	PCFLT_RELATED_OBJECTS pFltObjects,
	PVOID pvCompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
	)
{
	PSCANNER_STREAM_HANDLE_CONTEXT pStreamHandleContext;

#undef	__DEBUG_FOR_THIS_FUNCTION_ONLY__
#define	DEBUG_SCANNERPOSTWRITE	1//DEBUG_SCANNERPOSTWRITE


#if	DEBUG_SCANNERPOSTWRITE
	DbgPrint("==>ScannerPostWrite.");
#endif

	pStreamHandleContext = (PSCANNER_STREAM_HANDLE_CONTEXT)pvCompletionContext;
	if (NULL == pStreamHandleContext)
	{
#if	DEBUG_SCANNERPOSTWRITE
		DbgPrint("ScannerPostWrite: pFileobjectContext is NULL.");
#endif

		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (FLTFL_POST_OPERATION_DRAINING & Flags)
	{
		//
		//	Post operation draining, do not perform any activity.
		//
#if	DEBUG_SCANNERPOSTWRITE
		DbgPrint("ScannerPostWrite: Post operation draining.");
#endif

		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (!NT_SUCCESS(pCBData->IoStatus.Status))
	{
		//
		//	The operation has failed which means the file is not dirty.
		//	So no need to continue.
		//
#if	DEBUG_SCANNERPOSTWRITE
		DbgPrint("ScannerPostWrite: File is not dirty.");
#endif

		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (0 == pCBData->IoStatus.Information)
	{
#if	DEBUG_SCANNERPOSTWRITE
		DbgPrint("ScannerPostWrite: IoStatus.Information is 0.");
#endif

		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (pFltObjects->FileObject->Flags & FO_CLEANUP_COMPLETE)
	{
#if	1//DEBUG_SCANNERPOSTWRITE
		DbgPrint("ScannerPostWrite: !!! Cleanup is already called(%wZ) !!!", pStreamHandleContext->usFilePath);
#endif
		(VOID) RemoveFromFileCache(pStreamHandleContext->usFilePath, pStreamHandleContext->ulFilePathHash);
	}

	//
	//	Since the WRITE is successful, mark the file as modify.
	//
	pStreamHandleContext->bModify = TRUE;

#if	DEBUG_SCANNERPOSTWRITE
	DbgPrint("ScannerPostWrite: !!! File is modified !!!");
#endif

#if	DEBUG_SCANNERPOSTWRITE
	DbgPrint("<==ScannerPostWrite.");
#endif

	return FLT_POSTOP_FINISHED_PROCESSING;
}


#if (WINVER>=0x0602)

FLT_PREOP_CALLBACK_STATUS
ScannerPreFileSystemControl (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    Pre FS Control callback. 

Arguments:

    Data - The structure which describes the operation parameters.

    FltObject - The structure which describes the objects affected by this
        operation.

    CompletionContext - Output parameter which can be used to pass a context
        from this callback to the post-write callback.

Return Value:

    FLT_PREOP_SUCCESS_NO_CALLBACK or FLT_PREOP_COMPLETE

--*/
{
    FLT_PREOP_CALLBACK_STATUS returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    NTSTATUS status;
    ULONG fsControlCode;
    PSCANNER_STREAM_HANDLE_CONTEXT context = NULL;

    UNREFERENCED_PARAMETER( CompletionContext );

    FLT_ASSERT( Data != NULL );
    FLT_ASSERT( Data->Iopb != NULL );

    //
    //  If not client port just ignore this write.
    //

    if (ScannerData.ClientPort == NULL) {

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetStreamHandleContext( FltObjects->Instance,
                                        FltObjects->FileObject,
                                        &context );

    if (!NT_SUCCESS( status )) {

        //
        //  We are not interested in this file
        //

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    //  Use try-finally to cleanup
    //

    try {

        fsControlCode = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;

        if (fsControlCode == FSCTL_OFFLOAD_WRITE) {

            //
            //  Scanner cannot access the data in this offload write request.
            //  In a production-level filter, we would actually let user mode 
            //  scan the file after offload write completes (on cleanup etc).
            //  Since this is just a sample, block offload write with
            //  STATUS_ACCESS_DENIED, although this is not an acceptable
            //  production-level behavior.
            //
            
            //DbgPrint( "!!! scanner.sys -- blocking the offload write !!!\n" );

            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;

            returnStatus = FLT_PREOP_COMPLETE;
        }
                
    } finally {

        if (context) {

            FltReleaseContext( context );
        }
    }
    
    return returnStatus;
}

#endif

//////////////////////////////////////////////////////////////////////////
//  Local support routines.
//
/////////////////////////////////////////////////////////////////////////


NTSTATUS
ScannerpScanFileInUserModeEx(
	_In_ PFLT_INSTANCE Instance,
	_In_ PFILE_OBJECT FileObject,
	_In_ PWCHAR pszFilePath,
	_Out_ PBOOLEAN SafeToOpne
)
{
	HRESULT hrRetVal;
	ULONG ulReplyLength;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PSCANNER_NOTIFICATION pNotificaiton;

	if (NULL == Instance || NULL == FileObject || NULL == pszFilePath || NULL == SafeToOpne)
	{
		//DbgPrint("ScannerpScanFileInUserModeEx: Invalid parameter.\n");
		return STATUS_UNSUCCESSFUL;
	}
	
	*SafeToOpne = TRUE;

	if (NULL == ScannerData.ClientPort)
	{
		//DbgPrint("ScannerpScanFileInUserModeEx: Client is not connected.\n");
		return STATUS_UNSUCCESSFUL;
	}

	pNotificaiton = ExAllocatePoolWithTag(NonPagedPool, sizeof(SCANNER_NOTIFICATION), 'nacS');
	if (NULL == pNotificaiton)
	{
		//DbgPrint("ScannerpScanFileInUserModeEx: Memory allocation to pNotification failed.\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(pNotificaiton, sizeof(SCANNER_NOTIFICATION));

	hrRetVal = StringCchCopyW(pNotificaiton->szFilePath, 
							  sizeof(pNotificaiton->szFilePath) / sizeof(pNotificaiton->szFilePath[0]), 
							  pszFilePath
							  );
	if (FAILED(hrRetVal))
	{
		//DbgPrint("ScannerpScanFileInUserModeEx: COpying file failed.\n");
		ExFreePool(pNotificaiton);
		return STATUS_UNSUCCESSFUL;
	}
	pNotificaiton->ushFlag |= FILE_PATH_STORED;
	ulReplyLength = sizeof(SCANNER_REPLY);
	//DbgPrint("ScannerpScanFileInUserModeEx: File path to User mode(%S)\n", pNotificaiton->szFilePath);

	ntStatus = FltSendMessage(ScannerData.Filter,
							&ScannerData.ClientPort,
							pNotificaiton,
							sizeof(SCANNER_NOTIFICATION),
							pNotificaiton,
							&ulReplyLength,
							NULL
							);
	if (STATUS_SUCCESS == ntStatus)
	{
		*SafeToOpne = ((PSCANNER_REPLY)pNotificaiton)->SafeToOpen;
		//DbgPrint("ScannerpScanFileInUserModeEx:: File(%S) scan result (%d)\n", pNotificaiton->szFilePath, *SafeToOpne);
	}
	else
	{
		//DbgPrint("ScannerpScanFileInUserModeEx: FltSendMessage failed(0x%08x).\n", ntStatus);
	}
	
	ExFreePool(pNotificaiton);
	return ntStatus;
}

NTSTATUS
ScannerpScanFileInUserMode (
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _Out_ PBOOLEAN SafeToOpen
    )
/*++

Routine Description:

    This routine is called to send a request up to user mode to scan a given
    file and tell our caller whether it's safe to open this file.

    Note that if the scan fails, we set SafeToOpen to TRUE.  The scan may fail
    because the service hasn't started, or perhaps because this create/cleanup
    is for a directory, and there's no data to read & scan.

    If we failed creates when the service isn't running, there'd be a
    bootstrapping problem -- how would we ever load the .exe for the service?

Arguments:

    Instance - Handle to the filter instance for the scanner on this volume.

    FileObject - File to be scanned.

    SafeToOpen - Set to FALSE if the file is scanned successfully and it contains
                 foul language.

Return Value:

    The status of the operation, hopefully STATUS_SUCCESS.  The common failure
    status will probably be STATUS_INSUFFICIENT_RESOURCES.

--*/

{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID buffer = NULL;
    ULONG bytesRead;
    PSCANNER_NOTIFICATION notification = NULL;
    FLT_VOLUME_PROPERTIES volumeProps;
	LARGE_INTEGER offset = { 0 };
    ULONG replyLength, length;
    PFLT_VOLUME volume = NULL;

    *SafeToOpen = TRUE;

    //
    //  If not client port just return.
    //

    if (ScannerData.ClientPort == NULL) {

        return STATUS_SUCCESS;
    }

    try {

        ////
        ////  Obtain the volume object .
        ////

        status = FltGetVolumeFromInstance( Instance, &volume );

        if (!NT_SUCCESS( status )) {

            leave;
        }

        //
        //  Determine sector size. Noncached I/O can only be done at sector size offsets, and in lengths which are
        //  multiples of sector size. A more efficient way is to make this call once and remember the sector size in the
        //  instance setup routine and setup an instance context where we can cache it.
        //

        status = FltGetVolumeProperties( volume,
                                         &volumeProps,
                                         sizeof( volumeProps ),
                                         &length );
        //
        //  STATUS_BUFFER_OVERFLOW can be returned - however we only need the properties, not the names
        //  hence we only check for error status.
        //

        if (NT_ERROR( status )) {

            leave;
        }

        length = max( SCANNER_READ_BUFFER_SIZE, volumeProps.SectorSize );

        //
        //  Use non-buffered i/o, so allocate aligned pool
        //

        buffer = FltAllocatePoolAlignedWithTag( Instance,
                                                NonPagedPool,
                                                length,
                                                'nacS' );

        if (NULL == buffer) {

            status = STATUS_INSUFFICIENT_RESOURCES;
            leave;
        }

        notification = ExAllocatePoolWithTag( NonPagedPool,
                                              sizeof( SCANNER_NOTIFICATION ),
                                              'nacS' );

        if(NULL == notification) {

            status = STATUS_INSUFFICIENT_RESOURCES;
            leave;
        }

        
        //  Read the beginning of the file and pass the contents to user mode.
        
		offset.QuadPart = bytesRead = 0;
		status = FltReadFile(Instance,
			FileObject,
			&offset,
			length,
			buffer,
			FLTFL_IO_OPERATION_NON_CACHED |
			FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
			&bytesRead,
			NULL,
			NULL);

		if (NT_SUCCESS(status) && (0 != bytesRead)) {

			notification->BytesToScan = (ULONG)bytesRead;

			//
			//  Copy only as much as the buffer can hold
			//

			RtlCopyMemory(&notification->Contents,
				buffer,
				min(notification->BytesToScan, SCANNER_READ_BUFFER_SIZE));

			replyLength = sizeof(SCANNER_REPLY);

			status = FltSendMessage(ScannerData.Filter,
				&ScannerData.ClientPort,
				notification,
				sizeof(SCANNER_NOTIFICATION),
				notification,
				&replyLength,
				NULL);

			if (STATUS_SUCCESS == status) {

				*SafeToOpen = ((PSCANNER_REPLY)notification)->SafeToOpen;
				//DbgPrint("ScannerpScanFileInUserMode: SafeToOpen value: (%d)\n", *SafeToOpen);
			}
			else {

				//
				//  Couldn't send message
				//

				//DbgPrint("!!! scanner.sys --- couldn't send message to user-mode to scan file, status 0x%X\n", status);
			}
		}

    } finally {

        if (NULL != buffer) {

            FltFreePoolAlignedWithTag( Instance, buffer, 'nacS' );
        }

        if (NULL != notification) {

            ExFreePoolWithTag( notification, 'nacS' );
        }

        if (NULL != volume) {

            FltObjectDereference( volume );
        }
    }

    return status;
}


VOID
ScannerContextCleanup(
	PFLT_CONTEXT Context,
	FLT_CONTEXT_TYPE ContextType
)
{
	PSCANNER_INSTANCE_CONTEXT pInstanceContext;
	if (NULL == Context)
	{
		//DbgPrint("ScannerContextCleanup: Invalid Parameter.\n");
		return;
	}

	switch (ContextType)
	{
	case FLT_INSTANCE_CONTEXT:
		pInstanceContext = (PSCANNER_INSTANCE_CONTEXT)Context;
		
		if (NULL != pInstanceContext->usDosVolumeName.Buffer)
		{
			//DbgPrint("ScannerContextCallback: Memory for Volume Dos Name freed.\n");
			ExFreePool(pInstanceContext->usDosVolumeName.Buffer);
			pInstanceContext->usDosVolumeName.Buffer = NULL;
			pInstanceContext->usDosVolumeName.Length = 0;
			pInstanceContext->usDosVolumeName.MaximumLength = 0;
		}
		break;
	case FLT_STREAMHANDLE_CONTEXT:
		//DbgPrint("ScannerContextCallback: Context cleanup for STREAMHANDLE_CONTEXT.\n");
		break;
	default:
		break;
	}
}


NTSTATUS
getDosVolumeName(
	PCFLT_RELATED_OBJECTS pFltObject,
	/*PUNICODE_STRING pusDosName*/
	PSCANNER_INSTANCE_CONTEXT pInstanceContext
)
{
	NTSTATUS ntStatus;
	PDEVICE_OBJECT pDiskDeviceObj;

	if (NULL == pFltObject || NULL == pInstanceContext)
	{
		//DbgPrint("getDosVolumeName: Invalid parameter\n");
		return STATUS_INVALID_PARAMETER;
	}

	ntStatus = FltGetDiskDeviceObject(pFltObject->Volume, &pDiskDeviceObj);
	if (!NT_SUCCESS(ntStatus))
	{
		//DbgPrint("getDosVolumeName: FltGetDiskDeviceObject failed(0x%08x)", ntStatus);
		return ntStatus;
	}

	ntStatus = IoVolumeDeviceToDosName(pDiskDeviceObj, &pInstanceContext->usDosVolumeName);
	if (!NT_SUCCESS(ntStatus))
	{
		//DbgPrint("getDosVolumeName: IoVolumeDeviceToDosName failed(0x%08x)", ntStatus);
		RtlZeroMemory(&pInstanceContext->usDosVolumeName, sizeof(UNICODE_STRING));
		ObDereferenceObject(pDiskDeviceObj);
		return ntStatus;
	}
	
	//DbgPrint("getDosVolumeName: Dos name is(%S)\n", pInstanceContext->usDosVolumeName.Buffer);
	ObDereferenceObject(pDiskDeviceObj);
	return STATUS_SUCCESS;
}



BOOLEAN
getFilePath(
	PCFLT_RELATED_OBJECTS pFltObject,
	PFLT_FILE_NAME_INFORMATION pFileNameInfo,
	PWCHAR pszFilePath
)
{
	//BOOLEAN bRetVal;
	NTSTATUS ntStatus;
	PSCANNER_INSTANCE_CONTEXT pInstanceContext;

	if (NULL == pFltObject || NULL == pFileNameInfo || NULL == pszFilePath)
	{
		//DbgPrint("getFilepath: Invalid Parameter.\n");
		return FALSE;
	}

	ntStatus = FltGetInstanceContext(pFltObject->Instance, &pInstanceContext);
	if (!NT_SUCCESS(ntStatus))
	{
		//DbgPrint("ScannerPostCreate: FltGetInstanceContext failed(0x%08x)", ntStatus);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	if (NULL == pInstanceContext->usDosVolumeName.Buffer)
	{
		//DbgPrint("getFilePath: Volume Dos name not available.\n");
		FltReleaseContext(pInstanceContext);
		return FALSE;
	}

	ntStatus = RtlStringCchCatNW(pszFilePath, 
								MAX_FILE_PATH, 
								pInstanceContext->usDosVolumeName.Buffer, 
								pInstanceContext->usDosVolumeName.Length/sizeof(WCHAR)
								);
	if (!NT_SUCCESS(ntStatus))
	{
		//DbgPrint("getFilePath: Appending dos name failed(0x%08x)\n", ntStatus);
		FltReleaseContext(pInstanceContext);
		return FALSE;
	}

	FltReleaseContext(pInstanceContext);	// For FltGetInstanceContext.

	ntStatus = RtlStringCchCatNW(pszFilePath,
								MAX_FILE_PATH,
								pFileNameInfo->ParentDir.Buffer,
								pFileNameInfo->ParentDir.Length/sizeof(WCHAR)
								);
	if (!NT_SUCCESS(ntStatus))
	{
		//DbgPrint("getFilePath: Appending ParentDir path failed(0x%08x)\n", ntStatus);
		return FALSE;
	}

	ntStatus = RtlStringCchCatNW(pszFilePath,
								MAX_FILE_PATH,
								pFileNameInfo->FinalComponent.Buffer,
								pFileNameInfo->FinalComponent.Length/sizeof(WCHAR)
								);
	if (!NT_SUCCESS(ntStatus))
	{
		//DbgPrint("getFilePath: Appending FinalComponent failed(0x%08x)\n", ntStatus);
		return FALSE;
	}
	//DbgPrint("getFilePath: File Path is (%S)\n", pszFilePath);

	return TRUE;
}


BOOLEAN
IsSubstringPresentInString(
	PUNICODE_STRING pusString,
	PUNICODE_STRING pusSubString
)
{
	ULONG ulIndex;
	BOOLEAN bRetVal;
	if (NULL == pusString || NULL == pusSubString)
	{
		//DbgPrint("IsSubstringPresentInString: Invalid parameter.\n");
		return FALSE;
	}

	bRetVal = RtlEqualUnicodeString(pusString, pusSubString, TRUE);
	if (TRUE == bRetVal)
	{
		return TRUE;
	}

	for (ulIndex = 0; ulIndex + pusSubString->Length <= pusString->Length; ulIndex++)
	{
		if (0 == _wcsnicmp(&pusString->Buffer[ulIndex], pusSubString->Buffer, (pusSubString->Length / sizeof(WCHAR))))
		{
			return TRUE;
		}
	}
	return FALSE;
}