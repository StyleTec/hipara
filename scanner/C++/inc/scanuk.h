/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

    scanuk.h

Abstract:

    Header file which contains the structures, type definitions,
    constants, global variables and function prototypes that are
    shared between kernel and user mode.

Environment:

    Kernel & user mode

--*/

#ifndef __SCANUK_H__
#define __SCANUK_H__

//
//  Name of port used to communicate
//

const PWSTR ScannerPortName = L"\\ScannerPort";
const PWSTR CmdPortName = L"\\CmdPort";


#define SCANNER_READ_BUFFER_SIZE   1024
#define MAX_FILE_PATH				512

#define FILE_PATH_STORED			0x01
#define FILE_CONTENTS_STORED		0x02

typedef struct _SCANNER_NOTIFICATION {

    ULONG BytesToScan;
    ULONG Reserved;             // for quad-word alignement of the Contents structure
    UCHAR Contents[SCANNER_READ_BUFFER_SIZE];
	WCHAR szFilePath[MAX_FILE_PATH];
	USHORT ushFlag;				// Flag which will tell whether File name is stored or file contents are copied.
	BOOLEAN bIsSafeOperation;	// This will tell whether current file or file operation is safe or not.

} SCANNER_NOTIFICATION, *PSCANNER_NOTIFICATION;

//
//	Process notification data.
//
typedef struct _PROCESS_NOTIFICATION
{
	ULONG	ulProcessId;
	BOOLEAN	bCreate;

}	PROCESS_NOTIFICATION, *P_PROCESS_NOTIFICATION;

typedef struct _SCANNER_REPLY {

    BOOLEAN SafeToOpen;
    
} SCANNER_REPLY, *PSCANNER_REPLY;

#endif //  __SCANUK_H__


