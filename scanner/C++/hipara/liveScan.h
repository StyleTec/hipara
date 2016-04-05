#ifndef __LIVESCAN_H__
#define __LIVESCAN_H__

#include <Windows.h>
#include <fltUser.h>
#include "..\inc\scanuk.h"

//
//  Default and Maximum number of threads.
//

#define SCANNER_DEFAULT_REQUEST_COUNT		5
#define SCANNER_DEFAULT_THREAD_COUNT		2
#define SCANNER_MAX_THREAD_COUNT			64

#define MAX_FILE_PATH						512

#pragma pack(1)

typedef struct _SCANNER_MESSAGE {

	//
	//  Required structure header.
	//

	FILTER_MESSAGE_HEADER MessageHeader;


	//
	//  Private scanner-specific fields begin here.
	//

	SCANNER_NOTIFICATION Notification;

	//
	//  Overlapped structure: this is not really part of the message
	//  However we embed it instead of using a separately allocated overlap structure
	//

	OVERLAPPED Ovlp;

} SCANNER_MESSAGE, *PSCANNER_MESSAGE;

typedef struct _SCANNER_REPLY_MESSAGE {

	//
	//  Required structure header.
	//

	FILTER_REPLY_HEADER ReplyHeader;

	//
	//  Private scanner-specific fields begin here.
	//

	SCANNER_REPLY Reply;

} SCANNER_REPLY_MESSAGE, *PSCANNER_REPLY_MESSAGE;


typedef struct _SCANNER_THREAD_CONTEXT {

	HANDLE Port;
	HANDLE Completion;

} SCANNER_THREAD_CONTEXT, *PSCANNER_THREAD_CONTEXT;


typedef struct _YARA_CONTEXT{

	HANDLE hStopEvent;		// event to wait for finishing scan
	BOOLEAN bScanResult;	// set to TRUE if match found otherwise it returns FALSE.

} YARA_CONTEXT, *P_YARA_CONTEXT;


#endif