/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

    scanUser.c

Abstract:

    This file contains the implementation for the main function of the
    user application piece of scanner.  This function is responsible for
    actually scanning file contents.

Environment:

    User mode

--*/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <winioctl.h>
#include <string.h>
#include <crtdbg.h>
#include <assert.h>
#include <fltuser.h>
#include "scanuk.h"
#include "scanuser.h"
#include "libyara.h"
#include "compiler.h"
#include "rules.h"
//#include ""


//
//  Default and Maximum number of threads.
//

#define SCANNER_DEFAULT_REQUEST_COUNT       5
#define SCANNER_DEFAULT_THREAD_COUNT        2
#define SCANNER_MAX_THREAD_COUNT            64


FILE	*g_pYarFile;
FILE	*g_pLogFile;
YR_RULES *g_pYrRules;
YR_COMPILER *g_pYrCompiler;
UCHAR FoulString[] = "foul";

//
//  Context passed to worker threads
//

typedef struct _SCANNER_THREAD_CONTEXT {

    HANDLE Port;
    HANDLE Completion;

} SCANNER_THREAD_CONTEXT, *PSCANNER_THREAD_CONTEXT;


VOID
Usage (
    VOID
    )
/*++

Routine Description

    Prints usage

Arguments

    None

Return Value

    None

--*/
{

    printf( "Connects to the scanner filter and scans buffers \n" );
    //printf( "Usage: scanuser [requests per thread] [number of threads(1-64)]\n" );
	printf("Usage: scanuser [.yar file path which contains signature]\n");
}


BOOL
ScanBuffer (
    _In_reads_bytes_(BufferSize) PUCHAR Buffer,
	_In_ ULONG BufferSize
    )
/*++

Routine Description

    Scans the supplied buffer for an instance of FoulString.

    Note: Pattern matching algorithm used here is just for illustration purposes,
    there are many better algorithms available for real world filters

Arguments

    Buffer      -   Pointer to buffer
    BufferSize  -   Size of passed in buffer

Return Value

    TRUE        -    Found an occurrence of the appropriate FoulString
    FALSE       -    Buffer is ok

--*/
{
	int iRetVal;
	YARA_CONTEXT yaraContext;

	yaraContext.bScanResult = FALSE;
	yaraContext.hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (NULL == yaraContext.hStopEvent)
	{
		return FALSE;
	}

	//
	// Scan memory buffer for virus signatures.
	//
	iRetVal = yr_rules_scan_mem(g_pYrRules, Buffer, BufferSize, 0, yaraScanCallback, &yaraContext, 0);
	if (ERROR_SUCCESS != iRetVal)
	{
		return FALSE;
	}

	//
	// Wait till scanning is finished.
	// event will be set in yaraScanCallback function once scanning is finished.
	//
	WaitForSingleObject(yaraContext.hStopEvent, INFINITE);

	CloseHandle(yaraContext.hStopEvent);
	return yaraContext.bScanResult;
}


BOOLEAN
ScanFile(
	PWCHAR pszFilePath
)
{
	int iRetVal;
	errno_t errVal;
	size_t charsConverted;
	YARA_CONTEXT yaraContext;
	CHAR szFileName[MAX_FILE_PATH];

	yaraContext.bScanResult = FALSE;
	yaraContext.hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (NULL == yaraContext.hStopEvent)
	{
		return FALSE;
	}

	if (NULL == pszFilePath)
	{
		return FALSE;
	}
	//printf("ScanFile: File Path is(%S)\n", pszFilePath);
	errVal = wcstombs_s(&charsConverted, szFileName, sizeof(szFileName), pszFilePath, MAX_FILE_PATH);
	if (0 != errVal)
	{
		printf("ScanFile: wcstombs_s failed.\n");
		return FALSE;
	}
	printf("ScanFile: File Path is(%s)\n", szFileName);
	iRetVal = yr_rules_scan_file(g_pYrRules, szFileName, 0, yaraScanCallback, &yaraContext, 0);
	if (ERROR_SUCCESS != iRetVal)
	{
		printf("ScanFile: yr_rules_scan_file failed(%d).\n", iRetVal);
		return FALSE;
	}

	//
	// Wait till scanning is finished.
	// event will be set in yaraScanCallback function once scanning is finished.
	//
	WaitForSingleObject(yaraContext.hStopEvent, INFINITE);

	CloseHandle(yaraContext.hStopEvent);
	return yaraContext.bScanResult;
}


DWORD
ScannerWorker(
_In_ PSCANNER_THREAD_CONTEXT Context
    )
/*++

Routine Description

    This is a worker thread that


Arguments

    Context  - This thread context has a pointer to the port handle we use to send/receive messages,
                and a completion port handle that was already associated with the comm. port by the caller

Return Value

    HRESULT indicating the status of thread exit.

--*/
{
    PSCANNER_NOTIFICATION notification;
    SCANNER_REPLY_MESSAGE replyMessage;
    PSCANNER_MESSAGE message;
    LPOVERLAPPED pOvlp;
    BOOL result;
    DWORD outSize;
    HRESULT hr;
    ULONG_PTR key;

#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant

    while (TRUE) {

#pragma warning(pop)

        //
        //  Poll for messages from the filter component to scan.
        //

        result = GetQueuedCompletionStatus( Context->Completion, &outSize, &key, &pOvlp, INFINITE );

        //
        //  Obtain the message: note that the message we sent down via FltGetMessage() may NOT be
        //  the one dequeued off the completion queue: this is solely because there are multiple
        //  threads per single port handle. Any of the FilterGetMessage() issued messages can be
        //  completed in random order - and we will just dequeue a random one.
        //

        message = CONTAINING_RECORD( pOvlp, SCANNER_MESSAGE, Ovlp );

        if (!result) {

            //
            //  An error occured.
            //

            hr = HRESULT_FROM_WIN32( GetLastError() );
            break;
        }

        //printf( "Received message, size %d\n", pOvlp->InternalHigh );

        notification = &message->Notification;

		if (notification->ushFlag & FILE_CONTENTS_STORED)
		{

			assert(notification->BytesToScan <= SCANNER_READ_BUFFER_SIZE);
			_Analysis_assume_(notification->BytesToScan <= SCANNER_READ_BUFFER_SIZE);

			result = ScanBuffer(notification->Contents, notification->BytesToScan);

			replyMessage.ReplyHeader.Status = 0;
			replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;

			//
			//  Need to invert the boolean -- result is true if found
			//  foul language, in which case SafeToOpen should be set to false.
			//

			replyMessage.Reply.SafeToOpen = !result;

			//printf("Replying message, SafeToOpen: %d\n", replyMessage.Reply.SafeToOpen);
		}
		else
		{
			result = ScanFile(notification->szFilePath);

			replyMessage.ReplyHeader.Status = 0;
			replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;

			replyMessage.Reply.SafeToOpen = !result;
			printf("ScannerWorker: Scan result is(%d)\n", result);
		}

        hr = FilterReplyMessage( Context->Port,
                                 (PFILTER_REPLY_HEADER) &replyMessage,
                                 sizeof( replyMessage ) );

        if (SUCCEEDED( hr )) {

            printf( "Replied message\n" );

        } else {

            printf( "Scanner: Error replying message. Error = 0x%X\n", hr );
            break;
        }

        memset( &message->Ovlp, 0, sizeof( OVERLAPPED ) );

        hr = FilterGetMessage( Context->Port,
                               &message->MessageHeader,
                               FIELD_OFFSET( SCANNER_MESSAGE, Ovlp ),
                               &message->Ovlp );

        if (hr != HRESULT_FROM_WIN32( ERROR_IO_PENDING )) {

            break;
        }
    }

    if (!SUCCEEDED( hr )) {

        if (hr == HRESULT_FROM_WIN32( ERROR_INVALID_HANDLE )) {

            //
            //  Scanner port disconncted.
            //

            printf( "Scanner: Port is disconnected, probably due to scanner filter unloading.\n" );

        } else {

            printf( "Scanner: Unknown error occured. Error = 0x%X\n", hr );
        }
    }

    free( message );

    return hr;
}


//
// Callback function where scanned result is reported by yara.
//
int
yaraScanCallback(
	int message,
	void *pMessage_data,
	void *pUser_data
)
{
	int iRetVal;
	CHAR buff[80];
	SYSTEMTIME sysTime;
	P_YARA_CONTEXT pyaraContext;

	pyaraContext = (YARA_CONTEXT *)pUser_data;

	if (CALLBACK_MSG_RULE_MATCHING == message)
	{
		pyaraContext->bScanResult = TRUE;
		memset(buff, '0', 80);
		GetLocalTime(&sysTime);
		iRetVal = sprintf_s(buff, 80 * sizeof(CHAR), "Time : %d:%d = Virus Signature found\n", sysTime.wHour, sysTime.wMinute);
		fwrite(buff, sizeof(CHAR), iRetVal, g_pLogFile);
		printf("yaraScanCallback: CALLBACK_MSG_RULE_MATCHING.\n");
	}
	else if (CALLBACK_MSG_RULE_NOT_MATCHING == message)
	{
		//printf("yaraScanCallback: CALLBACK_MSG_RULE_NOT_MATCHING.\n");
	}
	else if (CALLBACK_MSG_IMPORT_MODULE == message)
	{
		printf("yaraScanCallback: CALLBACK_MSG_IMPORT_MODULE.\n");
	}
	else if (CALLBACK_MSG_SCAN_FINISHED == message)
	{
		SetEvent(pyaraContext->hStopEvent);
		printf("yaraScanCallback: CALLBACK_MSG_SCAN_FINISHED.\n");
	}
	return ERROR_SUCCESS;
}


//
// Yara library initialization function.
//
int initYara(CHAR *pszYaraFilePath)
{
	int iRetVal;
	DWORD dwRetVal;
	errno_t errRetVal;
	CHAR *pszYarFilePath = NULL;
	CHAR charrLogFilePath[] = "C:\\yaraLog.txt";

	if (NULL == pszYaraFilePath)
	{
		return ERROR_INVALID_PARAMETER;
	}

	iRetVal = yr_initialize();
	if (ERROR_SUCCESS != iRetVal)
	{
		return iRetVal;
	}

	iRetVal = yr_compiler_create(&g_pYrCompiler);
	if (ERROR_SUCCESS != iRetVal)
	{
		yr_finalize();
		return iRetVal;
	}

	g_pYarFile = fopen(pszYaraFilePath, "rb");
	if (NULL == g_pYarFile)
	{
		yr_compiler_destroy(g_pYrCompiler);
		yr_finalize();

		return -1;
	}

	iRetVal = yr_compiler_add_file(g_pYrCompiler, g_pYarFile, NULL, NULL);
	if (iRetVal > 0)
	{
		fclose(g_pYarFile);
		yr_compiler_destroy(g_pYrCompiler);
		yr_finalize();

		return iRetVal;
	}

	iRetVal = yr_compiler_get_rules(g_pYrCompiler, &g_pYrRules);
	if (ERROR_SUCCESS != iRetVal)
	{
		fclose(g_pYarFile);
		yr_compiler_destroy(g_pYrCompiler);
		yr_finalize();

		return iRetVal;
	}

	g_pLogFile = fopen(charrLogFilePath, "a");
	if (NULL == g_pLogFile)
	{
		printf("initYara: Failed to open log file.\n");
		yr_rules_destroy(g_pYrRules);
		yr_compiler_destroy(g_pYrCompiler);
		fclose(g_pYarFile);
		yr_finalize();
		return -1;
	}

	return ERROR_SUCCESS;
}


//
// yara library de-initialization function.
//
void
deinitYara()
{
	yr_rules_destroy(g_pYrRules);
	fclose(g_pYarFile);
	yr_compiler_destroy(g_pYrCompiler);
	yr_finalize();
	if (NULL != g_pLogFile)
	{
		fclose(g_pLogFile);
	}
}

int _cdecl
main (
    _In_ int argc,
    _In_reads_(argc) char *argv[]
    )
{
	HRESULT hr;
	DWORD i, j;
	DWORD threadId;
	PSCANNER_MESSAGE msg;
	HANDLE port, completion;
    SCANNER_THREAD_CONTEXT context;
	HANDLE threads[SCANNER_MAX_THREAD_COUNT];
	DWORD threadCount = SCANNER_DEFAULT_THREAD_COUNT;
	DWORD requestCount = SCANNER_DEFAULT_REQUEST_COUNT;

	//
	// Yara related variables.
	//
	int iRetVal;
	UINT uiPathLen;
	FILE	*pFile;
	DWORD dwRetVal;
	errno_t errRetVal;
	HANDLE pStopEvent;
	YR_RULES *pYrRules = NULL;
	CHAR *pszYarFilePath = NULL;
	YR_COMPILER *pYrCompiler = NULL;

	//
	// Check whether .yar file path is given by user or not.
	//
	if (argc <= 1)
	{
		Usage();
		return 1;
	}

	uiPathLen = strlen(argv[1]) + sizeof(NULL);
	if (uiPathLen == 0)
	{
		Usage();
		return 1;
	}

	pszYarFilePath = (CHAR *)malloc(uiPathLen * sizeof(CHAR));
	if (NULL == pszYarFilePath)
	{
		printf("main: memory allocation to pszYarFilePath is failed.\n");
		return 1;
	}

	errRetVal = strcpy_s(pszYarFilePath, uiPathLen, argv[1]);
	if (0 != errRetVal)
	{
		printf("main: strcpy_s failed.\n");
		free(pszYarFilePath);
		return 1;
	}

	iRetVal = initYara(pszYarFilePath);
	if (ERROR_SUCCESS != iRetVal)
	{
		printf("main: initYara failed.\n");
		free(pszYarFilePath);
		return 1;
	}

    //
    //  Open a commuication channel to the filter
    //

    printf( "Scanner: Connecting to the filter ...\n" );

    hr = FilterConnectCommunicationPort( ScannerPortName,
                                         0,
                                         NULL,
                                         0,
                                         NULL,
                                         &port );

    if (IS_ERROR( hr )) {

        printf( "ERROR: Connecting to filter port: 0x%08x\n", hr );
        return 2;
    }

    //
    //  Create a completion port to associate with this handle.
    //

    completion = CreateIoCompletionPort( port,
                                         NULL,
                                         0,
                                         threadCount );

    if (completion == NULL) {

        printf( "ERROR: Creating completion port: %d\n", GetLastError() );
        CloseHandle( port );
        return 3;
    }

    printf( "Scanner: Port = 0x%p Completion = 0x%p\n", port, completion );

    context.Port = port;
    context.Completion = completion;

    //
    //  Create specified number of threads.
    //

    for (i = 0; i < threadCount; i++) {

        threads[i] = CreateThread( NULL,
                                   0,
								   (LPTHREAD_START_ROUTINE)ScannerWorker,
                                   &context,
                                   0,
                                   &threadId );

        if (threads[i] == NULL) {

            //
            //  Couldn't create thread.
            //

            hr = GetLastError();
            printf( "ERROR: Couldn't create thread: %d\n", hr );
            goto main_cleanup;
        }

        for (j = 0; j < requestCount; j++) {

            //
            //  Allocate the message.
            //

#pragma prefast(suppress:__WARNING_MEMORY_LEAK, "msg will not be leaked because it is freed in ScannerWorker")
            msg = malloc( sizeof( SCANNER_MESSAGE ) );

            if (msg == NULL) {

                hr = ERROR_NOT_ENOUGH_MEMORY;
                goto main_cleanup;
            }

            memset( &msg->Ovlp, 0, sizeof( OVERLAPPED ) );

            //
            //  Request messages from the filter driver.
            //

            hr = FilterGetMessage( port,
                                   &msg->MessageHeader,
                                   FIELD_OFFSET( SCANNER_MESSAGE, Ovlp ),
                                   &msg->Ovlp );

            if (hr != HRESULT_FROM_WIN32( ERROR_IO_PENDING )) {

                free( msg );
                goto main_cleanup;
            }
        }
    }

    hr = S_OK;

    WaitForMultipleObjectsEx( i, threads, TRUE, INFINITE, FALSE );

main_cleanup:

    printf( "Scanner:  All done. Result = 0x%08x\n", hr );

    CloseHandle( port );
    CloseHandle( completion );

	//
	// clear all yara related initializations.
	//
	deinitYara();

    return hr;
}