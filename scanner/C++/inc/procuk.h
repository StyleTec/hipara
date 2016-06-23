/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

    procuk.h

Abstract:

    Header file which contains the structures, type definitions,
    constants, global variables and function prototypes that are
    shared between kernel and user mode.

Environment:

    Kernel & user mode

--*/

#ifndef __PROCUK_H__
#define __PROCUK_H__

//
//	Process notification data.
//
typedef struct _PROCESS_NOTIFICATION
{
	ULONG	ulProcessId;
	BOOLEAN	bCreate;

}	PROCESS_NOTIFICATION,	*P_PROCESS_NOTIFICATION;


#endif //  __PROCUK_H__


