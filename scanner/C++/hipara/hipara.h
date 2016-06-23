
// hipara.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols
#include "liveScan.h"
#include "libyara\include\yara\libyara.h"
#include "libyara\include\yara\compiler.h"
#include "libyara\include\yara\rules.h"


// CHiparaApp:
// See hipara.cpp for the implementation of this class
//

class CHiparaApp : public CWinApp
{
public:
	CHiparaApp();

// Overrides
public:
	static FILE *mpLogFile;

	virtual BOOL InitInstance();
	virtual int ExitInstance();

// Implementation

	DECLARE_MESSAGE_MAP()
};

extern CHiparaApp theApp;