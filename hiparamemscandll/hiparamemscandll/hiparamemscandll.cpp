#include <fcntl.h>
#include <tchar.h>

#include "hiparamemscandll.h"
#include "hiparahelper.h"
#include "libyara\include\yara\types.h"
#include "libyara\include\yara\compiler.h"

FILE *g_pYarFile;
FILE *g_pReportFile;
YR_RULES *g_pYrRules;
YR_COMPILER *g_pYrCompiler;


BOOLEAN hiparamemscan()
{
	int iRetVal;
	BOOLEAN bRetVal;
	WCHAR szErrorMessage[MAX_PATH_LEN];

	OutputDebugString(_T("hiparamemscan: Entry.\n"));

	iRetVal = initYara();
	if (0 == iRetVal)
	{
		OutputDebugString(_T("hiparamemscan: initYara failed.\n"));
		return FALSE;
	}

	//
	//	Scan running processes, modules(dll) loaded into each process and all open handle to file.
	//
	bRetVal = ScanProcessAndModules();
	if (FALSE == bRetVal)
	{
		OutputDebugString(_T("hiparamemscan: ScanProcessAndModules failed.\n"));
		deinitYara();
		return FALSE;
	}

	//
	//	Scan services.
	//
	bRetVal = ScanServices();
	if (FALSE == bRetVal)
	{
		OutputDebugString(_T("hiparamemscan: ScanServices failed.\n"));
		deinitYara();
		return FALSE;
	}

	deinitYara();
	OutputDebugString(_T("hiparamemscan: Exit.\n"));

	return TRUE;
}
