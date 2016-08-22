
// hiparaDlg.cpp : implementation file
//

#include "stdafx.h"
#include "hipara.h"
#include "hiparaDlg.h"
#include "DlgProxy.h"
#include "afxdialogex.h"
#include <strsafe.h>
#include "libyara\include\yara\scan.h"
#include "misc.h"
#include "..\update\include\Error.h"
#include "hiparamemscandll.h"
#include "cmdlog.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

TCHAR gszInstallationDir[MAX_FILE_PATH] = _T("C:\\Program Files\\Allsum\\Hipara");

TCHAR gszSignatureFolderPath[MAX_FILE_PATH] = _T("C:\\Program Files\\Allsum\\Hipara\\signatures");

CHAR gszReportFilePath[MAX_FILE_PATH] = "C:\\Program Files\\Allsum\\Hipara\\Report.txt";

CMD_THREAD_DATA CmdThreadData[MAX_CMD_MON_COUNT];
CMD_THREAD_CTX  CmdThreadCtx[MAX_CMD_MON_COUNT];

FILE* CHiparaDlg::mpLogFile = NULL;
BYTE gbyOnlyLogToServer;

CHiparaDlg *g_pThis;

// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CHiparaDlg dialog


IMPLEMENT_DYNAMIC(CHiparaDlg, CDialogEx);

CHiparaDlg::CHiparaDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CHiparaDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_pAutoProxy = NULL;

	mpYarFile = NULL;
	mpYrCompiler = NULL;
	mpYrRules = NULL;
	hLiveScanThread = NULL;
	mhEntireSystemScanThread = NULL;
	mhUpdateSignatureThread = NULL;
	mhMemoryScannerThread = NULL;
	bIsYaraLibraryInitialize = FALSE;
}

CHiparaDlg::~CHiparaDlg()
{
	// If there is an automation proxy for this dialog, set
	//  its back pointer to this dialog to NULL, so it knows
	//  the dialog has been deleted.
	if (m_pAutoProxy != NULL)
		m_pAutoProxy->m_pDialog = NULL;
}

void CHiparaDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CHiparaDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_CLOSE()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_SCANENTIRESYSTEM, &CHiparaDlg::OnBnClickedScanentiresystem)
	ON_BN_CLICKED(IDC_UPDATESIGNATURE, &CHiparaDlg::OnBnClickedUpdatesignature)
	ON_BN_CLICKED(IDC_MEMORYSCAN, &CHiparaDlg::OnBnClickedMemoryscan)
END_MESSAGE_MAP()


// CHiparaDlg message handlers

BOOL CHiparaDlg::OnInitDialog()
{
	int iRetVal;
	BOOLEAN bRetVal;

	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	g_pThis = this;

	bRetVal = InitUpdateLib();
	if (FALSE == bRetVal)
	{
		OutputDebugString(_T("OnInitDialog: Update library initialization failed.\n"));
		AfxMessageBox(_T("Update Library initialization failed."));
		return FALSE;
	}

	bRetVal = LoadFilter(FILTER_SCANNER_NAME);
	if (FALSE == bRetVal)
	{
		OutputDebugString(_T("OnInitDialog: LoadFilter() Failed for scanner.\n"));
		AfxMessageBox(_T("Loading scanner driver failed.."));
		return FALSE;
	}

	bRetVal = InstallMemoryScannerDriver(HIPARA_MEMORY_SCAN_DRIVER, HIPARA_MEMORY_SCAN_SERVICE);
	if (FALSE == bRetVal)
	{
		//OutputDebugString(_T("OnInitDialog: Installing driver failed.\n"));
		AfxMessageBox(_T("Installing Memory scanner driver failed."));

		return FALSE;
	}

	iRetVal = initYara();
	if (ERROR_SUCCESS != iRetVal)
	{
		OutputDebugString(_T("OnInitDialog: initYara failed.\n"));
		return FALSE;
	}

	bIsYaraLibraryInitialize = TRUE;

	mhStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (NULL == mhStopEvent)
	{
		OutputDebugString(_T("OnInitDialog:: CreateEvent failed.\n"));
		return FALSE;
	}

	mhUpdateAvailableEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (NULL == mhUpdateAvailableEvent)
	{
		OutputDebugString(_T("OnInitDialog:: CreateEvent for update event failed.\n"));
		return FALSE;
	}

	hLiveScanThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)liveScanThread, this, 0, NULL);
	if (NULL == hLiveScanThread)
	{
		OutputDebugString(_T("OnInitDialog: Creating live scan thread failed.\n"));
		return FALSE;
	}

	hCmdScanThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CmdScanThread, this, 0, NULL);
	if (NULL == hCmdScanThread)
	{
		OutputDebugString(_T("OnInitDialog: Creating cmd scan thread failed.\n"));
		/*SetEvent(mhStopEvent);
		WaitForSingleObject(hLiveScanThread, INFINITE);
		deinitYara();
		UnInstallMemoryScannerDriver(HIPARA_MEMORY_SCAN_SERVICE);
		DeInitUpdateLib();*/
		return FALSE;
	}

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CHiparaDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CHiparaDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CHiparaDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

// Automation servers should not exit when a user closes the UI
//  if a controller still holds on to one of its objects.  These
//  message handlers make sure that if the proxy is still in use,
//  then the UI is hidden but the dialog remains around if it
//  is dismissed.

void CHiparaDlg::OnClose()
{
	BOOLEAN bRetVal;

	OutputDebugStringA("OnClose:: Setting Stop event.\n");

	SetEvent(mhStopEvent);

	if (NULL != hCmdScanThread)
	{
		OutputDebugStringA("OnClose:: Waiting for CmdScanThread.\n");
		WaitForSingleObject(hCmdScanThread, INFINITE);

		OutputDebugStringA("OnClose:: CmdScanThread terminated.\n");
		CloseHandle(hCmdScanThread);
		hCmdScanThread = NULL;
	}

	if (NULL != hLiveScanThread)
	{
		OutputDebugStringA("OnClose:: Waiting for LivScanThread.\n");
		WaitForSingleObject(hLiveScanThread, INFINITE);

		OutputDebugStringA("OnClose:: LivScanThread terminated.\n");
		CloseHandle(hLiveScanThread);
		hLiveScanThread = NULL;
	}

	OutputDebugString(_T("OnClose: Live scanning thread terminated.\n"));

	if (NULL != mhEntireSystemScanThread)
	{
		OutputDebugString(_T("OnClose: Waiting for entire system scan thread.\n"));
		WaitForSingleObject(mhEntireSystemScanThread, INFINITE);

		CloseHandle(mhEntireSystemScanThread);
		mhEntireSystemScanThread = NULL;
		//OutputDebugString(_T("OnClose: Entire system scan thread terminated.\n"));
	}

	if (NULL != mhMemoryScannerThread)
	{
		OutputDebugString(_T("OnClose: Waiting for memory scan thread to finish.\n"));
		WaitForSingleObject(mhMemoryScannerThread, INFINITE);

		CloseHandle(mhMemoryScannerThread);
		mhMemoryScannerThread = NULL;
		OutputDebugString(_T("OnClose: Memory scan thread terminated.\n"));
	}

	bRetVal = UnInstallMemoryScannerDriver(HIPARA_MEMORY_SCAN_SERVICE);
	if (FALSE == bRetVal)
	{
		OutputDebugString(_T("OnClose: UnInstallMemoryScannerDriver failed.\n"));
	}

	CloseHandle(mhStopEvent);
	mhStopEvent = NULL;

	CloseHandle(mhUpdateAvailableEvent);
	mhUpdateAvailableEvent = NULL;

	OutputDebugString(_T("OnClose: Calling deinitYara.\n"));
	deinitYara();

	OutputDebugString(_T("OnClose: DeInitUpdateLib.\n"));
	DeInitUpdateLib();
	OutputDebugString(_T("OnClose: DeInitUpdateLib done.\n"));

	UnloadFilter(FILTER_SCANNER_NAME);

	if (CanExit())
		CDialogEx::OnClose();
}

void CHiparaDlg::OnOK()
{
	if (CanExit())
		CDialogEx::OnOK();
}

void CHiparaDlg::OnCancel()
{
	if (CanExit())
		CDialogEx::OnCancel();
}

BOOL CHiparaDlg::CanExit()
{
	// If the proxy object is still around, then the automation
	//  controller is still holding on to this application.  Leave
	//  the dialog around, but hide its UI.
	if (m_pAutoProxy != NULL)
	{
		ShowWindow(SW_HIDE);
		return FALSE;
	}

	return TRUE;
}



void CHiparaDlg::OnBnClickedScanentiresystem()
{
	// TODO: Add your control notification handler code here

	mhEntireSystemScanThread = CreateThread(NULL, 0, CHiparaDlg::entireSystemScan, this, 0, NULL);
	if (NULL == mhEntireSystemScanThread)
	{
		//OutputDebugString(_T("OnBnClickedScanentiresystem: Creating entire system scan thread failed.\n"));
	}
	
}


DWORD WINAPI CHiparaDlg::entireSystemScan(LPVOID lpvParameter)
{
	UINT uiCnt;
	DWORD dwWaitRet;
	BOOLEAN bRetVal;
	HANDLE hEvents[2];
	errno_t errRetVal;
	HANDLE hEnumThread;
	CHiparaDlg *pContext;
	BOOLEAN bIsScanningAborted;
	//SCAN_CONTEXT scanContext;

	if (NULL == lpvParameter)
	{
		//OutputDebugString(_T("entireSystemScan: Invalid Parameter.\n"));
		return 0;
	}

	pContext = (CHiparaDlg *)lpvParameter;

	bRetVal = pContext->isYaraLibraryInitialized();
	if (FALSE == bRetVal)
	{
		AfxMessageBox(_T("Yara signatures are out of date. Please update it first."));
		return 0;
	}

	pContext->GetDlgItem(IDC_SCANENTIRESYSTEM)->EnableWindow(FALSE);

	memset(&pContext->mScanContext, 0, sizeof(SCAN_CONTEXT));
	pContext->mScanContext.queueInfo.uiHead = -1;
	pContext->mScanContext.queueInfo.uiTail = -1;

	errRetVal = _tcscpy_s(pContext->mScanContext.szSignaturePath, gszSignatureFolderPath);
	if (0 != errRetVal)
	{
		//OutputDebugString(_T("OnBnClickedScanentiresystem: _tcscpy_s failed.\n"));
		pContext->GetDlgItem(IDC_SCANENTIRESYSTEM)->EnableWindow(TRUE);
		return 0;
	}

	pContext->mScanContext.queueInfo.hQueueMutex = CreateMutex(NULL, FALSE, NULL);
	if (NULL == pContext->mScanContext.queueInfo.hQueueMutex)
	{
		//OutputDebugString(_T("OnBnClickedScanentiresystem: CreateMutex for hQueueMutex failed.\n"));
		pContext->GetDlgItem(IDC_SCANENTIRESYSTEM)->EnableWindow(TRUE);
		return 0;
	}

	pContext->mScanContext.hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (NULL == pContext->mScanContext.hStopEvent)
	{
		//OutputDebugString(_T("OnBnClickedScanentiresystem: CreateEvent for hStopEvent failed"));
		CloseHandle(pContext->mScanContext.queueInfo.hQueueMutex);
		pContext->GetDlgItem(IDC_SCANENTIRESYSTEM)->EnableWindow(TRUE);
		return 0;
	}

	for (uiCnt = 0; uiCnt < MAX_SIZE_QUEUE; uiCnt++)
	{
		pContext->mScanContext.queueInfo.pvData[uiCnt] = NULL;
	}

	hEnumThread = CreateThread(NULL, 0, CHiparaDlg::enumFilesThread, pContext, 0, NULL);
	if (NULL == hEnumThread)
	{
		//OutputDebugString(_T("OnBnClickedScanentiresystem:: CreateThread failed.\n"));
		CloseHandle(pContext->mScanContext.hStopEvent);
		CloseHandle(pContext->mScanContext.queueInfo.hQueueMutex);
		pContext->GetDlgItem(IDC_SCANENTIRESYSTEM)->EnableWindow(TRUE);

		return 0;
	}

	bIsScanningAborted = FALSE;

	hEvents[0] = hEnumThread;
	hEvents[1] = pContext->mhStopEvent;
	dwWaitRet = WaitForMultipleObjects(2, hEvents, FALSE, INFINITE);
	if (1 == (dwWaitRet - WAIT_OBJECT_0))
	{
		//OutputDebugString(_T("OnBnClickedScanentiresystem: Stop event set.\n"));
		SetEvent(pContext->mScanContext.hStopEvent);

		//OutputDebugString(_T("entireSystemScan: Stop event set so waiting for enumFilesThread.\n"));
		dwWaitRet = WaitForSingleObject(hEnumThread, INFINITE);
		//OutputDebugString(_T("entireSystemScan: enumFilesThread terminated.\n"));
		bIsScanningAborted = TRUE;
	}
	else
	{
		//OutputDebugString(_T("entireSystemScan: enumFilesThread terminated. So setting stop event\n"));
		SetEvent(pContext->mScanContext.hStopEvent);
	}

	CloseHandle(pContext->mScanContext.queueInfo.hQueueMutex);
	CloseHandle(pContext->mScanContext.hStopEvent);

	for (uiCnt = 0; uiCnt < MAX_SIZE_QUEUE; uiCnt++)
	{
		if (NULL != pContext->mScanContext.queueInfo.pvData[uiCnt])
		{
			free(pContext->mScanContext.queueInfo.pvData[uiCnt]);
			pContext->mScanContext.queueInfo.pvData[uiCnt] = NULL;
		}
	}
	CloseHandle(hEnumThread);

	if (FALSE == bIsScanningAborted)
	{
		pContext->GetDlgItem(IDC_SCANENTIRESYSTEM)->EnableWindow(TRUE);
		AfxMessageBox(_T("Entire system has been scanned successfully.\n"));
	}

	//OutputDebugString(_T("entireSystemScan: Exit.\n"));
	return 0;
}


void CHiparaDlg::OnBnClickedUpdatesignature()
{
	BOOLEAN bRetVal;
	//OutputDebugString(_T("OnBnClickedUpdatesignature: Entry.\n"));

	bRetVal = updateYaraSignatures();
	if (FALSE == bRetVal)
	{
		//OutputDebugString(_T("OnBnClickedUpdatesignature: Failed to update yara signatures.\n"));
	}
	
	//OutputDebugString(_T("OnBnClickedUpdatesignature: Exit.\n"));
}


BOOLEAN CHiparaDlg::updateYaraSignatures()
{
	//OutputDebugString(_T("updateYaraSignatures: Entry.\n"));

	mhUpdateSignatureThread = CreateThread(NULL, 0, CHiparaDlg::updateSignatures, this, 0, NULL);
	if (NULL == mhUpdateSignatureThread)
	{
		//OutputDebugString(_T("updateYaraSignatures: Creating update signature thread failed.\n"));
		return FALSE;
	}

	//OutputDebugString(_T("updateYaraSignatures: Exit.\n"));
	return TRUE;
}


DWORD WINAPI CHiparaDlg::updateSignatures(LPVOID lpvParameter)
{
	int iRetVal;
	Update *pUpdate;
	CHiparaDlg *pContext;
	TCHAR errMsg[MAX_PATH];

	if (NULL == lpvParameter)
	{
		//OutputDebugString(_T("updateSignatures: Invalid Parameter.\n"));
	}
	OutputDebugString(_T("updateSignatures: Entry.\n"));
	pContext = (CHiparaDlg *)lpvParameter;

	pContext->GetDlgItem(IDC_UPDATESIGNATURE)->EnableWindow(FALSE);

	pUpdate = pContext->GetUpdateLibObj();

	OutputDebugString(_T("updateSignatures: Calling updateSignature.\n"));
	iRetVal = pUpdate->updateSignature();
	if (CurlError != 200)
	{
		_stprintf_s(errMsg, sizeof(errMsg), _T("The server is unreachable/unavailable at this time. Please check with your network administrator."));
		//OutputDebugString(errMsg);
		pContext->GetDlgItem(IDC_UPDATESIGNATURE)->EnableWindow(TRUE);
		AfxMessageBox(errMsg);

		_stprintf_s(errMsg, sizeof(errMsg), _T("Curl Error: %d."), CurlError);
		OutputDebugString(errMsg);
		return 0;
	}

	if (0 != iRetVal)
	{
		_stprintf_s(errMsg, sizeof(errMsg), _T("Update signature failed, Please check network connection or contact administrator."));
		//OutputDebugString(errMsg);
		pContext->GetDlgItem(IDC_UPDATESIGNATURE)->EnableWindow(TRUE);
		AfxMessageBox(errMsg);
		return 0;
	}
	else
	{
		OutputDebugString(_T("updateSignatures: Yara signatures has been updated successfully.\n"));
	}

	if (NULL != pContext->mhUpdateAvailableEvent)
	{
		OutputDebugString(_T("updateSignatures: setting update available event.\n"));
		SetEvent(pContext->mhUpdateAvailableEvent);
	}

	if (NULL != pContext->hLiveScanThread)
	{
		OutputDebugString(_T("updateSignatures: Waiting for live scan thread to terminate.\n"));
		WaitForSingleObject(pContext->hLiveScanThread, INFINITE);
		CloseHandle(pContext->hLiveScanThread);
		OutputDebugString(_T("updateSignatures: Live scan thread terminated.\n"));
	}

	if (pContext->isYaraLibraryInitialized())
	{
		OutputDebugString(_T("updateSignatures: Yara library has been already initialized, so deinitializing previous one.\n"));
		pContext->deinitYara();
	}
		
	iRetVal = pContext->initYara();
	if (ERROR_SUCCESS != iRetVal)
	{
		OutputDebugString(_T("updateSignatures: initYara failed.\n"));
		pContext->GetDlgItem(IDC_UPDATESIGNATURE)->EnableWindow(TRUE);
		AfxMessageBox(_T("Updating signatures failed.\n"));
		return 0;
	}

	pContext->setYaraLibraryInitializedFlag(TRUE);
	ResetEvent(pContext->mhUpdateAvailableEvent);

	pContext->hLiveScanThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CHiparaDlg::liveScanThread, lpvParameter, 0, NULL);
	if (NULL == pContext->hLiveScanThread)
	{
		//OutputDebugString(_T("updateSignatures: Creating live scan thread failed.\n"));
	}

	AfxMessageBox(_T("Signatures updated successfully"));
	pContext->GetDlgItem(IDC_UPDATESIGNATURE)->EnableWindow(TRUE);

	OutputDebugString(_T("updateSignatures: Exit.\n"));
	return 0;
}


int CHiparaDlg::initYara()
{
	int iRetVal;
	UINT uiOutLen;
	HRESULT hrRetVal;
	HANDLE hFileFind;
	CHAR *pszFileName;
	WIN32_FIND_DATA findData;
	TCHAR szSigFilePath[MAX_FILE_PATH] = { '\0' };
	TCHAR szTempFolderPath[MAX_FILE_PATH] = { '\0' };
	CHAR szFileName[MAX_FILE_PATH] = { '\0' };

	char msg[260];	//	For debug logs.

	_tcscpy_s(szTempFolderPath, MAX_FILE_PATH, gszSignatureFolderPath);

	hrRetVal = StringCchCat(szTempFolderPath, MAX_FILE_PATH, _T("\\*"));
	if (FAILED(hrRetVal))
	{
		//OutputDebugString(_T("initYara:: StringCchCat failed.\n"));
		return -1;
	}

	WCHAR wszPath[260];
	swprintf(wszPath, L"%s", szTempFolderPath);
	//OutputDebugString(wszPath);

	hFileFind = FindFirstFile(szTempFolderPath, &findData);
	if (INVALID_HANDLE_VALUE == hFileFind)
	{
		//OutputDebugString(_T("initYara:: FindFirstFile failed.\n"));
		AfxMessageBox(_T("Yara signature database is empty!! Please update it first and restart the application."));
		return -1;
	}

	do
	{
		if ((0 != _tcscmp(findData.cFileName, _T("."))) && (0 != _tcscmp(findData.cFileName, _T(".."))))
		{
			hrRetVal = StringCchPrintf(szSigFilePath, MAX_FILE_PATH, _T("%s\\%s"), gszSignatureFolderPath, findData.cFileName);
			if (FAILED(hrRetVal))
			{
				//OutputDebugString(_T("initYara::StringCchPrintf failed"));
				break;
			}

			iRetVal = yr_initialize();
			if (ERROR_SUCCESS != iRetVal)
			{
				//OutputDebugString(_T("initYara: yr_initialize failed.\n"));

				swprintf_s(wszPath, sizeof(wszPath), _T("initYara: yr_initialize failed for(%S)"), szSigFilePath);
				OutputDebugStringW(wszPath);

				return iRetVal;
			}

			iRetVal = yr_compiler_create(&mpYrCompiler);
			if (ERROR_SUCCESS != iRetVal)
			{
				yr_finalize();
				mpYrCompiler = NULL;
				//OutputDebugString(_T("initYara: yr_compiler_create failed.\n"));
				return iRetVal;
			}

			iRetVal = ConvertFromWideCharToMultiByte(szSigFilePath, _tcslen(szSigFilePath), &pszFileName, &uiOutLen);
			if (FALSE == iRetVal)
			{
				yr_compiler_destroy(mpYrCompiler);
				yr_finalize();
				mpYrCompiler = NULL;
				//OutputDebugString(_T("initYara: ConvertFromWideCharToMultiByte() failed.\n"));
				return -1;
			}

			mpYarFile = fopen(pszFileName, "rb");
			if (NULL == mpYarFile)
			{
				yr_compiler_destroy(mpYrCompiler);
				yr_finalize();
				mpYrCompiler = NULL;
				mpYarFile = NULL;

				sprintf_s(msg, sizeof(msg), "initYara: fopen failed for(%s)", pszFileName);
				//OutputDebugStringA(msg);

				return -1;
			}

			sprintf_s(msg, sizeof(msg), ("initYara: yr_compiler_add_file for(%S)"), pszFileName);
			//OutputDebugStringA(msg);

			iRetVal = yr_compiler_add_file(mpYrCompiler, mpYarFile, NULL, NULL);
			if (iRetVal > 0)
			{
				fclose(mpYarFile);
				yr_compiler_destroy(mpYrCompiler);
				yr_finalize();
				mpYrCompiler = NULL;
				mpYarFile = NULL;

				sprintf_s(msg, sizeof(msg), "initYara: yr_compiler_add_file failed for(%s)", pszFileName);
				//OutputDebugStringA(msg);

				return iRetVal;
			}

			iRetVal = yr_compiler_get_rules(mpYrCompiler, &mpYrRules);
			if (ERROR_SUCCESS != iRetVal)
			{
				fclose(mpYarFile);
				yr_compiler_destroy(mpYrCompiler);
				yr_finalize();

				mpYrCompiler = NULL;
				mpYarFile = NULL;
				mpYrRules = NULL;
				//OutputDebugString(_T("initYara: yr_compiler_get_rules failed.\n"));
				return iRetVal;
			}

			return ERROR_SUCCESS;
		}
	} while (FindNextFile(hFileFind, &findData) != 0);

	return 1;
}


void CHiparaDlg::deinitYara()
{
	//OutputDebugString(_T("deinitYara: Entry.\n"));

	if (FALSE == bIsYaraLibraryInitialize)
	{
		OutputDebugString(_T("deinitYara: Yara lib is not initialized.\n"));
		return;
	}
	if (NULL != mpYrRules)
	{
		yr_rules_destroy(mpYrRules);
	}

	if (NULL != mpYarFile)
	{
		fclose(mpYarFile);
	}

	if (NULL != mpYrCompiler)
	{
		yr_compiler_destroy(mpYrCompiler);
	}

	yr_finalize();

	bIsYaraLibraryInitialize = FALSE;
	//OutputDebugString(_T("deinitYara: Exit.\n"));
}


int CHiparaDlg::yaraScanCallback(int iMessage, void *pMessageData, void *pUserData)
{
	P_YARA_CONTEXT pyaraContext;
	////OutputDebugString(_T("yaraScanCalback: Entry.\n"));
	pyaraContext = (YARA_CONTEXT *)pUserData;

	if (CALLBACK_MSG_RULE_MATCHING == iMessage)
	{
		pyaraContext->bScanResult = TRUE;
		//OutputDebugString(_T("yaraScanCallback:: CALLBACK_MSG_RULE_MATCHING."));
	}
	else if (CALLBACK_MSG_RULE_NOT_MATCHING == iMessage)
	{
		//printf("yaraScanCallback: CALLBACK_MSG_RULE_NOT_MATCHING.\n");
	}
	else if (CALLBACK_MSG_IMPORT_MODULE == iMessage)
	{
		////OutputDebugString(_T("yaraScanCallback: CALLBACK_MSG_IMPORT_MODULE.\n"));
	}
	else if (CALLBACK_MSG_SCAN_FINISHED == iMessage)
	{
		SetEvent(pyaraContext->hStopEvent);
		////OutputDebugString(_T("yaraScanCallback: CALLBACK_MSG_SCAN_FINISHED.\n"));
	}
	////OutputDebugString(_T("yaraScanCalback: Exit.\n"));
	return ERROR_SUCCESS;
}


DWORD CHiparaDlg::liveScanThread(LPVOID lpContext)
{
	HRESULT hr;
	UINT uiCnt;
	UINT uiIndex;
	HANDLE hPort;
	BOOLEAN bRetVal;
	BOOLEAN bSuccess;
	HANDLE hCompletion;
	DWORD dwThreadCount;
	DWORD dwRequestCount;
	CHiparaDlg *pContext;
	PSCANNER_MESSAGE pMsg;
	HANDLE hThreads[SCANNER_MAX_THREAD_COUNT];

	//OutputDebugString(_T("liveScanThread: Entry.\n"));
	if (NULL == lpContext)
	{
		return 0;
	}

	pContext = (CHiparaDlg *)lpContext;

	bRetVal = pContext->isYaraLibraryInitialized();
	if (FALSE == bRetVal)
	{
		AfxMessageBox(_T("Yara signatures are out of date! Please update it first."));
		return 0;
	}

	bRetVal = GetConfigInfo(&gbyOnlyLogToServer);
	if (FALSE == bRetVal)
	{
		gbyOnlyLogToServer = 0;
	}

	dwThreadCount = SCANNER_DEFAULT_THREAD_COUNT;
	dwRequestCount = SCANNER_DEFAULT_REQUEST_COUNT;

	hr = FilterConnectCommunicationPort(ScannerPortName, 0, NULL, 0, NULL, &hPort);
	if (IS_ERROR(hr))
	{
		//OutputDebugString(_T("liveScanThread:: FilterConnectCommunicationPort failed.\n"));
		return 0;
	}

	hCompletion = CreateIoCompletionPort(hPort, NULL, 0, dwThreadCount);
	if (NULL == hCompletion)
	{
		//OutputDebugString(_T("liveScanThread:: CreateIoCompletionPort failed.\n"));
		CloseHandle(hPort);

		return 0;
	}

	pContext->mScannerContext.Port = hPort;
	pContext->mScannerContext.Completion = hCompletion;

	bSuccess = TRUE;
	//
	// Create thread pool.
	//
	//OutputDebugString(_T("liveScanThread: Creating thread pool.\n"));
	for (uiIndex = 0; uiIndex < dwThreadCount; uiIndex++)
	{
		hThreads[uiIndex] = CreateThread(NULL,
										0,
										(LPTHREAD_START_ROUTINE)scannerWorker,
										pContext,
										0,
										NULL);
		if (NULL == hThreads[uiIndex])
		{
			if (0 == uiIndex)
			{
				bSuccess = FALSE;
				break;
			}

			SetEvent(pContext->mhStopEvent);
			dwThreadCount = uiIndex - 1;
			if (0 == dwThreadCount)
			{
				WaitForSingleObject(hThreads[0], INFINITE);
				bSuccess = FALSE;
				break;
			}
			else
			{
				WaitForMultipleObjects(dwThreadCount + 1, hThreads, TRUE, INFINITE);
				bSuccess = FALSE;
				break;
			}
		}

		for (uiCnt = 0; uiCnt < dwRequestCount; uiCnt++)
		{
			#pragma prefast(suppress:__WARNING_MEMORY_LEAK, "msg will not be leaked because it is freed in ScannerWorker")
			pMsg = (PSCANNER_MESSAGE)malloc(sizeof(SCANNER_MESSAGE));
			if (NULL == pMsg)
			{
				::MessageBoxA(NULL, "liveScanThread: Not Enough Memory.", "Error", MB_OK);

				SetEvent(pContext->mhStopEvent);
				dwThreadCount = uiIndex;
				if (0 == dwThreadCount)
				{
					WaitForSingleObject(hThreads[0], INFINITE);
					bSuccess = FALSE;
					break;
				}
				else
				{
					WaitForMultipleObjects(dwThreadCount + 1, hThreads, TRUE, INFINITE);
					bSuccess = FALSE;
					break;
				}
			}

			memset(&pMsg->Ovlp, 0, sizeof(OVERLAPPED));

			hr = FilterGetMessage(hPort,
								&pMsg->MessageHeader,
								FIELD_OFFSET(SCANNER_MESSAGE, Ovlp),
								&pMsg->Ovlp);

			if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
			{
				SetEvent(pContext->mhStopEvent);
				dwThreadCount = uiIndex;
				if (0 == dwThreadCount)
				{
					WaitForSingleObject(hThreads[0], INFINITE);
					bSuccess = FALSE;
					break;
				}
				else
				{
					WaitForMultipleObjects(dwThreadCount + 1, hThreads, TRUE, INFINITE);
					bSuccess = FALSE;
					break;
				}
				free(pMsg);
			}
		}
	}

	if (TRUE == bSuccess)
	{
		//OutputDebugStringA("liveScanThread:: Waiting for all threads to terminate.\n");
		WaitForMultipleObjects(uiIndex, hThreads, TRUE, INFINITE);
		//OutputDebugStringA("liveScanThread:: All threads are terminated.\n");
		for (uiIndex = 0; uiIndex < dwThreadCount; uiIndex++)
		{
			CloseHandle(hThreads[uiIndex]);
			hThreads[uiIndex] = NULL;
		}
	}

	CloseHandle(hPort);
	CloseHandle(hCompletion);
	//OutputDebugString(_T("liveScanThread:: Exit.\n"));
	return 0;
}



DWORD CHiparaDlg::CmdScanThread(LPVOID lpContext)
{
	HRESULT hr;
	UINT uiCnt;
	UINT uiIndex;
	HANDLE hPort;
	BOOLEAN bSuccess;
	HANDLE hCompletion;
	DWORD dwThreadCount;
	DWORD dwRequestCount;
	CHiparaDlg *pContext;
	CMD_MESSAGE *pMsg;
	HANDLE hThreads[CMDFLT_MAX_THREAD_COUNT];

	//OutputDebugString(_T("CmdScanThread: Entry.\n"));
	if (NULL == lpContext)
	{
		return 0;
	}

	pContext = (CHiparaDlg *)lpContext;

	dwThreadCount = CMDFLT_DEFAULT_THREAD_COUNT;
	dwRequestCount = CMDFLT_DEFAULT_REQUEST_COUNT;

	hr = FilterConnectCommunicationPort(CmdPortName, 0, NULL, 0, NULL, &hPort);
	if (IS_ERROR(hr))
	{
		//OutputDebugString(_T("CmdScanThread:: FilterConnectCommunicationPort failed.\n"));
		return 0;
	}

	hCompletion = CreateIoCompletionPort(hPort, NULL, 0, dwThreadCount);
	if (NULL == hCompletion)
	{
		//OutputDebugString(_T("CmdScanThread:: CreateIoCompletionPort failed.\n"));
		CloseHandle(hPort);

		return 0;
	}

	pContext->mCmdFltContext.Port= hPort;
	pContext->mCmdFltContext.Completion = hCompletion;

	bSuccess = TRUE;
	//
	// Create thread pool.
	//
	OutputDebugString(_T("CmdScanThread: Creating thread pool.\n"));
	for (uiIndex = 0; uiIndex < dwThreadCount; uiIndex++)
	{
		hThreads[uiIndex] = CreateThread(NULL,
										0,
										(LPTHREAD_START_ROUTINE)CmdWorker,
										pContext,
										0,
										NULL);
		if (NULL == hThreads[uiIndex])
		{
			if (0 == uiIndex)
			{
				bSuccess = FALSE;
				break;
			}

			SetEvent(pContext->mhStopEvent);
			dwThreadCount = uiIndex - 1;
			if (0 == dwThreadCount)
			{
				WaitForSingleObject(hThreads[0], INFINITE);
				bSuccess = FALSE;
				break;
			}
			else
			{
				WaitForMultipleObjects(dwThreadCount + 1, hThreads, TRUE, INFINITE);
				bSuccess = FALSE;
				break;
			}
		}

		for (uiCnt = 0; uiCnt < dwRequestCount; uiCnt++)
		{
#pragma prefast(suppress:__WARNING_MEMORY_LEAK, "msg will not be leaked because it is freed in CmdWorker")
			pMsg = (PCMD_MESSAGE)malloc(sizeof(CMD_MESSAGE));
			if (NULL == pMsg)
			{
				::MessageBoxA(NULL, "CmdScanThread: Not Enough Memory.", "Error", MB_OK);

				SetEvent(pContext->mhStopEvent);
				dwThreadCount = uiIndex;
				if (0 == dwThreadCount)
				{
					WaitForSingleObject(hThreads[0], INFINITE);
					bSuccess = FALSE;
					break;
				}
				else
				{
					WaitForMultipleObjects(dwThreadCount + 1, hThreads, TRUE, INFINITE);
					bSuccess = FALSE;
					break;
				}
			}

			memset(&pMsg->Ovlp, 0, sizeof(OVERLAPPED));

			hr = FilterGetMessage(hPort,
				&pMsg->MessageHeader,
				FIELD_OFFSET(CMD_MESSAGE, Ovlp),
				&pMsg->Ovlp);

			if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
			{
				SetEvent(pContext->mhStopEvent);
				dwThreadCount = uiIndex;
				if (0 == dwThreadCount)
				{
					WaitForSingleObject(hThreads[0], INFINITE);
					bSuccess = FALSE;
					break;
				}
				else
				{
					WaitForMultipleObjects(dwThreadCount + 1, hThreads, TRUE, INFINITE);
					bSuccess = FALSE;
					break;
				}
				free(pMsg);
			}
		}
	}

	if (TRUE == bSuccess)
	{
		//OutputDebugStringA("CmdScanThread:: Waiting for all threads to terminate.\n");
		WaitForMultipleObjects(uiIndex, hThreads, TRUE, INFINITE);
		//OutputDebugStringA("CmdScanThread:: All threads are terminated.\n");
		for (uiIndex = 0; uiIndex < dwThreadCount; uiIndex++)
		{
			CloseHandle(hThreads[uiIndex]);
			hThreads[uiIndex] = NULL;
		}
	}

	CloseHandle(hPort);
	CloseHandle(hCompletion);
	OutputDebugString(_T("CmdScanThread:: Exit.\n"));
	return 0;
}


DWORD CHiparaDlg::scannerWorker(LPVOID lpContext)
{
	HRESULT hr;
	BOOL boResult;
	ULONG_PTR key;
	BOOLEAN result;
	DWORD dwOutSize;
	DWORD dwWaitRet;
	LPOVERLAPPED lpOvlp;
	CHiparaDlg *pContext;
	PSCANNER_MESSAGE pScannerMsg;
	SCANNER_REPLY_MESSAGE scannerReplyMsg;
	PSCANNER_NOTIFICATION pScannerNotification;

	if (NULL == lpContext)
	{
		::MessageBoxA(NULL, "scannerWorker: Invalid Parameter.", "Error", MB_OK);
		return 0;
	}

	pContext = (CHiparaDlg *)lpContext;
	pScannerMsg = NULL;

	while (TRUE)
	{
		////OutputDebugStringA("scannerWorker:: Calling GetQueuedCompletionStatus.\n");
		boResult = GetQueuedCompletionStatus(pContext->mScannerContext.Completion, &dwOutSize, &key, &lpOvlp, 2000);
		if (FALSE == boResult)
		{
			dwWaitRet = WaitForSingleObject(pContext->mhStopEvent, 0);
			if (WAIT_OBJECT_0 == dwWaitRet)
			{
				//OutputDebugString(_T("scannerWorker: 1 Stop event has been set.\n"));
				break;
			}

			dwWaitRet = WaitForSingleObject(pContext->mhUpdateAvailableEvent, 0);
			if (WAIT_OBJECT_0 == dwWaitRet)
			{
				//OutputDebugString(_T("scannerWorker: Update available event.\n"));
				break;
			}

			if (ERROR_ABANDONED_WAIT_0 == GetLastError())
			{
				//OutputDebugString(_T("scannerWorker: Connection with minifilter closed.\n"));
				break;
			}
			continue;
		}

		dwWaitRet = WaitForSingleObject(pContext->mhStopEvent, 0);
		if (WAIT_OBJECT_0 == dwWaitRet)
		{
			//OutputDebugString(_T("scannerWorker: Stop event has been set.\n"));
			break;
		}

		dwWaitRet = WaitForSingleObject(pContext->mhUpdateAvailableEvent, 0);
		if (WAIT_OBJECT_0 == dwWaitRet)
		{
			//OutputDebugString(_T("scannerWorker: Update available event.\n"));
			break;
		}

		////OutputDebugStringA("scannerWorker:: Returned GetQueuedCompletionStatus.\n");

		pScannerMsg = CONTAINING_RECORD(lpOvlp, SCANNER_MESSAGE, Ovlp);

		/*if (!boResult)
		{
			//OutputDebugString(_T("scannerWorker:: GetQueuedCompletionStatus() failed.\n"));
			hr = HRESULT_FROM_WIN32(GetLastError());
			break;
		}*/

		pScannerNotification = &pScannerMsg->Notification;

		scannerReplyMsg.ReplyHeader.Status = 0;
		scannerReplyMsg.ReplyHeader.MessageId = pScannerMsg->MessageHeader.MessageId;

		//
		//	By default file will be clean.
		//	This is because if we fail in creating scan file thread then we will declare file as clean.
		//
		scannerReplyMsg.Reply.SafeToOpen = TRUE;

		if (pScannerNotification->ushFlag & FILE_CONTENTS_STORED)
		{

			//assert(notification->BytesToScan <= SCANNER_READ_BUFFER_SIZE);
			_Analysis_assume_(pScannerNotification->BytesToScan <= SCANNER_READ_BUFFER_SIZE);

			result = pContext->scanBuffer(pScannerNotification->Contents, pScannerNotification->BytesToScan);

			//
			//  Need to invert the boolean -- result is true if found
			//  foul language, in which case SafeToOpen should be set to false.
			//

			if (0 == gbyOnlyLogToServer)
			{
				scannerReplyMsg.Reply.SafeToOpen = !result;
			}

			//printf("Replying message, SafeToOpen: %d\n", replyMessage.Reply.SafeToOpen);
		}
		else
		{
			WCHAR tempBuf[300];
			swprintf_s(tempBuf, 300, L"File: %s Thread(%u) Process(%u)\n", pScannerNotification->szFilePath, GetCurrentThreadId(), GetCurrentProcessId());
			OutputDebugString(tempBuf);

			result = pContext->scanFile(pScannerNotification->szFilePath);

			swprintf_s(tempBuf, 300, L"Scan Finished: %s Thread(%u) Process(%u)\n", pScannerNotification->szFilePath, GetCurrentThreadId(), GetCurrentProcessId());
			OutputDebugString(tempBuf);

			if (TRUE == result)
			{
				pContext->SendAlertMessageToServer(pScannerNotification->szFilePath, ALERT_FILE);
			}

			if (0 == gbyOnlyLogToServer)
			{
				scannerReplyMsg.Reply.SafeToOpen = !result;
			}
		}

		//OutputDebugStringA("scannerWorker:: Replying to minifilter.\n");

		hr = FilterReplyMessage(pContext->mScannerContext.Port,
								(PFILTER_REPLY_HEADER)&scannerReplyMsg,
								sizeof(scannerReplyMsg));

		if (FAILED(hr))
		{
			//OutputDebugStringA("scannerWorker:: FilterReplyMessage failed.\n");
			break;
		}

		//OutputDebugStringA("scannerWorker:: Calling FilterGetMessage\n");
		memset(&pScannerMsg->Ovlp, 0, sizeof(OVERLAPPED));

		hr = FilterGetMessage(pContext->mScannerContext.Port,
							&pScannerMsg->MessageHeader,
							FIELD_OFFSET(SCANNER_MESSAGE, Ovlp),
							&pScannerMsg->Ovlp);
		if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
		{
			//::MessageBoxA(NULL, "scannerWorker: FilterGetMessage failed.", "Error", MB_OK);
			//OutputDebugString(_T("scannerWorker:: FilterGetMessage failed.\n"));
			break;
		}
		//OutputDebugString(_T("scannerWorker:: Returned FilterGetMessage.\n"));
	}

	if (!SUCCEEDED(hr))
	{
		if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE))
		{
			//OutputDebugString(_T("scannerWorker:: Port is Disconnected, probably due to scanner filter unloading.\n"));
		}
		else
		{
			//OutputDebugString(_T("scannerWorker:: Unknown error occured.\n"));
		}
	}

	if (NULL != pScannerMsg)
	{
		free(pScannerMsg);
	}
	//OutputDebugString(_T("scannerWorker: Thread exiting.\n"));
	return 0;
}


BOOL CHiparaDlg::scanBuffer(PUCHAR Buffer, ULONG BufferSize)
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
	iRetVal = yr_rules_scan_mem(mpYrRules, Buffer, BufferSize, 0, CHiparaDlg::yaraScanCallback, &yaraContext, 0);
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



BOOLEAN CHiparaDlg::scanFile(PWCHAR pszFilePath)
{
	int iRetVal;
	errno_t errVal;
	size_t charsConverted;
	YARA_CONTEXT yaraContext;
	CHAR szFileName[MAX_FILE_PATH];

	////OutputDebugString(_T("scanFile: Entry.\n"));
	if (NULL == pszFilePath)
	{
		//OutputDebugString(_T("scanFile: Invalid parameter.\n"));
		return FALSE;
	}

	yaraContext.bScanResult = FALSE;
	yaraContext.hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (NULL == yaraContext.hStopEvent)
	{
		//OutputDebugString(_T("scanFile: CreateEvent failed.\n"));
		return FALSE;
	}

	//printf("ScanFile: File Path is(%S)\n", pszFilePath);
	errVal = wcstombs_s(&charsConverted, szFileName, sizeof(szFileName), pszFilePath, MAX_FILE_PATH);
	if (0 != errVal)
	{
		//OutputDebugString(_T("scanFile: wcstombs_s failed.\n"));
		CloseHandle(yaraContext.hStopEvent);
		return FALSE;
	}

	iRetVal = yr_rules_scan_file(mpYrRules, szFileName, 0, CHiparaDlg::yaraScanCallback, &yaraContext, 0);
	if (ERROR_SUCCESS != iRetVal)
	{
		//OutputDebugString(_T("scanFile: yr_rules_scan_file failed.\n"));
		CloseHandle(yaraContext.hStopEvent);
		return FALSE;
	}

	//
	// Wait till scanning is finished.
	// event will be set in yaraScanCallback function once scanning is finished.
	//
	////OutputDebugString(_T("scanFile: Waiting for scanning to finish.\n"));
	WaitForSingleObject(yaraContext.hStopEvent, INFINITE);
	////OutputDebugString(_T("scanFile: Scanning for file finished.\n"));

	CloseHandle(yaraContext.hStopEvent);

	////OutputDebugString(_T("scanFile: Exit.\n"));
	return yaraContext.bScanResult;
}


DWORD CHiparaDlg::enumFilesThread(LPVOID lpContext)
{
	USHORT ushCnt;
	DWORD dwRetLen;
	DWORD dwWaitRet;
	BOOLEAN bRetVal;
	UINT uiDriveType;
	BOOLEAN bDummyLoop;
	UINT uiThreadCount;
	CHiparaDlg *pContext;
	TCHAR *pszBuff = NULL;
	P_SCAN_CONTEXT pScanContext;
	TCHAR szFolderPath[4] = { '\0' };
	HANDLE hThreadPool[MAX_COUNT_THREADS];
	TCHAR szDriveBuffer[MAX_BUFF_SIZE] = { '\0' };
	TCHAR szSigFilePath[MAX_LENGTH_PATH] = { '\0' };
	TCHAR szTempFolderPath[MAX_LENGTH_PATH] = { '\0' };

	WCHAR errMsg[260];

	//OutputDebugString(_T("enumFilesThread: Entry.\n"));

	if (NULL == lpContext)
	{
		//OutputDebugString(_T("enumFilesThread: Invalid Parameter.\n"));
		return 0;
	}

	pContext = (CHiparaDlg *)lpContext;
	pScanContext = &pContext->mScanContext;

	bDummyLoop = FALSE;
	uiThreadCount = MAX_COUNT_THREADS;

	pScanContext->uiTaskCount = 0;
	pScanContext->queueInfo.uiHead = -1;
	pScanContext->queueInfo.uiTail = -1;

	bRetVal = pContext->CreateThreadPool(&uiThreadCount, hThreadPool, pContext, CHiparaDlg::scanFiles);
	if (FALSE == bRetVal)
	{
		//OutputDebugString(_T("enumFilesThread: CreateThreadPool failed.\n"));
		return 0;
	}

	dwRetLen = GetLogicalDriveStrings(sizeof(szDriveBuffer)-1, szDriveBuffer);
	if (0 == dwRetLen)
	{
		//OutputDebugString(_T("enumFilesThread: GetLogicalDriveStrings failed.\n"));
		SetEvent(pScanContext->hStopEvent);

		dwWaitRet = WaitForMultipleObjects(uiThreadCount, hThreadPool, TRUE, INFINITE);
		if (WAIT_FAILED == dwWaitRet)
		{
			//OutputDebugString(_T("enumFilesThread: Waiting on Threads from Pool Failed.\n"));
		}
		return 0;
	}

	//
	// Iterate over each drive letter and enumerate all files under that drive.
	//
	for (pszBuff = szDriveBuffer; '\0' != *pszBuff; pszBuff = pszBuff + _tcslen(pszBuff) + 1)
	{
		uiDriveType = GetDriveType(pszBuff);
		if (DRIVE_FIXED == uiDriveType || DRIVE_REMOVABLE == uiDriveType)
		{
			memset(szFolderPath, '\0', sizeof(szFolderPath));
			szFolderPath[0] = *pszBuff;
			szFolderPath[1] = *(++pszBuff);
			pContext->enumerateFiles(szFolderPath, pScanContext);
		}

		dwWaitRet = WaitForSingleObject(pScanContext->hStopEvent, 0);
		if (WAIT_OBJECT_0 == dwWaitRet)
		{
			//OutputDebugString(_T("enumFilesThread: Wait successfull on stop event.\n"));
			break;
		}
	}

	//
	// Now wait for all remaining files to scan.
	// When uiTaskCount becomes zero it means no more file to scan.
	//
	do
	{
		//OutputDebugString(_T("enumFilesThread: Waiting for all tasks to finish.\n"));
		dwWaitRet = WaitForSingleObject(pScanContext->queueInfo.hQueueMutex, INFINITE);
		if (WAIT_OBJECT_0 == dwWaitRet)
		{
			dwWaitRet = WaitForSingleObject(pScanContext->hStopEvent, 0);
			if (WAIT_OBJECT_0 == dwWaitRet)
			{
				//OutputDebugString(_T("enumFilesThread: All tasks has been finished.So setting stop event.\n"));
				//
				// Tell all scanning threads to stop.
				//
				SetEvent(pScanContext->hStopEvent);
				ReleaseMutex(pScanContext->queueInfo.hQueueMutex);

				break;
			}
			if (0 != pScanContext->uiTaskCount)
			{
				ReleaseMutex(pScanContext->queueInfo.hQueueMutex);
				continue;
			}
			ReleaseMutex(pScanContext->queueInfo.hQueueMutex);
			OutputDebugString(_T("enumFilesThread: All tasks has been finished.So setting stop event.\n"));
			//
			// Tell all scanning threads to stop.
			//
			SetEvent(pScanContext->hStopEvent);
			break;
		}
	} while (TRUE);

	//OutputDebugString(_T("enumFilesThread: Waiting for all threads to terminate.\n"));
	dwWaitRet = WaitForMultipleObjects(uiThreadCount, hThreadPool, TRUE, INFINITE);
	if (WAIT_FAILED == dwWaitRet)
	{
		OutputDebugString(_T("enumFilesThread: Waiting on Threads from Pool Failed.\n"));
	}
	//OutputDebugString(_T("enumFilesThread: All threads has been closed.\n"));

	for (ushCnt = 0; ushCnt < uiThreadCount; ushCnt++)
	{
		CloseHandle(hThreadPool[ushCnt]);
		hThreadPool[ushCnt] = NULL;
	}

	OutputDebugString(_T("enumFilesThread: Exit.\n"));
	return 0;
}


BOOLEAN
CHiparaDlg::CreateThreadPool(
	UINT *puiThreadCount,
	HANDLE *pThreadHandles,
	PVOID pContextToThreads,
	LPTHREAD_START_ROUTINE threadFunction
)
{
	UINT uiCnt;
	USHORT ushIndex;
	BOOLEAN bSuccess;
	DWORD dwThreadCnt;

	if (NULL == puiThreadCount || NULL == pThreadHandles || NULL == threadFunction)
	{
		//
		// Invalid Parameter.
		//
		return FALSE;
	}

	bSuccess = TRUE;

	for (uiCnt = 0; uiCnt < *puiThreadCount; uiCnt++)
	{
		pThreadHandles[uiCnt] = CreateThread(NULL, 0, threadFunction, pContextToThreads, 0, NULL);
		if (NULL == pThreadHandles[uiCnt])
		{
			printf("CreateThreadPool: CreateThread failed for %d thread\n", uiCnt);
			if (uiCnt)
			{
				SetEvent(((P_SCAN_CONTEXT)pContextToThreads)->hStopEvent);
				dwThreadCnt = uiCnt - 1;

				if (0 == dwThreadCnt)
				{
					WaitForSingleObject(pThreadHandles[0], INFINITE);
					bSuccess = FALSE;
					break;
				}
				else
				{
					WaitForMultipleObjects(dwThreadCnt + 1, pThreadHandles, TRUE, INFINITE);
					bSuccess = FALSE;
					break;
				}
			}
			bSuccess = FALSE;
			break;
		}
	}

	if (FALSE == bSuccess)
	{
		if (uiCnt)
		{
			for (ushIndex = uiCnt - 1; ushIndex >= 0; ushIndex--)
			{
				CloseHandle(pThreadHandles[ushIndex]);
			}
		}
	}
	else
	{
		*puiThreadCount = uiCnt;
	}

	return bSuccess;
}


void CHiparaDlg::enumerateFiles(TCHAR *pszFolderPath, SCAN_CONTEXT *pScanContext)
{
	DWORD dwWaitRet;
	BOOLEAN bRetVal;
	HRESULT hrRetVal;
	HANDLE hFindFile;
	DWORD dwLastError;
	BOOLEAN bIsExitCodeStop;
	WIN32_FIND_DATA findData;
	TCHAR szDirPath[MAX_LENGTH_PATH] = { '\0' };
	TCHAR szTempFolderPath[MAX_LENGTH_PATH] = { '\0' };

	//OutputDebugString(_T("enumerateFiles: Entry.\n"));

	if (NULL == pScanContext)
	{
		//OutputDebugString(_T("EnumerateFiles: Invalid Parameter.\n"));
		return;
	}

	//
	// Append '\*' to the folder path to tell enumerate all files.
	//
	_tcscpy_s(szTempFolderPath, MAX_LENGTH_PATH, pszFolderPath);
	hrRetVal = StringCchCat(szTempFolderPath, MAX_LENGTH_PATH, TEXT("\\*"));
	if (FAILED(hrRetVal))
	{
		//OutputDebugString(_T("enumerateFiles: StringCchCat failed.\n"));
		return;
	}

	hFindFile = FindFirstFile(szTempFolderPath, &findData);
	if (INVALID_HANDLE_VALUE == hFindFile)
	{
		//OutputDebugString(_T("enumerateFiles: FindFirstFile failed.\n"));
		return;
	}
	bIsExitCodeStop = 0;
	do
	{
		dwWaitRet = WaitForSingleObject(pScanContext->hStopEvent, 0);
		if (WAIT_OBJECT_0 == dwWaitRet)
		{
			bIsExitCodeStop = 1;
			//OutputDebugString(_T("enumerateFiles:Stop event has been set.\n"));
			break;
		}

		if ((0 != _tcscmp(findData.cFileName, _T("."))) && (0 != _tcscmp(findData.cFileName, _T(".."))))
		{
			hrRetVal = StringCchPrintf(szDirPath, MAX_LENGTH_PATH, _T("%s\\%s"), pszFolderPath, findData.cFileName);
			if (FAILED(hrRetVal))
			{
				//OutputDebugString(_T("enumerateFiles: StringCchPrintf failed.\n"));
				break;
			}

			if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				if (!StrStrI(szDirPath, gszInstallationDir))
				{
					enumerateFiles(szDirPath, pScanContext);
				}
			}
			else
			{
				bRetVal = insertInQueue(szDirPath, pScanContext);
				if (TRUE == bRetVal)
				{
					//OutputDebugString(_T("enumerateFiles: Added file to queue\n"));
				}
			}
		}
	} while (FindNextFile(hFindFile, &findData) != 0);

	if (0 == bIsExitCodeStop)
	{
		dwLastError = GetLastError();
		if (ERROR_NO_MORE_FILES != dwLastError)
		{
			printf("EnumerateAllFiles: Enumerating files failed(%d)\n", dwLastError);
		}
	}
	FindClose(hFindFile);
}


DWORD WINAPI CHiparaDlg::scanFiles(LPVOID lpvParameter)
{

	DWORD dwWaitRet;
	BOOLEAN bScanResult;
	TCHAR *pszFilePath;
	CHiparaDlg *pContext;
	P_SCAN_CONTEXT pScanContext;

	if (NULL == lpvParameter)
	{
		//OutputDebugString(_T("ScanFiles: Invalid Parameter.\n"));
		return 0;
	}

	pContext = (CHiparaDlg *)lpvParameter;
	pScanContext = &pContext->mScanContext;

	do
	{
		pszFilePath = pContext->deleteFromQueue(pScanContext);
		if (NULL != pszFilePath)
		{
			//OutputDebugString(_T("scanFiles: removed from queue.\n"));
			bScanResult = pContext->scanFile(pszFilePath);
			if (TRUE == bScanResult)
			{
				pContext->SendAlertMessageToFile(pszFilePath, (_tcslen(pszFilePath) + 1) * sizeof(TCHAR));
				pContext->SendAlertMessageToServer(pszFilePath, ALERT_FILE);
			}
			free(pszFilePath);
			pszFilePath = NULL;
		}

		dwWaitRet = WaitForSingleObject(pScanContext->hStopEvent, 0);
		if (WAIT_OBJECT_0 == dwWaitRet)
		{
			OutputDebugString(_T("scanFiles: Stop event set, so terminating.\n"));
			break;
		}

	} while (TRUE);

	//OutputDebugString(_T("scanFiles: Exit.\n"));
	return 0;
}


BOOLEAN CHiparaDlg::insertInQueue(TCHAR *pszFileName, SCAN_CONTEXT *pScanContext)
{
	DWORD dwRetVal;
	HRESULT hrRetVal;
	DWORD filePathlen;
	TCHAR *pszFilePath;

	if (NULL == pszFileName || NULL == pScanContext)
	{
		//OutputDebugString(_T("insertInQueue: Invalid Parameter.\n"));
		return FALSE;
	}

	dwRetVal = WaitForSingleObject(pScanContext->queueInfo.hQueueMutex, INFINITE);
	if (WAIT_FAILED == dwRetVal)
	{
		return FALSE;
	}

	if ((pScanContext->queueInfo.uiHead == 0 && pScanContext->queueInfo.uiTail == MAX_SIZE_QUEUE - 1) ||
		((pScanContext->queueInfo.uiTail + 1) == pScanContext->queueInfo.uiHead)
		)
	{
		ReleaseMutex(pScanContext->queueInfo.hQueueMutex);
		return FALSE;
	}

	filePathlen = _tcslen(pszFileName) + 1;		// + 1 for NULL character.

	pszFilePath = (TCHAR *)malloc(filePathlen * sizeof(TCHAR));
	if (NULL == pszFilePath)
	{
		//OutputDebugString(_T("insertInQueue: Error allocating memory to pszFilePath.\n"));
		ReleaseMutex(pScanContext->queueInfo.hQueueMutex);
		return FALSE;
	}

	hrRetVal = StringCchCopy(pszFilePath, filePathlen, pszFileName);
	if (FAILED(hrRetVal))
	{
		//OutputDebugString(_T("insertInQueue: StringCchCopy failed.\n"));
		free(pszFilePath);
		ReleaseMutex(pScanContext->queueInfo.hQueueMutex);
		return FALSE;
	}

	if (pScanContext->queueInfo.uiTail == MAX_SIZE_QUEUE - 1)
	{
		pScanContext->queueInfo.uiTail = 0;
	}
	else
	{
		pScanContext->queueInfo.uiTail++;
	}
	if (-1 == pScanContext->queueInfo.uiHead)
	{
		pScanContext->queueInfo.uiHead = 0;
	}

	pScanContext->queueInfo.pvData[pScanContext->queueInfo.uiTail] = pszFilePath;
	pScanContext->uiTaskCount++;

	ReleaseMutex(pScanContext->queueInfo.hQueueMutex);

	return TRUE;
}


TCHAR* CHiparaDlg::deleteFromQueue(SCAN_CONTEXT *pScanContext)
{
	DWORD dwRetVal;
	TCHAR *pszFileName;

	if (NULL == pScanContext)
	{
		//OutputDebugString(_T("deleteFromQueue: Invalid Parameter.\n"));
		return NULL;
	}

	dwRetVal = WaitForSingleObject(pScanContext->queueInfo.hQueueMutex, INFINITE);
	if (WAIT_FAILED == dwRetVal)
	{
		return NULL;
	}

	if (-1 == pScanContext->queueInfo.uiHead)
	{
		ReleaseMutex(pScanContext->queueInfo.hQueueMutex);
		return NULL;
	}

	pszFileName = (TCHAR*)pScanContext->queueInfo.pvData[pScanContext->queueInfo.uiHead];
	pScanContext->queueInfo.pvData[pScanContext->queueInfo.uiHead] = NULL;
	pScanContext->uiTaskCount--;

	if (pScanContext->queueInfo.uiHead == pScanContext->queueInfo.uiTail)
	{
		pScanContext->queueInfo.uiHead = -1;
		pScanContext->queueInfo.uiTail = -1;
	}
	else
	{
		if (pScanContext->queueInfo.uiHead == MAX_SIZE_QUEUE - 1)
		{
			pScanContext->queueInfo.uiHead = 0;
		}
		else
		{
			pScanContext->queueInfo.uiHead++;
		}
	}

	ReleaseMutex(pScanContext->queueInfo.hQueueMutex);

	return pszFileName;
}


BOOLEAN CHiparaDlg::isYaraLibraryInitialized()
{
	return bIsYaraLibraryInitialize;
}


void CHiparaDlg::setYaraLibraryInitializedFlag(BOOLEAN bIsInitialized)
{
	bIsYaraLibraryInitialize = bIsInitialized;
}


void CHiparaDlg::OnBnClickedMemoryscan()
{
	BOOLEAN bRetVal;

	bRetVal = isYaraLibraryInitialized();
	if (FALSE == bRetVal)
	{
		AfxMessageBox(_T("Yara signatures are out of date! Please update it first."));
		return;
	}

	mhMemoryScannerThread = CreateThread(NULL, 0, CHiparaDlg::scanMemoryThread, this, 0, NULL);
	if (NULL == mhMemoryScannerThread)
	{
		//OutputDebugString(_T("OnBnClickedMemoryscan: Creating memory scan thread failed.\n"));
	}
}

DWORD WINAPI CHiparaDlg::scanMemoryThread(LPVOID lpvParameter)
{
	BOOLEAN bRetVal;
	CHiparaDlg *pContext;

	//OutputDebugString(_T("scanMemoryThread: Entry.\n"));

	if (NULL == lpvParameter)
	{
		//OutputDebugString(_T("scanMemoryThread: Invalid Parameter.\n"));
		return 0;
	}

	pContext = (CHiparaDlg *)lpvParameter;

	pContext->GetDlgItem(IDC_MEMORYSCAN)->EnableWindow(FALSE);

	bRetVal = hiparamemscan();
	if (FALSE == bRetVal)
	{
		AfxMessageBox(_T("Memory scanning failed.!!"));
	}
	else
	{
		AfxMessageBox(_T("Scanned memory successfully.!!"));
	}

	pContext->GetDlgItem(IDC_MEMORYSCAN)->EnableWindow(TRUE);

	//OutputDebugString(_T("scanMemoryThread: Exit.\n"));
	return 0;
}


BOOLEAN
CHiparaDlg::GetSignatureServerUrl(
	WCHAR *pwszServerUrl,
	DWORD dwcchServerUrlLen
	)
{
	DWORD dwRetVal;
	HRESULT hrRetVal;
	TCHAR errMsg[MAX_FILE_PATH];
	WCHAR wszConfigFilePath[MAX_FILE_PATH];

	//OutputDebugString(_T("GetSignatureServerUrl: Entry.\n"));

	if (NULL == pwszServerUrl || 0 == dwcchServerUrlLen)
	{
		return FALSE;
	}

	hrRetVal = StringCchPrintf(wszConfigFilePath, MAX_FILE_PATH, _T("%s\\%s"), gszInstallationDir, HIPARA_CONFIG_FILE_NAME);
	if (FAILED(hrRetVal))
	{
		//OutputDebugString(_T("StringCchPrintf failed while creating ini file path.\n"));
		return FALSE;
	}

	_stprintf_s(errMsg, sizeof(errMsg), _T("GetSignatureServerUrl: Config file path(%s)\n."), wszConfigFilePath);
	//OutputDebugString(errMsg);

	dwRetVal = GetPrivateProfileString(
									HIPARA_UPDATE_SECTION_NAME,
									HIPARA_UPDATE_URL_KEY_NAME,
									NULL,
									pwszServerUrl,
									dwcchServerUrlLen,
									wszConfigFilePath
									);
	if (0 == dwRetVal)
	{
		_stprintf_s(errMsg, sizeof(errMsg), _T("GetPrivateProfileString failed with error(%d)."), GetLastError());
		//OutputDebugString(errMsg);
		return FALSE;
	}

	_stprintf_s(errMsg, sizeof(errMsg), _T("GetSignatureServerUrl: Server url path(%s)\n."), pwszServerUrl);
	//OutputDebugString(errMsg);

	//OutputDebugString(_T("GetSignatureServerUrl: Exit.\n"));
	return TRUE;
}


BOOLEAN
CHiparaDlg::GetServerUserNameAndPassword(
	WCHAR *pwszUserName,
	DWORD dwcchUserNameLen,
	WCHAR *pwszPassword,
	DWORD dwcchPasswordLen
	)
{
	DWORD dwRetVal;
	HRESULT hrRetVal;
	TCHAR errMsg[MAX_PATH];
	WCHAR wszConfigFilePath[MAX_FILE_PATH];

	if (NULL == pwszUserName || 0 == dwcchUserNameLen || NULL == pwszPassword || 0 == dwcchPasswordLen)
	{
		return FALSE;
	}

	hrRetVal = StringCchPrintf(wszConfigFilePath, MAX_FILE_PATH, _T("%s\\%s"), gszInstallationDir, HIPARA_CONFIG_FILE_NAME);
	if (FAILED(hrRetVal))
	{
		//OutputDebugString(_T("StringCchPrintf failed while creating ini file path.\n"));
		return FALSE;
	}

	_stprintf_s(errMsg, sizeof(errMsg), _T("Config file path(%s)\n."), wszConfigFilePath);
	//OutputDebugString(errMsg);

	dwRetVal = GetPrivateProfileString(
									HIPARA_UPDATE_SECTION_NAME,
									HIPARA_UPDATE_USERNAME_KEY_NAME,
									NULL,
									pwszUserName,
									dwcchUserNameLen,
									wszConfigFilePath
									);
	if (0 == dwRetVal)
	{
		_stprintf_s(errMsg, sizeof(errMsg), _T("GetPrivateProfileString for user name failed with error(%d)."), GetLastError());
		//OutputDebugString(errMsg);
		return FALSE;
	}

	_stprintf_s(errMsg, sizeof(errMsg), _T("User Name(%s)\n."), pwszUserName);
	//OutputDebugString(errMsg);

	dwRetVal = GetPrivateProfileString(
									HIPARA_UPDATE_SECTION_NAME,
									HIPARA_UPDATE_PASSWORD_KEY_NAME,
									NULL,
									pwszPassword,
									dwcchPasswordLen,
									wszConfigFilePath
									);
	if (0 == dwRetVal)
	{
		_stprintf_s(errMsg, sizeof(errMsg), _T("GetPrivateProfileString for password failed with error(%d)."), GetLastError());
		//OutputDebugString(errMsg);
		return FALSE;
	}

	_stprintf_s(errMsg, sizeof(errMsg), _T("Password(%s)\n."), pwszPassword);
	//OutputDebugString(errMsg);

	return TRUE;
}


DWORD CHiparaDlg::CmdWorker(LPVOID lpContext)
{
	P_PROCESS_NOTIFICATION notification;
	LPOVERLAPPED pOvlp;
	BOOL result;
	DWORD outSize;
	HRESULT hr;
	ULONG_PTR key;
	HANDLE hThread[5];
	DWORD dwEvent;
	DWORD dwIndex;
	DWORD dwThreadCount;
	CHiparaDlg *pContext;
	CMD_MESSAGE *pScannerMsg;
	TCHAR errMsg[MAX_PATH];

	if (NULL == lpContext)
	{
		::MessageBoxA(NULL, "scannerWorker: Invalid Parameter.", "Error", MB_OK);
		return 0;
	}

	pContext = (CHiparaDlg *)lpContext;
	pScannerMsg = NULL;
	dwIndex = 0;

#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant

	while (TRUE) {

#pragma warning(pop)

		//
		//  Poll for messages from the filter component to scan.
		//
		//OutputDebugString(_T("CmdWorker: Calling GetQueuedCompletionStatus.\n"));

		result = GetQueuedCompletionStatus(pContext->mCmdFltContext.Completion, &outSize, &key, &pOvlp, 2000);
		if (FALSE == result)
		{
			dwEvent = WaitForSingleObject(pContext->mhStopEvent, 0);
			if (WAIT_OBJECT_0 == dwEvent)
			{
				//OutputDebugString(_T("CmdWorker: App exit event signaled.\n"));
				break;
			}

			if (ERROR_ABANDONED_WAIT_0 == GetLastError())
			{
				//OutputDebugString(_T("CmdWorker: Connection with minifilter closed.\n"));
				break;
			}
			continue;
		}

		dwEvent = WaitForSingleObject(pContext->mhStopEvent, 0);
		if ((WAIT_OBJECT_0 + 0) == dwEvent)
		{
			OutputDebugString(_T("CmdWorker: App exit event signaled.\n"));
			break;
		}

		//
		//  Obtain the message: note that the message we sent down via FltGetMessage() may NOT be
		//  the one dequeued off the completion queue: this is solely because there are multiple
		//  threads per single port handle. Any of the FilterGetMessage() issued messages can be
		//  completed in random order - and we will just dequeue a random one.
		//

		pScannerMsg = CONTAINING_RECORD(pOvlp, CMD_MESSAGE, Ovlp);

		if (!result) {

			//
			//  An error occured.
			//

			hr = HRESULT_FROM_WIN32(GetLastError());
			break;
		}

		notification = &pScannerMsg->ProcessNotification;

		if (TRUE == notification->bCreate)
		{
			/*_stprintf_s(errMsg, sizeof(errMsg), L"CmdWorker: Received message, Process create PID : (%u)", notification->ulProcessId);
			OutputDebugString(errMsg);*/

			if (dwIndex < MAX_CMD_MON_COUNT)
			{
				hThread[dwIndex] = pContext->InitThread(notification->ulProcessId);
				++dwIndex;
			}
		}
		else
		{
			/*_stprintf_s(errMsg, sizeof(errMsg), L"CmdWorker: Received message, Process terminate PID : (%u)", notification->ulProcessId);
			OutputDebugString(errMsg);*/

			pContext->ReleaseThreadSlot(notification->ulProcessId);
			//OutputDebugString(_T("CmdWorker:After calling ReleaseThreadSlot.\n"));
		}

		memset(&pScannerMsg->Ovlp, 0, sizeof(OVERLAPPED));

		hr = FilterGetMessage(pContext->mCmdFltContext.Port,
			&pScannerMsg->MessageHeader,
			FIELD_OFFSET(CMD_MESSAGE, Ovlp),
			&pScannerMsg->Ovlp);

		if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {

			break;
		}
		//OutputDebugString(_T("CmdWorker: FilterGetMessage succeed.\n"));
	}

	dwThreadCount = 0;
	for (dwIndex = 0; dwIndex < MAX_CMD_MON_COUNT; dwIndex++)
	{
		if (TRUE == CmdThreadData[dwIndex].bAquired)
		{
			_stprintf_s(errMsg, sizeof(errMsg), L"CmdWorker: dwIndex : (%u)", dwIndex);
			OutputDebugString(errMsg);

			dwThreadCount++;
			hThread[dwIndex] = CmdThreadData[dwIndex].hThread;
		}
	}

	/*_stprintf_s(errMsg, sizeof(errMsg), L"CmdWorker: dwThreadCount : (%u)", dwThreadCount);
	OutputDebugString(errMsg);*/

	WaitForMultipleObjects(dwThreadCount, hThread, TRUE, INFINITE);

	if (!SUCCEEDED(hr)) {

		if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {

			//
			//  Scanner port disconncted.
			//

			printf("Scanner: Port is disconnected, probably due to scanner filter unloading.\n");

		}
		else {

			printf("Scanner: Unknown error occured. Error = 0x%X\n", hr);
		}
	}

	free(pScannerMsg);

	//OutputDebugString(_T("CmdWorker: Exit\n"));
	return hr;
}


HANDLE
CHiparaDlg::InitThread(
	DWORD dwPID
)
{
	BOOLEAN bRetVal;
	CMD_THREAD_CTX *pCmdThreadCtx;
	CMD_THREAD_DATA *pCmdThreadData;

#if	DEBUG_INITTHREAD
	_tprintf(_T("InitThread() Entry.\n"));
#endif

	OutputDebugString(_T("InitThread: Entry.\n"));
	bRetVal = AquireThreadSlot(dwPID, &pCmdThreadData, &pCmdThreadCtx);
	if (FALSE == bRetVal)
	{
		OutputDebugString(_T("AquireThreadSlot: Failed.\n"));
		return NULL;
	}

	pCmdThreadData->hThread = (HANDLE)_beginthread(CmdMonThread, 0, pCmdThreadCtx);
	if (-1L == (LONG)pCmdThreadData->hThread)
	{
#if	DEBUG_INITTHREAD
		_tprintf(_T("_beginthread() Failed. Error(%u)\n"));
#endif

		ReleaseThreadSlot(dwPID);
		return NULL;
	}

#if	DEBUG_INITTHREAD
	_tprintf(_T("InitThread() Exit.\n"));
#endif

	OutputDebugString(_T("InitThread: Exit.\n"));
	return pCmdThreadData->hThread;
}


void
CHiparaDlg::CmdMonThread(
void* pArguments
)
{
	DWORD dwEvent;
	HANDLE hProcess;
	HANDLE hWaitEvents[2];
	USHORT ushCommandCount;
	CMD_THREAD_CTX *pContext;

	OutputDebugString(_T("CmdMonThread: Entry."));
	if (NULL == pArguments)
	{
		OutputDebugString(_T("CmdMonThread: Invalid Parameter."));
		return;
	}

	pContext = (CMD_THREAD_CTX *)pArguments;

	hProcess = OpenProcess(SYNCHRONIZE, FALSE, pContext->dwProcessId);
	if (NULL == hProcess)
	{
#if	DEBUG_INITTHREAD
		_tprintf(_T("OpenProcess() Failed. Error(%u)\n"), GetLastError());
#endif
		return;
	}

	hWaitEvents[0] = *(pContext->phStopEvent);
	hWaitEvents[1] = hProcess;
	ushCommandCount = 0;

	while (TRUE)
	{
		//OutputDebugString(_T("CmdMonThread: Waiting on process terminate OR App exit event.\n"));

		dwEvent = WaitForMultipleObjects(2, hWaitEvents, FALSE, 0);
		if ((WAIT_OBJECT_0 + 0) == dwEvent)
		{
			//OutputDebugString(_T("CmdMonThread: App exit event signaled."));
			break;
		}
		else if ((WAIT_OBJECT_0 + 1) == dwEvent)
		{
			//OutputDebugString(_T("CmdMonThread: Process exit event signaled."));
			break;
		}

		LogCmdProcess(pContext->dwProcessId, *(pContext->phStopEvent), hProcess, &ushCommandCount);
	}

	ReleaseThreadSlot(pContext->dwProcessId);
	OutputDebugString(_T("CmdMonThread: Exit."));

	CloseHandle(hProcess);
	return;
}


BOOLEAN
CHiparaDlg::AquireThreadSlot(
	DWORD dwProcessID,
	CMD_THREAD_DATA **ppCmdThreadData,
	CMD_THREAD_CTX **ppCmdThreadCtx
)
{
	DWORD dwIndex;

	if (NULL == ppCmdThreadData)
	{
		return FALSE;
	}

	for (dwIndex = 0; dwIndex < MAX_CMD_MON_COUNT; dwIndex++)
	{
		if (FALSE == CmdThreadData[dwIndex].bAquired)
		{
			CmdThreadData[dwIndex].dwProcessID = dwProcessID;
			CmdThreadData[dwIndex].bAquired = TRUE;
			*ppCmdThreadData = (CmdThreadData + dwIndex);

			CmdThreadCtx[dwIndex].dwProcessId = dwProcessID;
			CmdThreadCtx[dwIndex].phStopEvent = &this->mhStopEvent;
			*ppCmdThreadCtx = (CmdThreadCtx + dwIndex);

			break;
		}
	}

	if (dwIndex == MAX_CMD_MON_COUNT)
	{
		return FALSE;
	}

	return TRUE;
}


BOOLEAN
CHiparaDlg::ReleaseThreadSlot(
DWORD dwProcessID
)
{
	DWORD dwIndex;

	for (dwIndex = 0; dwIndex < MAX_CMD_MON_COUNT; dwIndex++)
	{
		if (dwProcessID == CmdThreadData[dwIndex].dwProcessID)
		{
			CmdThreadData[dwIndex].dwProcessID = 0;
			CmdThreadData[dwIndex].bAquired = FALSE;
			break;
		}
	}

	return TRUE;
}


BOOLEAN
CHiparaDlg::InitUpdateLib(
)
{
	int iRetVal;
	UINT uiOutLen;
	BOOLEAN bRetVal;
	CHAR *pszUserName;
	CHAR *pszPassword;
	CHAR *pszServerUrl;
	CHiparaDlg *pContext;
	CHAR *pszSigFolderPath;
	TCHAR errMsg[MAX_PATH];
	WCHAR wszUserName[MAX_PATH];
	WCHAR wszPassword[MAX_PATH];
	WCHAR wszServerUrl[MAX_PATH];

	bRetVal = ConvertFromWideCharToMultiByte(gszSignatureFolderPath, _tcslen(gszSignatureFolderPath), &pszSigFolderPath, &uiOutLen);
	if (FALSE == bRetVal)
	{
		//OutputDebugString(_T("InitUpdateLib: ConvertFromWideCharToMultiByte Failed.\n"));
		return 0;
	}

	bRetVal = GetSignatureServerUrl(wszServerUrl, ARRAY_SIZE(wszServerUrl));
	if (FALSE == bRetVal)
	{
		//OutputDebugString(_T("InitUpdateLib: GetSignatureServerUrl failed.\n"));
		free(pszSigFolderPath);
		return 0;
	}

	bRetVal = ConvertFromWideCharToMultiByte(wszServerUrl, _tcslen(wszServerUrl), &pszServerUrl, &uiOutLen);
	if (FALSE == bRetVal)
	{
		//OutputDebugString(_T("InitUpdateLib: ConvertFromWideCharToMultiByte Failed.\n"));
		free(pszSigFolderPath);
		return 0;
	}

	OutputDebugStringA(pszSigFolderPath);
	OutputDebugString(_T("\n"));
	OutputDebugStringA(pszSigFolderPath);

	pObjUpdate = new Update(pszSigFolderPath, pszServerUrl);

	if (NULL == pObjUpdate)
	{
		//OutputDebugString(_T("InitUpdateLib: Creating Update class object failed.\n"));
		free(pszServerUrl);
		free(pszSigFolderPath);
		return 0;
	}

	//
	//	Not needed now.
	//
	free(pszServerUrl);
	free(pszSigFolderPath);

	iRetVal = pObjUpdate->init();
	if (0 != iRetVal)
	{
		OutputDebugString(_T("InitUpdateLib: Init failed.\n"));
		return 0;
	}

	bRetVal = GetServerUserNameAndPassword(wszUserName, ARRAY_SIZE(wszUserName), wszPassword, ARRAY_SIZE(wszPassword));
	if (FALSE == bRetVal)
	{
		//OutputDebugString(_T("InitUpdateLib: GetServerUserNameAndPassword failed.\n"));
		return 0;
	}

	bRetVal = ConvertFromWideCharToMultiByte(wszUserName, _tcslen(wszUserName), &pszUserName, &uiOutLen);
	if (FALSE == bRetVal)
	{
		//OutputDebugString(_T("InitUpdateLib: ConvertFromWideCharToMultiByte Failed.\n"));
		return 0;
	}

	bRetVal = ConvertFromWideCharToMultiByte(wszPassword, _tcslen(wszPassword), &pszPassword, &uiOutLen);
	if (FALSE == bRetVal)
	{
		//OutputDebugString(_T("InitUpdateLib: ConvertFromWideCharToMultiByte Failed.\n"));
		free(pszUserName);
		return 0;
	}

	OutputDebugStringA(pszUserName);
	OutputDebugStringA(pszPassword);

	iRetVal = pObjUpdate->login(pszUserName, pszPassword);
	if (0 != iRetVal)
	{
		OutputDebugString(_T("InitUpdateLib: Login failed.\n"));
		free(pszPassword);
		free(pszUserName);
		return 0;
	}

	free(pszPassword);
	free(pszUserName);

	return 1;
}

BOOLEAN
CHiparaDlg::DeInitUpdateLib(
)
{
	int iRetVal;

	OutputDebugString(_T("DeInitUpdateLib: Entry.\n"));
	if (NULL == pObjUpdate)
	{
		return FALSE;
	}

	//
	//	Logout.
	//
	OutputDebugString(_T("DeInitUpdateLib: Calling logout.\n"));
	iRetVal = pObjUpdate->logout();
	if (0 != iRetVal)
	{
		OutputDebugString(_T("DeInitUpdateLib: logout failed.\n"));
		return FALSE;
	}
	OutputDebugString(_T("DeInitUpdateLib: logout done.\n"));

	//
	//	Free update lib object.
	//
	delete pObjUpdate;
	pObjUpdate = NULL;

	OutputDebugString(_T("DeInitUpdateLib: Exit.\n"));
	return TRUE;
}


Update*
CHiparaDlg::GetUpdateLibObj(
)
{
	return pObjUpdate;
}


BOOLEAN
CHiparaDlg::SendAlertMessageToServer(
	WCHAR *pwszFilePath,
	ALERT_TYPE alertType,
	DWORD dwParentProcessId
)
{
	int iRetVal;
	UINT uiOutLen;
	DWORD dwcchLen;
	BOOLEAN bRetVal;
	Update *pUpdate;
	HRESULT hResult;
	CHAR *pszFilePath;
	SYSTEMTIME localTime;
	AlertMessage alertMessage;
	CHAR szLocalTime[MAX_ALERT_MSG_SIZE];
	CHAR szAlertMessage[MAX_ALERT_MSG_SIZE];
	CHAR szComputerName[MAX_COMPUTERNAME_LENGTH];

	WCHAR errMsg[MAX_PATH];

	//OutputDebugString(_T("SendAlertMessageToServer: Entry\n"));
	
	if (NULL == pwszFilePath)
	{
		return FALSE;
	}

	bRetVal = ConvertFromWideCharToMultiByte(pwszFilePath, _tcslen(pwszFilePath), &pszFilePath, &uiOutLen);
	if (FALSE == bRetVal)
	{
		OutputDebugString(_T("SendAlertMessageToServer: ConvertFromWideCharToMultiByte Failed.\n"));
		return FALSE;
	}

	GetLocalTime(&localTime);

	iRetVal = sprintf_s(szLocalTime, sizeof(szLocalTime), "%d:%d, %d/%d/%d", localTime.wHour, localTime.wMinute, localTime.wDay, localTime.wMonth, localTime.wYear);
	if (-1 == iRetVal)
	{
		OutputDebugString(_T("SendAlertMessageToServer: Formatting date and time failed.\n"));
		free(pszFilePath);
		return FALSE;
	}

	memset(errMsg, 0, sizeof(errMsg));
	_stprintf_s(errMsg, sizeof(errMsg), L"SendAlertMessageToServer:Time(%S)", szLocalTime);
	OutputDebugString(errMsg);

	dwcchLen = ARRAY_SIZE(szComputerName);
	bRetVal = GetComputerNameA(szComputerName, &dwcchLen);
	if (0 == bRetVal)
	{
		OutputDebugString(_T("SendAlertMessageToServer: GetComputerNameA failed\n"));
		free(pszFilePath);
		return FALSE;
	}

	memset(errMsg, 0, sizeof(errMsg));
	_stprintf_s(errMsg, sizeof(errMsg), L"SendAlertMessageToServer:Computer Name(%S)", szComputerName);
	OutputDebugString(errMsg);

	memset(szAlertMessage, 0, sizeof(szAlertMessage));
	hResult = StringCchCopyA(szAlertMessage, ARRAY_SIZE(szAlertMessage), "Sample Alert");
	if (FAILED(hResult))
	{
		OutputDebugString(_T("SendAlertMessageToServer: StringCchCopy failed.\n"));
		free(pszFilePath);
		return FALSE;
	}

	memset(&alertMessage, 0, sizeof(alertMessage));

	if (ALERT_CMD == alertType)
	{
		alertMessage.command = pszFilePath;
		alertMessage.parentProcessId = (LONG)dwParentProcessId;
		alertMessage.fileName = NULL;
	}
	else
	{
		alertMessage.fileName = pszFilePath;
		alertMessage.command = NULL;
	}

	alertMessage.hostName = szComputerName;
	alertMessage.alertMessage = szAlertMessage;
	alertMessage.timeStamp = szLocalTime;
	alertMessage.alertType = alertType;

	pUpdate = GetUpdateLibObj();
	if (NULL == pUpdate)
	{
		OutputDebugString(_T("SendAlertMessageToServer: Server library not initialized.\n"));
		free(pszFilePath);
		return FALSE;
	}

	/*memset(errMsg, 0, sizeof(errMsg));
	_stprintf_s(errMsg, sizeof(errMsg), L"Alert: File(%S) Host Name(%S) Time(%S) ParentProcessId(%d)", alertMessage.fileName, alertMessage.hostName, alertMessage.timeStamp, alertMessage.parentProcessId);
	OutputDebugString(errMsg);*/

	iRetVal = pUpdate->alert(&alertMessage);
	if (0 != iRetVal)
	{
		OutputDebugString(_T("Alert function failed.\n"));
		free(pszFilePath);
		return FALSE;
	}

	free(pszFilePath);
	//OutputDebugString(_T("SendAlertMessageToServer: Exit\n"));

	return TRUE;
}


BOOLEAN
CHiparaDlg::SendAlertMessageToFile(
	WCHAR *pwszFilePath,
	DWORD dwcbFilePathLen
)
{
	HANDLE hFile;
	BOOL boRetVal;
	time_t timer;
	struct tm* tm_info;
	WCHAR wszbuffer[26];
	TCHAR ErrMgg[MAX_PATH];
	DWORD dwNumberOfBytesReturned;
	LARGE_INTEGER liDistanceToMove;

	OutputDebugString(_T("SendAlertMessageToFile() Entry."));

	if (NULL == pwszFilePath || 0 == dwcbFilePathLen)
	{
		_stprintf_s(ErrMgg, sizeof(ErrMgg), L"Invalid parameter.");
		OutputDebugString(ErrMgg);

		return FALSE;
	}

	hFile = CreateFileA(gszReportFilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		_stprintf_s(ErrMgg, sizeof(ErrMgg), L"CreateFileW() Failed. Error(%u).", GetLastError());
		OutputDebugString(ErrMgg);

		return FALSE;
	}

	liDistanceToMove.QuadPart = 0;
	boRetVal = SetFilePointerEx(hFile, liDistanceToMove, NULL, FILE_END);
	if (FALSE == boRetVal)
	{
		_stprintf_s(ErrMgg, sizeof(ErrMgg), L"SetFilePointerEx() Failed. Error(%u).", GetLastError());
		OutputDebugString(ErrMgg);

		CloseHandle(hFile);
		return FALSE;
	}

	time(&timer);
	tm_info = localtime(&timer);

	wcsftime(wszbuffer, ARRAY_SIZE(wszbuffer), L"%Y:%m:%d %H:%M:%S ", tm_info);

	boRetVal = WriteFile(hFile, wszbuffer, wcslen(wszbuffer) * sizeof(wszbuffer[0]), &dwNumberOfBytesReturned, NULL);
	if (FALSE == boRetVal)
	{
		_stprintf_s(ErrMgg, sizeof(ErrMgg), L"WriteFile() Failed. Error(%u).", GetLastError());
		OutputDebugString(ErrMgg);

		CloseHandle(hFile);
		return FALSE;
	}

	boRetVal = WriteFile(hFile, pwszFilePath, dwcbFilePathLen, &dwNumberOfBytesReturned, NULL);
	if (FALSE == boRetVal)
	{
		_stprintf_s(ErrMgg, sizeof(ErrMgg), L"WriteFile() Failed. Error(%u).", GetLastError());
		OutputDebugString(ErrMgg);

		CloseHandle(hFile);
		return FALSE;
	}

	boRetVal = WriteFile(hFile, L"\r\n", wcslen(L"\r\n") * sizeof(WCHAR), &dwNumberOfBytesReturned, NULL);
	if (FALSE == boRetVal)
	{
		_stprintf_s(ErrMgg, sizeof(ErrMgg), L"WriteFile() Failed. Error(%u).", GetLastError());
		OutputDebugString(ErrMgg);

		CloseHandle(hFile);
		return FALSE;
	}

	OutputDebugString(_T("SendAlertMessageToFile() Exit."));

	CloseHandle(hFile);
	return TRUE;
}