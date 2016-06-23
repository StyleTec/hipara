
// hiparaDlg.h : header file
//

#pragma once

#define MAX_LENGTH_PATH		260
#define MAX_SIZE_QUEUE		100
#define MAX_COUNT_THREADS	10
#define MAX_BUFF_SIZE		256
#define MAX_CMD_MON_COUNT   5

#define	HIPARA_UPDATE_SECTION_NAME			L"Update"
#define HIPARA_UPDATE_URL_KEY_NAME			L"URL"
#define	HIPARA_UPDATE_USERNAME_KEY_NAME		L"USERNAME"
#define	HIPARA_UPDATE_PASSWORD_KEY_NAME		L"PWD"
#define	HIPARA_CONFIG_FILE_NAME				L"config.ini"

class CHiparaDlgAutoProxy;

#pragma pack(push, 1)
typedef struct tagQUEUE_INFO
{
	INT				uiHead;
	INT				uiTail;
	HANDLE			hQueueMutex;
	TCHAR			*pvData[MAX_SIZE_QUEUE];

}	QUEUE_INFO, *P_QUEUE_INFO;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct tagSCAN_CONTEXT
{
	FILE			*pYarFile;
	YR_RULES		*pYrRules;
	YR_COMPILER		*pYrCompiler;
	HANDLE			hStopEvent;
	UINT			uiTaskCount;
	TCHAR			szDirPath[MAX_LENGTH_PATH];
	TCHAR			szSignaturePath[MAX_LENGTH_PATH];
	QUEUE_INFO		queueInfo;
} SCAN_CONTEXT, *P_SCAN_CONTEXT;
#pragma pack(pop)


typedef struct tagCMD_THREAD_DATA
{
	BOOLEAN		bAquired;
	DWORD		dwProcessID;
	HANDLE		hThread;

}	CMD_THREAD_DATA, *P_CMD_THREAD_DATA;

typedef struct tagCMD_THREAD_CTX
{
	HANDLE		*phStopEvent;
	DWORD		dwProcessId;

}	CMD_THREAD_CTX, *P_CMD_THREAD_CTX;


// CHiparaDlg dialog
class CHiparaDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CHiparaDlg);
	friend class CHiparaDlgAutoProxy;

	FILE	*mpYarFile;
	static FILE	*mpLogFile;
	YR_RULES *mpYrRules;
	HANDLE	mhStopEvent;
	HANDLE	hLiveScanThread;
	HANDLE	hCmdScanThread;
	YR_COMPILER *mpYrCompiler;
	SCAN_CONTEXT mScanContext;
	HANDLE mhMemoryScannerThread;
	HANDLE mhUpdateSignatureThread;
	HANDLE mhEntireSystemScanThread;
	BOOLEAN bIsYaraLibraryInitialize;
	SCANNER_THREAD_CONTEXT mScannerContext;
	SCANNER_THREAD_CONTEXT mCmdFltContext;

// Construction
public:
	CHiparaDlg(CWnd* pParent = NULL);	// standard constructor
	virtual ~CHiparaDlg();

	//
	//	Yara library initialization function.
	//
	int initYara();

	//
	//	Yara library de-initialization function.
	//
	void deinitYara();

	//
	//	yara callback function.
	//	Scan result will be returned to this function.
	//
	static int yaraScanCallback(
		int iMessage,
		void *pMessageData,
		void *pUserData
		);

	//
	//	live scanner thread.
	//
	static DWORD liveScanThread(LPVOID lpContext);

	static DWORD CmdScanThread(LPVOID lpContext);

	//
	//	Scanner worker thread.
	//
	static DWORD scannerWorker(LPVOID lpContext);

	static DWORD CmdWorker(LPVOID lpContext);

	//
	//	File enumeration thread.
	//
	static DWORD WINAPI enumFilesThread(LPVOID lpvParameter);

	//
	//	Scan file thread.
	//
	static DWORD WINAPI scanFiles(LPVOID lpvParameter);

	BOOL scanBuffer(PUCHAR Buffer, ULONG BufferSize);
	BOOLEAN scanFile(PWCHAR pszFilePath);

	//
	//	Creates thread pool.
	//
	BOOLEAN CreateThreadPool(UINT *puiThreadCount, HANDLE *pThreadHandles, PVOID pContextToThreads, LPTHREAD_START_ROUTINE threadFunction);

	//
	//	Enumerate all files within given drive.
	//
	void enumerateFiles(TCHAR *pszFolderPath, SCAN_CONTEXT *pScanContext);

	//
	//	Insert data in queue.
	//
	BOOLEAN insertInQueue(TCHAR *pszFileName, SCAN_CONTEXT *pScanContext);

	//
	//	Delete from queue.
	//
	TCHAR* deleteFromQueue(SCAN_CONTEXT *pScanContext);

	//
	//	Entire system scan thread.
	//
	static DWORD WINAPI entireSystemScan(LPVOID lpvParameter);

	//
	//	Update signature thread.
	//
	static DWORD WINAPI updateSignatures(LPVOID lpvParameter);

	//
	//	Update yara signatures.
	//
	BOOLEAN updateYaraSignatures();

	//
	//	Memory scanner thread.
	//
	static DWORD WINAPI scanMemoryThread(LPVOID lpvParameter);

	BOOLEAN isYaraLibraryInitialized();
	void setYaraLibraryInitializedFlag(BOOLEAN bIsInitialized);

	BOOLEAN GetSignatureServerUrl(WCHAR *pwszServerUrl, DWORD dwcchServerUrlLen);

	BOOLEAN GetServerUserNameAndPassword(WCHAR *pwszUserName, DWORD dwcchUserNameLen, WCHAR *pwszPassword, DWORD dwcchPasswordLen);

	HANDLE
	InitThread(
		DWORD dwPID
		);


	static void
	CmdMonThread(
		void* pArguments
		);


	BOOLEAN
	AquireThreadSlot(
		DWORD dwProcessID,
		CMD_THREAD_DATA **ppCmdThreadData,
		CMD_THREAD_CTX **ppCmdThreadCtx
		);


	static BOOLEAN
	ReleaseThreadSlot(
		DWORD dwProcessID
		);


// Dialog Data
	enum { IDD = IDD_HIPARA_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	CHiparaDlgAutoProxy* m_pAutoProxy;
	HICON m_hIcon;

	BOOL CanExit();

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnClose();
	virtual void OnOK();
	virtual void OnCancel();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedScanentiresystem();
	afx_msg void OnBnClickedUpdatesignature();
	afx_msg void OnBnClickedMemoryscan();
};
