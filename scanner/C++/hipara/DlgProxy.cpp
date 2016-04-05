
// DlgProxy.cpp : implementation file
//

#include "stdafx.h"
#include "hipara.h"
#include "DlgProxy.h"
#include "hiparaDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CHiparaDlgAutoProxy

IMPLEMENT_DYNCREATE(CHiparaDlgAutoProxy, CCmdTarget)

CHiparaDlgAutoProxy::CHiparaDlgAutoProxy()
{
	EnableAutomation();
	
	// To keep the application running as long as an automation 
	//	object is active, the constructor calls AfxOleLockApp.
	AfxOleLockApp();

	// Get access to the dialog through the application's
	//  main window pointer.  Set the proxy's internal pointer
	//  to point to the dialog, and set the dialog's back pointer to
	//  this proxy.
	ASSERT_VALID(AfxGetApp()->m_pMainWnd);
	if (AfxGetApp()->m_pMainWnd)
	{
		ASSERT_KINDOF(CHiparaDlg, AfxGetApp()->m_pMainWnd);
		if (AfxGetApp()->m_pMainWnd->IsKindOf(RUNTIME_CLASS(CHiparaDlg)))
		{
			m_pDialog = reinterpret_cast<CHiparaDlg*>(AfxGetApp()->m_pMainWnd);
			m_pDialog->m_pAutoProxy = this;
		}
	}
}

CHiparaDlgAutoProxy::~CHiparaDlgAutoProxy()
{
	// To terminate the application when all objects created with
	// 	with automation, the destructor calls AfxOleUnlockApp.
	//  Among other things, this will destroy the main dialog
	if (m_pDialog != NULL)
		m_pDialog->m_pAutoProxy = NULL;
	AfxOleUnlockApp();
}

void CHiparaDlgAutoProxy::OnFinalRelease()
{
	// When the last reference for an automation object is released
	// OnFinalRelease is called.  The base class will automatically
	// deletes the object.  Add additional cleanup required for your
	// object before calling the base class.

	CCmdTarget::OnFinalRelease();
}

BEGIN_MESSAGE_MAP(CHiparaDlgAutoProxy, CCmdTarget)
END_MESSAGE_MAP()

BEGIN_DISPATCH_MAP(CHiparaDlgAutoProxy, CCmdTarget)
END_DISPATCH_MAP()

// Note: we add support for IID_Ihipara to support typesafe binding
//  from VBA.  This IID must match the GUID that is attached to the 
//  dispinterface in the .IDL file.

// {646AA8B3-6B4C-40DE-9221-A2FB94763E69}
static const IID IID_Ihipara =
{ 0x646AA8B3, 0x6B4C, 0x40DE, { 0x92, 0x21, 0xA2, 0xFB, 0x94, 0x76, 0x3E, 0x69 } };

BEGIN_INTERFACE_MAP(CHiparaDlgAutoProxy, CCmdTarget)
	INTERFACE_PART(CHiparaDlgAutoProxy, IID_Ihipara, Dispatch)
END_INTERFACE_MAP()

// The IMPLEMENT_OLECREATE2 macro is defined in StdAfx.h of this project
// {F8B449ED-5131-4EF3-B49A-B7F0BDBA5FC3}
IMPLEMENT_OLECREATE2(CHiparaDlgAutoProxy, "hipara.Application", 0xf8b449ed, 0x5131, 0x4ef3, 0xb4, 0x9a, 0xb7, 0xf0, 0xbd, 0xba, 0x5f, 0xc3)


// CHiparaDlgAutoProxy message handlers
