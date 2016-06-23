
// DlgProxy.h: header file
//

#pragma once

class CHiparaDlg;


// CHiparaDlgAutoProxy command target

class CHiparaDlgAutoProxy : public CCmdTarget
{
	DECLARE_DYNCREATE(CHiparaDlgAutoProxy)

	CHiparaDlgAutoProxy();           // protected constructor used by dynamic creation

// Attributes
public:
	CHiparaDlg* m_pDialog;

// Operations
public:

// Overrides
	public:
	virtual void OnFinalRelease();

// Implementation
protected:
	virtual ~CHiparaDlgAutoProxy();

	// Generated message map functions

	DECLARE_MESSAGE_MAP()
	DECLARE_OLECREATE(CHiparaDlgAutoProxy)

	// Generated OLE dispatch map functions

	DECLARE_DISPATCH_MAP()
	DECLARE_INTERFACE_MAP()
};

