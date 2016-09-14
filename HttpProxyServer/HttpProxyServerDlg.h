
// HttpProxyServerDlg.h : 头文件
//

#pragma once
#include <header.h>
#include <httpcore.h>

// CHttpProxyServerDlg 对话框
class CHttpProxyServerDlg : public CDialog
{
// 构造
public:
	CHttpProxyServerDlg(CWnd* pParent = NULL);	// 标准构造函数

    enum {
        STATE_START=1,
        STATE_STOP,
    };
// 对话框数据
	enum { IDD = IDD_HTTPPROXYSERVER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持
    void ControlOpt();
    void OnOK();
    void OnCancel();
// 实现
protected:
	HICON m_hIcon;
    HTTPSERVICE_PARAMS m_httpservice_params;
    PHS_HANDLE  m_hProxyHttpService;
    SCG_HANDLE  m_hSSLConfigHandle;
    DWORD m_state;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
    afx_msg void OnClose();
    afx_msg void OnConfig();
    afx_msg void OnBnClickedButton1();
	DECLARE_MESSAGE_MAP()

public:
    void insert_reqlist(const char* szurl, int len);
private:
    CListBox m_ctrl_requestlistbox;
    
};
