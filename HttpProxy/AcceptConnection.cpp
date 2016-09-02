#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <WinSock2.h>
#include <stdlib.h>
#include <stdio.h>
#include "BaseHTTPRequestHandler.h"
#include "AcceptConnection.h"
#include "CommonFuncs.h"


AcceptConnection::AcceptConnection(HANDLE hCompletionPort, SOCKET acp, sockaddr_in remoteaddr, HTTPSERVICE_PARAMS *pHttpService_Params) :m_accept(acp) {

    
    memset(m_overlapped, 0, sizeof(session_overlapped) * 2);
    m_overlapped[RECV].pac = m_overlapped[SEND].pac = this;

    memset(m_flags, 0, sizeof(DWORD) * 2);
    memset(m_bytes_transferred, 0, sizeof(DWORD) * 2);
    memset(m_wsabuf, 0, sizeof(WSABUF) * 2);

    memset(&m_remoteaddr, 0, sizeof(m_remoteaddr));
    memcpy_s(&m_remoteaddr, sizeof(m_remoteaddr), &remoteaddr, sizeof(remoteaddr));
    m_hCompletionPort = hCompletionPort;

    m_commstate = RECVING;

    //初始化
    init();

    memset(&m_httpservice_params, 0, sizeof(HTTPSERVICE_PARAMS));
    //初始化m_httpservice_params
    m_httpservice_params.bSSH = FALSE;
    m_httpservice_params.port = 8206;
    strcpy_s(m_httpservice_params.ip, 16, "127.0.0.1");


    if (!::IsBadReadPtr(pHttpService_Params, sizeof(HTTPSERVICE_PARAMS))) {
        //不能读取参数大小的内存
        memcpy_s(&m_httpservice_params, sizeof(HTTPSERVICE_PARAMS), pHttpService_Params, sizeof(HTTPSERVICE_PARAMS));
    }

    
    //初始化处理
    Init_DataHandlerObj(); 
    InitializeCriticalSection(&m_lock);
}


void AcceptConnection::Init_DataHandlerObj()
{
    m_handler = new BaseHTTPRequestHandler(&m_httpservice_params, &m_httpsession); 
}

AcceptConnection::~AcceptConnection() {

    m_httpsession.revert(); //初始化

    if (m_handler != NULL) {
        delete m_handler;
        m_handler = NULL;
    }


    shutdown(m_accept, SD_BOTH);
    closesocket(m_accept);
    m_accept = INVALID_SOCKET;
    DeleteCriticalSection(&m_lock);
}


void AcceptConnection::init() {
    //初始化

    //初始化接收结构
    m_wsabuf[RECV].buf = m_recvbuf;
    m_wsabuf[RECV].len = 4096;


    //初始化发送结构
    m_wsabuf[SEND].buf = m_httpsession.m_pSendbuf;
    m_wsabuf[SEND].len = m_httpsession.m_SizeofSendbuf;

    //记录一次发送的数据
    m_bytessend = 0;
}
/*
处理消息
返回值:错误返回-1，成功返回 >0的值(接受完成的字节数)
*/
int AcceptConnection::HandleIoCompletion(DWORD numberbytes, session_overlapped  *poverlapped) {
    int     ret = -1;
    DWORD   Flags = 0;
    DWORD   dwRecved = 0;
    DWORD   dwSended = 0;
    BaseDataHandler_RET   ret_handler = { 0 };

    _entry_();  //锁定，进行操作

    //判断
    if (poverlapped == &m_overlapped[RECV])
    {//接收数据
        m_handler->handler_request(m_recvbuf, numberbytes, &ret_handler);//处理数据
        switch (ret_handler.dwOpt)
        {
        case BaseDataHandler::RET_RECV:
        {
            m_commstate = RECVING;
        }
        break;
        case BaseDataHandler::RET_SEND:
        {

            if (m_httpsession.m_resultstate == HttpSession::HS_RESULT_SERVER_NOEXIST)
            {
                m_commstate = CLOSING;
            }
            else {
                m_commstate = SENDING;
                m_wsabuf[SEND].buf = m_httpsession.m_pSendbuf;
                m_wsabuf[SEND].len = m_httpsession.m_SizeofSendbuf;
            }        
        }
        break;
        }
    }
    else if (poverlapped == &m_overlapped[SEND])
    {//发送数据
        m_bytessend += numberbytes;   //已经发送的字节

        if (m_bytessend == m_httpsession.m_SizeofSendbuf) {
            m_wsabuf[SEND].buf = NULL;
            m_wsabuf[SEND].len = 0;
            m_httpsession.revert();
            m_bytessend = 0;

            if(m_httpsession.m_bKeepAlive==FALSE)
                m_commstate = CLOSING;
            else
                m_commstate = RECVING;
        }      
    }

    session_send();
    session_recv();
    session_close();
    _leave_();
    return ret;
};


//接受数据
void AcceptConnection::session_recv()
{
    if (m_commstate == RECVING) {
        if (WSARecv(m_accept, &m_wsabuf[RECV], 1, &m_bytes_transferred[RECV], &m_flags[RECV], (LPWSAOVERLAPPED)&m_overlapped[RECV], NULL) == SOCKET_ERROR) {
            if (WSAGetLastError() != ERROR_IO_PENDING)
            {
#if _DEBUG
                DWORD dwerror = WSAGetLastError();
                printf("session_recv error_code:%d\n",dwerror);
#endif
                m_commstate = CLOSING;  //
            }
        }
    }
}


//发送数据
void AcceptConnection::session_send()
{
    if (m_wsabuf[SEND].len == 0) return;

    if (m_commstate != SENDING) return;
    if (WSASend(m_accept, &m_wsabuf[SEND], 1, &m_bytes_transferred[SEND], m_flags[SEND], (LPWSAOVERLAPPED)&m_overlapped[SEND], NULL) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING)
        {
#if _DEBUG
            DWORD dwerror = WSAGetLastError();
            printf("session_send error_code:%d\n",dwerror);
#endif
            m_commstate = CLOSING;
        }
    } 
}

//关闭
void AcceptConnection::session_close()
{
    BOOL bRet = FALSE;
    int error = 0;
    if (m_commstate == CLOSING) {
        /*bRet=PostQueuedCompletionStatus(m_hCompletionPort, 0, 0, &m_overlapped[RECV].overlapped);
        if (!bRet) {
#if _DEBUG
            printf("AcceptConnection::session_close Error:%d",GetLastError());
#endif
        }*/

        shutdown(m_accept, SD_BOTH);
        closesocket(m_accept);
        m_accept = INVALID_SOCKET;
    }


}


void AcceptConnection::_entry_() {
    EnterCriticalSection(&m_lock);
}

void AcceptConnection::_leave_() {
    LeaveCriticalSection(&m_lock);
}