#ifndef _ACCEPTCONNECTION_H_
#define _ACCEPTCONNECTION_H_


#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <WinSock2.h>
#include "httpsession.h"
#include "header.h"
#include "BaseDataHandler.h"

class AcceptConnection;
typedef struct _session_overlapped_ {
    WSAOVERLAPPED overlapped;
    AcceptConnection *pac;
}session_overlapped;

class AcceptConnection {
public:
    session_overlapped  m_overlapped[2];
    DWORD               m_flags[2];
    DWORD               m_bytes_transferred[2];
    HANDLE              m_hCompletionPort;
    DWORD               m_commstate;       //通讯状态
    CRITICAL_SECTION    m_lock;            //通讯同步锁


    SOCKET      m_accept;               //连接的socket
    sockaddr_in m_remoteaddr;           //接受的远程地址
    WSABUF      m_wsabuf[2];            //客户端地址信息
    CHAR        m_recvbuf[4096];        //接收数据缓冲区
    DWORD       m_bytessend;            //已经发送的数据长度
    HttpSession m_httpsession;          //HttpSession类贯穿整个的处理过程，所需要对结果的状态都保存在session中
    HTTPSERVICE_PARAMS  m_httpservice_params;   //保存http传入的变量
    enum {
        RECV,
        SEND,
    };

    enum {
        RECVING,
        SENDING,
        CLOSING, 
    };
public:
    AcceptConnection(HANDLE hCompletionPort, SOCKET acp, sockaddr_in remoteaddr, HTTPSERVICE_PARAMS *pHttpService_Params);
    ~AcceptConnection();
    void init();
public:
    /*
    处理消息
    返回值:错误返回-1，成功返回 >0的值(接受完成的字节数)
    */
    int HandleIoCompletion(DWORD numberbytes,session_overlapped  *poverlapped);
private:
    void session_recv();    //接受数据
    void session_send();    //发送数据
    void session_close();   //关闭

    void _entry_();
    void _leave_();

public:
    BaseDataHandler *m_handler;

public:
    //数据处理对象的初始化工作
    void Init_DataHandlerObj(); //可重载，用户切换数据处理方法
};

typedef AcceptConnection* PACCEPTCONNECTION;

#endif