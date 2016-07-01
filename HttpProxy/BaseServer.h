#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include "header.h"
#include "AcceptConnection.h"



//保存分配的acceptConnection
typedef struct _list_acceptconnection_
{
    LIST_ENTRY list_entry;
    AcceptConnection* pAcceptConnection;
}LIST_ACCEPTCONNECTION, *PLIST_ACCEPTCONNECTION;

#define CONTROL_EVENT "Global\\{385EF596-7239-421F-8A68-981052921C7E}"  //控制程序暂停，继续执行命令
class BaseServer {
public:
    BaseServer(HTTPSERVICE_PARAMS *pHttpService_Params);
    ~BaseServer();  //后续处理
    enum {
        BHSR_SUCCESS = 0x0000000,
        BHSR_ERROR_PORT,
        BHSR_ERROR_IP,
        BHSR_ERROR_INITLISTENSOCKET,
        BHSR_ERROR_START,                   //启动服务失败
        BHSR_ERROR_INITSSL,                 //初始化SSL失败
        BHSR_ERROR_GENERATE_CONTROLEVENT,   //生成状态控制事件错误
        BHSR_ERROR_GEN_SOCKET,              //创建套接字出错
        BHSR_ERROR_GEN_CONNECT,             //连接出错
        BHSR_ERROR_SOCKET_OPT,              //opt设置错误
        BHSR_ERROR_CREATE_SEVICE,           //创建服务失败
        BHSR_ERROR_CLOSEWORKTHREAD,         //关闭IO工作线程失败
    };

    enum {
        STATUS_GET      =0x00000000,
        STATUS_RUN      =0x00000001,
        STATUS_PAUSE    =0x00000002,
        STATUS_CONTINUE =0x00000004,
        STATUS_STOP     =0x00000008,
    };
public:
    //operation
    ULONG               status(ULONG bPause, ULONG *dwRet);  //服务状态控制
private:
    ULONG               http_server();
    static DWORD WINAPI work_proc(LPVOID lparam);
    void                server_loop(LPVOID lparam, size_t len);     //
    void                counter(BOOL bDec);                         //计数
    static DWORD WINAPI ServerThread(LPVOID lparam);                //独立服务线程
    ULONG               handle_status();
    static DWORD WINAPI StopServerThread(LPVOID lparam);
    void                stopserver();
    void                Release_AcceptConnectionList();
    void                DeleteElem_AcceptConnectionList(AcceptConnection *addr);
    ULONG               init_httpserver();                          //初始化代理
    void                uninit_httpserver();                //反初始化
    ULONG               server_forever(int bNewThread);     //启动服务
    ULONG               stop();                             //关闭服务

private:
    sockaddr_in         m_httpserver_address;   //需要创建的服务器地址
    HTTPSERVICE_PARAMS  m_HttpService_Params;    //输入的参数
    UINT_PTR            m_listensocket;
    int                 m_ThreadCount;
    HANDLE*             m_pThreadArray;
    HANDLE              m_hServerThread;    //指向独立的服务线程句柄
    HANDLE              m_hCompletionPort;
    HANDLE              m_hMainThread;      //服务根线程
    DWORD               m_counter;  //计数器
    ULONG               m_status;
    LIST_ENTRY          m_AcceptConnectList; //保存内存的list的状态
#ifdef _DEBUG
    CRITICAL_SECTION    m_lock_counter;
#endif
private:
    //以下函数的目的是确保BaseHttpServer作为其他服务器的独立性
    int                 init_httpserver_ex();
    void                uninit_httpserver_ex();
};