#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <WinSock2.h>
#include <headers.h>
#include <stdlib.h>
#include <stdio.h>
#include <io.h>
#include <curl\curl.h>
#include "BaseSSLConfig.h"

#include "list_entry.h"
#include "AcceptConnection.h"
#include "httpcore.h"
#include "BaseServer.h"


enum _ControlCode_ {
    CONTROLCODE_NONE = 0,
    CONTROLCODE_SHUTDOWN = 1,
    CONTROLCODE_IOCONTINUE = 2,
}g_ControlCode;


//默认服务状态回调
void __stdcall Default_ServerStatus_Callback(ULONG status)
{
#ifdef _DEBUG
    //::OutputDebugStringA("Default_ServerStatus_Callback\n");
#endif
}

#define INVOKE_CALLBACK(status_code) m_HttpService_Params.serverstatus_callback(status_code);

BaseServer::BaseServer(HTTPSERVICE_PARAMS *pHttpService_Params) :
    m_hCompletionPort(INVALID_HANDLE_VALUE), m_ThreadCount(0),
    m_listensocket(INVALID_SOCKET), m_hServerThread(NULL), m_status(STATUS_GET),
    m_hMainThread(NULL)
{
    memcpy_s(&m_HttpService_Params, sizeof(HTTPSERVICE_PARAMS), pHttpService_Params, sizeof(HTTPSERVICE_PARAMS));

    //设置服务回调函数
    if (m_HttpService_Params.serverstatus_callback == NULL) {
        m_HttpService_Params.serverstatus_callback = Default_ServerStatus_Callback;
    }
    //
    InitializeListHead(&m_AcceptConnectList);
    //
    m_counter = 0;
#ifdef _DEBUG
    InitializeCriticalSection(&m_lock_counter); //初始化
#endif

    memset(&m_httpserver_address, 0, sizeof(struct sockaddr_in));
}

//
BaseServer::~BaseServer() {

}

//初始化
ULONG BaseServer::init_httpserver()
{
    WSADATA wsa;
    int ret = BaseServer::BHSR_SUCCESS;

    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return BaseServer::BHSR_ERROR_INITLISTENSOCKET;

    //create a completation port
    m_hCompletionPort = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, 0);
    if (m_hCompletionPort == INVALID_HANDLE_VALUE)
        return BaseServer::BHSR_ERROR_CREATE_SEVICE;

    //
    if (m_HttpService_Params.numofworkthread == 0) {
        //get the count of threads will be created
        SYSTEM_INFO sysinfo = { 0 };
        ::GetSystemInfo(&sysinfo);
        m_ThreadCount = sysinfo.dwNumberOfProcessors * 2;
        m_pThreadArray = (HANDLE*)malloc(m_ThreadCount * sizeof(HANDLE));
        memset(m_pThreadArray, 0, sizeof(m_ThreadCount * sizeof(HANDLE)));
    }
    else
    {
        m_ThreadCount = m_HttpService_Params.numofworkthread;
        m_pThreadArray = (HANDLE*)malloc(m_ThreadCount * sizeof(HANDLE));
        memset(m_pThreadArray, 0, sizeof(m_ThreadCount * sizeof(HANDLE)));
    }

    ret = init_httpserver_ex();

    return ret;
}


//no safe???
void BaseServer::uninit_httpserver()
{
    if (m_ThreadCount != 0 && m_pThreadArray != NULL) {
        for (int i = 0; i < m_ThreadCount; i++) {
            CloseHandle(m_pThreadArray[i]);
        }

        m_ThreadCount = 0;
    }


    if (m_pThreadArray != NULL)
        ::free(m_pThreadArray);

    if (m_hCompletionPort != INVALID_HANDLE_VALUE)
        ::CloseHandle(m_hCompletionPort);

    m_ThreadCount = 0;

    
    if (m_listensocket != INVALID_SOCKET) {
        
        shutdown(m_listensocket, SD_BOTH);
        ::closesocket(m_listensocket);
        m_listensocket = INVALID_SOCKET;
    }

    uninit_httpserver_ex();

    return;
}

DWORD BaseServer::ServerThread(LPVOID lparam)
{
    BaseServer* pthis = (BaseServer*)lparam;
    pthis->http_server();
    return 0L;
}

/*
bNewThread 1 新线程启动
0 当前线程
注意:bNewThread应当设置为１，主要是防止阻塞主线程
*/
ULONG BaseServer::server_forever(int bNewThread)
{
    if (bNewThread)
    {
        m_hMainThread = ::CreateThread(NULL, 0, ServerThread, this, 0, 0);
    }
    else {
        http_server();
    }
    if (m_hMainThread == NULL)
    {
        return BaseServer::BHSR_ERROR_START;
    }
    return BaseServer::BHSR_SUCCESS;
}

DWORD WINAPI BaseServer::StopServerThread(LPVOID lparam)
{
    BaseServer*pthis = (BaseServer*)lparam;
    pthis->stopserver();
    return 0L;
}

void BaseServer::stopserver()
{
    DWORD dwRet = WaitForMultipleObjects(m_ThreadCount, m_pThreadArray, TRUE, INFINITE);
    Release_AcceptConnectionList();
    uninit_httpserver();
}
/*
关闭http服务器
*/
ULONG BaseServer::stop()
{
    //关闭监听线程
    if (m_listensocket != INVALID_SOCKET) {
        shutdown(m_listensocket, SD_BOTH);
        ::closesocket(m_listensocket);
        m_listensocket = INVALID_SOCKET;
    }

    ::CreateThread(NULL, 0, StopServerThread, this, 0, 0);
    for (int i = 0; i < m_ThreadCount; i++) {
        BOOL bRet=PostQueuedCompletionStatus(m_hCompletionPort, 0, (ULONG_PTR)CONTROLCODE_SHUTDOWN, 0); //向所有的工作线程发送消息
        if (!bRet) {
            //错误处理
        }
        else {

        }
    }
    
   return  BaseServer::BHSR_SUCCESS;
}

DWORD WINAPI BaseServer::work_proc(LPVOID lparam)
{
    BaseServer *pthis = reinterpret_cast<BaseServer*>(lparam);
    pthis->server_loop(NULL, 0);
    return 0L;
}


//
void BaseServer::server_loop(LPVOID lparam, size_t len)
{
    //完成端口句柄直接利用
    while (TRUE) {
        DWORD BytesTransferred = 0;
        LPOVERLAPPED Overlapped = NULL;
        PACCEPTCONNECTION pAcceptConnection = NULL;
        session_overlapped *psession = NULL;
        DWORD ControlCode = 0;
        //接收数据
        if (GetQueuedCompletionStatus(m_hCompletionPort, &BytesTransferred,
            (PULONG_PTR)&ControlCode, (LPOVERLAPPED *)&Overlapped, INFINITE) == 0)
        {
            //可以不处理
        }

        //
        if (ControlCode == CONTROLCODE_IOCONTINUE)
        {

            psession = reinterpret_cast<session_overlapped*>(Overlapped);
            if (psession == NULL) {
                continue;
            }

            pAcceptConnection = (PACCEPTCONNECTION)psession->pac;
            if (pAcceptConnection != NULL && BytesTransferred == 0) {
                DeleteElem_AcceptConnectionList(pAcceptConnection);
                counter(TRUE);
                continue;
            }

            pAcceptConnection->HandleIoCompletion(BytesTransferred, psession);
        }
        else if (ControlCode == CONTROLCODE_SHUTDOWN)
        {
            break;
        }

    }
    return;
}

//http server
ULONG BaseServer::http_server()
{

    if (m_hCompletionPort == INVALID_HANDLE_VALUE)
        return BaseServer::BHSR_ERROR_CREATE_SEVICE;

    //根据处理器的数量，创建完成的端口执行所需要的线程
    for (int i = 0; i < m_ThreadCount; i++)
    {
        m_pThreadArray[i] = ::CreateThread(NULL, 0, work_proc, this, 0, 0);
    }

    //创建监听
    m_listensocket = ::WSASocketA(AF_INET, SOCK_STREAM, 0, 0, 0, WSA_FLAG_OVERLAPPED);
    if (m_listensocket == INVALID_SOCKET)
        return BaseServer::BHSR_ERROR_GEN_SOCKET;

    m_httpserver_address.sin_addr.S_un.S_addr = inet_addr(m_HttpService_Params.ip);
    m_httpserver_address.sin_family = AF_INET;
    m_httpserver_address.sin_port = htons(m_HttpService_Params.port);
    ::bind(m_listensocket, (const struct sockaddr*)&m_httpserver_address, sizeof(struct sockaddr));

    listen(m_listensocket, 5);

    SOCKET accept_socket = INVALID_SOCKET;
    sockaddr_in accept_addr = { 0 };
    int addrlen = sizeof(struct sockaddr_in);
    int tcpopt = 1;//
    DWORD single_status = 0;
    while (TRUE){      
        //accept 
        accept_socket = ::WSAAccept(m_listensocket, (struct sockaddr*)&accept_addr, &addrlen, NULL, 0);
        if (accept_socket == INVALID_SOCKET)
        {
            int error = WSAGetLastError();
            break;
        }

        setsockopt(accept_socket, IPPROTO_TCP, TCP_NODELAY, (const char*)&tcpopt, 1);

        //传入的数据需要初始化  
        PACCEPTCONNECTION ac = new AcceptConnection(m_hCompletionPort, accept_socket, accept_addr, &m_HttpService_Params);
        PLIST_ACCEPTCONNECTION plist_acceptconnection = (PLIST_ACCEPTCONNECTION)malloc(sizeof(LIST_ACCEPTCONNECTION));
        memset(plist_acceptconnection, 0, sizeof(LIST_ACCEPTCONNECTION));
        plist_acceptconnection->pAcceptConnection = ac;
        InsertHeadList(&m_AcceptConnectList, &plist_acceptconnection->list_entry);

        counter(FALSE);
        
        if (!CreateIoCompletionPort((HANDLE)accept_socket, m_hCompletionPort, (ULONG_PTR)CONTROLCODE_IOCONTINUE, 0)) {
            delete ac;
            return BaseServer::BHSR_ERROR_CREATE_SEVICE;
        }

        DWORD RecvBytes = 0;
        DWORD Flags = 0;
        if (WSARecv(accept_socket, &ac->m_wsabuf[AcceptConnection::RECV], 1, &RecvBytes, &Flags, (LPWSAOVERLAPPED)&ac->m_overlapped[AcceptConnection::RECV].overlapped, NULL) == SOCKET_ERROR) {
            if (WSAGetLastError() != ERROR_IO_PENDING)
            {

                int error = WSAGetLastError();
                return BaseServer::BHSR_ERROR_CREATE_SEVICE;
            }
        }
    }

    return BaseServer::BHSR_SUCCESS;
}


void BaseServer::Release_AcceptConnectionList() //
{
    PLIST_ENTRY plist;
    struct _list_acceptconnection_ *pelem = NULL;
    int i = 0;
    int count = 0;
    for (plist = m_AcceptConnectList.Flink; plist != &m_AcceptConnectList; plist = plist->Flink)
    {
        pelem = CONTAINING_RECORD(plist, struct _list_acceptconnection_, list_entry);
        if (pelem->pAcceptConnection != NULL) delete pelem->pAcceptConnection;

        count++;
    }

    for (i = 0; i < count; i++)
    {
        PLIST_ENTRY pList = RemoveHeadList(&m_AcceptConnectList);
        free(pList);
    }
}

//清空某一个元素
void BaseServer::DeleteElem_AcceptConnectionList(AcceptConnection *addr)
{
    PLIST_ENTRY plist;
    struct _list_acceptconnection_ *pelem = NULL;
    BOOL bFind = FALSE;
    for (plist = m_AcceptConnectList.Flink; plist != &m_AcceptConnectList; plist = plist->Flink)
    {
        pelem = CONTAINING_RECORD(plist, struct _list_acceptconnection_, list_entry);
        //
        if (pelem->pAcceptConnection == addr) {
            if (pelem->pAcceptConnection != NULL)
                delete pelem->pAcceptConnection;
            bFind = TRUE;
            break;
        }
    }

    if (bFind) {
        RemoveElement(plist);
        free(plist);
    }
}


//
/*
服务器状态控制, 返回当前状态值
*/
ULONG BaseServer::status(ULONG status_val, ULONG *dwRet)
{
    if (dwRet == NULL)
        return m_status;


    if (status_val&STATUS_GET) {
        return m_status;
    }
    else
        m_status = status_val;


    *dwRet= handle_status();

    return m_status;
}

/*
处理状态，返回当前状态值
*/
ULONG BaseServer::handle_status()
{//
    ULONG dwRet = BHSR_SUCCESS;

    //启动
    if (m_status&STATUS_RUN)
    {
        dwRet = init_httpserver();
        if(dwRet==BHSR_SUCCESS)
            dwRet=server_forever(TRUE);
    }

    //停止
    if (m_status&STATUS_STOP) {
        dwRet = stop();
    }

    
    INVOKE_CALLBACK(m_status)

    return dwRet;
}

//
int BaseServer::init_httpserver_ex()
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
    return BaseServer::BHSR_SUCCESS;
}


//反初始化扩展
void BaseServer::uninit_httpserver_ex()
{
    curl_global_cleanup();
}


/*测试计数，只在Debug下起作用*/
void BaseServer::counter(BOOL bDec)
{
#ifdef _DEBUG
    EnterCriticalSection(&m_lock_counter);
    if (bDec)
        m_counter--;
    else
        m_counter++;

    printf("the number of AcceptionConnection:%d\n", m_counter);

    LeaveCriticalSection(&m_lock_counter);
#endif
}