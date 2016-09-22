#ifndef _HEADER_H_
#define _HEADER_H_


/*#ifdef HTTPCORE_EXPORTS
#   define HTTPCORE_API __declspec(dllexport)
#   define EXPIMP_TEMPLATE
#else
#   define HTTPCORE_API __declspec(dllimport)
#   define EXPIMP_TEMPLATE extern
#endif*/

#ifdef _DLL_EXPORT
#   define HTTPCORE_API __declspec(dllexport)
#elif _DLL_IMPORT
#   define HTTPCORE_API __declspec(dllimport)
#elif _STATIC
#   define HTTPCORE_API
#endif


//custom http tag
#define CHT_HTTPREQUESTURI  "HttpRequestUri"


//CALLBACK_DATA_TYPE
#define CDT_REQUEST 0x00000001
#define CDT_RESPONSE 0x00000002


typedef struct _CALLBACK_DATA_ {
    ULONG   cdt; //回调类型(空缺)
    char *  buf;
    DWORD   len;
}CALLBACK_DATA,*PCALLBACK_DATA;

#define SCT_NORMAL      0x00000000  //不执行任何操作
#define SCT_PAUSE       0x00000001  //暂停服务
#define SCT_CONTINUE    0x00000002  //继续

typedef struct _SERVICE_CONTROL_ {
    ULONG ct;   //控制类型
    char *buf;  //附加数据
    DWORD len;  //数据长度
}SERVICE_CONTROL,*PSERVICE_CONTROL;

//服务状态控制
#define SERVER_STATUS_RUN       0x00000001
#define SERVER_STATUS_PAUSE     0x00000002
#define SERVER_STATUS_CONTINUE  0x00000004
#define SERVER_STATUS_STOP      0x00000008


//回调函数的过程不应过于耗时，耗时太长，容易造成网络连接失败，返回错误的信息
// *注意* 回调传入的数据不需要用户释放
typedef void( __stdcall *_Request_Callback_)(PCALLBACK_DATA);                 //接收到完整的请求头后调用
typedef void( __stdcall *_Response_Callback_)(PCALLBACK_DATA);                //接收到服务请的响应后，执行调用

//状态回调
typedef void(__stdcall *_ServerStatus_Callback_)(/*OUT*/ULONG status);        //处理完服务状态后返回

//服务控制回调(开始) 返回给服务器服务控制字
//返回的服务控制字所分配的内存，由结束回调函数释放
typedef PSERVICE_CONTROL (__stdcall *_ServiceControl_Callback_Begin_)();  
//服务控制回调(结束) 
//其中pservice_control就是服务控制回调(开始)中返回的PSERVICE_CONTROL结构地址
typedef void(__stdcall * _ServiceControl_Callback_End_)(PSERVICE_CONTROL pservice_control);



typedef struct _HTTPSERVICE_PARAMS_ {
    //服务器属性
    char ip[16];
    WORD port;
    BOOL bSSH;
    DWORD numofworkthread;  //服务器工作线程数，默认为处理器核心数量
    _Request_Callback_  request_callback;
    _Response_Callback_ response_callback;
    _ServerStatus_Callback_ serverstatus_callback; //暂时没有使用
}HTTPSERVICE_PARAMS, *PHTTPSERVICE_PARAMS;


#endif
