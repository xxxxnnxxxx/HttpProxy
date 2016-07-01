#pragma once

#include <Windows.h>


//BaseHTTPRequestHandler与服务器之间的通讯所用
typedef struct _ret_ {
    DWORD dwOpt;    //操作类型:继续接收数据，停止接收数据，中断，发送数据
}BaseDataHandler_RET;


class BaseDataHandler {
public:
    BaseDataHandler();
    virtual ~BaseDataHandler();
    enum {
        RET_FINISH = 1,
        RET_SEND = 2,
        RET_RECV = 3,
        RET_ERROR = 4,
        RET_UNKNOWN = 0xFFFFFFFF,
    };
public:
    virtual void handler_request(void *buf, DWORD len, BaseDataHandler_RET * ret)=0;
};