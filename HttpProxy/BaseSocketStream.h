#ifndef _BASESOCKET_H_
#define _BASESOCKET_H_

#include <windows.h>
#include "header.h"

class  BaseSocketStream
{
public:
    BaseSocketStream(char**pprecv_buf,DWORD *len_recv_buf,char**ppsend_buf,DWORD *len_send_buf);
    ~BaseSocketStream();

    enum {
        BSS_RET_ERROR=-1,
        BSS_RET_RESULT=1,
        BSS_RET_SEND,
        BSS_RET_RECV,
        BSS_RET_UNKNOWN,
    };
public:
    virtual int write(void *buf,DWORD len);    //写入数据
    virtual int read(void *buf,DWORD len);     //读取数据
    virtual char * _classname(char *buf, DWORD len);
public:
    int m_socket;

    DWORD *m_plen_recv_buf;
    DWORD *m_plen_send_buf;

    char * *m_pprecv_buf;
    char * *m_ppsend_buf;
};

#endif