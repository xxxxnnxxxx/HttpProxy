#ifndef _BASEHTTPREQUESTHANDLER_H_
#define _BASEHTTPREQUESTHANDLER_H_

#include "header.h"
#include "httpheaders.h"
#include "httpcontent.h"
#include "httprequest.h"
#include "httpsession.h"    
#include "BaseSocketStream.h"
#include "BaseDataHandler.h"

class BaseHTTPRequestHandler:public BaseDataHandler {
public:
    BaseHTTPRequestHandler(HTTPSERVICE_PARAMS *pHttpService_Params, HttpSession * pHttpSession);
    ~BaseHTTPRequestHandler();
public:
    virtual void do_OPTIONS();
    virtual void do_GET();
    virtual void do_HEAD();
    virtual void do_POST();
    virtual void do_PUT();
    virtual void do_DELETE();
    virtual void do_TRACE();
    virtual void do_CONNECT();
private:
    //
    virtual void connect_intercept();   //中断后处理
    virtual void connect_relay();       //直接转发
public:
    virtual void handler_request(void *buf, DWORD len, BaseDataHandler_RET * ret);
private:
    size_t find_httpheader(const char* buf, size_t bufsize);
private:
    void invokeMethod(const char *methdo);
    void invokeRequestCallback(HttpHeaders *http_headers);
    void invokeResponseCallback(char *buf,size_t len);
    void reset();   //重置，在不完全的接收到所有数据，都需要重置

private:
    //特定功能函数
    void headerfilterforAgent(HttpHeaders*pHttpHeaders);  //根据代理服务器的需要过滤指定的头

private:
    HttpHeaders             http_items;
    HttpContent             httpcontent;
    HttpRequest             httprequest;
    HTTPSERVICE_PARAMS*     m_pHttpService_Params;
    BaseSocketStream *      m_pBaseSockeStream;
    WORD                    m_port;        //保存端口号
    char                    m_uri[1024];   //保存主机地址
public:
    char *                  m_precv_buf;      //接受数据的缓冲区，要分析的
    DWORD                   m_len_recvbuf;    //处理后得到的缓冲区长度
    HttpSession *           m_pHttpSession;
};

#endif
