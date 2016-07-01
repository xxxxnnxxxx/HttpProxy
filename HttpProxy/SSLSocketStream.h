#ifndef _SSLSOCKET_H_
#define _SSLSOCKET_H_

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <openssl\ssl.h>
#include <openssl\err.h>
#include <openssl\bio.h>
#ifdef __cplusplus
}
#endif

#include "header.h"
#include "BaseSocketStream.h"

class  SSLSocketStream:public BaseSocketStream
{
public:
    SSLSocketStream(char**pprecv_buf, DWORD *len_recv_buf, char**ppsend_buf, DWORD *len_send_buf);
    ~SSLSocketStream();

private:
    void            init();
    void            uninit();  //∑¥≥ı ºªØ
    char *          get_OpenSSL_Error();
public:
    virtual int     write(void *buf,DWORD len);
    virtual int     read(void *buf,DWORD Len);
    virtual char *  _classname(char *buf, DWORD len);
private:
    char m_szErrorMsg[1024];
    BIO *m_send_bio;
    BIO *m_recv_bio;
    SSL * m_ssl;
};

#endif
