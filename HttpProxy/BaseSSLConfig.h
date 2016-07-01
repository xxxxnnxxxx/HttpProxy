#pragma once


#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#ifdef __cplusplus
extern "C" {
#endif
#include <openssl\ssl.h>
#include <openssl\err.h>
#ifdef __cplusplus
}
#endif

typedef struct _CERT_LIST_ {
    LIST_ENTRY list;
    EVP_PKEY *key;
    X509* cert;
}CERT_LIST,*PCERT_LIST;

class BaseSSLConfig/*final*/ {

protected:
    BaseSSLConfig();
public:
    ~BaseSSLConfig();
    enum {
        NUMOfKEYBITS=2048,
    };

    enum {
        STATUS_UNINIT   =0x00000000,
        STATUS_INITFINAL=0x00000001,
        STATUS_UNKNOWN  =0xFFFFFFFF,
    };
public:
    static BaseSSLConfig* CreateInstance();
public:
    BOOL        init_ssl();
    void        uninit_ssl();
    SSL_CTX *   context();
    ULONG       status() const { return m_status; }  //状态表所有的都是成功或完成
    BOOL        TrustRootCert();
    BOOL        ExportRootCert(unsigned char *buf,int *len);    //导出根证书
private:
    BOOL CreateRootCert(); //生成根证书
private:
    ULONG   m_status;
    SSL_CTX *m_ctx;
    X509 *m_rootcert;   //根证书
    EVP_PKEY *m_rootkeypair;    //根密钥对
    static BaseSSLConfig* instance;
    //
    LIST_ENTRY m_HeaderofCertList;  //证书链表头
};