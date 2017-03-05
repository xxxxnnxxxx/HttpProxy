// httpcore.cpp : Defines the exported functions for the DLL application.
//
#include "BaseServer.h"
#include "BaseSSLConfig.h"
#include "CertificateProvider.h"
#include "httpcore.h"




BaseSSLConfig *g_BaseSSLConfig = NULL;  //全局唯一

#define ProxyHttpService BaseServer
#define PHS_HANDLE2PROXYHTTPSERVER(handle) reinterpret_cast<ProxyHttpService*>(handle)
#define HJH_HANLDE2BaseSSLConfig(handle) reinterpret_cast<BaseSSLConfig*>(handle)


PHS_HANDLE __stdcall Create_ProxyHttpService(HTTPSERVICE_PARAMS *pHttpService_params) {
    ProxyHttpService* pProxyHttpService= new ProxyHttpService(pHttpService_params);
    
    if (pProxyHttpService != NULL) {
        return pProxyHttpService;
    }
    return NULL;
}
//启动服务
BOOL __stdcall Start_ProxyHttpService(PHS_HANDLE handle) {
    ULONG dwRet = ProxyHttpService::BHSR_SUCCESS;

    if (handle == NULL)
        return FALSE;

    ProxyHttpService *pProxyHttpService = PHS_HANDLE2PROXYHTTPSERVER(handle);
    pProxyHttpService->status(ProxyHttpService::STATUS_RUN,&dwRet);

    if (dwRet != ProxyHttpService::BHSR_SUCCESS)
        return FALSE;
    return TRUE;
}
//停止服务
BOOL __stdcall Stop_ProxyHttpService(PHS_HANDLE handle) {
    ULONG dwRet = ProxyHttpService::BHSR_SUCCESS;

    if (handle == NULL)
        return FALSE;


    ProxyHttpService *pProxyHttpService = PHS_HANDLE2PROXYHTTPSERVER(handle);
    pProxyHttpService->status(ProxyHttpService::STATUS_STOP|ProxyHttpService::STATUS_CONTINUE, &dwRet);

    if (dwRet != ProxyHttpService::BHSR_SUCCESS)
        return FALSE;

    return TRUE;
}
//设置Https劫持
SCG_HANDLE __stdcall Hijack_Https(PHS_HANDLE handle) {

    BOOL bRet = FALSE;

    /*判断是否已经初始化服务器*/
    if (handle == NULL)
        return NULL;


    g_BaseSSLConfig = BaseSSLConfig::CreateInstance();
    if (g_BaseSSLConfig != NULL) {
        g_BaseSSLConfig->init_ssl();
    }
    return (SCG_HANDLE)g_BaseSSLConfig;
}
//反劫持
BOOL __stdcall Dishijack_Https(SCG_HANDLE handle) {

    BOOL bRet = FALSE;
    if (handle == NULL)
        return FALSE;

    BaseSSLConfig* pBaseSSLConfig = HJH_HANLDE2BaseSSLConfig(handle);

    pBaseSSLConfig->uninit_ssl();
    return TRUE;
}
//添加到系统信任根证书
BOOL __stdcall TrustRootCert(SCG_HANDLE handle) {
    if (handle == NULL)
        return FALSE;

    BaseSSLConfig* pBaseSSLConfig = HJH_HANLDE2BaseSSLConfig(handle);

    return pBaseSSLConfig->TrustRootCert();
}
//重置系统证书和添加到系统中的个人证书
BOOL __stdcall ResetCert(SCG_HANDLE handle) {
    if (handle == NULL)
        return FALSE;

    BaseSSLConfig* pBaseSSLConfig = HJH_HANLDE2BaseSSLConfig(handle);
    return TRUE;
}
//导出根证书
BOOL __stdcall ExportRootCert(SCG_HANDLE handle,unsigned char *buf, int *len) {
    if (handle == NULL)
        return FALSE;

    BaseSSLConfig* pBaseSSLConfig = HJH_HANLDE2BaseSSLConfig(handle);
    return pBaseSSLConfig->ExportRootCert(buf,len);
}

#ifdef _DEBUG
int __stdcall Unittest() {

    int ret=0;

#if 0
    EVP_PKEY*pKey=CertificateProvider::generate_keypair(2048);
    X509* x509_root=CertificateProvider::generate_certificate(pKey,"xxxxnnxxxx");
    PKCS12*pkcs12=CertificateProvider::x509topkcs12(x509_root,pKey,"123456","xxxxnnxxxx",NULL);
    CertificateProvider::addCert2WindowsAuth(pkcs12,"ROOT",L"123456");
    
    PKCS12*pkcs12_tmp=CertificateProvider::get_pkcs12fromWindowsAuth(L"123456","xxxxnnxxxx","ROOT","xxxxnnxxxx");
    if(pkcs12_tmp!=NULL)
    {
        
    }

    //
    EVP_PKEY *pkey_tmp=NULL;
    X509*x509_tmp=NULL;
    X509*CA=NULL;

    CertificateProvider::pkcs12_getx509(pkcs12_tmp,"123456",6,&x509_tmp,&pkey_tmp,&CA);

   

    if(x509_root!=NULL)
    {
        unsigned char buf[1024*5]={0};
        int len=CertificateProvider::exportx509(x509_root,buf,1024*5);

        HANDLE hFile=::CreateFileA("d:\\root.crt",GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if(hFile!=NULL)
        {
            DWORD dwWrited=0;
            if(::WriteFile(hFile,buf,len,&dwWrited,NULL))
            {

            }

            ::CloseHandle(hFile);
        }
    }

    EVP_PKEY*pKey_server=CertificateProvider::generate_keypair(2048);
    X509* x509_server=CertificateProvider::generate_certificate(pKey_server,"*.baidu.com");



    if(CertificateProvider::x509_certify(x509_server,x509_root,pKey))
    {
        unsigned char buf[1024*5]={0};
        int len=CertificateProvider::exportx509(x509_server,buf,1024*5);

        HANDLE hFile=::CreateFileA("d:\\ss.crt",GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if(hFile!=NULL)
        {
            DWORD dwWrited=0;
            if(::WriteFile(hFile,buf,len,&dwWrited,NULL))
            {
            
            }

            ::CloseHandle(hFile);
        }
    }
    else
    {
        MessageBoxA(NULL,"faild","msg",MB_OK);
    }
#endif

    //生成根证书和私钥文件
#if 0
    EVP_PKEY *pKey = CertificateProvider::generate_keypair(2048);
    if (pKey == NULL)
        return -1;

    X509 *x509 = CertificateProvider::generate_certificate(pKey, "xxxxnnxxxx");
    if (x509 == NULL)/*这个地方还是存在问题，应当在为空的情况下释放m_rootkeypair*/
    {
        EVP_PKEY_free(pKey);
        pKey=NULL;
        return -1;
    }
    
    //保存密钥和证书到文件
    
    CertificateProvider::savePriKeytofile(pKey,"D:\\PriKey.pem");
    CertificateProvider::saveX509tofile(x509,"D:\\RootCert.pem");

    OPENSSL_free(x509);
    OPENSSL_free(pKey);
    

#endif
    return ret;
}
#endif