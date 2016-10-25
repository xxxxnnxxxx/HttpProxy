
#include "CertificateProvider.h"
#include "BaseSSLConfig.h"
#include "RootCert_PriKey/PriKey.h"
#include "RootCert_PriKey/RootCert.h"
#include "RootCert_PriKey/RootCertConfig.h"

//初始化SSL
typedef CRITICAL_SECTION	ssl_lock;
struct CRYPTO_dynlock_value {
    ssl_lock lock;
};
int number_of_locks = 0;
ssl_lock *ssl_locks = NULL;


void ssl_lock_callback(int mode, int n, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
        EnterCriticalSection(&ssl_locks[n]);
    else
        LeaveCriticalSection(&ssl_locks[n]);
}

CRYPTO_dynlock_value* ssl_lock_dyn_create_callback(const char *file, int line)
{
    CRYPTO_dynlock_value *l = (CRYPTO_dynlock_value*)malloc(sizeof(CRYPTO_dynlock_value));
    InitializeCriticalSection(&l->lock);
    return l;
}

void ssl_lock_dyn_callback(int mode, CRYPTO_dynlock_value* l, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
        EnterCriticalSection(&l->lock);
    else
        LeaveCriticalSection(&l->lock);
}

void ssl_lock_dyn_destroy_callback(CRYPTO_dynlock_value* l, const char *file, int line)
{
    DeleteCriticalSection(&l->lock);
    free(l);
}


BaseSSLConfig* BaseSSLConfig::instance = NULL;  /*初始化为NULL*/

BaseSSLConfig::BaseSSLConfig()
{
    m_rootcert = NULL;
    m_rootkeypair = NULL;
    m_status = STATUS_UNINIT;
}

BaseSSLConfig::~BaseSSLConfig()
{

}


BaseSSLConfig* BaseSSLConfig::CreateInstance()
{
    if (instance == NULL) {
        instance = new BaseSSLConfig();
    }

    return instance;
}

BOOL BaseSSLConfig::InitRootCert()
{
    void* ret = NULL;
    PKCS12*pkcs12 = NULL;
    X509* CA = NULL;

    //导入证书文件
    ret = CertificateProvider::importx509(&m_rootcert, ___Cert_PriKey_RootCert_pem, ___Cert_PriKey_RootCert_pem_len);
    if( ret == NULL ){
        return FALSE;
    }


    ret = CertificateProvider::importPriKey(&m_rootkeypair, ___Cert_PriKey_PriKey_pem, ___Cert_PriKey_PriKey_pem_len);
    if( ret == NULL ){
        OPENSSL_free(m_rootcert);
        m_rootcert = NULL;
        m_rootkeypair = NULL;
        return FALSE;
    }

    return TRUE;
}

BOOL BaseSSLConfig::TrustRootCert()
{
    PKCS12 *pkcs12;
    int ret = 0;

    if (m_status == BaseSSLConfig::STATUS_INITFINAL) {

        //判断是否存在证书
        ret = CertificateProvider::is_certexist(m_rootcert, "ROOT", PASSWORD);

        if(ret){

        }
        else{
            pkcs12 = CertificateProvider::x509topkcs12(m_rootcert, m_rootkeypair, PASSWORD, NULL, NULL);
            if(pkcs12 == NULL){
                return FALSE;
            }
            return CertificateProvider::addCert2WindowsAuth_ROOT(m_rootcert);
        }
       
    }
    return FALSE;
}

BOOL BaseSSLConfig::init_ssl()
{
    BOOL bRet = FALSE;
    do {

        number_of_locks = CRYPTO_num_locks();

        if (number_of_locks > 0) {
            ssl_locks = (ssl_lock*)malloc(number_of_locks * sizeof(ssl_lock));
            for (int n = 0; n < number_of_locks; ++n)
                InitializeCriticalSection(&ssl_locks[n]);
        }

        CRYPTO_set_locking_callback(&ssl_lock_callback);
        CRYPTO_set_dynlock_create_callback(&ssl_lock_dyn_create_callback);
        CRYPTO_set_dynlock_lock_callback(&ssl_lock_dyn_callback);
        CRYPTO_set_dynlock_destroy_callback(&ssl_lock_dyn_destroy_callback);
        //init
        SSL_load_error_strings();
        SSL_library_init();

        bRet=InitRootCert();
    } while (0);

    if (bRet) {
        m_status = STATUS_INITFINAL;
    }
    return bRet;
}

void BaseSSLConfig::uninit_ssl()
{

    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_dynlock_create_callback(NULL);
    CRYPTO_set_dynlock_lock_callback(NULL);
    CRYPTO_set_dynlock_destroy_callback(NULL);

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_state(0);
    ERR_free_strings();

    if (NULL != ssl_locks) {
        for (int n = 0; n < number_of_locks; ++n)
            DeleteCriticalSection(&ssl_locks[n]);

        free(ssl_locks);
        ssl_locks = NULL;
        number_of_locks = 0;
    }

    if(m_rootcert != NULL)
    {
        X509_free(m_rootcert);
        m_rootcert=NULL;
    }

    if(m_rootkeypair != NULL)
    {
        EVP_PKEY_free(m_rootkeypair);
        m_rootkeypair=NULL;
    }

    m_status = STATUS_UNINIT;
}

BOOL BaseSSLConfig::ExportRootCert(unsigned char *buf, int *len)
{
    BOOL bRet=FALSE;
    int ret=0;

    if(len == NULL || buf == NULL) 
        return FALSE;

    ret=CertificateProvider::exportx509(m_rootcert, buf, *len);

    if(ret>0)
        *len=ret;

    return (BOOL)ret;
}

/*签名*/
int BaseSSLConfig::CA(X509*x509)
{
    int ret = 0;

    ret = CertificateProvider::x509_certify(x509, m_rootcert, m_rootkeypair);

    return ret;
}