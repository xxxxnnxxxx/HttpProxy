#pragma once

/*
证书提供者，主要用于生成所需要的根证书和对请求的网站每次签发证书
*/
#include <windows.h>
#include <openssl/x509.h>
class CertificateProvider
{
public:
    CertificateProvider();
    ~CertificateProvider();

public:
    static int          write_to_disk(EVP_PKEY * pkey, X509 * x509);
    static X509*        csr2crt(X509_REQ *x509_req, EVP_PKEY *pKey);
    static X509*        CreateCertificate(EVP_PKEY * pkey, BOOL bRoot);
    static EVP_PKEY *   Generate_KeyPair(int numofbits);  //生成密钥对
    static int          addCert2WindowsAuth(unsigned char *buf_x509_der, int len_x509_der, const char *pos);
    static int          addCert2WindowsAuth(X509* x509, const char *pos);
    static int          rand_serial(BIGNUM *b, ASN1_INTEGER *ai);
    static int          exportx509(X509* x509,unsigned char *buf,int len);
    static int          generate_server_crt(X509_REQ *x509,EVP_PKEY* pKey,char *url); //给网站签名的url
private:
    int                 x509_certify(X509_STORE *ctx, char *CAfile, const EVP_MD *digest,
                                    X509 *x, X509 *xca, EVP_PKEY *pkey,
                                    STACK_OF(OPENSSL_STRING) *sigopts, char *serial,
                                    int create, int days, int clrext, CONF *conf,
                                    char *section, ASN1_INTEGER *sno, int reqfile);
    ASN1_INTEGER *      x509_load_serial(char *CAfile, char *serialfile, int create);
    BIGNUM *            load_serial(char *serialfile, int create, ASN1_INTEGER **retai);
    int                 do_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md,STACK_OF(OPENSSL_STRING) *sigopts);
};