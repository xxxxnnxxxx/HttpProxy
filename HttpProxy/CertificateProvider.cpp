#include "CertificateProvider.h"
#include <openssl\x509.h>
#include <openssl\pem.h>
#include <openssl/crypto.h>
#include <openssl/x509v3.h>
#include <openssl/ossl_typ.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl\evp.h>
#include <stdio.h>


#undef POSTFIX
#define POSTFIX ".srl"
/*
证书操作，这个地方没有写CA签名的过程，只是简单生成了一个证书
*/


CertificateProvider::CertificateProvider()
{

}

CertificateProvider::~CertificateProvider()
{

}
int CertificateProvider::rand_serial(BIGNUM *b, ASN1_INTEGER *ai)
{
    BIGNUM *btmp;
    int ret = 0;

    if (b)
        btmp = b;
    else
        btmp = BN_new();

    if (btmp == NULL)
        return 0;

    if (!BN_pseudo_rand(btmp, 64, 0, 0))
        goto error;
    if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
        goto error;

    ret = 1;

error:

    if (btmp != b)
        BN_free(btmp);

    return ret;
}
////////////////////
X509 *CertificateProvider::load_cert(const char *file, int format)
{
    X509 *x = NULL;
    FILE *fp=NULL;
    errno_t err;

    err=fopen_s(&fp,file,"rb");
    if(err!=0||fp==NULL)
        return NULL;
    

    if (format == FORMAT_ASN1)
        x = d2i_X509_fp(fp,NULL);
    else if (format == FORMAT_PEM)
        x = PEM_read_X509(fp,NULL,NULL,NULL);
    
    fclose(fp);
    return (x);
}


////////////////////

/*
根据csr文件生成crt文件
*/
X509 * CertificateProvider::csr2crt(X509_REQ *x509_req, EVP_PKEY *pKey)
{
    if (x509_req == NULL || pKey == NULL)return NULL;

    return X509_REQ_to_X509(x509_req, 2000, pKey);
}

/*
生成密钥对
*/
EVP_PKEY * CertificateProvider::generate_keypair(int numofbits)
{
    EVP_PKEY * pkey = EVP_PKEY_new();
    if (!pkey)
    {
        printf("Unable to create EVP_PKEY structure.\n");
        return NULL;
    }

    RSA * rsa = RSA_generate_key(numofbits, RSA_F4, NULL, NULL);
    if (!EVP_PKEY_assign_RSA(pkey, rsa))
    {
        printf("Unable to generate 2048-bit RSA key.\n");
        EVP_PKEY_free(pkey);
        return NULL;
    }

    return pkey;
}

/*
生成证书
*/
X509* CertificateProvider::generate_certificate(EVP_PKEY * pkey, char * url,int len,BOOL bRoot)
{
    ASN1_INTEGER* aserial = NULL;
    X509 * x509 = X509_new();
    if (!x509)
    {
        printf("Unable to create X509 structure.\n");
        return NULL;
    }
    if(!bRoot)
    {
        if(::IsBadReadPtr(url,len))
            return NULL;

        if(*(url+len)!='\0')
            return NULL;
    }
    
    aserial = M_ASN1_INTEGER_new();
    rand_serial(NULL, aserial);
    X509_set_serialNumber(x509, aserial);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    X509_set_pubkey(x509, pkey);
    X509_NAME * name = X509_get_subject_name(x509);

    if(aserial!=NULL)
        ASN1_INTEGER_free(aserial);
    /*
    C   = country
    ST  = state
    L   = locality
    O   = organisation
    OU  = organisational unit
    CN  = common name
    */
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"CN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char*)"Beijing", -1, -1, 0);


    if(bRoot)
    {    
        X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char*)"xxxxnnxxxx", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"xxxxnnxxxx", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"xxxxnnxxxx", -1, -1, 0);
    }
    else
    {
        X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char*)url, -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)url, -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)url, -1, -1, 0);
    }
    X509_set_issuer_name(x509, name);
    
    

    
    if (!X509_sign(x509, pkey, EVP_sha256()))
    {
        X509_free(x509);
        return NULL;
    }

    return x509;
}

/*
添加证书到系统指定的位置
pos: "ROOT","MY","SPC","CA"
*/
int CertificateProvider::addCert2WindowsAuth(unsigned char *buf_x509_der, int len_x509_der, const char *pos)
{
    int ret = 0;
    int error = 0;
    HCERTSTORE hRootCertStore = CertOpenSystemStoreA(NULL, pos);
    if (hRootCertStore != NULL)
    {
        //读取证书内容
        if (CertAddEncodedCertificateToStore(hRootCertStore,
            X509_ASN_ENCODING,
            buf_x509_der, len_x509_der,
            CERT_STORE_ADD_USE_EXISTING, NULL))
        {
#ifdef _DEBUG
            printf("Successful\n");
#endif
            ret = 1;
        }
        else {
#ifdef _DEBUG
            error = GetLastError();
            printf("CertAddEncodeCerificateToStore->GetLastError():%d", error);
#endif
        }
        CertCloseStore(hRootCertStore, 0);
    }

    return ret;
}


/*

*/
int CertificateProvider::addCert2WindowsAuth(X509* x509, const char *pos)
{
    int len_x509 = 0;
    unsigned char * buf_x509 = NULL;
    int ret = 0;
    int error = 0;

    len_x509 = i2d_X509(x509, &buf_x509);
    if (len_x509 > 0) {
        HCERTSTORE hRootCertStore = CertOpenSystemStoreA(NULL, pos);
        if (hRootCertStore != NULL)
        {
            //读取证书内容
            if (CertAddEncodedCertificateToStore(hRootCertStore,
                X509_ASN_ENCODING,
                buf_x509, len_x509,
                CERT_STORE_ADD_USE_EXISTING, NULL))
            {
#ifdef _DEBUG
                printf("Successful\n");
#endif
                ret = 1;
            }
            else {
#ifdef _DEBUG
                error = GetLastError();
                printf("CertAddEncodeCerificateToStore->GetLastError():%d", error);
#endif
            }
            CertCloseStore(hRootCertStore, 0);
        }
    }

    return ret;
}

/*buf=NULL || len==0 返回需要的内存空间长度*/
int CertificateProvider::exportx509(X509* x509,unsigned char *buf,int len)
{
    int len_x509=0;
    unsigned char *buf_x509=NULL;

    //加密x509 to DER
    len_x509 = i2d_X509(x509, &buf_x509);
    if(len_x509<0)
        return 0;

    if(buf==NULL || len==0)
    {
        if(buf_x509!=NULL)
            OPENSSL_free(buf_x509);
        return len_x509;
    }

    if(::IsBadReadPtr(buf,len)){
        OPENSSL_free(buf_x509);
        return 0;
    }

    memcpy_s(buf,len,buf_x509,((len>len_x509)?len_x509:len));
    if(buf_x509!=NULL)
        OPENSSL_free(buf_x509);
    return len_x509;
}

int CertificateProvider::saveX509tofile(X509* x509,char *path)
{
    unsigned char * buf=NULL;
    HANDLE hFile=INVALID_HANDLE_VALUE;
    int ret=0;
    DWORD dwWrited=0;
    int len=exportx509(x509,NULL,0);
    if(len<=0)
        return 0;

    buf=(unsigned char*)malloc(len);
    memset(buf,0,len);

    len=exportx509(x509,buf,len);

    hFile=::CreateFileA(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(hFile!=INVALID_HANDLE_VALUE)
    {
        BOOL bRet=::WriteFile(hFile,buf,len,&dwWrited,NULL);
        if(bRet)
            ret=len;
        else
            ret=0;
    }

    if(hFile!=INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    if(buf!=NULL)
    {
        free(buf);
        buf=NULL;
    }

    return ret;
    
}


////private
int CertificateProvider::pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value)
{
    int rv;
    char *stmp, *vtmp = NULL;
    stmp = OPENSSL_strdup(value);
    if (!stmp)
        return -1;
    vtmp = strchr(stmp, ':');
    if (vtmp) {
        *vtmp = 0;
        vtmp++;
    }
    rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);
    OPENSSL_free(stmp);
    return rv;
}

int CertificateProvider::do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey, const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts)
{
    EVP_PKEY_CTX *pkctx = NULL;
    int i;

    if (ctx == NULL)
        return 0;
    if (!EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey))
        return 0;
    for (i = 0; i < sk_OPENSSL_STRING_num(sigopts); i++) {
        char *sigopt = sk_OPENSSL_STRING_value(sigopts, i);
        if (pkey_ctrl_string(pkctx, sigopt) <= 0) {
            return 0;
        }
    }
    return 1;
}
 int CertificateProvider::do_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md,STACK_OF(OPENSSL_STRING) *sigopts)
{
    int rv;
    EVP_MD_CTX *mctx = EVP_MD_CTX_create();

    rv = do_sign_init(mctx, pkey, md, sigopts);
    if (rv > 0)
        rv = X509_sign_ctx(x, mctx);
    EVP_MD_CTX_destroy(mctx);
    return rv > 0 ? 1 : 0;
}

int CertificateProvider::x509_certify(X509*x,X509*xca,EVP_PKEY*pkey_ca)
{
    int ret=0;
    ASN1_INTEGER *bs = NULL;
    X509_STORE_CTX xsc;
    EVP_PKEY *upkey;
    ASN1_INTEGER* aserial = NULL;

    X509_STORE *ctx = NULL;
    ctx = X509_STORE_new();

    if(ctx==NULL)
        return 0;

    upkey= X509_get_pubkey(xca);
    EVP_PKEY_copy_parameters(upkey, pkey_ca);

    if (!X509_STORE_CTX_init(&xsc, ctx, x, NULL)) {
        goto end;
    }

    X509_STORE_CTX_set_cert(&xsc, x);
    X509_STORE_CTX_set_flags(&xsc, X509_V_FLAG_CHECK_SS_SIGNATURE);
    if (!X509_check_private_key(xca, pkey_ca)) {
        goto end;
    }
    if (!X509_set_issuer_name(x, X509_get_subject_name(xca)))
        goto end;

    bs = M_ASN1_INTEGER_new();
    CertificateProvider::rand_serial(NULL, bs);
    if (!X509_set_serialNumber(x, bs))
        goto end;

    if (X509_gmtime_adj(X509_get_notBefore(x), 0L) == NULL)
        goto end;

    if (X509_time_adj_ex(X509_get_notAfter(x), 30, 0, NULL) == NULL)
        goto end;

    if (!do_X509_sign(x, pkey_ca, EVP_sha1(), NULL))
        goto end;
    ret = 1;

 end:
    X509_STORE_CTX_cleanup(&xsc);

    if(ctx!=NULL)
        X509_STORE_free(ctx);
    if(bs!=NULL)
        ASN1_INTEGER_free(bs);
    if(aserial!=NULL)
        ASN1_INTEGER_free(aserial);

    return ret;
}