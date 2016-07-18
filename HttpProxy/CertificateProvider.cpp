#include "CertificateProvider.h"
#include <openssl\x509.h>
#include <openssl\pem.h>
#include <openssl/crypto.h>
#include <openssl/x509v3.h>
#include <openssl/ossl_typ.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl\evp.h>


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
EVP_PKEY * CertificateProvider::Generate_KeyPair(int numofbits)
{
    EVP_PKEY * pkey = EVP_PKEY_new();
    if (!pkey)
    {
        printf("Unable to create EVP_PKEY structure.\n");
        return NULL;
    }

    RSA * rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
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
X509* CertificateProvider::CreateCertificate(EVP_PKEY * pkey, BOOL bRoot)
{
    X509 * x509 = X509_new();
    if (!x509)
    {
        printf("Unable to create X509 structure.\n");
        return NULL;
    }

    ASN1_INTEGER* aserial = NULL;
    aserial = M_ASN1_INTEGER_new();
    rand_serial(NULL, aserial);
    X509_set_serialNumber(x509, aserial);

    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    X509_set_pubkey(x509, pkey);

    X509_NAME * name = X509_get_subject_name(x509);

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
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char*)"xxxxnnxxxx", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"xxxxnnxxxx", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"xxxxnnxxxx", -1, -1, 0);

    X509_set_issuer_name(x509, name);

    
    if (!X509_sign(x509, pkey, EVP_sha1()))
    {
        printf("Error signing certificate.\n");
        X509_free(x509);
        return NULL;
    }

    return x509;
}


int CertificateProvider::generate_server_crt(X509_REQ *x509,EVP_PKEY* pKey,char *url)
{
    int ret=0;
    


    return ret;
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
    hRootCertStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        NULL,
        CERT_SYSTEM_STORE_LOCAL_MACHINE,
        pos);
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
        hRootCertStore = CertOpenStore(
            CERT_STORE_PROV_SYSTEM,
            0,
            NULL,
            CERT_SYSTEM_STORE_LOCAL_MACHINE,
            pos);
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

int CertificateProvider::exportx509(X509* x509,unsigned char *buf,int len)
{
    int len_x509=0;
    unsigned char *buf_x509=NULL;
    if(buf==NULL)
        return 0;
    //加密x509 to DER
    len_x509 = i2d_X509(x509, &buf_x509);
    if(len_x509<0)
        return 0;

    if(::IsBadReadPtr(buf,len)){
        OPENSSL_free(buf_x509);
        return 0;
    }

    memcpy_s(buf,len,buf_x509,((len>len_x509)?len_x509:len));
    
    return len_x509;
}


////private
BIGNUM *CertificateProvider::load_serial(char *serialfile, int create, ASN1_INTEGER **retai)
{
    BIO *in = NULL;
    BIGNUM *ret = NULL;
    char buf[1024];
    ASN1_INTEGER *ai = NULL;

    ai = ASN1_INTEGER_new();
    if (ai == NULL)
        goto err;

    in = BIO_new_file(serialfile, "r");
    if (in == NULL) {
        if (!create) {
            perror(serialfile);
            goto err;
        }
        ERR_clear_error();
        ret = BN_new();
        if (ret == NULL || !rand_serial(ret, ai)){}
            //BIO_printf(bio_err, "Out of memory\n");
    } else {
        if (!a2i_ASN1_INTEGER(in, ai, buf, 1024)) {
            /*BIO_printf(bio_err, "unable to load number from %s\n",
                serialfile);*/
            goto err;
        }
        ret = ASN1_INTEGER_to_BN(ai, NULL);
        if (ret == NULL) {
            /*BIO_printf(bio_err,
                "error converting number from bin to BIGNUM\n");*/
            goto err;
        }
    }

    if (ret && retai) {
        *retai = ai;
        ai = NULL;
    }
err:
    BIO_free(in);
    ASN1_INTEGER_free(ai);
    return (ret);
}

#undef BSIZE
#define BSIZE 256
int save_serial(char *serialfile, char *suffix, BIGNUM *serial,
                ASN1_INTEGER **retai)
{
    char buf[1][BSIZE];
    BIO *out = NULL;
    int ret = 0;
    ASN1_INTEGER *ai = NULL;
    int j;

    if (suffix == NULL)
        j = strlen(serialfile);
    else
        j = strlen(serialfile) + strlen(suffix) + 1;
    if (j >= BSIZE) {
        //BIO_printf(bio_err, "file name too long\n");
        goto err;
    }

    if (suffix == NULL)
        BUF_strlcpy(buf[0], serialfile, BSIZE);
    else {
#ifndef OPENSSL_SYS_VMS
        j = BIO_snprintf(buf[0], sizeof buf[0], "%s.%s", serialfile, suffix);
#else
        j = BIO_snprintf(buf[0], sizeof buf[0], "%s-%s", serialfile, suffix);
#endif
    }
    out = BIO_new_file(buf[0], "w");
    if (out == NULL) {
        //ERR_print_errors(bio_err);
        goto err;
    }

    if ((ai = BN_to_ASN1_INTEGER(serial, NULL)) == NULL) {
//        BIO_printf(bio_err, "error converting serial to ASN.1 format\n");
        goto err;
    }
    i2a_ASN1_INTEGER(out, ai);
    BIO_puts(out, "\n");
    ret = 1;
    if (retai) {
        *retai = ai;
        ai = NULL;
    }
err:
    BIO_free_all(out);
    ASN1_INTEGER_free(ai);
    return (ret);
}

int rotate_serial(char *serialfile, char *new_suffix, char *old_suffix)
{
    char buf[5][BSIZE];
    int i, j;

    i = strlen(serialfile) + strlen(old_suffix);
    j = strlen(serialfile) + strlen(new_suffix);
    if (i > j)
        j = i;
    if (j + 1 >= BSIZE) {
        //BIO_printf(bio_err, "file name too long\n");
        goto err;
    }
#ifndef OPENSSL_SYS_VMS
    j = BIO_snprintf(buf[0], sizeof buf[0], "%s.%s", serialfile, new_suffix);
    j = BIO_snprintf(buf[1], sizeof buf[1], "%s.%s", serialfile, old_suffix);
#else
    j = BIO_snprintf(buf[0], sizeof buf[0], "%s-%s", serialfile, new_suffix);
    j = BIO_snprintf(buf[1], sizeof buf[1], "%s-%s", serialfile, old_suffix);
#endif
    if (rename(serialfile, buf[1]) < 0 && errno != ENOENT
#ifdef ENOTDIR
        && errno != ENOTDIR
#endif
        ) {
////            BIO_printf(bio_err,
//                "unable to rename %s to %s\n", serialfile, buf[1]);
            perror("reason");
            goto err;
    }
    if (rename(buf[0], serialfile) < 0) {
        //BIO_printf(bio_err,
        //    "unable to rename %s to %s\n", buf[0], serialfile);
        perror("reason");
        rename(buf[1], serialfile);
        goto err;
    }
    return 1;
err:
    return 0;
}

ASN1_INTEGER *CertificateProvider::x509_load_serial(char *CAfile, char *serialfile,int create)
{
    char *buf = NULL, *p;
    ASN1_INTEGER *bs = NULL;
    BIGNUM *serial = NULL;
    size_t len;

    len = ((serialfile == NULL)
        ? (strlen(CAfile) + strlen(POSTFIX) + 1)
        : (strlen(serialfile))) + 1;
    buf = (char*)OPENSSL_malloc(len);
    if (serialfile == NULL) {
        BUF_strlcpy(buf, CAfile, len);
        for (p = buf; *p; p++)
            if (*p == '.') {
                *p = '\0';
                break;
            }
            BUF_strlcat(buf, POSTFIX, len);
    } else
        BUF_strlcpy(buf, serialfile, len);

    serial = load_serial(buf, create, NULL);
    if (serial == NULL)
        goto end;

    if (!BN_add_word(serial, 1)) {
//        BIO_printf(bio_err, "add_word failure\n");
        goto end;
    }

    if (!save_serial(buf, NULL, serial, &bs))
        goto end;

end:
    OPENSSL_free(buf);
    BN_free(serial);
    return bs;
}
int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value)
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

 int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey,
                        const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts)
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
int CertificateProvider::x509_certify(X509_STORE *ctx, char *CAfile, const EVP_MD *digest,
                        X509 *x, X509 *xca, EVP_PKEY *pkey,
                        STACK_OF(OPENSSL_STRING) *sigopts,
                        char *serialfile, int create,
                        int days, int clrext, CONF *conf, char *section,
                        ASN1_INTEGER *sno, int reqfile)
{
    int ret = 0;
    ASN1_INTEGER *bs = NULL;
    X509_STORE_CTX xsc;
    EVP_PKEY *upkey;

    //upkey = X509_get0_pubkey(xca);
    upkey= X509_get_pubkey(xca);
    EVP_PKEY_copy_parameters(upkey, pkey);

    if (!X509_STORE_CTX_init(&xsc, ctx, x, NULL)) {
    //    BIO_printf(bio_err, "Error initialising X509 store\n");
        goto end;
    }
    if (sno)
        bs = sno;
    else if ((bs = x509_load_serial(CAfile, serialfile, create)) == NULL)
        goto end;

    /*
     * NOTE: this certificate can/should be self signed, unless it was a
     * certificate request in which case it is not.
     */
    X509_STORE_CTX_set_cert(&xsc, x);
    X509_STORE_CTX_set_flags(&xsc, X509_V_FLAG_CHECK_SS_SIGNATURE);
    if (!reqfile && X509_verify_cert(&xsc) <= 0)
        goto end;

    if (!X509_check_private_key(xca, pkey)) {
        //BIO_printf(bio_err,"CA certificate and CA private key do not match\n");
        goto end;
    }

    if (!X509_set_issuer_name(x, X509_get_subject_name(xca)))
        goto end;
    if (!X509_set_serialNumber(x, bs))
        goto end;

    if (X509_gmtime_adj(X509_get_notBefore(x), 0L) == NULL)
        goto end;

    /* hardwired expired */
    if (X509_time_adj_ex(X509_get_notAfter(x), days, 0, NULL) == NULL)
        goto end;

    if (clrext) {
        while (X509_get_ext_count(x) > 0)
            X509_delete_ext(x, 0);
    }

    if (conf) {
        X509V3_CTX ctx2;
        X509_set_version(x, 2); /* version 3 certificate */
        X509V3_set_ctx(&ctx2, xca, x, NULL, NULL, 0);
        X509V3_set_nconf(&ctx2, conf);
        if (!X509V3_EXT_add_nconf(conf, &ctx2, section, x))
            goto end;
    }

    if (!do_X509_sign(x, pkey, digest, sigopts))
        goto end;
    ret = 1;
 end:
    X509_STORE_CTX_cleanup(&xsc);
   /* if (!ret)
        ERR_print_errors(bio_err);*/
    if (!sno)
        ASN1_INTEGER_free(bs);
    return ret;
}
