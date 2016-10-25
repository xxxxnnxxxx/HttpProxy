#include <Windows.h>
#include <stdio.h>
#include "..\HttpProxy\CertificateProvider.h"
#include "getopt.h"

#define INI_NAME        "conf.ini"
#define RootCert_NAME   "RootCert.pem"
#define PriKey_NAME     "PriKey.pem"
#define RCConf_NAME     "RootCertConfig.h"  //生成配置文件



//cmdline paramters
#define PARAM_OUTPUTDIR 0x00000001
#define PARAM_ISSUSER   0x00000002
#define PARAM_PWD       0x00000004


#define RCConf_Content(x,y)\
    "#ifndef _ROOTCERTCONFIG_H_\r\n" \
    "#define _ROOTCERTCONFIG_H_\r\n" \
    "#define ISSUSER \""## x ##  "\"\r\n" \
    "#define PASSWORD \"" ## y ## "\"\r\n" \
    "#endif"

typedef struct _RC_CONF_
{
    char szO[200];
    char szOU[200];
    char szCN[200];
    int  valdays;
    char szCurrentDir[MAX_PATH];
}RC_CONF,*PRC_CONF;

void ImportConfInfo(PRC_CONF pconf)
{
    char szConfPath[MAX_PATH] = {0};

    GetCurrentDirectoryA(MAX_PATH,pconf->szCurrentDir);
    strcat_s(pconf->szCurrentDir,MAX_PATH,"\\");
    strcpy_s(szConfPath,MAX_PATH,pconf->szCurrentDir);
    strcat_s(szConfPath,MAX_PATH,INI_NAME);
    
    //obtain issuser
    GetPrivateProfileStringA("ROOTCERT", "organisation", "xxxxnnxxxx", pconf->szO,sizeof(pconf->szO),szConfPath);
    GetPrivateProfileStringA("ROOTCERT", "organisational_unit", "xxxxnnxxxx", pconf->szOU, sizeof(pconf->szOU), szConfPath);
    GetPrivateProfileStringA("ROOTCERT", "common_name", "xxxxnnxxx", pconf->szCN,sizeof(pconf->szCN), szConfPath);
    pconf->valdays = GetPrivateProfileIntA("ROOTCERT", "valdatys", 1000, szConfPath);

}


void GenRCConfHeader(const char* file,const char * content, size_t len)
{
    FILE *fp = NULL;
    errno_t error = 0;
    size_t wsize = 0;

    if( file == NULL)
        return;

    error = fopen_s(&fp,file,"wb+");

    if(error == 0){
    
        wsize = fwrite(content, 1, len,fp);
        
    }
    
    if( fp != NULL) fclose( fp );
}


#define CA_TEST 1

/*CA测试签名*/
#if CA_TEST
void ca_test()
{

    EVP_PKEY *pKey_root = NULL;
    X509 * x509_root = NULL;

    EVP_PKEY *pKey = NULL;
    X509 * x509 = NULL;

    int ret = 0;

    pKey_root = CertificateProvider::generate_keypair(2048);

    if (pKey_root == NULL)
        return ;

    x509_root = CertificateProvider::generate_certificate(pKey, "xxxxnnxxxx@126.com", "xxxxnnxxxx@126.com", "xxxxnnxxxx@126.com",1000);

    if (x509_root == NULL)
    {
        EVP_PKEY_free(pKey_root);
        pKey_root=NULL;
        return ;
    }

    //

    pKey = CertificateProvider::generate_keypair(2048);

    if (pKey == NULL)
        return ;

    x509 = CertificateProvider::generate_certificate(pKey, "www.baidu.com", "www.baidu.com", "www.baidu.com",1000);

    if (x509 == NULL)
    {
        EVP_PKEY_free(pKey);
        pKey=NULL;
        EVP_PKEY_free(pKey_root);
        pKey_root=NULL;
        return ;
    }

    //签名
    ret = CertificateProvider::x509_certify(x509, x509_root, pKey_root);

    if(ret){//success
        int len = 0;
        unsigned char * buf = NULL;
        len = CertificateProvider::exportx509(x509, NULL, 0);
        if(len){
            buf = (unsigned char*)malloc(len);
            memset(buf, 0, len);
            len = CertificateProvider::exportx509(x509, buf, len);
            if(len){
                //可以导出文件
            
            }
        }
    
    }
    
}
#endif

int main(int argc, char **argv)
{
    char szPriKeyPath[MAX_PATH] = {0};
    char szRootCertPath[MAX_PATH] = {0};
    char szRCConf[MAX_PATH] = {0}; 
    RC_CONF rc_conf;
    char * szParamter = NULL;
    char szOutputDir[MAX_PATH] = {0};
    int c;
    int digit_optind = 0;
    int option_index = 0;
    char szIssuser[200] = {0};
    char szPwd[200] = {0};
    unsigned int opt = 0;
    EVP_PKEY *pKey = NULL;
    X509 *x509 = NULL;
    char  rcconf_header[200] = {0};    


    while(1){
        static struct option long_options[] = {
            {"outputdir", required_argument, 0,  0 },
            {"issuer",  required_argument, 0,  0 },
            {"password", required_argument, 0, 0},
#if CA_TEST
            {"casign",  required_argument, 0, 0},/*测试签名*/
#endif
            {0,         0,                 0,  0 }
        };


        c = getopt_long(argc, argv, "o:i:p:c",
            long_options, &option_index);
        if (c == -1)
            break;

        switch(c){
        case 'o':
            {
                if(optarg != NULL){
                    szParamter = optarg;
                    GetFullPathNameA(szParamter,MAX_PATH,szOutputDir,NULL);
                    opt |= PARAM_OUTPUTDIR;                    
                }
            }
            break;
        case 'i':
            {
                if(optarg != NULL){
                    strcpy_s(szIssuser, 200, optarg);
                    opt |= PARAM_ISSUSER;
                }
            }
            break;
        case 'p':
            {
                if(optarg != NULL){
                    strcpy_s(szPwd, 200, optarg);
                    opt |= PARAM_PWD;
                }
            }
            break;
#if CA_TEST
        case 'c':
            {
                ca_test();
            }
            break;
#endif
        }
    
    }
    if( opt & PARAM_OUTPUTDIR ){

        ImportConfInfo(&rc_conf);
        pKey = CertificateProvider::generate_keypair(2048);

        if (pKey == NULL)
            return -1;

        x509 = CertificateProvider::generate_certificate(pKey, rc_conf.szO, rc_conf.szOU, rc_conf.szCN,rc_conf.valdays);

        if (x509 == NULL)
        {
            EVP_PKEY_free(pKey);
            pKey=NULL;
            return -1;
        }

        //保存密钥和证书到文件
        strcpy_s(szPriKeyPath,sizeof(szPriKeyPath), szOutputDir);
        strcat_s(szPriKeyPath,sizeof(szPriKeyPath), PriKey_NAME);

        strcpy_s(szRootCertPath,sizeof(szRootCertPath), szOutputDir);
        strcat_s(szRootCertPath,sizeof(szRootCertPath), RootCert_NAME);

        CertificateProvider::savePriKeytofile(pKey, szPriKeyPath);
        CertificateProvider::saveX509tofile(x509, szRootCertPath);

        OPENSSL_free(x509);
        OPENSSL_free(pKey);
    }

    if( opt & PARAM_ISSUSER  && opt & PARAM_PWD ){
        strcpy_s(szRCConf,sizeof(szRCConf), szOutputDir);
        strcat_s(szRCConf,sizeof(szRCConf), RCConf_NAME);
        
        wsprintfA(rcconf_header, RCConf_Content("%s","%s"), szIssuser, szPwd);
    
        GenRCConfHeader(szRCConf, rcconf_header, strlen(rcconf_header));
        
        
    }

    return 0L;
}