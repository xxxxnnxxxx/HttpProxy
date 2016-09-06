#include <Windows.h>
#include <stdio.h>
#include "..\HttpProxy\CertificateProvider.h"

#define INI_NAME        "conf.ini"
#define RootCert_NAME   "RootCert.pem"
#define PriKey_NAME     "PriKey.pem"

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

int main(int argc, char **argv)
{
    char szPriKeyPath[MAX_PATH] = {0};
    char szRootCertPath[MAX_PATH] = {0};
    RC_CONF rc_conf;
    char * szParamter = NULL;
    char szOutputDir[MAX_PATH] = {0};

    if(argc!=2)
        return -1L;

    szParamter = argv[1];

    GetFullPathNameA(szParamter,MAX_PATH,szOutputDir,NULL);

    
    ImportConfInfo(&rc_conf);
    
    EVP_PKEY *pKey = CertificateProvider::generate_keypair(2048);
    if (pKey == NULL)
        return -1;

    X509 *x509 = CertificateProvider::generate_certificate(pKey, rc_conf.szO, rc_conf.szOU, rc_conf.szCN,rc_conf.valdays);

    if (x509 == NULL)/*这个地方还是存在问题，应当在为空的情况下释放m_rootkeypair*/
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




    return 0L;
}