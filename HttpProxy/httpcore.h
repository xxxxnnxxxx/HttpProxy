#ifndef _HTTPCORE_H_
#define _HTTPCORE_H_

#include <Windows.h>
#include "header.h"


//macro
typedef void* PHS_HANDLE;
typedef void* SCG_HANDLE;   //Hijack_Https Handle

//注意
//必须调用Https的劫持函数，因为没有对SSL的透明代理过程

//创建代理服务器
extern "C" HTTPCORE_API PHS_HANDLE  __stdcall Create_ProxyHttpService(HTTPSERVICE_PARAMS *pHttpService_params);
extern "C" HTTPCORE_API BOOL        __stdcall Start_ProxyHttpService(PHS_HANDLE handle);   //启动服务
extern "C" HTTPCORE_API BOOL        __stdcall Stop_ProxyHttpService(PHS_HANDLE handle);    //停止服务
extern "C" HTTPCORE_API SCG_HANDLE  __stdcall Hijack_Https(PHS_HANDLE handle);      //过滤https
//extern "C" HTTPCORE_API BOOL        __stdcall Dishijack_Https(SCG_HANDLE handle);   //放过https
extern "C" HTTPCORE_API BOOL        __stdcall TrustRootCert(SCG_HANDLE handle);
extern "C" HTTPCORE_API BOOL        __stdcall ExportRootCert(/*IN*/SCG_HANDLE handle,/*OUT*/unsigned char *buf,/*IN/OUT*/int *len);
//extern "C" HTTPCORE_API BOOL        __stdcall ResetCert(SCG_HANDLE handle);
#endif