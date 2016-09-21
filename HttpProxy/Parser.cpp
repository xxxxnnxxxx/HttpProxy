#include <Windows.h>
#include "Parser.h"


void Parser::RequestHttpHeadersParser(HttpHeaders *headers)
{
    char *list[] = { "Proxy-Connection", "proxy-authenticate", "proxy-authorization", "Strict-Transport-Security",NULL };
    int i = 0;
    char *p = NULL;
    for (;; i++) {
        p = list[i];
        if (p == NULL)break;
        headers->del(p);
    }
}

void Parser::ResponseHttpHeadersParser(HttpHeaders *response_headers, const HttpHeaders* request_headers)
{
    char *list[] = { "Proxy-Connection", "proxy-authenticate", "proxy-authorization", "Strict-Transport-Security",NULL };
    int i = 0;
    char *p = NULL;
    char *request_uri = NULL;
    long len_uri = NULL;

    for (;; i++) {
        p = list[i];
        if (p == NULL)break;
        response_headers->del(p);
    }

    //±ê¼Ç
    len_uri = request_headers->get_request_uri(NULL, 0);
    
    if( len_uri != 0 ){
        request_headers = (char*)malloc(len_uri + 1);
        memset(request_headers, 0, len_uri + 1);
        request_headers->get_request_uri(request_uri, len_uri);

        response_headers->insert("HttpProxyUri", request_uri);

        if( request_uri != NULL ){
            free(request_uri);
            request_uri = NULL;
        }
    }


}