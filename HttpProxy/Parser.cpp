#include <Windows.h>
#include "headers.h"
#include "Parser.h"

void Parser::RequestHttpHeadersParser(HttpHeaders *headers) {
    char *list[] = { "Proxy-Connection", "proxy-authenticate", "proxy-authorization", "Strict-Transport-Security",NULL };
    int i = 0;
    char *p = NULL;
    for (;; i++) {
        p = list[i];
        if (p == NULL)break;
        headers->del(p);
    }
}

void Parser::ResponseHttpHeadersParser(HttpHeaders *response_headers, HttpHeaders* request_headers) {

    char *list[] = { "Proxy-Connection", "proxy-authenticate", "proxy-authorization", "Strict-Transport-Security",NULL };
    int i = 0;
    char *p = NULL;
    char *request_uri = NULL;
    size_t len_uri = 0;

    for (;; i++) {
        p = list[i];
        if (p == NULL)break;
        response_headers->del(p);
    }

    //±ê¼Ç
    len_uri = request_headers->get_request_uri(NULL, 0);
    
    if( len_uri != 0 ){
        request_uri = (char*)malloc(len_uri + 1);
        memset(request_uri, 0, len_uri + 1);
        request_headers->get_request_uri(request_uri, len_uri);

        response_headers->insert(CHT_HTTPREQUESTURI, request_uri);

        if( request_uri != NULL ){
            free(request_uri);
            request_uri = NULL;
        }
    }
}