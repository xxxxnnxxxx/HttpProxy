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

void Parser::ResponseHttpHeadersParser(HttpHeaders *headers)
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