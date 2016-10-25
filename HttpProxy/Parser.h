#ifndef _PARSER_H_
#define _PARSER_H_

#include "httpheaders.h"

class Parser
{
public:
    static void RequestHttpHeadersParser(HttpHeaders *request_headers);
    static void ResponseHttpHeadersParser(HttpHeaders *response_headers, HttpHeaders * request_headers);
};


#endif