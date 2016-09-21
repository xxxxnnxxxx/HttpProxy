#ifndef _PARSER_H_
#define _PARSER_H_

#include "httpheaders.h"

class Parser
{
public:
    static void RequestHttpHeadersParser(HttpHeaders *headers);
    static void ResponseHttpHeadersParser(HttpHeaders *headers);
};


#endif