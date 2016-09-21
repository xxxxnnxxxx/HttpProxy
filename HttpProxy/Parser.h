#ifndef _PARSER_H_
#define _PARSER_H_

#include "httpheaders.h"

class Parser
{
public:
    static void HttpHeadersParser(HttpHeaders *headers);
};


#endif