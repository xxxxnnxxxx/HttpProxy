#ifndef _HTMLENTITY_H_
#define _HTMLENTITY_H_

#include <windows.h>
#include "header.h"
#include "list_entry.h"

typedef struct _list_httpcontent_block_ {
    LIST_ENTRY list_entry;
    char *buf;
    int len;
}HttpContent_Block;

class HttpContent{

public:
    HttpContent();
    ~HttpContent();
public:
    void release();
    void insert(const char *buf, int len);
    char * getbuffer(size_t *len);
public://attributes
    size_t m_length;
private:
    LIST_ENTRY m_ListContent;
    int m_count;
};


#endif
