#ifndef _CONTENTHANDLE_H_
#define _CONTENTHANDLE_H_

#include <Windows.h>

class ContentHandle
{
 public:
        static BOOL     __stdcall search_content(const char *sbuf, size_t bufsize, const char *reg, char **pFirstPos, size_t *offset);
};

#endif // _CONTENTHANDLE_H_