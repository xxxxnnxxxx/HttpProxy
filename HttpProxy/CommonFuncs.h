#ifndef _COMMONFUNCS_H_
#define _COMMONFUNCS_H_

#include <Windows.h>

class CommonFuncs {
public:
    static int      __stdcall w2a(const wchar_t * wstr, char ** cstr);
    static int      __stdcall a2w(const char *cstr, wchar_t **wstr);
    static char *   __stdcall GetCurrentDir(char* value, int len);
    static int      __stdcall trim(char *str, size_t len);
    static char *   __stdcall _realloc(char ** buf, size_t len, size_t relen); //重新分配内存
    static DWORD    __stdcall _min(DWORD a, DWORD b);
};


#endif