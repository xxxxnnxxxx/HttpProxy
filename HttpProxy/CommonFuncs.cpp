
#include "CommonFuncs.h"

int __stdcall CommonFuncs::w2a(const wchar_t * wstr, char ** cstr) {

    int nByte = 0;
    nByte = WideCharToMultiByte(CP_ACP, 0, wstr, -1, NULL, 0, NULL, NULL);
    *cstr = (char*)malloc(nByte);
    return WideCharToMultiByte(CP_ACP, 0, wstr, -1, *cstr, nByte, NULL, NULL);
}

int __stdcall CommonFuncs::a2w(const char *cstr, wchar_t **wstr) {

    int nWideCharLen = 0;
    nWideCharLen = MultiByteToWideChar(CP_ACP, 0, cstr, -1, NULL, 0);
    *wstr = (wchar_t*)malloc(nWideCharLen * sizeof(wchar_t));
    return MultiByteToWideChar(CP_ACP, 0, cstr, -1, *wstr, nWideCharLen * sizeof(wchar_t));
}

int __stdcall CommonFuncs::trim(char *str, size_t len) {

    char *pHeader = str;
    char *buf = NULL;
    char *end;

    if (len == 0 || str==NULL)
        return -1;

    while (isspace(*str)) str++;

    if (*str == 0)
        return 0;

    end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) end--;

    *(end + 1) = 0;

    buf = (char*)malloc(len);
    if(buf==NULL)
        return 0;

    memset(buf, 0, len);

    strcpy_s(buf, len, str);
    memset(pHeader, 0, len);
    strcpy_s(pHeader, len, buf);
    
    if (buf != NULL) {
        free(buf);
    }
    return strlen(pHeader);
}

char * __stdcall CommonFuncs::_realloc(char ** buf, size_t len,size_t relen)
{
    char * result = NULL;

    if (relen < len) return NULL;

    result = (char*)malloc(relen);
    if(result==NULL)
        return NULL;

    memset(result, 0, relen);

    if (len > 0 && *buf!=NULL) {
        memcpy_s(result, relen, *buf, len);
        free(*buf);
        *buf = NULL;
    }
    return result;
}

EXTERN_C IMAGE_DOS_HEADER __ImageBase;
char * __stdcall CommonFuncs::GetCurrentDir(char* value, int len) {

    MEMORY_BASIC_INFORMATION membinfo;
    if (VirtualQuery(GetCurrentDir, &membinfo, sizeof(membinfo)) == sizeof(MEMORY_BASIC_INFORMATION))
        GetModuleFileNameA((HMODULE)(DWORD)membinfo.AllocationBase, value, len);
    else
        GetModuleFileNameA((HMODULE)&__ImageBase, value, len);

    if (strlen(value) != 0) {
        char*p = strrchr(value, '\\');
        if (p != NULL)
            *p = '\0';

        return value;
    }
    return (char*)0;
}

unsigned long __stdcall CommonFuncs::_min(unsigned long a, unsigned long b) {
    return (a > b) ? b : a;
}
