
#define PCRE2_CODE_UNIT_WIDTH 8
#define PCRE2_STATIC
#include "..\include\pcre\pcre2.h"
#include "CommonFuncs.h"

int __stdcall CommonFuncs::w2a(const wchar_t * wstr, char ** cstr)
{
    int nByte = 0;
    nByte = WideCharToMultiByte(CP_ACP, 0, wstr, -1, NULL, 0, NULL, NULL);
    *cstr = (char*)malloc(nByte);
    return WideCharToMultiByte(CP_ACP, 0, wstr, -1, *cstr, nByte, NULL, NULL);
}


int __stdcall CommonFuncs::a2w(const char *cstr, wchar_t **wstr)
{
    int nWideCharLen = 0;
    nWideCharLen = MultiByteToWideChar(CP_ACP, 0, cstr, -1, NULL, 0);
    *wstr = (wchar_t*)malloc(nWideCharLen * sizeof(wchar_t));
    return MultiByteToWideChar(CP_ACP, 0, cstr, -1, *wstr, nWideCharLen * sizeof(wchar_t));
}

int __stdcall CommonFuncs::trim(char *str, size_t len)
{
    char *pHeader = str;
    char *buf = NULL;
    if (len == 0 || str==NULL)
        return -1;


    char *end;

    // Trim leading space
    while (isspace(*str)) str++;

    // All spaces?
    if (*str == 0) {
        return 0;
    }
        


    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) end--;

    // Write new null terminator
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

    if (len > 0 && *buf!=NULL) {//分配注意内存
        memcpy_s(result, relen, *buf, len);
        free(*buf);//释放原有的空间
        *buf = NULL;
    }
    return result;
}

BOOL __stdcall CommonFuncs::search_content(const char *sbuf, size_t bufsize, const char *reg, char **pFirstPos, size_t *offset)
{
    pcre2_code *re;
    PCRE2_SPTR pattern = (PCRE2_SPTR)reg;     /* PCRE2_SPTR is a pointer to unsigned code units of */
    size_t pos = 0;
    int errornumber;
    int rc;

    PCRE2_SIZE erroroffset=0;
    PCRE2_SIZE *ovector=NULL;
    size_t subject_length = bufsize;
    pcre2_match_data *match_data;


    if (sbuf == NULL || bufsize == 0)
        return FALSE;

    re = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);
    if (re == NULL) {
        /*error*/
        return FALSE;
    }

    match_data = pcre2_match_data_create_from_pattern(re, NULL);
    rc = pcre2_match(
        re,                   /* the compiled pattern */
        (PCRE2_SPTR)sbuf,     /* the subject string */
        subject_length,       /* the length of the subject */
        0,                    /* start at offset 0 in the subject */
        0,                    /* default options */
        match_data,           /* block for storing the result */
        NULL);                /* use default match context */

    if (rc == PCRE2_ERROR_NOMATCH) {
        pcre2_match_data_free(match_data);
        pcre2_code_free(re);
        if (pFirstPos != NULL) *pFirstPos = NULL;
        return FALSE;
    }

    ovector = pcre2_get_ovector_pointer(match_data);

    if (ovector == NULL)
    {
        pcre2_match_data_free(match_data);
        pcre2_code_free(re);
        if (pFirstPos != NULL) *pFirstPos = NULL;
        return FALSE;
    }
    PCRE2_SPTR substring_start = (PCRE2_SPTR)sbuf + ovector[0];


    if (pFirstPos != NULL)
        *pFirstPos = (char*)substring_start;

    if (offset != NULL)
        *offset = ovector[0];

    pcre2_match_data_free(match_data);
    pcre2_code_free(re);
    return  TRUE;
}
EXTERN_C IMAGE_DOS_HEADER __ImageBase;
char * __stdcall CommonFuncs::GetCurrentDir(char* value, int len)
{
    MEMORY_BASIC_INFORMATION membinfo;
    if (VirtualQuery(GetCurrentDir, &membinfo, sizeof(membinfo)) == sizeof(MEMORY_BASIC_INFORMATION))
    {
        GetModuleFileNameA((HMODULE)(DWORD)membinfo.AllocationBase, value, len);
    }
    else
    {
        GetModuleFileNameA((HMODULE)&__ImageBase, value, len);
    }

    if (strlen(value) != 0) {
        char*p = strrchr(value, '\\');
        if (p != NULL)
            *p = '\0';

        return value;
    }

    return (char*)0;
}

DWORD __stdcall CommonFuncs::_min(DWORD a, DWORD b)
{
    return (a > b) ? b : a;
}
