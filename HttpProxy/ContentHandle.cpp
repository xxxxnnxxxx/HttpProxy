#define PCRE2_CODE_UNIT_WIDTH 8
#define PCRE2_STATIC
#include "..\include\pcre\pcre2.h"
#include "ContentHandle.h"

//from pcre document
BOOL __stdcall ContentHandle::search_content(const char *sbuf, 
                                             size_t bufsize, 
                                             const char *reg, 
                                             char **pFirstPos, 
                                             size_t *offset) {
    pcre2_code *re;
    PCRE2_SPTR pattern = (PCRE2_SPTR)reg; 
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

    if (ovector == NULL) {
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