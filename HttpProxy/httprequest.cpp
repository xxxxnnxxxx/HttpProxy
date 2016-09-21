#include <windows.h>
#include <winhttp.h>
#include "CommonFuncs.h"
#include "httprequest.h"
#include <curl\curl.h>


#pragma comment(lib,"winhttp.lib")


#define DEFAULT_USERAGENT   L"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0"


// 页面数据回调函数 ,也是非连续的数据，需要叠加 
static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *stream)
{
    int len = size * nmemb;
    HttpContent*pEntity = (HttpContent*)stream;
    pEntity->insert((const char*)ptr, len);
    return len;
}
// 返回http header回调函数  
/*

*/
static size_t header_callback(void *ptr, size_t size, size_t nmemb, void *stream)
{
    int len = size * nmemb;
    HttpHeaders *pHttpHeaders = (HttpHeaders*)stream;
    const char *pPos = (char*)ptr;
    int i = 0;

    if (*(WORD*)ptr == 0x0a0d)
        return len;
    if (_strnicmp((const char*)ptr, "HTTP/", 5) == 0) {
        while (i < len) {
            if (*(pPos + i) == ' ')break;
            i++;
        }

        memcpy_s(pHttpHeaders->m_version, 10, pPos, CommonFuncs::_min(10,i));
        char* endptr = NULL;
        pHttpHeaders->m_response_status= strtol(pPos+i, &endptr, 10);

    }
    else {
        while (i < len) {
            if (*(pPos + i) == ':')break;
            i++;
        }

        //tmpbuf
        char *key = (char*)malloc(i + 1);
        char *val = (char*)malloc(len - i + 1);

        memset(key, 0, i + 1);
        memset(val, 0, len - i + 1);

        memcpy_s(key, i + 1, ptr, i);
        memcpy_s(val, len - i + 1, (char*)ptr + i+1, len-i-3);

        pHttpHeaders->insert(key, val);
    

        if (key != NULL) {
            free(key);
        }

        if (val != NULL) {
            free(val);
        }
    }
    
    
    return len;
}

HttpRequest::HttpRequest() {

    
}

HttpRequest::~HttpRequest() {
    
}

int HttpRequest::http_request(HttpHeaders *request_headers,
                              HttpContent *request_content,
                              HttpHeaders* response_headers,
                              HttpContent *response_content)
{
    int ret = HttpRequest::CURL_LAST;

    CURL *curl;
    CURLcode res;
    struct curl_slist *chunk = NULL;
    BOOL bPOST = FALSE;
    size_t retsize = 0;
    char* uri = NULL;
    size_t result = NULL;

    curl = curl_easy_init();
    if (curl) {
        //遍历request_headers
        for (int i = 0; i < request_headers->get_count(); i++) {
            char *key = NULL;
            char *val = NULL;

            if (request_headers->search(i, &key, &val)) {
                char *buf = NULL;
                size_t Len_key = strlen(key);
                size_t Len_val = strlen(val);

                buf = (char*)malloc(Len_key + Len_val + 2);
                memset(buf, 0, Len_key + Len_val + 2);

                memcpy_s(buf, Len_key + Len_val + 2, key, Len_key);
                memcpy_s(buf + Len_key, Len_val + 2, ":", 1);
                memcpy_s(buf + Len_key + 1, Len_val + 1, val, Len_val);

                chunk = curl_slist_append(chunk, buf);
            }
        }

        if (_stricmp(request_headers->m_method, "POST") == 0) {
            bPOST = TRUE;
        }
        else
            bPOST = FALSE;

        //curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);   //设置请求超时为10s
        //curl_easy_setopt(curl, CURLOPT_ACCEPTTIMEOUT_MS, 5000L);    //接受数据超时这个地方不应当设置
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);    //设置connect的连接时间
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "http");
        curl_easy_setopt(curl, CURLOPT_PORT, request_headers->m_port);
        curl_easy_setopt(curl, CURLOPT_HTTP_TRANSFER_DECODING, 0);
        size_t len_uri = request_headers->get_request_uri(NULL, 0);
        uri = (char*)malloc(len_uri+1);
        memset(uri, 0, len_uri + 1);
        request_headers->get_request_uri(uri, len_uri);
        curl_easy_setopt(curl, CURLOPT_URL, uri);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        if (bPOST) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_content->getbuffer(&retsize));
        }

        // 设置回调函数  
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, response_headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_content);



        res = curl_easy_perform(curl);
        res = (CURLcode)handleError(res, response_headers, response_content);
        /* always cleanup */
        if (uri != NULL) free(uri);
        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);
        chunk = NULL;

        ret = res;//保持返回值不变
    }
    return ret;
}

int HttpRequest::https_request(HttpHeaders *request_headers,
                                HttpContent *request_content,
                                HttpHeaders *response_headers,
                                HttpContent *response_content)
{
    int ret = HttpRequest::CURL_LAST;

    CURL *curl;
    CURLcode res;
    struct curl_slist *chunk = NULL;
    BOOL bPOST = FALSE;
    size_t retsize = 0;
    char * uri = NULL;

    curl = curl_easy_init();
    if (curl) {
        //遍历request_headers
        for (int i = 0; i < request_headers->get_count(); i++) {
            char *key = NULL;
            char *val = NULL;

            if (request_headers->search(i, &key, &val)) {
                char *buf = NULL;
                size_t Len_key = strlen(key);
                size_t Len_val = strlen(val);

                buf = (char*)malloc(Len_key + Len_val + 2);
                memset(buf, 0, Len_key + Len_val + 2);

                memcpy_s(buf, Len_key + Len_val + 2, key, Len_key);
                memcpy_s(buf + Len_key, Len_val + 2, ":", 1);
                memcpy_s(buf + Len_key + 1, Len_val + 1, val, Len_val);

                chunk = curl_slist_append(chunk, buf);
                /*if (buf != NULL) {
                    free(buf);
                    buf = NULL;
                }*/
            }
        }

        if (_stricmp(request_headers->m_method, "POST") == 0) {
            bPOST = TRUE;
        }
        else
            bPOST = FALSE;

        //curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);                 //设置请求超时为10s
        //curl_easy_setopt(curl, CURLOPT_ACCEPTTIMEOUT_MS, 5000L);      //接受数据超时这个地方不应当设置
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);             //跳过证书的认证
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);            //设置connect的连接时间
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
        curl_easy_setopt(curl, CURLOPT_PORT, request_headers->m_port);
        curl_easy_setopt(curl, CURLOPT_HTTP_TRANSFER_DECODING, 0);
        size_t len_uri = request_headers->get_request_uri(NULL, 0);
        uri = (char*)malloc(len_uri+1);
        memset(uri, 0, len_uri+1);
        request_headers->get_request_uri(uri, len_uri);
        curl_easy_setopt(curl, CURLOPT_URL, uri);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
        if (bPOST) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_content->getbuffer(&retsize));
        }

        // 设置回调函数  
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, response_headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_content);


        res = curl_easy_perform(curl);
        res = (CURLcode)handleError(res, response_headers, response_content);

        /* always cleanup */
        if (uri != NULL)free(uri);
        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);
        chunk = NULL;

        ret = res;//保持返回值不变
    }
    return ret;
}


int HttpRequest::handleError(int dwError, HttpHeaders *response_headers, HttpContent *response_content)
{
    int ret = dwError;
    switch (dwError)
    {
    case CURLE_OK:
        break;
    case CURLE_GOT_NOTHING:
    {
        char *rescontent = "ReadResponse() failed: The server did not return a complete response for this request. Server returned 0 bytes";
        char tmp[32] = { 0 };
        struct tm newtime;
        __time32_t aclock;
        _time32(&aclock);   // Get time in seconds.
        _localtime32_s(&newtime, &aclock);   // Convert time to struct tm form.
        asctime_s(tmp, 32, &newtime);
        *(tmp + strlen(tmp) - 1) = '\0';
        response_headers->insert("Date", tmp);
        response_headers->insert("Content-Type", " text/html; charset=UTF-8");
        wsprintfA(tmp, "%d", strlen(rescontent));
        response_headers->insert("Content-Length", tmp);
        response_headers->insert("Connection", " close");
        response_headers->insert("Cache-Control", " no-cache,must-revalidate");
        strcpy_s(response_headers->m_version, sizeof(response_headers->m_version), "HTTP/1.1");
        response_headers->m_response_status = 504;

        //TimeStamp //时间戳
        char timestamp[255] = { 0 };
        SYSTEMTIME systime = { 0 };

        GetLocalTime(&systime);
        wsprintfA(timestamp, "%d:%d:%d.%d", systime.wHour, systime.wMinute, systime.wSecond, systime.wMilliseconds);
        response_headers->insert("Timestamp", timestamp);
      
        response_content->insert(rescontent, strlen(rescontent));
        ret = 0;
    }
    break;
    case CURLE_OPERATION_TIMEDOUT:
    {

    }
    break;
    default:
        break;
    }
    return ret;
}