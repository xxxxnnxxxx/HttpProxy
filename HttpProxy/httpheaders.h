#ifndef _HTTPHEADERS_H_
#define _HTTPHEADERS_H_

#include "header.h"
#include "list_entry.h"

typedef struct _list_ {
    LIST_ENTRY list_entry;
    char *key;
    char *val;
    int  key_len;   //key的长度
    int  val_len;   //val的长度
}HttpHeader_Attribute;

class  HttpHeaders {
public:
    HttpHeaders();
    ~HttpHeaders();
    enum {
        HTTP_REQUEST,
        HTTP_RESPONSE,
    };
public:
    
public:
    char *operator[](char *key);
    char *operator[](int index);
    char *search(char*key); //根据key,返回val
    int  search(int index, char **key, char** val);
    PLIST_ENTRY enumheaders(int index);
    HttpHeaders& operator=(const HttpHeaders hh);
    
    void insert(const char *key, const char *val);
    void insert(const char *key, size_t len_key, const char *val, size_t len_val);
    void del(const char *key);
    void del(int index);    //根据索引删除信息
    void release(); //释放
    int  parse_httpheaders(const char *headers, size_t len,int bHttpRequest);
    int  get_count() const { return m_count; }
    int  separat_httpattributes(const char *attr);
    char* getbuffer(size_t *len);   //返回长度
    static char * get_status_code_descript(int statuscode);
    int  parse_request_line(char *rl, int len);
    int  parse_response_line(char *rl, int len);
    size_t  get_request_uri(char *buf, size_t len);   //获取请求的整个uri,对于https的形式，一般会包括host属性
    int  set_request_uri(char *buf, size_t len);      //设置主机的uri,主要是请求首行的,如果针对了host的修改，则会修改host属性
    size_t length();    //获取头的长度，不包括content内容部分
private:
    int m_count;                //保存的key_val的数组长度
    LIST_ENTRY m_ListHeader;
public:
    static WORD HTTP_DEFAULT_PORT;
    static WORD HTTPS_DEFALUT_PORT;
public:
    DWORD m_response_status;    //http返回状态
    char m_version[10];         //http版本
    char m_method[10];          //http方法
    char *m_uri;                //请求的uri
    char *m_host;               //保存host地址
    //size_t m_length;            //length of httpheaders
    WORD m_port;
};
#endif
