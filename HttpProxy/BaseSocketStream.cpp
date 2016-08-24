#include "BaseSocketStream.h"
#include "CommonFuncs.h"


BaseSocketStream::BaseSocketStream(char**pprecv_buf, DWORD *plen_recv_buf, char**ppsend_buf, DWORD *plen_send_buf)
{
    m_socket = INVALID_SOCKET;
    m_pprecv_buf = pprecv_buf;
    m_ppsend_buf = ppsend_buf;

    *m_ppsend_buf = NULL;

    m_plen_send_buf = plen_send_buf;
    *m_plen_send_buf = 0;

    m_plen_recv_buf = plen_recv_buf;
}


BaseSocketStream::~BaseSocketStream()
{//传递出的内存地址，只能由处理的类清理，不能直接清理
    
}

//不需要处理
int BaseSocketStream::init(void* buf,int len)
{
    return 1;
}

//返回类名字
char * BaseSocketStream::_classname(char *buf, DWORD len)
{
    if (buf == NULL || len == 0) return NULL;
    
    strcpy_s(buf, len, "BaseSocketStream");
    return buf;
}
/*
通过套接字写入数据
*/
int BaseSocketStream::read(void *buf,DWORD len)
{
    //清空数据
    *m_pprecv_buf = CommonFuncs::_realloc(m_pprecv_buf, *m_plen_recv_buf, *m_plen_recv_buf+len);
    if (*m_pprecv_buf == NULL) 
    {
        return BaseSocketStream::BSS_RET_ERROR;
    }
    memcpy_s(*m_pprecv_buf + *m_plen_recv_buf, *m_plen_recv_buf+len, buf, len);
    *m_plen_recv_buf = *m_plen_recv_buf + len;   //初始化长度
    return BaseSocketStream::BSS_RET_RESULT;
}

/*
通过套接字读取数据
*/
int BaseSocketStream::write(void *buf,DWORD len)
{
    if (buf != NULL && len != 0) {
        *m_ppsend_buf = (char*)malloc(len);
        memcpy_s(*m_ppsend_buf, len, buf, len);
        *m_plen_send_buf = len;   //初始化长度
    }
    return BaseSocketStream::BSS_RET_RESULT;;
}