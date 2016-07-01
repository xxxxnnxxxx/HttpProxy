#ifndef _HTTPSESSION_H_
#define _HTTPSESSION_H_

#include <windows.h>

class HttpSession {
public:
    HttpSession();
    ~HttpSession();

    enum {
        HS_RESULT_OK,                   //返回正常
        HS_RESULT_DATAEMPTY,            //数据结果为空
        HS_RESULT_SERVER_NOEXIST,       //服务器不存在
    };

public:
    void revert();
public:
    char*   m_pSendbuf;
    DWORD   m_SizeofSendbuf;
    DWORD   m_resultstate;    //数据结果状态
    BOOL    m_bKeepAlive;     //是否保持活动状态

};

#endif
