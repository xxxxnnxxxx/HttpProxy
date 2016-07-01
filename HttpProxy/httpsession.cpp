#include "httpsession.h"


HttpSession::HttpSession()
{
    m_pSendbuf = NULL;
    m_SizeofSendbuf = 0;
    m_resultstate = HS_RESULT_OK;
    m_bKeepAlive = TRUE;
}


HttpSession::~HttpSession()
{
    if (m_pSendbuf != NULL) {
        free(m_pSendbuf);
        m_pSendbuf = NULL;
    }
    m_SizeofSendbuf = 0;
    m_resultstate = HS_RESULT_OK;
}



//释放HttpSession，还原到处是状态
void HttpSession::revert()
{
    if (m_pSendbuf != NULL) {
        free(m_pSendbuf);
        m_pSendbuf = NULL;
    }

    m_SizeofSendbuf = 0;
    m_resultstate = HS_RESULT_OK;
}