#include "httpcontent.h"

HttpContent::HttpContent() {
    InitializeListHead(&m_ListContent);  //初始化LIST_ENTRY
    m_count = 0;
    m_length = 0;
}
HttpContent::~HttpContent() {
    release();
}
//插入数据块
void HttpContent::insert(const char *buf, int len) {

    struct _list_httpcontent_block_ *pBlock = NULL;

    if(len <= 0) 
        return;    //

    pBlock = (struct _list_httpcontent_block_*)malloc(sizeof(struct _list_httpcontent_block_));
    memset(pBlock, 0, sizeof(struct _list_httpcontent_block_));

    pBlock->buf = (char*)malloc(len);
    memset(pBlock->buf, 0, len);
    pBlock->len = len;

    memcpy_s(pBlock->buf, len, buf, len);

    m_length += len;    //保存整体上的空间长度
    //插入到列表中
    InsertTailList(&m_ListContent, (PLIST_ENTRY)&pBlock->list_entry);
    //计数加一
    m_count++;
}

char * HttpContent::getbuffer(size_t *len) {

    char *result = NULL;
    size_t pos = 0;
    PLIST_ENTRY plist = NULL;
    struct _list_httpcontent_block_ *pelem = NULL;

    result = (char*)malloc(m_length);
    memset(result, 0, m_length);
    for (plist = m_ListContent.Flink; plist != &m_ListContent; plist = plist->Flink) {
        pelem = CONTAINING_RECORD(plist, struct _list_httpcontent_block_, list_entry);
        memcpy_s(result + pos, m_length - pos, pelem->buf, pelem->len);
        pos = pos + pelem->len;
    }
    *len = pos;
    return result;
}

void HttpContent::release() {

    PLIST_ENTRY plist;
    struct _list_httpcontent_block_ *pelem = NULL;
    int i = 0;
    for (plist = m_ListContent.Flink; plist != &m_ListContent; plist = plist->Flink) {
        pelem = CONTAINING_RECORD(plist, struct _list_httpcontent_block_, list_entry);
        if (pelem->buf != NULL) free(pelem->buf);
    }

    for (i = 0; i < m_count; i++) {
        PLIST_ENTRY pList = RemoveHeadList(&m_ListContent);
        free(pList);
    }

    m_count = 0;
}