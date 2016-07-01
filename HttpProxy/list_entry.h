#ifndef _LIST_ENTRY_H_
#define _LIST_ENTRY_H_

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

VOID		InitializeListHead( __out PLIST_ENTRY ListHead);
BOOLEAN		IsListEmpty(__in const LIST_ENTRY * ListHead);
VOID		InsertTailList(__inout PLIST_ENTRY ListHead,__inout PLIST_ENTRY Entry);
VOID		InsertHeadList(__inout PLIST_ENTRY ListHead,__inout PLIST_ENTRY Entry);
PLIST_ENTRY RemoveTailList(__inout PLIST_ENTRY ListHead);
PLIST_ENTRY RemoveHeadList(__inout PLIST_ENTRY ListHead);
BOOLEAN     RemoveElement(PLIST_ENTRY Entry);

#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (PCHAR)(address) - \
                                                  (ULONG_PTR)(&((type *)0)->field)))

#endif