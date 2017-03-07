#include "list_entry.h"

///////
//list_entry functions list
////////////////////////////
VOID InitializeListHead( __out PLIST_ENTRY ListHead)
{
    ListHead->Flink = ListHead->Blink = ListHead;
}

BOOLEAN IsListEmpty(__in const LIST_ENTRY * ListHead) {
    return (BOOLEAN)(ListHead->Flink == ListHead);
}

VOID InsertTailList( __inout PLIST_ENTRY ListHead,  __inout PLIST_ENTRY Entry) {
    PLIST_ENTRY Blink;

    Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
}

VOID InsertHeadList( __inout PLIST_ENTRY ListHead,__inout PLIST_ENTRY Entry) {
    PLIST_ENTRY Flink;

    Flink = ListHead->Flink;
    Entry->Flink = Flink;
    Entry->Blink = ListHead;
    Flink->Blink = Entry;
    ListHead->Flink = Entry;
}


PLIST_ENTRY RemoveTailList(__inout PLIST_ENTRY ListHead) {
    PLIST_ENTRY Blink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Blink;
    Blink = Entry->Blink;
    ListHead->Blink = Blink;
    Blink->Flink = ListHead;
    return Entry;
}

PLIST_ENTRY RemoveHeadList( __inout PLIST_ENTRY ListHead) {
    PLIST_ENTRY Flink;
    PLIST_ENTRY Entry;

    Entry = ListHead->Flink;
    Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}

BOOLEAN RemoveElement(PLIST_ENTRY Entry) { 
    PLIST_ENTRY Blink;
    PLIST_ENTRY Flink;

    Flink = Entry->Flink;
    Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return (BOOLEAN)(Flink == Blink);
}