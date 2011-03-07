/*
* Skype Chat Logger, base class
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <Windows.h>
#include <new>
using namespace std;

#ifndef __QSkype_h__
#define __QSkype_h__

#include "QAgent.h"
#include "QProperty.h"

class QSkype : public QAgent
{
	protected:
		HWND hwChat, hwUserList, hwLogin, hwContacts, hwHistory;

	public:  
		QSkype();
		BOOL GrabHistory(){return FALSE;}

		static BOOL Is(const HWND hw);
		static UINT Version(const HWND hw);
		static UINT VersionEx(const HWND hw);
		const PWCHAR GetMessenger();
};

#endif
