/*
* ICQ logger, base class
*
* Coded by: Quequero
* Date: 16/Nov/2010
*
*/

using namespace std;

#ifndef __QIcq_h__
#define __QIcq_h__

#include "QAgent.h"

class QIcq : public QAgent
{
	protected:
		HWND hwChat, hwUserList, hwLogin, hwContacts, hwHistory;

	public:
		QIcq(HWND hw);
		static BOOL Is(HWND hw);
		static UINT Version(HWND hw);
		static UINT VersionEx(const HWND hw);
		const PWCHAR GetMessenger();
};

#endif
