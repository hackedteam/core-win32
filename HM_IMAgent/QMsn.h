/*
* MSN logger, base class
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

using namespace std;

#ifndef __QMsn_h__
#define __QMsn_h__

#include "QAgent.h"

class QMsn : public QAgent
{
	protected:
		HWND hwChat, hwUserList, hwLogin, hwContacts, hwHistory;

	public:
		QMsn();
		static BOOL Is(HWND hw);
		static UINT Version(HWND hw);
		static UINT VersionEx(const HWND hw);
		const PWCHAR GetMessenger();
};

#endif
