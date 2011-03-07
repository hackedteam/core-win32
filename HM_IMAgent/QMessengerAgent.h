/* 
*	QMessengerAgent class
*
*	Version: 1.0
*	Author: Quequero
*	Date: 22/Feb/2008
*/

#include <windows.h>
#include <exception>
#include "QList.h"
#include "QMsn.h"
#include "QAgent.h"
using namespace std;

#ifndef __QMessengerAgent_h__
#define __QMessengerAgent_h__

class QMessengerAgent
{
	private:
		QList list;

	public: 
		BOOL UpdateWindowList();
		UINT GetMessengerType();
		void ChatAcquired();
		BOOL IsUpdated();
		UINT GetHistoryLength();
		PWCHAR GetHistory();
		UINT GetListLength();
		PWCHAR GetTopic();
		PWCHAR GetUsers();
		const PWCHAR GetMessengerName();
		void Next();

	private:
		BOOL IsPresent(HWND hw);
		BOOL CompareId();
		static BOOL CheckWindow(QAgent *pAgent);
		static BOOL CALLBACK FillList(HWND hwnd, LPARAM lParam);
};

#endif
