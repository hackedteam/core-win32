/*
* MSN Messenger v6.x logger
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <exception>
using namespace std;

#include "QMsn6.h"

QMsn6::QMsn6(HWND hw)
{
	ole.Init();
	ole.SetHandle(hw);
	properties.SetHandle(hw);
}

QMsn6::~QMsn6()
{
	ole.Clean();
	ole.UnInit();
}

BOOL QMsn6::GrabHistory() {
	//throw "Not yet implemented";
	return FALSE;
}

BOOL QMsn6::GrabTopic() {
	//throw "Not yet implemented";
	return FALSE;
}

BOOL QMsn6::GrabUserList() {
	//throw "Not yet implemented";
	return FALSE;
}

BOOL QMsn6::UpdateId(PWCHAR pwId) {
	//throw "Not yet implemented";
	return FALSE;
}

BOOL QMsn6::Is() {
	//throw "Not yet implemented";
	return FALSE;
}

UINT QMsn6::Version() {
	//throw "Not yet implemented";
	return 0;
}

