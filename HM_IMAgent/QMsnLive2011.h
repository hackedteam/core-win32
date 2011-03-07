/*
* MSN Live Messenger 2011 logger
*
*/

#include <exception>
using namespace std;

#ifndef __QMsnLive2011_h__
#define __QMsnLive2011_h__

#include "QMsnLive2009.h"

class QMsnLive2011: public QMsnLive2009
{
	private:
		static PWCHAR wChatTree[], wMarker[], wUserList[];

	public:
		QMsnLive2011(HWND hw);
		~QMsnLive2011();
		BOOL GrabHistory();
		BOOL GrabTopic();
		BOOL GrabUserList();
		static HWND GetNextChild(HWND hw, HWND hc);
};

#endif
