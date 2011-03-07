/*
* MSN Live Messenger 2009 logger
*
* Coded by: Quequero
* Date: 09/Mar/2009
*
*/

#include <exception>
using namespace std;

#ifndef __QMsnLive2009_h__
#define __QMsnLive2009_h__

#include "QMsnLive85.h"

class QMsnLive2009: public QMsnLive85
{
	private:
		static PWCHAR wChatTree[], wMarker[], wUserList[];

	public:
		QMsnLive2009(HWND hw);
		~QMsnLive2009();
		BOOL GrabHistory();
		BOOL GrabTopic();
		BOOL GrabUserList();
};

#endif
