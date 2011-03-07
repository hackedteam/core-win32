/*
* MSN Live Messenger v8.5 logger
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <exception>
using namespace std;

#ifndef __QMsnLive85_h__
#define __QMsnLive85_h__

#include "QMsnLive.h"

class QMsnLive85: public QMsnLive
{
	private:
		static PWCHAR wChatTree[], wMarker[];

	public:
		QMsnLive85(HWND hw);
		~QMsnLive85();
		BOOL GrabHistory();
		BOOL GrabTopic();
		BOOL GrabUserList();
};

#endif
