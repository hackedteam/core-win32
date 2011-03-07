/*
* MSN Messenger v7.x logger
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <exception>
using namespace std;

#ifndef __QMsnLive_h__
#define __QMsnLive_h__

#include "QMsn6.h"

class QMsnLive: public QMsn6
{
	private:
		static PWCHAR wChatTree[];
		static PWCHAR wChatTree2009[];

	public:
		QMsnLive(HWND hw);
		~QMsnLive();
		BOOL GrabHistory();
		BOOL GrabTopic();
		BOOL GrabUserList();
};

#endif
