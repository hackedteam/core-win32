/*
* Yahoo! Messenger v8.x Logger
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <exception>
using namespace std;

#ifndef __QYim8_h__
#define __QYim8_h__

#include "QYim7.h"

class QYim8: public QYim7
{
	private:
		static PWCHAR wChatTree[], wChatUserListTree[], wMarker[];
		PWCHAR pwConv;

	private:
		BOOL FixString(PWCHAR bChat);

	public:
		QYim8(HWND hw);
		~QYim8();
		BOOL GrabHistory();
		BOOL GrabTopic();
		BOOL GrabUserList();
};

#endif
