/*
* Yahoo! Messenger v10.x Logger
*
* Coded by: Quequero
* Date: 15/Dec/2009
*
*/

#include <exception>
using namespace std;

#ifndef __QYim10_h__
#define __QYim10_h__

#include "QYim8.h"

class QYim10: public QYim8
{
	private:
		static PWCHAR wChatTree[], wChatUserListTree[], wMarker[];
		PWCHAR pwConv;

	private:
		BOOL FixString(PWCHAR bChat);

	public:
		QYim10(HWND hw);
		~QYim10();
		BOOL GrabHistory();
		BOOL GrabTopic();
		BOOL GrabUserList();
};

#endif
