/*
* Yahoo! Messenger v9.x Logger
*
* Coded by: Quequero
* Date: 22/May/2009
*
*/

#include <exception>
using namespace std;

#ifndef __QYim9_h__
#define __QYim9_h__

#include "QYim8.h"

class QYim9: public QYim8
{
	private:
		static PWCHAR wChatTree[], wChatUserListTree[], wMarker[];
		PWCHAR pwConv;

	private:
		BOOL FixString(PWCHAR bChat);

	public:
		QYim9(HWND hw);
		~QYim9();
		BOOL GrabHistory();
		BOOL GrabTopic();
		BOOL GrabUserList();
};

#endif
