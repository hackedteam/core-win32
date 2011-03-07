/*
* ICQ v7.x logger
*
* Coded by: Quequero
* Date: 16/Nov/2010
*
*/

#include <exception>
using namespace std;

#ifndef __QIcq7_h__
#define __QIcq7_h__

#include "QIcq.h"

class QIcq7: public QIcq
{
	private:
		static PWCHAR wChatTree[];
		DWORD last_chat_len;

	public:
		QIcq7(HWND hw);
		~QIcq7();
		static HWND GetNextChild(HWND hw, HWND hc);
		BOOL GrabHistory();
		BOOL GrabTopic();
		BOOL GrabUserList();
};

#endif
