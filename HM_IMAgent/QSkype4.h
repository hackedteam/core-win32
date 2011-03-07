/*
* Skype Chat Logger
*
* Coded by: Quequero
* Date: 10/Feb/2009
*
*/

#include <string>
#include <vector>
#include <exception>
using namespace std;

#ifndef __QSkype4_h__
#define __QSkype4_h__

#include "QSkype3.h"

class QSkype4: public QSkype3
{
	private:
		static PWCHAR wChatTree[], wChatUserListTree[], wLoginTree[], wContactTree[], wHistoryTree[];

	public:
		QSkype4(const HWND hw);
		~QSkype4();
		BOOL GrabHistory();
		BOOL GrabTopic();
		BOOL GrabUserList();
};

#endif
