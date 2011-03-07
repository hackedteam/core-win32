/*
* Skype Chat Logger
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <string>
#include <vector>
#include <exception>
using namespace std;

#ifndef __QSkype3_h__
#define __QSkype3_h__

#include "QSkype2.h"

class QSkype3: public QSkype2
{
	private:
		static PWCHAR wChatTree[], wChatUserListTree[], wLoginTree[], wContactTree[], wHistoryTree[];

	public:
		QSkype3(const HWND hw);
		~QSkype3();
		BOOL GrabHistory();
		BOOL GrabTopic();
		BOOL GrabUserList();
};

#endif
