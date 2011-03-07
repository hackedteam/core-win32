/*
* Skype Chat Logger
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <Windows.h>
using namespace std;

#ifndef __QSkype2_h__
#define __QSkype2_h__

#include "QOleWalker.h"
#include "QSkype.h"

class QSkype2: public QSkype
{
	public: 
		QSkype2(const HWND hw);
		~QSkype2();
		BOOL GrabHistory();
		BOOL GrabTopic();
		BOOL GrabUserList();
};

#endif
