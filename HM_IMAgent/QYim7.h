/*
* Yahoo! Messenger v7.x Logger
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <exception>
using namespace std;

#ifndef __QYim7_h__
#define __QYim7_h__

#include "QYim.h"

class QYim7: public QYim
{
	public:
		QYim7(const HWND hwnd);
		~QYim7();
		BOOL GrabHistory();
		BOOL GrabTopic();
		BOOL GrabUserList();
};

#endif
