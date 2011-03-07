/* 
*	QList class
*
*	Version: 1.0
*	Author: Quequero
*	Date: 22/Feb/2008
*/

#include <windows.h>
#include <exception>
using namespace std;

#ifndef __QList_h__
#define __QList_h__

#include "QAgent.h"

#define SKYPE	0x00000001L
#define MSN		0x00000002L

typedef struct _ImList IM_LIST, *PIM_LIST;

struct _ImList{
	PIM_LIST next;
	PIM_LIST previous;
	QAgent *pAgent;
};

class QList
{
	private: 
		PIM_LIST list;
		UINT uListLength;

	public: 
		QList();
		~QList();
		PIM_LIST& operator++();		// ++list
		PIM_LIST& operator++(int);	// list++
		PIM_LIST& operator--();		// ++list
		PIM_LIST& operator--(int);	// list++
		PIM_LIST& operator+=(QAgent *pAgent);
		PIM_LIST& operator-=(QAgent *pAgent);
		UINT GetQueueLength();
		QAgent* GetAgent();
		void Clear();
		BOOL Remove();
};

#endif
