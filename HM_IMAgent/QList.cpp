/* 
*	QList class
*
*	Version: 1.0
*	Author: Quequero
*	Date: 22/Feb/2008
*/
#include <new>
#include <exception>
using namespace std;

#include "QList.h"
#include "QMessengerAgent.h"
#include "QAgent.h"

QList::QList()
{
	list = NULL;
	uListLength = 0;
}

QList::~QList()
{
	Clear();
}

PIM_LIST& QList::operator++() 
{
	if(list != NULL && list->next != NULL){
		list = list->next;
	}

	return list;
}

PIM_LIST& QList::operator++(int) 
{
	if(list != NULL && list->next != NULL){
		list = list->next;
	}

	return list;
}

PIM_LIST& QList::operator--() 
{
	if(list != NULL && list->previous != NULL){
		list = list->previous;
	}

	return list;
}

PIM_LIST& QList::operator--(int) 
{
	if(list != NULL && list->previous != NULL){
		list = list->previous;
	}

	return list;
}

PIM_LIST& QList::operator+=(QAgent *pAgent) 
{
	register UINT i;
	PIM_LIST last, iter;

	for(i = 0, iter = list; i < uListLength; i++, iter = iter->next){
		if(iter->pAgent == pAgent){
			list = iter;
			return list;
		}
	}

	last = new(std::nothrow) IM_LIST;

	if(last == NULL)
		return list;

	memset(last, 0x00, sizeof(IM_LIST));

	if(list != NULL){
		iter = list->next;

		list->next = last;
		last->previous = list;
		last->next = iter;
		last->next->previous = last;
		list = last;
	}else{
		list = last;
		list->next = list;
		list->previous = list;
	}

	list->pAgent = pAgent;

	uListLength++;

	return list;
}

PIM_LIST& QList::operator-=(QAgent *pAgent) 
{
	PIM_LIST prev, next, tmp, iter;
	register UINT i;

	if(uListLength == 0)
		return list;

	prev = list->previous;
	next = list->next;

	if(list == NULL || prev == NULL || next == NULL)
		return list;

	prev->next = list->next;
	next->previous = list->previous;

	tmp = list;
	list = prev->next;

	if(tmp->pAgent == pAgent){
		delete tmp->pAgent;
		tmp->pAgent = NULL;

		delete tmp;
	}else{
		for(i = 0, iter = tmp; i < uListLength; i++, iter = iter->next){
			if(tmp->pAgent == pAgent){
				prev = iter->previous;
				next = iter->next;

				prev->next = iter->next;
				next->previous = iter->previous;

				if(iter->pAgent != NULL)
					delete iter->pAgent;

				delete iter;
				iter = NULL;

				break;
			}
		}
	}

	uListLength--;
	return list;
}

// Rimuove l'elemento attualmente puntato da list
BOOL QList::Remove()
{
	PIM_LIST prev, next, tmp;

	if(uListLength == 0)
		return FALSE;

	prev = list->previous;
	next = list->next;

	if(list == NULL || prev == NULL || next == NULL)
		return FALSE;

	prev->next = list->next;
	next->previous = list->previous;

	tmp = list;
	list = prev->next;

	if(tmp->pAgent != NULL){
		delete tmp->pAgent;
		tmp->pAgent = NULL;
	}

	delete tmp;

	uListLength--;

	if(!uListLength)
		list = NULL;

	return TRUE;
}

UINT QList::GetQueueLength() 
{
	return uListLength;
}

QAgent* QList::GetAgent() 
{
	return list->pAgent;
}

void QList::Clear() 
{
	while(uListLength)
		Remove();
}

