/*
* Yahoo! Messenger v7.x Logger
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <exception>
#include <new>

using namespace std;

#include "QYim7.h"
#include "QOleWalker.h"
#include "QYim.h"

#define MIN_SEARCH_LENGTH 200

QYim7::QYim7(const HWND hwnd)
{
	hwMain = hwnd;

	ole.Init();
	ole.SetHandle(hwnd);

	properties.SetHandle(hwnd);
}

QYim7::~QYim7()
{
	ole.Clean();
	ole.UnInit();
}

BOOL QYim7::GrabHistory()
{
	return TRUE;
}

BOOL QYim7::GrabTopic()
{
	return TRUE;
}

/**
* Prende l'elenco dei partecipanti e lo mette nelle proprieta'.
*/
BOOL QYim7::GrabUserList()
{
	return TRUE;
}

