/*
* QOleWalker, OLE object parser/walker class
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <exception>
#include <OleAcc.h>
#include <Mshtml.h>
#include <atlbase.h>
using namespace std;

#ifndef __QOleWalker_h__
#define __QOleWalker_h__

class QOleWalker;

class QOleWalker
{
	private: 
		IAccessible *iAcc, *tiAcc, *yiAcc;
		UINT uType, uCounter, nMsg;
		LONG uChildrenCount, uTi, uYi, uIa;
		HWND hwnd;
		VARIANT trVariant;
		BOOL bInit;
		HINSTANCE hInst;

	public:
		QOleWalker();
		~QOleWalker();
		BOOL Init();
		void UnInit();
		BOOL SetInterface();
		INT GetRole(UINT uChid);
		PWCHAR GetName();
		PWCHAR GetValue();
		LONG GetChildCount();
		HWND GetHandleFromClass(PWCHAR *wClassTree);
		void SetHandle(HWND hw);
		HWND GetHandle();
		UINT GetType();
		void SetType(UINT uType);
		BOOL SetInterfaceFromType(UINT uType, UINT uIndex);
		BOOL SetDispatchInterfaceFromType(UINT uType, UINT uIndex);
		BOOL SetYimRecursiveInterface();
		BOOL SetYimUserListInterface(HWND hw);
		UINT GetDispatchTypeCount(UINT uType);
		UINT GetTypeCountFromTi(UINT uType);
		UINT GetTypeCountFromYi(UINT uType);
		UINT RecursiveTypeCountFromYi(IAccessible* pAcc, UINT uType);
		LONG GetInterfaceChildrenCount();
		UINT GetYimTypeCount(UINT uType);
		BOOL GetLineFromContainer(BSTR *bLine, UINT uIndex);
		BOOL GetLineFromContainer(BSTR *bLine, UINT uIndex, UINT uType);
		BOOL GetSpecificLineFromContainer(BSTR *bLine, UINT uIndex, UINT uType);
		BOOL GetYimSpecificLineFromContainer(IAccessible* pAcc, BSTR *bLine, UINT uIndex, UINT uType);
		BOOL GetValueFromContainer(BSTR *bLine, UINT uIndex);
		BOOL GetValueFromIEContainer(BSTR *bLine);
		BOOL GetDescriptionFromContainer(BSTR *bLine, UINT uIndex);
		void Clean();

	private:
		void tiAccRelease();
		void yiAccRelease();
		void iAccRelease();
};

#endif
