/*
* QProperty class
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <exception>
using namespace std;

#ifndef __QProperty_h__
#define __QProperty_h__

#include <windows.h>

#define TRUNCATE_LENGTH 200

class QProperty
{
	private: 
		UINT uVersion;
		HWND hwnd;
		PWCHAR pwId;
		PWCHAR pwHistory;
		PWCHAR pwUsers;
		PWCHAR pwIm;
		BOOL bAcquired;
		BOOL bUpdated;

	public:
		QProperty();
		~QProperty();
		const HWND GetHandle();
		void SetHandle(const HWND hw);
		const PWCHAR GetId();
		BOOL SetId(PWCHAR pId);
		const PWCHAR GetHistory();
		BOOL SetHistory(PWCHAR pHistory);
		UINT GetHistoryLength();
		const PWCHAR GetUsers();
		BOOL SetUsers(PWCHAR pUsersList);
		const PWCHAR GetType();
		BOOL SetType(PWCHAR pwType);
		BOOL GetAcquiredStatus();
		void SetAcquiredStatus(BOOL bStatus);
		BOOL GetUpdated();
		void SetUpdated(BOOL bUp);
		const PWCHAR GetLastLine();
		BOOL CompareLastLine(PWCHAR pwLast);
		BOOL AppendHistory(PWCHAR pHistory);
		BOOL AppendUser(PWCHAR pUser, BOOL bTerminator);
		BOOL AppendTerminator();
		/**
		 * Questa funzione cancella la history attualmente grabbata ma ne conserva 
		 * l'ultima riga per i confronti con i successivi grab.
		 */
		BOOL CleanHistory();
		BOOL ClearHistory();
		void ClearUsersList();
		BOOL ConvertNewLine();
		BOOL ConvertNewLine(PWCHAR wHistory);
		BOOL StripCarriageReturn();
		BOOL StripLeadingReturn();
		const PWCHAR FindLine(PWCHAR wSearch) const;
		BOOL TruncateHistory();
		const PWCHAR wcsrstr(PWCHAR str, PWCHAR search);
};

#endif
