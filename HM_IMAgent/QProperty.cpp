/*
* QProperty class
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <exception>
#include <new>
using namespace std;

#include "QProperty.h"

QProperty::QProperty()
{
	uVersion = 0;
	hwnd = NULL;
	pwId = NULL;
	pwHistory = NULL;
	pwUsers = NULL;
	pwIm = NULL;
	bAcquired = TRUE;
	bUpdated = FALSE;
}

QProperty::~QProperty()
{
	if(pwId)
		delete[] pwId;

	if(pwHistory)
		delete[] pwHistory;

	if(pwUsers)
		delete[] pwUsers;

	if(pwIm)
		delete[] pwIm;
}

const HWND QProperty::GetHandle() {
	return hwnd;
}

void QProperty::SetHandle(const HWND hw) {
	hwnd = hw;
}

const PWCHAR QProperty::GetId() {
	if(pwId == NULL)
		return L"";

	return pwId;
}

BOOL QProperty::SetId(PWCHAR pId) {
	UINT len;

	if(pwId != NULL){
		delete[] pwId;
		pwId = NULL;
	}

	len = wcslen(pId);

	pwId = new(std::nothrow) WCHAR[len + 2];

	if(pwId == NULL)
		return FALSE;

	memset(pwId, 0x00, len + 2);

	if(!wcsncpy_s(pwId, len + 2, pId, len))
		return TRUE;

	return FALSE;
}

const PWCHAR QProperty::GetHistory() {
	//if(pwHistory == NULL)
	//	return L"";

	return pwHistory;
}

UINT QProperty::GetHistoryLength()
{
	if(pwHistory == NULL)
		return 0;

	return wcslen(pwHistory);
}

// Effettua l'inizializzazione della history durante il primo grab
BOOL QProperty::SetHistory(PWCHAR pHistory) {
	return AppendHistory(pHistory);
}

const PWCHAR QProperty::GetUsers() {
	if(pwUsers == NULL)
		return L"";

	return pwUsers;
}

BOOL QProperty::SetUsers(PWCHAR pUsersList) {
	UINT len;

	if(pwUsers != NULL){
		delete[] pwUsers;
		pwUsers = NULL;
	}

	len = wcslen(pUsersList);

	pwUsers = new(std::nothrow) WCHAR[len + 2];

	if(pwUsers == NULL)
		return FALSE;

	memset(pwUsers, 0x00, len + 2);

	if(!wcsncpy_s(pwUsers, len + 2, pUsersList, len))
		return TRUE;

	return FALSE;
}

const PWCHAR QProperty::GetType()
{
	if(pwIm == NULL)
		return L"";

	return pwIm;
}

BOOL QProperty::SetType(PWCHAR pwType)
{
	UINT uLen;

	if(pwType == NULL)
		return FALSE;

	if(pwIm != NULL){
		delete[] pwIm;
		pwIm = NULL;
	}

	uLen = wcslen(pwType) + 1;

	pwIm = new(std::nothrow) WCHAR[uLen];

	if(pwIm == NULL)
		return FALSE;

	memset(pwIm, 0x00, uLen * sizeof(WCHAR));
	memcpy(pwIm, pwType, (uLen - 1) * sizeof(WCHAR));

	return TRUE;
}

BOOL QProperty::GetAcquiredStatus()
{
	return bAcquired;
}

void QProperty::SetAcquiredStatus(BOOL bStatus)
{
	bAcquired = bStatus;
}

BOOL QProperty::GetUpdated()
{
	return bUpdated;
}

void QProperty::SetUpdated(BOOL bUp)
{
	bUpdated = bUp;
}

// Torna l'ultima riga contenuta nella history, la funzione deve
// discriminare tra gli "a capo" inseriti da noi e quelli che,
// eventualmente, puo' aver inserito l'utente nella chat con ctrl + invio.
const PWCHAR QProperty::GetLastLine()
{
	UINT len;
	PWCHAR wLast;
	register UINT i;

	if(pwHistory == NULL)
		return L"";

	len = GetHistoryLength();

	if(len == 0)
		return NULL;

	wLast = pwHistory + (len - 1);

	for(i = len - 2; i > 0; i--){
		if(!wcsncmp(pwHistory + i, L"\n", 1)){
			// Se prima del \n c'e' un \r non e' una riga di history, ma
			// una riga utente.
			if(wcsncmp(pwHistory + i - 1, L"\r", 1))
				return pwHistory + i;
		}
	}

	if(pwHistory[0] == '\n')
		return pwHistory + 1;

	return pwHistory;
}

BOOL QProperty::CompareLastLine(PWCHAR pwLast)
{
	UINT uLastLen, uHistLen;

	if(pwLast == NULL || GetHistory() == NULL)
		return FALSE;

	uLastLen = wcslen(pwLast);
	uHistLen = GetHistoryLength();

	if(uHistLen == 0)
		return FALSE;

	if(pwLast[uLastLen - 1] == '\n'){
		if(!wcsncmp(GetLastLine(), pwLast, uHistLen))
			return TRUE;		
	}else{
		if(uLastLen != uHistLen - 1)
			return FALSE;

		if(!wcsncmp(GetLastLine(), pwLast, uHistLen - 1))
			return TRUE;
	}

	return FALSE;
}

// Accoda alla history pHistory e se necessario appende un \n. Se
// non e' presente alcuna history allora viene allocata memoria
// e la history viene inizializzata.
BOOL QProperty::AppendHistory(PWCHAR pHistory) {
	UINT wHistoryLength, wActualHistoryLength, wNewHistoryLength;
	PWCHAR wNewHistory = NULL;

	if(pHistory == NULL)
		return TRUE;

	wHistoryLength = wcslen(pHistory); 

	// Se abbiamo gia' una history, appendi la nuova e, se non c'e'
	// gia', aggiungi uno "\n"
	if(wHistoryLength != 0 && pwHistory != NULL){
		if(!wcsncmp(GetLastLine(), pHistory, wHistoryLength))
			return TRUE;

		wActualHistoryLength = GetHistoryLength();
		wNewHistory = new(std::nothrow) WCHAR[wActualHistoryLength + wHistoryLength + 2];
		wNewHistoryLength = wActualHistoryLength + wHistoryLength + 2;

		if(wNewHistory == NULL)
			return FALSE;

		memset(wNewHistory, 0x00, sizeof(WCHAR) * (wNewHistoryLength));

		if(wcsncpy_s(wNewHistory, wNewHistoryLength, pwHistory, wActualHistoryLength)){
			delete[] wNewHistory;
			return FALSE;
		}

		wcscat_s(wNewHistory, wNewHistoryLength, pHistory);

		if(wcsncmp(wNewHistory + (wNewHistoryLength - 1), L"\n", 1) && wcsncmp(pwHistory + (wHistoryLength - 1), L"\r", 1))
			wcscat_s(wNewHistory, wNewHistoryLength, L"\n");

		delete[] pwHistory;
		pwHistory = wNewHistory;
		return TRUE;
	}


	wHistoryLength = wcslen(pHistory);

	// Se e' la prima volta che chiamiamo questa funzione, inizializza
	// la prima riga di history
	if(wHistoryLength != 0 && pwHistory == NULL){
		pwHistory = new(std::nothrow) WCHAR[wHistoryLength + 2];

		if(pwHistory == NULL)
			return FALSE;

		memset(pwHistory, 0x00, (sizeof(WCHAR) * wHistoryLength) + (2 * sizeof(WCHAR)));

		wcsncpy_s(pwHistory, wHistoryLength + 2, pHistory, wHistoryLength);

		if(wcsncmp(pwHistory + (wHistoryLength - 1), L"\n", 1) && wcsncmp(pwHistory + (wHistoryLength - 1), L"\r", 1))
			wcscat_s(pwHistory, wHistoryLength + 2, L"\n");

		return TRUE;
	}

	if(wNewHistory)
		delete[] wNewHistory;

	return FALSE;
}

// Aggiunge un user alla coda degli utenti ed effettua l'escape,
// il delimiter scelto e' il seguente, virgolette escluse: " | ".
// Se bTerminator e' FALSE il terminatore non viene accodato.
BOOL QProperty::AppendUser(PWCHAR pUser, BOOL bTerminator)
{
	UINT uLen, uPipes;
	PWCHAR wTmp, wIter, wUsersIter, wNewList;

	if(pUser == NULL || pUser[0] == 0)
		return TRUE;

	wIter = pUser;
	uPipes = 0;

	// Contiamo i pipe
	while(wTmp = wcschr(wIter, '|')){
		uPipes++;
		wIter = wTmp + 1;
	}

	if(uPipes){
		if(pwUsers == NULL){
			uLen = wcslen(pUser) + uPipes + sizeof(WCHAR);

			if(bTerminator)
				uLen += sizeof(" | ");

			pwUsers = new(std::nothrow) WCHAR[uLen];
			wUsersIter = pwUsers;

			if(pwUsers == NULL)
				return FALSE;

			memset(pwUsers, 0x00, sizeof(WCHAR) * uLen);

			wIter = pUser;

			// Raddoppia tutti i pipes
			while(wTmp = wcschr(wIter, '|')){
				memcpy(wUsersIter, wIter, ((UINT)wTmp - (UINT)wIter) + sizeof(WCHAR));
				wUsersIter += (wTmp - wIter) + 1;
				memcpy(wUsersIter, L"|", sizeof(L"|"));
				wUsersIter += 1;
				wIter = wTmp + 1;
			}
			
			memcpy(wUsersIter, wIter, wcslen(wIter) * sizeof(WCHAR));
		}else{
			uLen = wcslen(pwUsers) + wcslen(pUser) + uPipes + sizeof(WCHAR);

			if(bTerminator)
				uLen += sizeof(" | ");

			wNewList = new(std::nothrow) WCHAR[uLen];
			
			if(wNewList == NULL)
				return FALSE;

			memset(wNewList, 0x00, uLen * sizeof(WCHAR));
			memcpy(wNewList, pwUsers, wcslen(pwUsers) * sizeof(WCHAR));

			wIter = pUser;
			wUsersIter = wNewList + wcslen(pwUsers);

			// Raddoppia tutti i pipes
			while(wTmp = wcschr(wIter, '|')){
				memcpy(wUsersIter, wIter, ((UINT)wTmp - (UINT)wIter) + sizeof(WCHAR));
				wUsersIter += (wTmp - wIter) + 1;
				memcpy(wUsersIter, L"|", sizeof(L"|"));
				wUsersIter += 1;
				wIter = wTmp + 1;
			}

			memcpy(wUsersIter, wIter, wcslen(wIter) * sizeof(WCHAR));
			delete[] pwUsers;
			pwUsers = wNewList;
		}
	}else{
		if(pwUsers == NULL){
			uLen = wcslen(pUser) + sizeof(WCHAR);

			if(bTerminator)
				uLen += sizeof(" | ");

			pwUsers = new(std::nothrow) WCHAR[uLen];
			wUsersIter = pwUsers;

			if(pwUsers == NULL)
				return FALSE;

			memset(pwUsers, 0x00, sizeof(WCHAR) * uLen);
			memcpy(pwUsers, pUser, sizeof(WCHAR) * wcslen(pUser));
		}else{
			uLen = wcslen(pwUsers) + wcslen(pUser) + sizeof(WCHAR);

			if(bTerminator)
				uLen += sizeof(" | ");

			wNewList = new(std::nothrow) WCHAR[uLen];

			if(wNewList == NULL)
				return FALSE;

			memset(wNewList, 0x00, uLen * sizeof(WCHAR));
			memcpy(wNewList, pwUsers, wcslen(pwUsers) * sizeof(WCHAR));

			wUsersIter = wNewList + wcslen(pwUsers);

			memcpy(wUsersIter, pUser, wcslen(pUser) * sizeof(WCHAR));

			delete[] pwUsers;
			pwUsers = wNewList;
		}
	}

	if(bTerminator)
		wcsncat_s(pwUsers, uLen, L" | ", sizeof(L" | "));

	return TRUE;
}

// Appende il terminatore " | " soltanto se c'e' gia' qualche
// username nella lista
BOOL QProperty::AppendTerminator()
{
	UINT uLen;
	PWCHAR pUsers = NULL;

	if(pwUsers == NULL || !wcslen(pwUsers))
		return FALSE;

	uLen = wcslen(pwUsers) + sizeof(" | ") + sizeof(WCHAR);

	pUsers = new(std::nothrow) WCHAR[uLen];

	if(pUsers == NULL)
		return FALSE;

	memset(pUsers, 0x00, uLen * sizeof(WCHAR));
	memcpy(pUsers, pwUsers, wcslen(pwUsers) * sizeof(WCHAR));

	wcsncat_s(pUsers, uLen, L" | ", 3);

	delete[] pwUsers;
	pwUsers = pUsers;
	return TRUE;
}

BOOL QProperty::CleanHistory()
{
	UINT uLen;
	PWCHAR wLast, wNewHistory;

	wLast = GetLastLine();

	// Non abbiamo grabbato nulla, quindi non c'e'
	// nulla cancellare.
	if(wLast == NULL){
		bUpdated = FALSE;
		return TRUE;
	}

	uLen = wcslen(wLast);

	if(uLen == GetHistoryLength())
		return TRUE;

	wNewHistory = new(std::nothrow) WCHAR[uLen + 1];

	if(wNewHistory == NULL){
		bUpdated = FALSE;
		return FALSE;
	}
		
	if(wLast == NULL){
		delete[] wNewHistory;
		bUpdated = FALSE;
		return FALSE;
	}

	memset(wNewHistory, 0x00, sizeof(WCHAR) * (uLen + 1));
	memcpy(wNewHistory, wLast, sizeof(WCHAR) * uLen);

	if(pwHistory)
		delete[] pwHistory;

	pwHistory = wNewHistory;

	return TRUE;
}

BOOL QProperty::ClearHistory()
{
	if(pwHistory == NULL)
		return TRUE;

	delete[] pwHistory;
	pwHistory = NULL;

	return TRUE;
}

void QProperty::ClearUsersList()
{
	if(pwUsers){
		delete[] pwUsers;
		pwUsers = NULL;
	}
}

// Helper function per MSN, converte i \r in \n
// In UNICODE: 
// "\n" = 0A00
// "\r" = 0D00
BOOL QProperty::ConvertNewLine() {
	PWCHAR wTmp, wIter;

	if(pwHistory == NULL)
		return FALSE;

	wIter = pwHistory;

	while(wTmp = wcschr(wIter, '\r')){
		wTmp[0] = '\n';
		wIter = wTmp;
	}

	return TRUE;
}

BOOL QProperty::ConvertNewLine(PWCHAR wHistory)
{
	PWCHAR wTmp, wIter;

	if(wHistory == NULL || !wcslen(wHistory))
		return FALSE;

	wIter = wHistory;

	while(wTmp = wcschr(wIter, '\r')){
		wTmp[0] = '\n';
		wIter = wTmp;
	}

	return TRUE;
}

BOOL QProperty::StripCarriageReturn()
{
	UINT len, i, j, uCount = 0;
	PWCHAR wOut = NULL;

	if(pwHistory == NULL || wcslen(pwHistory) == 0)
		return FALSE;

	len = wcslen(pwHistory);

	for(i = 0; i < len; i++){
		if(pwHistory[i] != '\r')
			uCount++;
	}

	wOut = new(std::nothrow) WCHAR[uCount + 1];

	if(wOut == NULL)
		return FALSE;

	memset(wOut, 0x00, sizeof(WCHAR) * (uCount + 1));

	for(i = 0, j = 0; i < uCount; i++){
		if(pwHistory[i] != '\r'){
			wOut[j] = pwHistory[i];
			j++;
		}
	}

	delete[] pwHistory;
	pwHistory = wOut;

	return TRUE;
}

BOOL QProperty::StripLeadingReturn()
{
	DWORD csrc, cdst;

	if(pwHistory == NULL || wcslen(pwHistory) == 0)
		return FALSE;

	// Strippiamo tutti gli "a capo" all'inizio del testo
	for(csrc=0; pwHistory[csrc]==L'\r' || pwHistory[csrc]==L'\n'; csrc++);
	for(cdst=0; pwHistory[csrc]; cdst++, csrc++)
		pwHistory[cdst] = pwHistory[csrc];
	pwHistory[cdst] = 0;
	return TRUE;
}

// Cerca wSearch nella history e ne torna il puntatore alla prima occorrenza
const PWCHAR QProperty::FindLine(PWCHAR wSearch) const
{
	if(pwHistory == NULL || !wcslen(pwHistory) || wSearch == NULL || !wcslen(wSearch))
		return NULL;

	return wcsstr(pwHistory, wSearch);
}

// Tronca la history ad una lunghezza predefinita
BOOL QProperty::TruncateHistory()
{
	UINT uLen;
	PWCHAR wHistory;

	uLen = GetHistoryLength();

	if(pwHistory == NULL || uLen < TRUNCATE_LENGTH)
		return FALSE;

	wHistory = new(std::nothrow) WCHAR[TRUNCATE_LENGTH + 1];

	if(wHistory == NULL)
		return FALSE;

	memset(wHistory, 0x00, (TRUNCATE_LENGTH + 1) * sizeof(WCHAR));
	memcpy(wHistory, pwHistory + (uLen - TRUNCATE_LENGTH), TRUNCATE_LENGTH * sizeof(WCHAR));

	delete[] pwHistory;
	pwHistory = wHistory;
	return TRUE;
}

const PWCHAR QProperty::wcsrstr(PWCHAR str, PWCHAR search)
{
	UINT uLenStr, uLenSearch;
	PWSTR wTmp, wIter;

	uLenStr = wcslen(str);
	uLenSearch = wcslen(search);

	if(uLenStr == 0 && uLenSearch)
		return NULL;

	// Se si cerca con una stringa vuota, torna il puntatore
	// all'inizio della stringa in cui cercare
	if(uLenSearch == 0 && uLenStr)
		return str;

	// Se la stringa da cercare e' piu' lunga della stringa in cui
	// cercare, torna NULL.
	if(uLenStr < uLenSearch)
		return NULL;

	if(uLenSearch == uLenStr)
		return wcsstr(str, search);

	wTmp = str + (uLenStr - uLenSearch);

	do{
		wIter = wcsstr(wTmp, search);

		if(wIter)
			return wIter;

		//wTmp -= uLenSearch;
		wTmp--;

	}while(wTmp >= str);

	return wcsstr(str, search);
}