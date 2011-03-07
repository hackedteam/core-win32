/*
* QOleWalker, OLE object parser/walker class
*
* Coded by: Quequero
* Date: 14/Mar/2008
*
*/

#include <exception>
#include <new>
#include <iostream>
using namespace std;

#include "QOleWalker.h"
#include "..\HM_SafeProcedures.h"
#include "..\common.h"

QOleWalker::QOleWalker()
{
	iAcc = tiAcc = yiAcc = NULL;
	uChildrenCount = uTi = uYi = uIa = 0;
	bInit = FALSE;

	hInst = LoadLibraryW(L"OLEACC.DLL");
	nMsg = FNC(RegisterWindowMessageW)(L"WM_HTML_GETOBJECT");
}

QOleWalker::~QOleWalker()
{
	if(hInst)
		FreeLibrary(hInst);

	tiAccRelease();
	yiAccRelease();
	iAccRelease();
	UnInit();
}

void QOleWalker::Clean()
{
	if(bInit == FALSE)
		return;

	tiAccRelease();
	yiAccRelease();
	iAccRelease();
}

// Inizializza la libreria COM, va chiamata soltanto la prima
// volta che si usa l'oggetto.
BOOL QOleWalker::Init()
{
	HRESULT hr;

	if(bInit == TRUE)
		return TRUE;

	// Inizializza la libreria COM ed una VARIANT struct
	hr = CoInitialize(NULL);
	
	// S_FALSE indica che la lib e' gia' inizializzata
	if(hr != S_OK && hr != S_FALSE){
		bInit = FALSE;
		return bInit;
	}

	VariantInit(&trVariant);

	bInit = TRUE;
	return bInit;
}

// Deinizializza la libreria COM, va chiamata solo se si vuole
// deinizializzare manualmente lo stato dell'oggetto.
void QOleWalker::UnInit()
{
	if(bInit == FALSE)
		return;

	VariantClear(&trVariant);
	CoUninitialize();

	bInit = FALSE;
}

// Prima di chiamare questa funzione, va chiamato SetHandle() con
// l'handle della finestra dalla quale si vuole ottenere l'IAccessible
BOOL QOleWalker::SetInterface()
{
	if(bInit == FALSE)
		return FALSE;

	if(hwnd == NULL)
		return FALSE;

	iAccRelease();

	if(FNC(AccessibleObjectFromWindow)(hwnd, OBJID_WINDOW, IID_IAccessible, (void **)&iAcc) != S_OK)
		return FALSE;

	uIa++; // Incrementa il reference counter di iAcc 

	iAcc->get_accChildCount(&uChildrenCount);

	if(uChildrenCount == 0)
		return FALSE;

	return TRUE;
}


INT QOleWalker::GetRole(UINT uChid) {
	VARIANT lrVariant, retVal;
	LONG lRole;

	if(bInit == FALSE || iAcc == NULL)
		return -1;

	VariantInit(&lrVariant);

	lrVariant.vt = VT_I4;
	lrVariant.lVal = uChid;

	iAcc->get_accRole(lrVariant, &retVal);
	lRole = retVal.lVal;

	VariantClear(&lrVariant);
	VariantClear(&retVal);

	return lRole;
}

PWCHAR QOleWalker::GetName() {
	//throw "Not yet implemented";
	return NULL;
}

PWCHAR QOleWalker::GetValue() {
	//throw "Not yet implemented";
	return NULL;
}

LONG QOleWalker::GetChildCount() {
	if(bInit == FALSE)
		return -1;

	return uChildrenCount;
}

HWND QOleWalker::GetHandleFromClass(PWCHAR *wClassTree) {
	HWND hwndFinal;
	UINT i = 1, len;
	PWCHAR wClassName = NULL;

	if(hwnd == NULL || wClassTree == NULL)
		return NULL;

	if((UINT)wcslen(wClassTree[0]) == 0)
		return NULL;

	hwndFinal = hwnd;

	len = (UINT)wcslen(wClassTree[0]);
	wClassName = new WCHAR[len + 1];
	ZeroMemory(wClassName, len + sizeof(WCHAR));

	// Prendi il nome della classe a partire dall'handle
	if(!FNC(GetClassNameW)(hwnd, wClassName, len + 1)){
		delete[] wClassName;
		return NULL;
	}

	// Controlla che sia uguale al primo elemento passato tramite wClassTree
	if(wcsncmp(wClassName, wClassTree[0], len)){
		delete[] wClassName;
		return NULL;
	}

	delete[] wClassName;

	// L'utente ha passato solo una classe, quindi dopo aver matchato il
	// nome torniamo con l'handle originale
	if(wClassTree[1] == 0)
		return hwnd;

	// Se la trovi, scorri l'albero e trova l'handle del controllo
	while(wClassTree[i] != 0){
		hwndFinal = FNC(FindWindowExW)(hwndFinal, NULL, wClassTree[i], NULL);

		if(hwndFinal == NULL)
			return NULL;

		i++;
	}

	return hwndFinal;
}

void QOleWalker::SetHandle(HWND hw) {
	hwnd = hw;
}

HWND QOleWalker::GetHandle()
{
	return hwnd;
}

UINT QOleWalker::GetType() {
	//throw "Not yet implemented";
	return 0;
}

void QOleWalker::SetType(UINT uType) {
	//throw "Not yet implemented";
}

// FIX - niente leak
// Ritorna in this->tiAcc la uIndex-esima interfaccia di tipo uType
BOOL QOleWalker::SetInterfaceFromType(UINT uType, UINT uIndex)
{
	long childCount, returnCount, i, j;
	UINT uCount = 0;
	VARIANT vtChild, varChild, *pArray = NULL;
	HRESULT hr;

	if(bInit == FALSE || iAcc == NULL)
		return FALSE;

	tiAccRelease();
	tiAcc = NULL;

	if(iAcc->get_accChildCount(&childCount) != S_OK || childCount == 0)
		return FALSE;

	pArray = new(std::nothrow) VARIANT[childCount];

	if(pArray == NULL)
		return FALSE;

	if(FAILED(FNC(AccessibleChildren)(iAcc, 0L, childCount, pArray, &returnCount))){
		delete pArray;
		return FALSE;
	}

	// Scorri i children
	for (i = 0; i < returnCount; i++){
		tiAccRelease();
		tiAcc = NULL;

		vtChild = pArray[i];

		if(vtChild.vt != VT_DISPATCH)
			continue;

		if((vtChild.pdispVal)->QueryInterface(IID_IAccessible, (void**)&tiAcc) != S_OK){
			tiAccRelease();
			tiAcc = NULL;
			continue;
		}

		uTi++; // Incrementa il reference counter di tiAcc

		varChild.vt = VT_I4;

		// XXX vedere se possiamo rimuovere questa linea
		//varChild.lVal = CHILDID_SELF;
	
		// XXX Nel caso di skype, quando si chiama la GrabUserList() al terzo loop
		// il server solleva un'eccezione, non fa nulla ma non ho idea del perche'.
		hr = tiAcc->get_accRole(varChild, &trVariant);

		if(hr == S_OK && trVariant.vt == VT_I4){
			if(trVariant.lVal == uType && uCount == uIndex){
				VariantClear(&varChild);

				for(j = 0; j < returnCount; ++j)
					VariantClear(&pArray[j]);

				// XXX delete[] o delete?
				delete pArray;
				return TRUE;
			}

			if(trVariant.lVal == uType)
				uCount++;
		}

		tiAccRelease();
		tiAcc = NULL;
	}

	VariantClear(&varChild);

	for(i = 0; i < returnCount; ++i)
		VariantClear(&pArray[i]);

	// XXX delete[] o delete?
	if(pArray)
		delete pArray;

	tiAccRelease();
	tiAcc = NULL;

	return FALSE;
}
// FIX niente leak ora
BOOL QOleWalker::SetDispatchInterfaceFromType(UINT uType, UINT uIndex)
{
	long childCount, returnCount, i, j;
	UINT uCount = 0;
	VARIANT vtChild, varChild, *pArray = NULL;
	HRESULT hr;

	if(bInit == FALSE || iAcc == NULL)
		return FALSE;

	tiAccRelease();
	tiAcc = NULL;

	if(iAcc->get_accChildCount(&childCount) != S_OK || childCount == 0)
		return FALSE;

	pArray = new(std::nothrow) VARIANT[childCount];

	if(pArray == NULL)
		return FALSE;

	if(FAILED(FNC(AccessibleChildren)(iAcc, 0L, childCount, pArray, &returnCount))){
		delete pArray;
		return FALSE;
	}

	// Scorri i children
	for (i = 0; i < returnCount; i++){
		vtChild = pArray[i];

		if(vtChild.vt != VT_DISPATCH)
			continue;

		if((vtChild.pdispVal)->QueryInterface(IID_IAccessible, (void**)&tiAcc) != S_OK){
			tiAccRelease();
			tiAcc = NULL;
			continue;
		}

		uTi++; // Incrementa il reference counter di tiAcc

		varChild.vt = VT_I4;
		varChild.lVal = CHILDID_SELF;

		hr = tiAcc->get_accRole(varChild, &trVariant);

		if(hr == S_OK && trVariant.vt == VT_I4){
			if(trVariant.lVal == uType && uCount == uIndex){
				VariantClear(&varChild);

				for(j = 0; j < returnCount; ++j)
					VariantClear(&pArray[j]);

				delete pArray;
				return TRUE;
			}

			if(trVariant.lVal == uType)
				uCount++;
		}

		tiAccRelease();
		tiAcc = NULL;
	}

	VariantClear(&varChild);

	for(i = 0; i < returnCount; ++i)
		VariantClear(&pArray[i]);

	if(pArray)
		delete pArray;
	
	tiAccRelease();
	tiAcc = NULL;

	return FALSE;
}


// All'uscita di questa funzione, il reference counter su yiAcc sara' 1
BOOL QOleWalker::SetYimRecursiveInterface()
{
	long childCount, returnCount;
	VARIANT vtChild;

	if(bInit == FALSE || iAcc == NULL)
		return FALSE;

	yiAccRelease();
	yiAcc = NULL;

	if(iAcc->get_accChildCount(&childCount) != S_OK || childCount == 0)
		return FALSE;

	// Pannello (parent) -> testo/testo/testo...
	if(childCount != 1)
		return FALSE;

	//VariantInit(&vtChild);

	if(FAILED(FNC(AccessibleChildren)(iAcc, 0L, childCount, &vtChild, &returnCount))){
		VariantClear(&vtChild);
		return FALSE;
	}

	if(vtChild.vt != VT_DISPATCH){
		VariantClear(&vtChild);
		return FALSE;
	}

	if((vtChild.pdispVal)->QueryInterface(IID_IAccessible, (void**)&yiAcc) != S_OK){
		yiAccRelease();
		yiAcc = NULL;
		VariantClear(&vtChild);
		return FALSE;
	}

	uYi++; // Incrementa il reference counter di yiAcc

	// XXX ho disabilitato questa ed ho abilitato l'ultima VariantClear()
	// verificare che vada bene
	//(vtChild.pdispVal)->Release();

	// Lista dei children
	if(yiAcc->get_accChildCount(&childCount) != S_OK || childCount == 0){
		yiAccRelease();
		yiAcc = NULL;
		VariantClear(&vtChild);  // Crasha....
		return FALSE;
	}

	// In teoria questa chiama la Release() di vtChild.pdispVal
	// perche' e' settato VT_DISPATCH ma non VT_BYREF
	VariantClear(&vtChild);

	return TRUE;
}

UINT QOleWalker::GetYimTypeCount(UINT uType)
{
	long childCount, returnCount, i;
	UINT uCount = 0;
	VARIANT vtChild, *pArray = NULL;

	if(bInit == FALSE || yiAcc == NULL)
		return FALSE;

	if(yiAcc->get_accChildCount(&childCount) != S_OK || childCount == 0)
		return FALSE;

	pArray = new(std::nothrow) VARIANT[childCount];

	if(pArray == NULL)
		return FALSE;

	//for (int i = 0; i < childCount; i++)
	//	VariantInit(&pArray[i]);

	if(FAILED(FNC(AccessibleChildren)(yiAcc, 0L, childCount, pArray, &returnCount))){
		//for (int i = 0; i < childCount; i++)
		//	VariantClear(&pArray[i]);

		delete pArray;
		return FALSE;
	}

	// Scorri i children
	for (i = 0; i < returnCount; i++){
		vtChild = pArray[i];

		if(vtChild.vt != VT_I4) // Ci interessano solo i children per YIM
			continue;

		yiAcc->get_accRole(vtChild, &trVariant);

		if(trVariant.lVal == uType)
			uCount++;

		VariantClear(&trVariant);
	}

	for(i = 0; i < returnCount; i++)
		VariantClear(&pArray[i]);

	if(pArray)
		delete pArray;

	return uCount;
}

BOOL QOleWalker::SetYimUserListInterface(HWND hw)
{
	long childCount, returnCount, i;
	VARIANT vtChild, *pArray = NULL;
	IAccessible *liAcc;

	if(FNC(AccessibleObjectFromWindow)(hw, OBJID_WINDOW, IID_IAccessible, (void **)&liAcc) != S_OK)
		return FALSE;

	if(liAcc->get_accChildCount(&childCount) != S_OK || childCount == 0)
		return FALSE;

	pArray = new(std::nothrow) VARIANT[childCount];

	if(pArray == NULL){
		liAcc->Release();
		return FALSE;
	}

	if(FAILED(FNC(AccessibleChildren)(liAcc, 0L, childCount, pArray, &returnCount))){
		delete pArray;
		liAcc->Release();
		return FALSE;
	}

	// Il terzo children contiene la lista degli utenti
	vtChild = pArray[3];
	
	if(vtChild.vt != VT_DISPATCH){
		for(i = 0; i < returnCount; ++i)
			VariantClear(&pArray[i]);

		liAcc->Release();
		delete pArray;
		return FALSE;
	}

	if((vtChild.pdispVal)->QueryInterface(IID_IAccessible, (void**)&yiAcc) != S_OK){
		for(i = 0; i < returnCount; ++i)
			VariantClear(&pArray[i]);

		yiAcc = NULL;
		liAcc->Release();
		delete pArray;
		return FALSE;
	}

	uYi++; // Incrementa il reference counter di yiAcc

	yiAcc->get_accChildCount(&childCount);

	if(liAcc)
		liAcc->Release();

	// Lista dei children
	if(yiAcc->get_accChildCount(&childCount) != S_OK || childCount == 0){
		for(i = 0; i < returnCount; ++i)
			VariantClear(&pArray[i]);

		yiAccRelease();
		delete pArray;
		return FALSE;
	}

	for(i = 0; i < returnCount; ++i)
		VariantClear(&pArray[i]);

	delete pArray;
	return TRUE;
}

// Torna il numero di interfacce Dispatch di tipo uType presenti
// nel container.
UINT QOleWalker::GetDispatchTypeCount(UINT uType)
{
	long childCount, returnCount, i;
	UINT uCount = 0;
	VARIANT lrVariant, vtChild, *pArray = NULL;

	if(bInit == FALSE || iAcc == NULL)
		return FALSE;

	lrVariant.vt = VT_I4;
	lrVariant.lVal = CHILDID_SELF;

	tiAccRelease();
	tiAcc = NULL;

	if(iAcc->get_accChildCount(&childCount) != S_OK || childCount == 0)
		return FALSE;

	pArray = new(std::nothrow) VARIANT[childCount];

	if(pArray == NULL)
		return FALSE;

	if(FAILED(FNC(AccessibleChildren)(iAcc, 0L, childCount, pArray, &returnCount))){
		delete pArray;
		return FALSE;
	}

	// Scorri i children
	for (i = 0; i < returnCount; i++){
		vtChild = pArray[i];

		if(vtChild.vt != VT_DISPATCH)
			continue;

		if((vtChild.pdispVal)->QueryInterface(IID_IAccessible, (void**)&tiAcc) != S_OK){
			tiAccRelease();
			tiAcc = NULL;
			continue;
		}

		uTi++; // Incrementa il reference counter di tiAcc

		tiAcc->get_accRole(lrVariant, &trVariant);

		if(trVariant.lVal == uType)
			uCount++;

		VariantClear(&trVariant);
		tiAccRelease();
		tiAcc = NULL;
	}

	// XXX da testare, dovrebbe essere stabile comunque
	// ed in teoria dovrebbe chiamare la Release() di eventuali VT_DISPATCH
	for(i = 0; i < returnCount; i++)
		VariantClear(&pArray[i]);

	__try {
		if(pArray)
			delete[] pArray;
	}
	__except(EXCEPTION_EXECUTE_HANDLER) {
		pArray = NULL;
	}

	tiAccRelease();
	tiAcc = NULL;

	return uCount;
}

// Torna il numero di controlli di tipo uType puntati da tiAcc
UINT QOleWalker::GetTypeCountFromTi(UINT uType)
{
	long childCount, returnCount, i;
	UINT uCount = 0;
	VARIANT vtChild, *pArray = NULL;

	if(bInit == FALSE || tiAcc == NULL)
		return FALSE;

	if(tiAcc->get_accChildCount(&childCount) != S_OK || childCount == 0)
		return FALSE;

	pArray = new(std::nothrow) VARIANT[childCount];

	if(pArray == NULL)
		return FALSE;

	//for (int i = 0; i < childCount; i++)
	//	VariantInit(&pArray[i]);

	if(FAILED(FNC(AccessibleChildren)(tiAcc, 0L, childCount, pArray, &returnCount))){
		//for (int i = 0; i < childCount; i++)
		//	VariantClear(&pArray[i]);

		delete pArray;
		return FALSE;
	}

	// Scorri i children
	for (i = 0; i < returnCount; i++){
		vtChild = pArray[i];

		if(vtChild.vt != VT_I4) // Ci interessano solo i children per YIM
			continue;

		tiAcc->get_accRole(vtChild, &trVariant);

		if(trVariant.lVal == uType)
			uCount++;

		VariantClear(&trVariant);
	}

	for(i = 0; i < returnCount; ++i)
		VariantClear(&pArray[i]);

	if(pArray)
		delete pArray;

	return uCount;
}

// Torna il numero di controlli di tipo uType puntati da yiAcc
UINT QOleWalker::GetTypeCountFromYi(UINT uType)
{
	long childCount, returnCount, i;
	UINT uCount = 0;
	VARIANT vtChild, *pArray = NULL;
	IAccessible *iWalk = NULL;

	if(bInit == FALSE || yiAcc == NULL)
		return FALSE;

	if(yiAcc->get_accChildCount(&childCount) != S_OK || childCount == 0)
		return FALSE;

	pArray = new(std::nothrow) VARIANT[childCount];

	if(pArray == NULL)
		return FALSE;

	//for (int i = 0; i < childCount; i++)
	//	VariantInit(&pArray[i]);

	if(FAILED(FNC(AccessibleChildren)(yiAcc, 0L, childCount, pArray, &returnCount))){
		//for (int i = 0; i < childCount; i++)
		//	VariantClear(&pArray[i]);

		delete pArray;
		return FALSE;
	}

	// Scorri i children
	for (i = 0; i < returnCount; i++){
		vtChild = pArray[i];

		if(vtChild.vt == VT_DISPATCH){
			if((vtChild.pdispVal)->QueryInterface(IID_IAccessible, (void**)&iWalk) != S_OK){
				if(iWalk)
					iWalk->Release();

				iWalk = NULL;
				continue;
			}

			vtChild.lVal = CHILDID_SELF;
			iWalk->get_accRole(vtChild, &trVariant);
			iWalk->get_accChildCount(&childCount);

			if(trVariant.lVal == uType)
				uCount++;

			iWalk->Release();
			iWalk = NULL;

			VariantClear(&trVariant);
			continue;
		}

		if(vtChild.vt != VT_I4) // Ci interessano solo i children per YIM
			continue;

		yiAcc->get_accRole(vtChild, &trVariant);

		if(trVariant.lVal == uType)
			uCount++;

		VariantClear(&trVariant);
	}

	for(i = 0; i < returnCount; i++)
		VariantClear(&pArray[i]);

	if(pArray)
		delete pArray;

	return uCount;
}

// Effettua il conteggio degli elementi di tipo uType in maniera ricorsiva.
// Questo metodo va chiamato con NULL come primo parametro, la funzione
// inizializza internamente il membro pAcc prendendolo dall'attributo yiAcc
// che deve esser stato settato in precedenza tramite SetYimRecursiveInterface()
UINT QOleWalker::RecursiveTypeCountFromYi(IAccessible* pAcc, UINT uType)
{
	HRESULT hr;
	LONG childCount, returnCount;
	IAccessible *iWalk;

	if(bInit == FALSE || yiAcc == NULL)
		return FALSE;

	if(pAcc == NULL){
		uCounter = 0;
		iWalk = yiAcc;
	}else
		iWalk = pAcc;

	hr = iWalk->get_accChildCount(&childCount);

	if(FAILED(hr) || childCount == 0)
		return 0;

	VARIANT* pArray = new(std::nothrow) VARIANT[childCount];

	if(pArray == NULL)
		return 0;

	hr = FNC(AccessibleChildren)(iWalk, 0L, childCount, pArray, &returnCount);

	if(FAILED(hr)){
		delete pArray;
		return 0;
	}

	// Iterate through children.
	for(int x = 0; x < returnCount; x++){
		VARIANT vtChild = pArray[x];

		// If it's an accessible object, get the IAccessible, and recurse.
		if (vtChild.vt == VT_DISPATCH)
		{
			IDispatch* pDisp = vtChild.pdispVal;
			IAccessible* pChild = NULL;

			hr = pDisp->QueryInterface(IID_IAccessible, (void**) &pChild);

			if(hr == S_OK){
				//pChild->get_accRole(vtChild, &trVariant);

				//if(trVariant.lVal == uType)
				//	uCounter++;

				RecursiveTypeCountFromYi(pChild, uType);
				pChild->Release();
			}

			// XXX disabilito questa in funzione della VariantClear() in fondo
			//pDisp->Release();
		}
		// Else it's a child element so we have to call accNavigate on the parent,
		//   and we don't recurse since child elements can't have children.
		else
		{
			iWalk->get_accRole(vtChild, &trVariant);

			if(trVariant.lVal == uType)
				uCounter++;

			VariantClear(&trVariant);
		}
	}

	for(int i = 0; i < returnCount; i++)
		VariantClear(&pArray[i]);

	if(pArray)
		delete pArray;

	return uCounter;
}

// Torna il numero di children nella IAccessible temporanea
LONG QOleWalker::GetInterfaceChildrenCount()
{
	LONG lCount;

	if(bInit == FALSE || tiAcc == NULL)
		return -1;

	if(tiAcc->get_accChildCount(&lCount) != S_OK)
		return -1;

	return lCount;
}

// Prende la riga uIndex-esima dal container identificato da this->tiAcc
BOOL QOleWalker::GetLineFromContainer(BSTR *bLine, UINT uIndex)
{
	VARIANT vtChild;

	vtChild.vt = VT_I4;
	vtChild.lVal = uIndex;

	if(bInit == FALSE || tiAcc == NULL)
		return FALSE;

	if(tiAcc->get_accName(vtChild, bLine) != S_OK)
		return FALSE;

	return TRUE;
}

// Torna il parametro Name del controllo con ID uIndex di tipo uType (se esiste)
BOOL QOleWalker::GetSpecificLineFromContainer(BSTR *bLine, UINT uIndex, UINT uType)
{
	VARIANT vtChild, trVariant;
	LONG childCount, i;
	UINT uCount = 0;

	vtChild.vt = VT_I4;

	if(bInit == FALSE || tiAcc == NULL)
		return FALSE;

	tiAcc->get_accChildCount(&childCount);

	for(i = 0; i <= childCount; i++){
		vtChild.lVal = i;
		tiAcc->get_accRole(vtChild, &trVariant);

		if(uCount == uIndex && trVariant.lVal == uType){
			if(tiAcc->get_accName(vtChild, bLine) == S_OK)
				return TRUE;
			else
				return FALSE;
		}

		if(trVariant.lVal == uType)
			uCount++;
	}

	return FALSE;
}

BOOL QOleWalker::GetYimSpecificLineFromContainer(IAccessible* pAcc, BSTR *bLine, UINT uIndex, UINT uType)
{
	HRESULT hr;
	LONG childCount, returnCount;
	IAccessible *iWalk;

	if(bInit == FALSE || yiAcc == NULL)
		return FALSE;

	if(pAcc == NULL){
		uCounter = 0;
		iWalk = yiAcc;
	}else
		iWalk = pAcc;

	hr = iWalk->get_accChildCount(&childCount);

	if(FAILED(hr) || childCount == 0)
		return FALSE;

	VARIANT* pArray = new(std::nothrow) VARIANT[childCount];

	if(pArray == NULL)
		return FALSE;

	hr = FNC(AccessibleChildren)(iWalk, 0L, childCount, pArray, &returnCount);

	if(FAILED(hr)){
		delete pArray;
		return FALSE;
	}

	// Iterate through children.
	for(int x = 0; x < returnCount; x++){
		VARIANT vtChild = pArray[x];
		// If it's an accessible object, get the IAccessible, and recurse.
		if(vtChild.vt == VT_DISPATCH){
			IDispatch* pDisp = vtChild.pdispVal;
			IAccessible* pChild = NULL;

			hr = pDisp->QueryInterface(IID_IAccessible, (void**) &pChild);

			if(hr == S_OK){
				pChild->get_accRole(vtChild, &trVariant);

				GetYimSpecificLineFromContainer(pChild, bLine, uIndex, uType);
				pChild->Release();
			}

			// XXX disabilito questa in funzione della VariantClear() in fondo
			//pDisp->Release();
		}
		// Else it's a child element so we have to call accNavigate on the parent,
		//   and we don't recurse since child elements can't have children.
		else
		{

			iWalk->get_accRole(vtChild, &trVariant);

			if(*bLine != NULL && uCounter != uIndex)
				SAFE_SYSFREESTR(*bLine);

			// Salta le tabelle
			if(trVariant.lVal == ROLE_SYSTEM_TABLE){
				VariantClear(&trVariant);
				break;
			}

			if(uCounter == uIndex && trVariant.lVal == uType){
				if(iWalk->get_accName(vtChild, bLine) == S_OK){
					uCounter++;
					VariantClear(&trVariant);
					break;
				}
			}

			if(trVariant.lVal == uType)
				uCounter++;

			VariantClear(&trVariant);
		}
	}

	for(int i = 0; i < returnCount; i++)
		VariantClear(&pArray[i]);

	if(pArray)
		delete pArray;

	return TRUE;
}

// Torna il parametro Name dell'uIndex-esimo controllo di tipo uType (se esiste)
BOOL QOleWalker::GetLineFromContainer(BSTR *bLine, UINT uIndex, UINT uType)
{
	VARIANT vtChild, trVariant;
	UINT uCount = 0;

	vtChild.vt = VT_I4;
	vtChild.lVal = uIndex;

	if(bInit == FALSE || tiAcc == NULL)
		return FALSE;

	tiAcc->get_accRole(vtChild, &trVariant);

	if(trVariant.lVal != uType)
		return FALSE;

	if(tiAcc->get_accName(vtChild, bLine) != S_OK)
		return FALSE;

	VariantClear(&trVariant);
	return TRUE;
}

BOOL QOleWalker::GetValueFromContainer(BSTR *bLine, UINT uIndex)
{
	VARIANT vtChild;

	vtChild.vt = VT_I4;
	vtChild.lVal = uIndex;

	if(bInit == FALSE || tiAcc == NULL)
		return FALSE;

	if(tiAcc->get_accValue(vtChild, bLine) != S_OK)
		return FALSE;

	VariantClear(&vtChild);
	return TRUE;
}

BOOL QOleWalker::GetValueFromIEContainer(BSTR *bLine)
{
	CComPtr<IHTMLDocument2> spDoc;
	LRESULT lRes;
	HRESULT hr;

	if(hInst == NULL || nMsg == 0)
		return FALSE;

	HM_SafeSendMessageTimeoutW(hwnd, nMsg, 0L, 0L, SMTO_ABORTIFHUNG, 1000, (DWORD*)&lRes);

	LPFNOBJECTFROMLRESULT pfObjectFromLresult = (LPFNOBJECTFROMLRESULT)GetProcAddress(hInst, "ObjectFromLresult");

	if(pfObjectFromLresult != NULL){
		hr = (*pfObjectFromLresult)(lRes, IID_IHTMLDocument2, 0, (void**)&spDoc);

		if(SUCCEEDED(hr)){
			CComPtr<IHTMLElement> pHTMLElement; 
			hr=spDoc->get_body(&pHTMLElement);
			pHTMLElement->get_innerText(bLine);
			return TRUE;
		}
	}

	return FALSE;
}


BOOL QOleWalker::GetDescriptionFromContainer(BSTR *bLine, UINT uIndex)
{
	VARIANT vtChild;

	vtChild.vt = VT_I4;
	vtChild.lVal = uIndex;

	if(bInit == FALSE || tiAcc == NULL)
		return FALSE;

	if(tiAcc->get_accDescription(vtChild, bLine) != S_OK)
		return FALSE;

	VariantClear(&vtChild);
	return TRUE;
}

void QOleWalker::tiAccRelease()
{
	if(tiAcc && uTi){
		while(uTi){
			tiAcc->Release();
			uTi--;
		}
			
		tiAcc = NULL;
	}

	tiAcc = NULL;
}

void QOleWalker::yiAccRelease()
{
	if(yiAcc && uYi){
		while(uYi){
			yiAcc->Release();
			uYi--;
		}

		yiAcc = NULL;
	}

	yiAcc = NULL;
}

void QOleWalker::iAccRelease()
{
	if(iAcc && uIa){
		while(uIa){
			iAcc->Release();
			uIa--;
		}

		iAcc = NULL;
	}

	iAcc = NULL;
}