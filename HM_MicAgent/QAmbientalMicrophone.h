#pragma once

#include "..\speex\speex.h"

typedef void *(*speex_encoder_init_t)(SpeexMode *);
typedef int (*speex_encoder_ctl_t)(void *, int, void *);
typedef void (*speex_encoder_destroy_t)(void *);
typedef int (*speex_encode_t)(void *, float *, SpeexBits *);
typedef void (*speex_bits_init_t)(SpeexBits *);
typedef void (*speex_bits_reset_t)(SpeexBits *);
typedef int (*speex_bits_write_t)(SpeexBits *, char *, int);
typedef void (*speex_bits_destroy_t)(SpeexBits *);
typedef SpeexMode *(*speex_lib_get_mode_t)(int);

class QAmbientalMicrophone{

	private:
		DWORD dwTid;
		HANDLE hThread;

	public:
		BOOL bVista, bCalibrate;
		INT iSilenceBlocks; // Sono pubblici perche' devono essere accessibili dal thread
		UINT uVoiceThreshold;

	private:
		BOOL ResolveCodecSymbols(HMODULE);
		
	public:
		QAmbientalMicrophone(HMODULE hSpeex, BOOL bModify, UINT uThreshold, INT iSilence);
		~QAmbientalMicrophone();

		static BOOL WaveWrite(DWORD sample_rate, FILETIME *Fid, PBYTE data, UINT uLen);

		// Routine del thread principale
		static DWORD WINAPI ThreadProc(LPVOID obj);
};