#include <stdio.h>
#include <math.h>
#include "QSpeechDetect.h"

#define SLICE_INTERVAL 4 // 1/4 di secondo

// pBuffer				-> Puntatore al buffer che contiene i dati
// uSamplesPerSecond	-> Samples acquisiti ogni secondo
// uBitsPerSecond		-> Bits di precisione per ogni sample
// uRecordChannels		-> Canali di registrazione
// uBufLen				-> Lunghezza (in byte) del buffer puntato da pBuffer
QSpeechDetect::QSpeechDetect(PBYTE pBuffer, UINT uSamplesPerSecond, UINT uBitsPerSecond, UINT uRecordChannels, UINT uBufLen, FLOAT fThresh):
uBits(16), uChannels(2), uSamples(44100), fZeroThreshold(0.26f)
{
	register UINT i, j;

	if(pBuffer == NULL || uSamplesPerSecond == 0 || uBitsPerSecond == 0 || uRecordChannels == 0 || uBufLen == 0)
		return;

	if(uBufLen < uRecordChannels * (uBitsPerSecond / 8))
		return;

	fZeroThreshold = fThresh;
	uSamples = uSamplesPerSecond;
	uBits = 16; // Lo settiamo a 16 in ogni caso perche' allochiamo pData come SHORT
	uChannels = uRecordChannels;
	uLength = uBufLen;
	uTotalSamples = uLength / (uBits / 8);
	uTotalSamplesPerChannel = uTotalSamples / uChannels;

	pData = NULL;
	pTable = NULL;
	pData = new(std::nothrow) SHORT[uTotalSamplesPerChannel];

	if(pData == NULL)
		return;

	pTable = new(std::nothrow) SHORT[0xFFFF + 1];

	if(pTable == NULL)
		return;

	for(i = 0, j = 0; i < uBufLen; i += (uBits / 8) * uChannels, j++)
		pData[j] = *((SHORT *)(&pBuffer[i]));
}

QSpeechDetect::~QSpeechDetect()
{
	if(pData){
		delete[] pData;
		pData = NULL;
	}

	if(pTable){
		delete[] pTable;
		pTable = NULL;
	}

	return;
}

void QSpeechDetect::SetBuffer(PBYTE pBuffer, UINT uBufLen)
{
	register UINT i, j;

	if(pBuffer == NULL || uBufLen < uChannels * (uBits / 8))
		return;

	uLength = uBufLen;
	uTotalSamples = uLength / (uBits / 8);
	uTotalSamplesPerChannel = uTotalSamples / uChannels;

	if(pData){
		delete[] pData;
		pData = NULL;
	}

	pData = new(std::nothrow) SHORT[uTotalSamplesPerChannel];

	if(pData == NULL)
		return;

	for(i = 0, j = 0; i < uBufLen; i += (uBits / 8) * uChannels, j++)
		pData[j] = *((SHORT *)(&pBuffer[i]));
}

BOOL QSpeechDetect::IsVoice()
{
	INT iTmp;
	UINT i, j, k;
	UINT uSamplesPerInterval, uIntervals, uPerc = 0;
	SHORT sSampleA, sSampleB;
	FLOAT fAvg, fEntropy = 0.0f, fVar;
	PFLOAT fZero = NULL;

	if(pData == NULL || pTable == NULL)
		return FALSE;

	memset(pTable, 0x00, sizeof(SHORT) * 0xFFFF);

	// Calcoliamo lo zero-crossing rate su un intervallo lungo SLICE_INTERVAL
	uSamplesPerInterval = uSamples / SLICE_INTERVAL;			// Sample in un intervallo
	uIntervals = uTotalSamplesPerChannel / uSamplesPerInterval; // Numero di slice da analizzare
	fZero = new(std::nothrow) FLOAT[uIntervals + 1];

	if(fZero == NULL)
		return TRUE; // Nel dubbio, diciamo che c'e' voce :)

	for(i = 0, k = 0; i < uTotalSamplesPerChannel; i += uSamplesPerInterval, k++){
		fAvg = 0.0f;

		for(j = i; j < i + uSamplesPerInterval - 1 && j < uTotalSamplesPerChannel - 1; j++){
			sSampleA = pData[j];
			sSampleB = pData[j + 1];

			iTmp = abs(((sSampleB >= 0) ? 1 : -1) - ((sSampleA >= 0) ? 1 : -1));
			fAvg += (FLOAT)iTmp;
		}

		fAvg /= 2.0f * uTotalSamplesPerChannel;
		fZero[k] = fAvg * 100.0f;
	}

	uPerc = 0;

	for(i = 0; i < uIntervals; i++){
		if(fZero[i] <= fZeroThreshold && fZero[i] >= ZERO_SILENCE_THRESHOLD)
			uPerc++;
	}

	// Tabella per l'entropia
	for(i = 0; i < uTotalSamplesPerChannel; i++){
		pTable[(USHORT)pData[i]] += 1;
	}

	// Calcola l'entropia
	for(i = 0; i < 0xFFFF; i++){
		if(pTable[i]){
			fVar = (FLOAT)pTable[i] / (FLOAT)uTotalSamplesPerChannel;
			fEntropy += (-(fVar * log2(fVar)));
		}
	}

	if(pData){
		delete[] pData;
		pData = NULL;
	}

	if(fZero)
		delete[] fZero;

	// Per disabilitare il filtro sull'entropia e' sufficiente
	// commentare: "&& fEntropy > ENTROPY"
	if(uPerc > ZERO_SENSITIVITY && fEntropy > ENTROPY)
		return TRUE;
	else
		return FALSE;
}

inline FLOAT QSpeechDetect::log2(float x)
{
	return ( log(x) / log((FLOAT)2) );
}