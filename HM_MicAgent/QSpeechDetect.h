#pragma once
#include <new>
#include <Windows.h>

#define ZERO_CROSSING_THRESHOLD 0.2f
#define ZERO_SILENCE_THRESHOLD 0.005f
#define ZERO_SENSITIVITY 5
#define ENTROPY	10.0f

class QSpeechDetect{
	private:
		UINT uSamples, uBits, uChannels, uLength, uTotalSamples, uTotalSamplesPerChannel;
		PSHORT pData, pTable;
		FLOAT fZeroThreshold;

	public:
		QSpeechDetect(PBYTE pBuffer, UINT uSamplesPerSecond, UINT uBitsPerSecond, UINT uRecordChannels, UINT uBufLen, FLOAT fThresh);
		~QSpeechDetect();
		void SetBuffer(PBYTE pBuffer, UINT uBufLen);
		BOOL IsVoice();

	private:
		FLOAT log2(FLOAT x);
};