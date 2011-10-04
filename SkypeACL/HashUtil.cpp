#include <windows.h>
#include "sha256.h"
#include "../md5.h"


void hex2ascii(char *lpOutput, char *lpInput, int size)
{
	char *ascii = "0123456789abcdef";

	while(size-- > 0)
	{
		*lpOutput++ = ascii[(*lpInput & 0xf0) >> 4];
		*lpOutput++ = ascii[(*lpInput & 0x0f)];
		*lpInput++;
	}

	*lpOutput = 0x00;
}

void hex2ascii(char *lpOutput, wchar_t *lpInput, int size)
{
	char *ascii = "0123456789abcdef";

	while(size-- > 0)
	{
		unsigned short c = (unsigned short) *lpInput;

		if ((c & 0xff00) != 0)
		{
			if ((c & 0xf000) != 0)
				*lpOutput++ = ascii[(c & 0xf000) >> 12];

			*lpOutput++ = ascii[(c & 0x0f00) >> 8];
		}

		*lpOutput++ = ascii[(c & 0xf0) >> 4];
		*lpOutput++ = ascii[(c & 0x0f)];
		
		lpInput++;
	}

	*lpOutput = 0x00;
}

///////////////////////////////////////////////////////////////////////////////
// SHA256 of file
//	Input:
//		lpFileName	: full path of plugin
//	Output:
//		sha256		: SHA256 in plain-text (lower case)
//
BOOL SHA256_Array(char *lpOutChecksum, void *array, int size)
{
	SHA256Context context;

	Sha256_Init(&context);

	Sha256_Update(&context, (byte *) array, (size_t) size);

	unsigned char sha256_digest[32];

	Sha256_Final(&context, sha256_digest);

	hex2ascii(lpOutChecksum, (char *) sha256_digest, sizeof(sha256_digest));

	return TRUE;
}

///////////////////////////////////////////////////////////////////////////////
// MD5 of file
//	Input:
//		lpFileName	: full path of plugin
//	Output:
//		sha256		: SHA256 in plain-text (lower case)
//
BOOL MD5_Plugin(char *lpFileName, char *lpOutChecksum)
{
	if (lpFileName == NULL || lpOutChecksum == NULL)
		return FALSE;


	HANDLE hFile = CreateFile(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	MD5_CTX context;

	MD5Init(&context);

	void *buffer = malloc(64000);

	DWORD dwBytesRead = 0;

	while(ReadFile(hFile, buffer, 64000, &dwBytesRead, NULL) == TRUE)
	{
		if (dwBytesRead == 0)	// end of file?
			break;

		MD5Update(&context, (byte *) buffer, (size_t) dwBytesRead);
	}

	CloseHandle(hFile);
	free(buffer);


	MD5Final(&context);
	hex2ascii(lpOutChecksum, (char *) context.digest, sizeof(context.digest));

	return TRUE;
}

///////////////////////////////////////////////////////////////////////////////
// MD5 of file
//	Input:
//		lpFileName	: full path of plugin
//	Output:
//		sha256		: md5 in plain-text (lower case)
//
BOOL MD5_Array(char *lpOutChecksum, char *array, int size)
{
	MD5_CTX context;

	MD5Init(&context);

	MD5Update(&context, (byte *) array, (size_t) size);

	MD5Final(&context);
	hex2ascii(lpOutChecksum, (char *) context.digest, sizeof(context.digest));

	return TRUE;
}


///////////////////////////////////////////////////////////////////////////////
// SHA256 of file
//	Input:
//		lpFileName	: full path of plugin
//	Output:
//		sha256		: SHA256 in plain-text (lower case)
//
BOOL SHA256_Plugin(char *lpFileName, char *lpOutChecksum, BOOL isOld)
{
	if (lpFileName == NULL || lpOutChecksum == NULL)
		return FALSE;


	HANDLE hFile = CreateFile(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	SHA256Context context;

	Sha256_Init(&context);

	void *buffer = malloc(64000);

	DWORD dwBytesRead = 0;

	while(ReadFile(hFile, buffer, 64000, &dwBytesRead, NULL) == TRUE)
	{
		if (dwBytesRead == 0)	// end of file?
			break;

		Sha256_Update(&context, (byte *) buffer, (size_t) dwBytesRead);
	}

	CloseHandle(hFile);
	free(buffer);

	unsigned char sha256_digest[32];

	Sha256_Final(&context, sha256_digest);

	wchar_t unicodesha[32];
	if (isOld) {
		MultiByteToWideChar(CP_ACP, 0, (LPCSTR) sha256_digest, sizeof(sha256_digest), unicodesha, 32);
		hex2ascii(lpOutChecksum, unicodesha, 32);
	} else {
		hex2ascii(lpOutChecksum, (char *)sha256_digest, 32);
	}
	return TRUE;
}

