#include <windows.h>
#include <stdio.h>
#include "HashUtil.h"
#include "KeyGen_SBOX.h"

void StrToUpperCase(char *lpOutString, char *lpInString)
{
	while(*lpInString != 0x00)
		*lpOutString++ = toupper(*lpInString++);
}

void StrToLowerCase(char *lpOutString, char *lpInString)
{
	while(*lpInString != 0x00)
		*lpOutString++ = tolower(*lpInString++);
}

///////////////////////////////////////////////////////////////////////////////
// Skype ACL KeyGen
// Input: 
//		lpUserName	: skype accountname
//		lpFileName	: full path of plugin
// Output: All fields are encrypted!
//		lpOutKey1	: Key1
//		lpOutKey2	: Key2
//		lpOutKey3	: Key3
//		lpOutKey4	: Key4
//		lpOutPath	: Path
//
BOOL SkypeACLKeyGen(char *lpUserName, char *lpFileName, char *lpOutKey1, char *lpOutKey2, char *lpOutKey3, char *lpOutKey4, char *lpOutKey5, char *lpOutKey6, char *lpOutPath, BOOL isOld)
{
	char szPluginDigest_SHA256[(32*2) * 2];
	char szPluginDigest_MD5[17 * 2];
	char *szPassphrase1 = "Element'ry!penguiNs;-)SingingHarekrishna_";
	char *szPassphrase2 = "Element'ry!penguiNs;-)SingingHareKrishna_";

	const int username_len = strlen(lpUserName);

	SHA256_Plugin(lpFileName, szPluginDigest_SHA256, isOld);
	MD5_Plugin(lpFileName, szPluginDigest_MD5);
	
	char *szUSERNAME = (char *) malloc(strlen(lpUserName)+1);
	char *szFILENAME = (char *) malloc(strlen(lpFileName)+1);

	RtlZeroMemory(szUSERNAME, strlen(lpUserName)+1);
	RtlZeroMemory(szFILENAME, strlen(lpFileName)+1);

	StrToUpperCase(szFILENAME, lpFileName);
	StrToUpperCase(szUSERNAME, lpUserName);

	char *result = NULL;
	char temp[512];

	char tmp[1024];

	// /Client/Key1
	char _md5_filename[MD5_DIGEST_SIZE * 2 + 1];

	char _md5_key1_0[MD5_DIGEST_SIZE * 2 + 1];
	char _md5_key1_1[MD5_DIGEST_SIZE * 2 + 1];
	char _md5_key1[MD5_DIGEST_SIZE * 4 + 1];

	char passSBOX[4][MD5_DIGEST_SIZE*2+1];

	RtlZeroMemory(_md5_filename, MD5_DIGEST_SIZE * 2 + 1);

	MD5_Array(_md5_filename, szFILENAME, strlen(szFILENAME));

	if(isOld) {
		sprintf(tmp, "%s%s", _md5_filename, szPassphrase1);
		MD5_Array(_md5_key1_0, tmp, strlen(tmp));
		sprintf(tmp, "%s%s", szPluginDigest_MD5, szPassphrase1);
		MD5_Array(_md5_key1_1, tmp, strlen(tmp));
	} else {
		sprintf(tmp, "%s%s", _md5_filename, szPassphrase2);
		MD5_Array(_md5_key1_0, tmp, strlen(tmp));
		sprintf(tmp, "%s%s", szPluginDigest_MD5, szPassphrase2);
		MD5_Array(_md5_key1_1, tmp, strlen(tmp));
	}
	sprintf(_md5_key1, "%s%s", _md5_key1_0, _md5_key1_1);

	// Encrypt sha256 /Client/Key1
	result = Encrypt(lpUserName, _md5_key1);
	RtlCopyMemory(lpOutKey1, result, strlen(result));
	free(result);

	//// Encrypt sha256 /Client/Key2
	//sprintf(tmp, "%s%s%s%s", szUSERNAME, "ke:", szFILENAME, "1a");
	//RtlZeroMemory(temp, sizeof(temp));
	//MD5_Array(temp, tmp, strlen(tmp));
	//result = Encrypt(lpUserName, temp);
	//RtlCopyMemory(lpOutKey2, result, strlen(result));
	//free(result);

	// generate all keys to find correct!
	sprintf(tmp, "%s%s%s%s", szUSERNAME, "ke:", szFILENAME, "1a");
	RtlZeroMemory(temp, sizeof(temp));
	MD5_Array(passSBOX[0], tmp, strlen(tmp));
	
	sprintf(tmp, "%s%s%s%s", "1u", szFILENAME, "ba", szUSERNAME);
	RtlZeroMemory(temp, sizeof(temp));
	MD5_Array(passSBOX[1], tmp, strlen(tmp));

	sprintf(tmp, "%s%s%s%s", "ky", szUSERNAME, "s1", szFILENAME);
	RtlZeroMemory(temp, sizeof(temp));
	MD5_Array(passSBOX[2], tmp, strlen(tmp));

	sprintf(tmp, "%s%s%s%s", "p0", szUSERNAME, "1e", szFILENAME);
	RtlZeroMemory(temp, sizeof(temp));
	MD5_Array(passSBOX[3], tmp, strlen(tmp));

	// Encrypt sha256 /Client/Key2
	result = Encrypt(lpUserName, passSBOX[1]);
	RtlCopyMemory(lpOutKey2, result, strlen(result));
	free(result);

	// Encrypt sha256 /Client/Key3
	result = Encrypt(lpUserName, passSBOX[3]);
	RtlCopyMemory(lpOutKey3, result, strlen(result));
	free(result);

	// Encrypt sha256 /Client/Key4
	RtlZeroMemory(temp, sizeof(temp));
	StrToUpperCase(temp, szPluginDigest_SHA256);
	result = Encrypt(lpUserName, temp);
	RtlCopyMemory(lpOutKey4, result, strlen(result)+1);
	free(result);

	// Encrypt path	//Client/Path
	result = Encrypt(lpUserName, lpFileName);
	RtlCopyMemory(lpOutPath, result, strlen(result));
	free(result);

	// encrypt date
	char today[32];
	SYSTEMTIME sys_time;
	GetSystemTime(&sys_time);
	GetDateFormatA(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &sys_time, NULL, today, sizeof(today));

	char count[4];
	count[0] = '3';
	count[1] = 0x00;
	count[2] = 0x00;
	count[3] = 0x00;

	result = Encrypt(lpUserName, today);
	RtlCopyMemory(lpOutKey5, result, strlen(result));
	free(result);

	result = Encrypt(lpUserName, count);
	RtlCopyMemory(lpOutKey6, result, strlen(result));
	free(result);

	free(szUSERNAME);
	free(szFILENAME);

	return TRUE;
}