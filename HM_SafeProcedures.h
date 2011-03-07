#include <windows.h>

extern BOOL WINAPI HM_SafeReadProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
extern BOOL WINAPI HM_SafeWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
extern HANDLE WINAPI HM_SafeCreateRemoteThread(HANDLE hProcessRem, 
								 LPSECURITY_ATTRIBUTES lpThreadAttributes,
								 SIZE_T dwStackSize,
								 LPTHREAD_START_ROUTINE lpStartAddress,
								 LPVOID lpParameter,
								 DWORD dwCreationFlags,
								 LPDWORD lpThreadId);
extern HANDLE WINAPI HM_SafeCreateThread(	LPSECURITY_ATTRIBUTES lpThreadAttributes,
									SIZE_T dwStackSize,
									LPTHREAD_START_ROUTINE lpStartAddress,
									LPVOID lpParameter,
									DWORD dwCreationFlags,
									LPDWORD lpThreadId);
extern void *HM_SafeGetProcAddress(HMODULE hModule, char *func_to_search);
extern LPVOID WINAPI HM_SafeVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
extern int WINAPI HM_SafeGetWindowTextW(HWND hWnd, LPWSTR lpString, int nMaxCount);
extern int WINAPI HM_SafeGetWindowTextA(HWND hWnd, LPSTR lpString, int nMaxCount);
extern LRESULT WINAPI HM_SafeSendMessageTimeoutW(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam, UINT fuflags, UINT utimeout, PDWORD_PTR lpdwresult);
extern BOOL WINAPI HM_SafeVirtualProtectEx(HANDLE hProcess, LPVOID lpBaseAddress, SIZE_T nSize, DWORD flNewProtect, PDWORD lpflOldProtect);
