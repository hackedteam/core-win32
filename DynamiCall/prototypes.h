#ifndef prototypes_h__
#define prototypes_h__

#include <Windows.h>
#include <MMSystem.h>
#include <TlHelp32.h>
#include <WinNls.h>
#include <WinUser.h>
#include <winhttp.h>
#include <lm.h> // for NETAPI32.DLL
#include <Psapi.h>
#include <Wincrypt.h>
#include <OleAcc.h>
#include <ImageHlp.h>
#include <Shlwapi.h>
#include <WinGDI.h>
#include <Sddl.h>
#include <Winsvc.h>
#include <Shlobj.h>
#include <Ole2.h>

/************************************************************************/
/* NETAPI32.DLL                                                         */
/************************************************************************/

typedef NET_API_STATUS (NET_API_FUNCTION *PROTO_NetUserGetInfo)(
							  __in   LPCWSTR servername,
							  __in   LPCWSTR username,
							  __in   DWORD level,
							  __out  LPBYTE *bufptr
							  );

typedef NET_API_STATUS (NET_API_FUNCTION *PROTO_NetApiBufferFree)(
								__in  LPVOID Buffer
								);

/************************************************************************/
/* WINHTTP.DLL                                                          */
/************************************************************************/

typedef BOOL (WINAPI *PROTO_WinHttpGetIEProxyConfigForCurrentUser)(
	__inout  WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *pProxyConfig
	);

typedef BOOL (WINAPI *PROTO_WinHttpReadData)(
							__in   HINTERNET hRequest,
							__out  LPVOID lpBuffer,
							__in   DWORD dwNumberOfBytesToRead,
							__out  LPDWORD lpdwNumberOfBytesRead
							);

typedef BOOL (WINAPI *PROTO_WinHttpReceiveResponse)(
								   __in        HINTERNET hRequest,
								   __reserved  LPVOID lpReserved
								   );

typedef BOOL (WINAPI *PROTO_WinHttpSendRequest)(
							   __in      HINTERNET hRequest,
							   __in_opt  LPCWSTR pwszHeaders,
							   __in      DWORD dwHeadersLength,
							   __in_opt  LPVOID lpOptional,
							   __in      DWORD dwOptionalLength,
							   __in      DWORD dwTotalLength,
							   __in      DWORD_PTR dwContext
							   );

typedef BOOL (WINAPI *PROTO_WinHttpQueryOption)(
							   __in     HINTERNET hInternet,
							   __in     DWORD dwOption,
							   __out    LPVOID lpBuffer,
							   __inout  LPDWORD lpdwBufferLength
							   );

typedef BOOL (WINAPI *PROTO_WinHttpWriteData)(
							 __in   HINTERNET hRequest,
							 __in   LPCVOID lpBuffer,
							 __in   DWORD dwNumberOfBytesToWrite,
							 __out  LPDWORD lpdwNumberOfBytesWritten
							 );

typedef HINTERNET (WINAPI *PROTO_WinHttpOpen)(
							 __in  LPCWSTR pwszUserAgent,
							 __in  DWORD dwAccessType,
							 __in  LPCWSTR pwszProxyName,
							 __in  LPCWSTR pwszProxyBypass,
							 __in  DWORD dwFlags
							 );


typedef BOOL (WINAPI *PROTO_WinHttpSetOption)(
							 __in  HINTERNET hInternet,
							 __in  DWORD dwOption,
							 __in  LPVOID lpBuffer,
							 __in  DWORD dwBufferLength
							 );

typedef BOOL (WINAPI *PROTO_WinHttpAddRequestHeaders)(
									 __in  HINTERNET hRequest,
									 __in  LPCWSTR pwszHeaders,
									 __in  DWORD dwHeadersLength,
									 __in  DWORD dwModifiers
									 );

typedef BOOL (WINAPI *PROTO_WinHttpGetProxyForUrl)(
								  __in   HINTERNET hSession,
								  __in   LPCWSTR lpcwszUrl,
								  __in   WINHTTP_AUTOPROXY_OPTIONS *pAutoProxyOptions,
								  __out  WINHTTP_PROXY_INFO *pProxyInfo
								  );

typedef HINTERNET (WINAPI *PROTO_WinHttpConnect)(
								__in        HINTERNET hSession,
								__in        LPCWSTR pswzServerName,
								__in        INTERNET_PORT nServerPort,
								__reserved  DWORD dwReserved
								);

typedef BOOL (WINAPI *PROTO_WinHttpSetTimeouts)(
							   __in  HINTERNET hInternet,
							   __in  int dwResolveTimeout,
							   __in  int dwConnectTimeout,
							   __in  int dwSendTimeout,
							   __in  int dwReceiveTimeout
							   );

typedef HINTERNET (WINAPI *PROTO_WinHttpOpenRequest)(
									__in  HINTERNET hConnect,
									__in  LPCWSTR pwszVerb,
									__in  LPCWSTR pwszObjectName,
									__in  LPCWSTR pwszVersion,
									__in  LPCWSTR pwszReferrer,
									__in  LPCWSTR *ppwszAcceptTypes,
									__in  DWORD dwFlags
									);

/************************************************************************/
/* PSAPI.DLL                                                            */
/************************************************************************/

typedef DWORD (WINAPI *PROTO_GetModuleFileNameExA)(
								 __in      HANDLE hProcess,
								 __in_opt  HMODULE hModule,
								 __out     LPSTR lpFilename,
								 __in      DWORD nSize
								 );

typedef DWORD (WINAPI *PROTO_GetDeviceDriverBaseNameW)(
									 __in   LPVOID ImageBase,
									 __out  LPWSTR lpBaseName,
									 __in   DWORD nSize
									 );

typedef BOOL (WINAPI *PROTO_EnumDeviceDrivers)(
							  __out  LPVOID *lpImageBase,
							  __in   DWORD cb,
							  __out  LPDWORD lpcbNeeded
							  );

typedef DWORD (WINAPI *PROTO_GetModuleFileNameExW)(
								 __in      HANDLE hProcess,
								 __in_opt  HMODULE hModule,
								 __out     LPWSTR lpFilename,
								 __in      DWORD nSize
								 );

typedef BOOL (WINAPI *PROTO_EnumProcessModules)(
							   __in   HANDLE hProcess,
							   __out  HMODULE *lphModule,
							   __in   DWORD cb,
							   __out  LPDWORD lpcbNeeded
							   );


/************************************************************************/
/* SHLWAPI.dll                                                          */
/************************************************************************/

typedef LPSTR (WINAPI *PROTO_StrRChrA)(__in LPCSTR lpStart, __in_opt LPCSTR lpEnd, __in WORD wMatch);
typedef int (WINAPI *PROTO_wnsprintfW)(__out_ecount(cchLimitIn) LPWSTR lpOut, int cchLimitIn, LPCWSTR lpFmt, ...);

/************************************************************************/
/* WINMM.dll                                                            */
/************************************************************************/

typedef MMRESULT (WINAPI *PROTO_mixerSetControlDetails)( __in_opt HMIXEROBJ hmxobj, __in LPMIXERCONTROLDETAILS pmxcd, __in DWORD fdwDetails);
typedef MMRESULT (WINAPI *PROTO_mixerGetControlDetailsA)( __in_opt HMIXEROBJ hmxobj, __inout LPMIXERCONTROLDETAILS pmxcd, __in DWORD fdwDetails);
typedef MMRESULT (WINAPI *PROTO_mixerGetLineControlsA)( __in_opt HMIXEROBJ hmxobj, __inout LPMIXERLINECONTROLSA pmxlc, __in DWORD fdwControls);
typedef MMRESULT (WINAPI *PROTO_mixerGetLineInfoA)( __in_opt HMIXEROBJ hmxobj, __out LPMIXERLINEA pmxl, __in DWORD fdwInfo);
typedef MMRESULT (WINAPI *PROTO_waveInClose)( __in HWAVEIN hwi);
typedef MMRESULT (WINAPI *PROTO_waveInReset)( __in HWAVEIN hwi);
typedef MMRESULT (WINAPI *PROTO_waveInOpen)( __out_opt LPHWAVEIN phwi, __in UINT uDeviceID,
									__in LPCWAVEFORMATEX pwfx, __in_opt DWORD_PTR dwCallback, __in_opt DWORD_PTR dwInstance, __in DWORD fdwOpen);
typedef MMRESULT (WINAPI *PROTO_mixerOpen)( __out_opt LPHMIXER phmx, __in UINT uMxId, __in_opt DWORD_PTR dwCallback, __in_opt DWORD_PTR dwInstance, __in DWORD fdwOpen);
typedef MMRESULT (WINAPI *PROTO_mixerClose)( __in HMIXER hmx);
typedef MMRESULT (WINAPI *PROTO_mixerGetDevCapsA)( __in UINT_PTR uMxId, __out_bcount(cbmxcaps) LPMIXERCAPSA pmxcaps, __in UINT cbmxcaps);
typedef UINT (WINAPI *PROTO_mixerGetNumDevs)(void);

/************************************************************************/
/* CRYPT32.dll                                                          */
/************************************************************************/

typedef BOOL (WINAPI *PROTO_CertFreeCertificateContext)(
						   __in_opt PCCERT_CONTEXT pCertContext
						   );

typedef BOOL (WINAPI *PROTO_CryptUnprotectData)(
				   IN              DATA_BLOB*      pDataIn,             // in encr blob
				   __deref_opt_out_opt LPWSTR*     ppszDataDescr,       // out
				   IN OPTIONAL     DATA_BLOB*      pOptionalEntropy,
				   __reserved      PVOID           pvReserved,
				   IN OPTIONAL     CRYPTPROTECT_PROMPTSTRUCT*  pPromptStruct,
				   IN              DWORD           dwFlags,
				   OUT             DATA_BLOB*      pDataOut
				   );

/************************************************************************/
/* OLEACC.dll                                                           */
/************************************************************************/

typedef HRESULT (WINAPI *PROTO_AccessibleChildren)(IAccessible* paccContainer, LONG iChildStart,LONG cChildren, VARIANT* rgvarChildren,LONG* pcObtained);
typedef HRESULT (WINAPI *PROTO_AccessibleObjectFromWindow)(HWND hwnd, DWORD dwId, REFIID riid, void **ppvObject);

/************************************************************************/
/* imagehlp.dll                                                         */
/************************************************************************/

typedef BOOL (WINAPI *PROTO_MapAndLoad)(
				__in   PSTR ImageName,
				__in   PSTR DllPath,
				__out  PLOADED_IMAGE LoadedImage,
				__in   BOOL DotDll,
				__in   BOOL ReadOnly
				);

typedef BOOL (WINAPI *PROTO_UnMapAndLoad)(
				  __in  PLOADED_IMAGE LoadedImage
				  );

/************************************************************************/
/* VERSION.DLL                                                          */
/************************************************************************/

typedef BOOL (WINAPI *PROTO_VerQueryValueW)(
						  __in   LPCVOID pBlock,
						  __in   LPCWSTR lpSubBlock,
						  __out  LPVOID *lplpBuffer,
						  __out  PUINT puLen
						  );

typedef DWORD (WINAPI *PROTO_GetFileVersionInfoSizeW)(
									__in       LPCWSTR lptstrFilename,
									__out_opt  LPDWORD lpdwHandle
									);

typedef BOOL (WINAPI *PROTO_GetFileVersionInfoW)(
							   __in        LPCWSTR lptstrFilename,
							   __reserved  DWORD dwHandle,
							   __in        DWORD dwLen,
							   __out       LPVOID lpData
							   );

/************************************************************************/
/* KERNEL32.DLL                                                         */
/************************************************************************/

typedef HANDLE (WINAPI *PROTO_CreateFileMappingA)(
										__in      HANDLE hFile,
										__in_opt  LPSECURITY_ATTRIBUTES lpAttributes,
										__in      DWORD flProtect,
										__in      DWORD dwMaximumSizeHigh,
										__in      DWORD dwMaximumSizeLow,
										__in_opt  LPCSTR lpName
										);

typedef BOOL (WINAPI *PROTO_UnmapViewOfFile)(
									__in  LPCVOID lpBaseAddress
									);

typedef DWORD (WINAPI *PROTO_GetTickCount)(void);

typedef BOOL (WINAPI *PROTO_TerminateProcess)(
									 __in  HANDLE hProcess,
									 __in  UINT uExitCode
									 );

typedef HANDLE (WINAPI *PROTO_CreateFileW)(
								 __in      LPCWSTR lpFileName,
								 __in      DWORD dwDesiredAccess,
								 __in      DWORD dwShareMode,
								 __in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
								 __in      DWORD dwCreationDisposition,
								 __in      DWORD dwFlagsAndAttributes,
								 __in_opt  HANDLE hTemplateFile
								 );

typedef DWORD (WINAPI *PROTO_GetFileSize)(
								 __in       HANDLE hFile,
								 __out_opt  LPDWORD lpFileSizeHigh
								 );

typedef HANDLE (WINAPI *PROTO_OpenProcess)(
								  __in  DWORD dwDesiredAccess,
								  __in  BOOL bInheritHandle,
								  __in  DWORD dwProcessId
								  );

typedef DWORD (WINAPI *PROTO_GetCurrentProcessId)(void);

typedef DWORD (WINAPI *PROTO_GetCurrentProcessId)(void);

typedef UINT (WINAPI *PROTO_GetSystemDirectoryA)(
									   __out  LPSTR lpBuffer,
									   __in   UINT uSize
									   );

typedef DWORD (WINAPI *PROTO_GetEnvironmentVariableW)(
	__in_opt   LPCWSTR lpName,
	__out_opt  LPWSTR lpBuffer,
	__in       DWORD nSize
	);

typedef BOOL (WINAPI *PROTO_FindClose)(
							  __inout  HANDLE hFindFile
							  );

typedef BOOL (WINAPI *PROTO_FindNextFileW)(
								 __in   HANDLE hFindFile,
								 __out  LPWIN32_FIND_DATAW lpFindFileData
								 );

typedef BOOL (WINAPI *PROTO_CopyFileW)(
							 __in  LPCWSTR lpExistingFileName,
							 __in  LPCWSTR lpNewFileName,
							 __in  BOOL bFailIfExists
							 );

typedef BOOL (WINAPI *PROTO_RemoveDirectoryW)(
									__in  LPCWSTR lpPathName
									);

typedef HANDLE (WINAPI *PROTO_FindFirstFileW)(
			   __in  LPCWSTR lpFileName,
			   __out LPWIN32_FIND_DATAW lpFindFileData
			   );

typedef BOOL (WINAPI *PROTO_CreateDirectoryW)(
				 __in     LPCWSTR lpPathName,
				 __in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes
				 );

typedef BOOL (WINAPI *PROTO_WriteFile)(
		  __in        HANDLE hFile,
		  __in_bcount_opt(nNumberOfBytesToWrite) LPCVOID lpBuffer,
		  __in        DWORD nNumberOfBytesToWrite,
		  __out_opt   LPDWORD lpNumberOfBytesWritten,
		  __inout_opt LPOVERLAPPED lpOverlapped
		  );

typedef HANDLE (WINAPI *PROTO_CreateFileA)(
			__in     LPCSTR lpFileName,
			__in     DWORD dwDesiredAccess,
			__in     DWORD dwShareMode,
			__in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes,
			__in     DWORD dwCreationDisposition,
			__in     DWORD dwFlagsAndAttributes,
			__in_opt HANDLE hTemplateFile
			);

typedef VOID (WINAPI *PROTO_ExitProcess)(
			__in UINT uExitCode
			);

typedef UINT (WINAPI *PROTO_GetDriveTypeW)(
			  __in_opt LPCWSTR lpRootPathName
			  );

typedef BOOL (WINAPI *PROTO_ReadFile)(
		 __in        HANDLE hFile,
		 __out_bcount_part_opt(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
		 __in        DWORD nNumberOfBytesToRead,
		 __out_opt   LPDWORD lpNumberOfBytesRead,
		 __inout_opt LPOVERLAPPED lpOverlapped
		 );

typedef DWORD (WINAPI *PROTO_GetModuleFileNameA)(
				   __in_opt HMODULE hModule,
				   __out_ecount_part(nSize, return + 1) LPCH lpFilename,
				   __in     DWORD nSize
				   );

typedef HLOCAL (WINAPI *PROTO_LocalFree)(
		  __deref HLOCAL hMem
		  );

typedef HLOCAL (WINAPI *PROTO_LocalAlloc)(
		   __in UINT uFlags,
		   __in SIZE_T uBytes
		   );

typedef DWORD (WINAPI *PROTO_GetLastError)(VOID);

typedef HANDLE (WINAPI *PROTO_CreateToolhelp32Snapshot)(
						 DWORD dwFlags,
						 DWORD th32ProcessID
						 );

typedef BOOL (WINAPI *PROTO_Process32First)(
			   HANDLE hSnapshot,
			   LPPROCESSENTRY32 lppe
			   );

typedef BOOL (WINAPI *PROTO_Process32Next)(
			  HANDLE hSnapshot,
			  LPPROCESSENTRY32 lppe
			  );

typedef BOOL (WINAPI *PROTO_Module32First)(
			  HANDLE hSnapshot,
			  LPMODULEENTRY32 lpme
			  );

typedef BOOL (WINAPI *PROTO_Module32Next)(
			 HANDLE hSnapshot,
			 LPMODULEENTRY32 lpme
			 );

typedef FARPROC (WINAPI *PROTO_GetProcAddress) (
				__in HMODULE hModule,
				__in LPCSTR lpProcName
				);

typedef HANDLE (WINAPI *PROTO_FindFirstFileA)(
			   __in  LPCSTR lpFileName,
			   __out LPWIN32_FIND_DATAA lpFindFileData
			   );

typedef DWORD (WINAPI *PROTO_GetEnvironmentVariableA)(
						__in_opt LPCSTR lpName,
						__out_ecount_part_opt(nSize, return + 1) LPSTR lpBuffer,
						__in DWORD nSize
						);

typedef BOOL (WINAPI *PROTO_GetFileInformationByHandle)(
						   __in  HANDLE hFile,
						   __out LPBY_HANDLE_FILE_INFORMATION lpFileInformation
						   );

typedef BOOL (WINAPI *PROTO_Process32FirstW)(
				HANDLE hSnapshot,
				LPPROCESSENTRY32W lppe
				);

typedef BOOL (WINAPI *PROTO_Process32NextW)(
			   HANDLE hSnapshot,
			   LPPROCESSENTRY32W lppe
			   );

typedef BOOL (WINAPI *PROTO_FreeLibrary) (
			 __in HMODULE hLibModule
			 );

typedef HANDLE (WINAPI *PROTO_GetCurrentProcess)(VOID);

typedef BOOL (WINAPI *PROTO_GetDiskFreeSpaceExW)(
					__in_opt  LPCWSTR lpDirectoryName,
					__out_opt PULARGE_INTEGER lpFreeBytesAvailableToCaller,
					__out_opt PULARGE_INTEGER lpTotalNumberOfBytes,
					__out_opt PULARGE_INTEGER lpTotalNumberOfFreeBytes
					);

typedef int (WINAPI *PROTO_GetLocaleInfoW)(
			   __in LCID     Locale,
			   __in LCTYPE   LCType,
			   __out_ecount_opt(cchData) LPWSTR  lpLCData,
			   __in int      cchData);

typedef BOOL (WINAPI *PROTO_GlobalMemoryStatusEx)(
					 __out LPMEMORYSTATUSEX lpBuffer
					 );

typedef VOID (WINAPI *PROTO_GetSystemInfo)(
			  __out LPSYSTEM_INFO lpSystemInfo
			  );

typedef BOOL (WINAPI *PROTO_GetSystemPowerStatus)(
					 __out LPSYSTEM_POWER_STATUS lpSystemPowerStatus
					 );

typedef BOOL (WINAPI *PROTO_GetVolumeInformationW)(
					  __in_opt  LPCWSTR lpRootPathName,
					  __out_ecount_opt(nVolumeNameSize) LPWSTR lpVolumeNameBuffer,
					  __in      DWORD nVolumeNameSize,
					  __out_opt LPDWORD lpVolumeSerialNumber,
					  __out_opt LPDWORD lpMaximumComponentLength,
					  __out_opt LPDWORD lpFileSystemFlags,
					  __out_ecount_opt(nFileSystemNameSize) LPWSTR lpFileSystemNameBuffer,
					  __in      DWORD nFileSystemNameSize
					  );

typedef HMODULE (WINAPI *PROTO_LoadLibraryW)(
			 __in LPCWSTR lpLibFileName
			 );

typedef DWORD (WINAPI *PROTO_WaitForSingleObject)(
					__in HANDLE hHandle,
					__in DWORD dwMilliseconds
					);

typedef BOOL (WINAPI *PROTO_SetFileAttributesW)(
				   __in LPCWSTR lpFileName,
				   __in DWORD dwFileAttributes
				   );

typedef VOID (WINAPI *PROTO_SetLastError)(
			 __in DWORD dwErrCode
			 );

typedef SIZE_T (WINAPI *PROTO_VirtualQueryEx)(
			   __in     HANDLE hProcess,
			   __in_opt LPCVOID lpAddress,
			   __out_bcount_part(dwLength, return) PMEMORY_BASIC_INFORMATION lpBuffer,
			   __in     SIZE_T dwLength
			   );

typedef BOOL (WINAPI *PROTO_Module32FirstW)(
			   HANDLE hSnapshot,
			   LPMODULEENTRY32W lpme
			   );

typedef BOOL (WINAPI *PROTO_Module32NextW)(
			  HANDLE hSnapshot,
			  LPMODULEENTRY32W lpme
			  );

typedef int (WINAPI *PROTO_WideCharToMultiByte)(
					__in UINT     CodePage,
					__in DWORD    dwFlags,
					__in_ecount(cchWideChar) LPCWSTR  lpWideCharStr,
					__in int      cchWideChar,
					__out_bcount_opt(cbMultiByte) __transfer(lpWideCharStr) LPSTR   lpMultiByteStr,
					__in int      cbMultiByte,
					__in_opt LPCSTR   lpDefaultChar,
					__out_opt LPBOOL  lpUsedDefaultChar);

typedef DWORD (WINAPI *PROTO_GetShortPathNameW)(
				  __in LPCWSTR lpszLongPath,
				  __out_ecount_part(cchBuffer, return + 1) LPWSTR  lpszShortPath,
				  __in DWORD cchBuffer
				  );

typedef DWORD (WINAPI *PROTO_ExpandEnvironmentStringsW)(
						  __in LPCWSTR lpSrc,
						  __out_ecount_part_opt(nSize, return) LPWSTR lpDst,
						  __in DWORD nSize
						  );

typedef DWORD (WINAPI *PROTO_ExpandEnvironmentStringsA)(
						  __in LPCSTR lpSrc,
						  __out_ecount_part_opt(nSize, return) LPSTR lpDst,
						  __in DWORD nSize
						  );

typedef BOOL (WINAPI *PROTO_VirtualFreeEx)(
			  __in HANDLE hProcess,
			  __in LPVOID lpAddress,
			  __in SIZE_T dwSize,
			  __in DWORD  dwFreeType
			  );

typedef VOID (WINAPI *PROTO_GetSystemTimeAsFileTime)(
						__out LPFILETIME lpSystemTimeAsFileTime
						);

typedef BOOL (WINAPI *PROTO_DeleteFileA)(
			__in LPCSTR lpFileName
			);

typedef BOOL (WINAPI *PROTO_SetFileAttributesA)(
				   __in LPCSTR lpFileName,
				   __in DWORD dwFileAttributes
				   );

typedef DWORD (WINAPI *PROTO_GetLongPathNameA)(
				 __in LPCSTR lpszShortPath,
				 __out_ecount_part(cchBuffer, return + 1) LPSTR  lpszLongPath,
				 __in DWORD cchBuffer
				 );

typedef LPWSTR (WINAPI *PROTO_GetCommandLineW)(VOID);
typedef LPSTR (WINAPI *PROTO_GetCommandLineA)(VOID);

typedef BOOL (WINAPI *PROTO_MoveFileExA)(
			__in     LPCSTR lpExistingFileName,
			__in_opt LPCSTR lpNewFileName,
			__in     DWORD    dwFlags
			);

typedef BOOL (WINAPI *PROTO_GlobalUnlock)(
			 __in HGLOBAL hMem
			 );

typedef HANDLE (WINAPI *PROTO_OpenFileMappingA)(
				 __in DWORD dwDesiredAccess,
				 __in BOOL bInheritHandle,
				 __in LPCSTR lpName
				 );

typedef BOOL (WINAPI *PROTO_CopyFileA)(
		  __in LPCSTR lpExistingFileName,
		  __in LPCSTR lpNewFileName,
		  __in BOOL bFailIfExists
		  );

typedef BOOL (WINAPI *PROTO_FindNextFileA)(
			  __in  HANDLE hFindFile,
			  __out LPWIN32_FIND_DATAA lpFindFileData
			  );

typedef BOOL (WINAPI *PROTO_GetDiskFreeSpaceExA)(
					__in_opt  LPCSTR lpDirectoryName,
					__out_opt PULARGE_INTEGER lpFreeBytesAvailableToCaller,
					__out_opt PULARGE_INTEGER lpTotalNumberOfBytes,
					__out_opt PULARGE_INTEGER lpTotalNumberOfFreeBytes
					);

typedef DWORD (WINAPI *PROTO_SetFilePointer)(
			   __in        HANDLE hFile,
			   __in        LONG lDistanceToMove,
			   __inout_opt PLONG lpDistanceToMoveHigh,
			   __in        DWORD dwMoveMethod
			   );

typedef BOOL (WINAPI *PROTO_IsDebuggerPresent)(
				  VOID
				  );

typedef BOOL (WINAPI *PROTO_GetFileTime)(
			__in      HANDLE hFile,
			__out_opt LPFILETIME lpCreationTime,
			__out_opt LPFILETIME lpLastAccessTime,
			__out_opt LPFILETIME lpLastWriteTime
			);

typedef HGLOBAL (WINAPI *PROTO_GlobalFree)(
		   __deref HGLOBAL hMem
		   );

typedef HMODULE (WINAPI *PROTO_LoadLibraryExA)(
			   __in       LPCSTR lpLibFileName,
			   __reserved HANDLE hFile,
			   __in       DWORD dwFlags
			   );

typedef HGLOBAL (WINAPI *PROTO_GlobalAlloc) (
			 __in UINT uFlags,
			 __in SIZE_T dwBytes
			 );

typedef BOOL (WINAPI *PROTO_DeviceIoControl)(
				__in        HANDLE hDevice,
				__in        DWORD dwIoControlCode,
				__in_bcount_opt(nInBufferSize) LPVOID lpInBuffer,
				__in        DWORD nInBufferSize,
				__out_bcount_part_opt(nOutBufferSize, *lpBytesReturned) LPVOID lpOutBuffer,
				__in        DWORD nOutBufferSize,
				__out_opt   LPDWORD lpBytesReturned,
				__inout_opt LPOVERLAPPED lpOverlapped
				);

typedef BOOL (WINAPI *PROTO_VirtualFree)(
			__in LPVOID lpAddress,
			__in SIZE_T dwSize,
			__in DWORD dwFreeType
			);

typedef BOOL (WINAPI *PROTO_VirtualProtectEx)(
				 __in  HANDLE hProcess,
				 __in  LPVOID lpAddress,
				 __in  SIZE_T dwSize,
				 __in  DWORD flNewProtect,
				 __out PDWORD lpflOldProtect
				 );

typedef BOOL (WINAPI *PROTO_WriteProcessMemory)(
				   __in      HANDLE hProcess,
				   __in      LPVOID lpBaseAddress,
				   __in_bcount(nSize) LPCVOID lpBuffer,
				   __in      SIZE_T nSize,
				   __out_opt SIZE_T * lpNumberOfBytesWritten
				   );

typedef BOOL (WINAPI *PROTO_ReadProcessMemory)(
				  __in      HANDLE hProcess,
				  __in      LPCVOID lpBaseAddress,
				  __out_bcount_part(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
				  __in      SIZE_T nSize,
				  __out_opt SIZE_T * lpNumberOfBytesRead
				  );

typedef HANDLE (WINAPI *PROTO_CreateRemoteThread)(
				   __in      HANDLE hProcess,
				   __in_opt  LPSECURITY_ATTRIBUTES lpThreadAttributes,
				   __in      SIZE_T dwStackSize,
				   __in      LPTHREAD_START_ROUTINE lpStartAddress,
				   __in_opt  LPVOID lpParameter,
				   __in      DWORD dwCreationFlags,
				   __out_opt LPDWORD lpThreadId
				   );

typedef BOOL (WINAPI *PROTO_SystemTimeToFileTime)(
					 __in  CONST SYSTEMTIME *lpSystemTime,
					 __out LPFILETIME lpFileTime
					 );

typedef VOID (WINAPI *PROTO_GetSystemTime)(
			  __out LPSYSTEMTIME lpSystemTime
			  );

typedef BOOL (WINAPI *PROTO_FlushFileBuffers)(
			__in  HANDLE hFile
			);

typedef int (WINAPI *PROTO_lstrcmpA)(
						   __in  LPCSTR lpString1,
						   __in  LPCSTR lpString2
						   );

typedef DWORD (WINAPI *PROTO_GetFileAttributesW)(
									   __in  LPCWSTR lpFileName
									   );

typedef int (WINAPI *PROTO_MultiByteToWideChar)(
					__in UINT     CodePage,
					__in DWORD    dwFlags,
					__in_bcount(cbMultiByte) LPCSTR   lpMultiByteStr,
					__in int      cbMultiByte,
					__out_ecount_opt(cchWideChar) __transfer(lpMultiByteStr) LPWSTR  lpWideCharStr,
					__in int      cchWideChar);

typedef DWORD (WINAPI *PROTO_GetPrivateProfileStringW)(
						 __in_opt LPCWSTR lpAppName,
						 __in_opt LPCWSTR lpKeyName,
						 __in_opt LPCWSTR lpDefault,
						 __out_ecount_part_opt(nSize, return + 1) LPWSTR lpReturnedString,
						 __in     DWORD nSize,
						 __in_opt LPCWSTR lpFileName
						 );

typedef LPSTR (WINAPI *PROTO_lstrcatA)(
		 __inout LPSTR lpString1,
		 __in    LPCSTR lpString2
		 );

typedef LPSTR (WINAPI *PROTO_lstrcpyA)(
		 __out LPSTR lpString1,
		 __in  LPCSTR lpString2
		 );

typedef int (WINAPI *PROTO_lstrcmpW)(
		 __in LPCWSTR lpString1,
		 __in LPCWSTR lpString2
		 );

typedef BOOL (WINAPI *PROTO_GetVolumeInformationA)(
					  __in_opt  LPCSTR lpRootPathName,
					  __out_ecount_opt(nVolumeNameSize) LPSTR lpVolumeNameBuffer,
					  __in      DWORD nVolumeNameSize,
					  __out_opt LPDWORD lpVolumeSerialNumber,
					  __out_opt LPDWORD lpMaximumComponentLength,
					  __out_opt LPDWORD lpFileSystemFlags,
					  __out_ecount_opt(nFileSystemNameSize) LPSTR lpFileSystemNameBuffer,
					  __in      DWORD nFileSystemNameSize
					  );

typedef BOOL (WINAPI *PROTO_SetFileTime)(
			__in     HANDLE hFile,
			__in_opt CONST FILETIME *lpCreationTime,
			__in_opt CONST FILETIME *lpLastAccessTime,
			__in_opt CONST FILETIME *lpLastWriteTime
			);

typedef BOOL (WINAPI *PROTO_IsBadStringPtrW)(
				__in_opt LPCWSTR lpsz,
				__in     UINT_PTR ucchMax
				);

typedef LPVOID (WINAPI *PROTO_MapViewOfFile)(
			  __in HANDLE hFileMappingObject,
			  __in DWORD dwDesiredAccess,
			  __in DWORD dwFileOffsetHigh,
			  __in DWORD dwFileOffsetLow,
			  __in SIZE_T dwNumberOfBytesToMap
			  );

typedef BOOL (WINAPI *PROTO_DeleteFileW)(
			__in LPCWSTR lpFileName
			);

/************************************************************************/
/* USER32.DLL                                                           */
/************************************************************************/

typedef int (WINAPI *PROTO_MessageBoxA)(
										__in_opt HWND hWnd,
										__in_opt LPCSTR lpText,
										__in_opt LPCSTR lpCaption,
										__in UINT uType);

typedef int (WINAPI *PROTO_ToUnicode)(
		  __in UINT wVirtKey,
		  __in UINT wScanCode,
		  __in_bcount_opt(256) CONST BYTE *lpKeyState,
		  __out_ecount(cchBuff) LPWSTR pwszBuff,
		  __in int cchBuff,
		  __in UINT wFlags);

typedef BOOL (WINAPI *PROTO_EnumChildWindows)(
				 __in_opt HWND hWndParent,
				 __in WNDENUMPROC lpEnumFunc,
				 __in LPARAM lParam);

typedef int (WINAPI *PROTO_GetClassNameW)(
			  __in HWND hWnd,
			  __out_ecount_part(nMaxCount, return) LPWSTR lpClassName,
			  __in int nMaxCount
			  );

typedef UINT (WINAPI *PROTO_RegisterWindowMessageW)(
					   __in LPCWSTR lpString); 

typedef int (WINAPI *PROTO_GetKeyNameTextW)(
				__in LONG lParam,
				__out_ecount(cchSize) LPWSTR lpString,
				__in int cchSize);

typedef BOOL (WINAPI *PROTO_CloseClipboard)(VOID);
typedef HANDLE (WINAPI *PROTO_GetClipboardData)(__in UINT uFormat);
typedef BOOL (WINAPI *PROTO_OpenClipboard)(__in_opt HWND hWndNewOwner);
typedef BOOL (WINAPI *PROTO_EnumWindows)(__in WNDENUMPROC lpEnumFunc, __in LPARAM lParam);
typedef BOOL (WINAPI *PROTO_IsWindow)(__in_opt HWND hWnd);
typedef HWND (WINAPI *PROTO_FindWindowExW)(
			  __in_opt HWND hWndParent,
			  __in_opt HWND hWndChildAfter,
			  __in_opt LPCWSTR lpszClass,
			  __in_opt LPCWSTR lpszWindow);

typedef LRESULT (WINAPI *PROTO_SendMessageTimeoutW)(
					__in HWND hWnd,
					__in UINT Msg,
					__in WPARAM wParam,
					__in LPARAM lParam,
					__in UINT fuFlags,
					__in UINT uTimeout,
					__out_opt PDWORD_PTR lpdwResult);

typedef int (WINAPI *PROTO_GetWindowTextW)(
			   __in HWND hWnd,
			   __out_ecount(nMaxCount) LPWSTR lpString,
			   __in int nMaxCount);

typedef int (WINAPI *PROTO_GetWindowTextA)(
			   __in HWND hWnd,
			   __out_ecount(nMaxCount) LPSTR lpString,
			   __in int nMaxCount);

typedef BOOL (WINAPI *PROTO_SystemParametersInfoA)(
					  __in UINT uiAction,
					  __in UINT uiParam,
					  __inout_opt PVOID pvParam,
					  __in UINT fWinIni);

typedef HWND (WINAPI *PROTO_GetForegroundWindow)(VOID);
typedef HWND (WINAPI *PROTO_GetDesktopWindow)(VOID);
typedef BOOL (WINAPI *PROTO_GetWindowInfo)(__in HWND hwnd, __inout PWINDOWINFO pwi);
typedef DWORD (WINAPI *PROTO_GetWindowThreadProcessId)(
						 __in HWND hWnd,
						 __out_opt LPDWORD lpdwProcessId);

/************************************************************************/
/* GDI32.dll                                                            */
/************************************************************************/

typedef int (WINAPI *PROTO_GetDIBits)( __in HDC hdc, __in HBITMAP hbm, __in UINT start, __in UINT cLines,  __out_opt LPVOID lpvBits, __inout_xcount(sizeof(BITMAPINFOHEADER)) LPBITMAPINFO lpbmi, __in UINT usage);  // SAL actual size of lpbmi is computed from structure elements

/************************************************************************/
/* ADVAPI32.dll                                                         */
/************************************************************************/

typedef BOOL (WINAPI *PROTO_SetSecurityDescriptorSacl) (
						   __inout  PSECURITY_DESCRIPTOR pSecurityDescriptor,
						   __in     BOOL bSaclPresent,
						   __in_opt PACL pSacl,
						   __in     BOOL bSaclDefaulted
						   );

typedef LSTATUS (APIENTRY *PROTO_RegOpenKeyA) (
			 __in HKEY hKey,
			 __in_opt LPCSTR lpSubKey,
			 __out PHKEY phkResult
			 );

typedef LSTATUS (APIENTRY *PROTO_RegQueryValueExA) (
				  __in HKEY hKey,
				  __in_opt LPCSTR lpValueName,
				  __reserved LPDWORD lpReserved,
				  __out_opt LPDWORD lpType,
				  __out_bcount_part_opt(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
				  __inout_opt LPDWORD lpcbData
				  );

typedef LSTATUS (APIENTRY *PROTO_RegCreateKeyA) (
			   __in HKEY hKey,
			   __in_opt LPCSTR lpSubKey,
			   __out PHKEY phkResult
			   );

typedef BOOL (WINAPI *PROTO_LookupAccountSidA)(
				  __in_opt LPCSTR lpSystemName,
				  __in PSID Sid,
				  __out_ecount_part_opt(*cchName, *cchName + 1) LPSTR Name,
				  __inout  LPDWORD cchName,
				  __out_ecount_part_opt(*cchReferencedDomainName, *cchReferencedDomainName + 1) LPSTR ReferencedDomainName,
				  __inout LPDWORD cchReferencedDomainName,
				  __out PSID_NAME_USE peUse
				  );

typedef BOOL (WINAPI *PROTO_GetUserNameA) (
			  __out_ecount_part_opt(*pcbBuffer, *pcbBuffer) LPSTR lpBuffer,
			  __inout LPDWORD pcbBuffer
			  );

typedef LSTATUS (APIENTRY *PROTO_RegLoadKeyW) (
			 __in HKEY    hKey,
			 __in_opt LPCWSTR  lpSubKey,
			 __in LPCWSTR  lpFile
			 );

typedef LSTATUS (APIENTRY *PROTO_RegCreateKeyW) (
			   __in HKEY hKey,
			   __in_opt LPCWSTR lpSubKey,
			   __out PHKEY phkResult
			   );

typedef LSTATUS (APIENTRY *PROTO_RegSetValueExA) (
				__in HKEY hKey,
				__in_opt LPCSTR lpValueName,
				__reserved DWORD Reserved,
				__in DWORD dwType,
				__in_bcount_opt(cbData) CONST BYTE* lpData,
				__in DWORD cbData
				);

typedef LSTATUS (APIENTRY *PROTO_RegUnLoadKeyW) (
			   __in HKEY    hKey,
			   __in_opt LPCWSTR lpSubKey
			   );

typedef LSTATUS (APIENTRY *PROTO_RegOpenKeyW) (
			 __in HKEY hKey,
			 __in_opt LPCWSTR lpSubKey,
			 __out PHKEY phkResult
			 );

typedef LSTATUS (APIENTRY *PROTO_RegEnumKeyW) (
			 __in HKEY hKey,
			 __in DWORD dwIndex,
			 __out_ecount_part_opt(cchName,cchName + 1) LPWSTR lpName,
			 __in DWORD cchName
			 );

typedef BOOL (WINAPI *PROTO_OpenProcessToken) (
				  __in        HANDLE ProcessHandle,
				  __in        DWORD DesiredAccess,
				  __deref_out PHANDLE TokenHandle
				  );

typedef BOOL (WINAPI *PROTO_LookupPrivilegeValueA)(
					  __in_opt LPCSTR lpSystemName,
					  __in     LPCSTR lpName,
					  __out    PLUID   lpLuid
					  );

typedef BOOL (WINAPI *PROTO_AdjustTokenPrivileges) (
					   __in      HANDLE TokenHandle,
					   __in      BOOL DisableAllPrivileges,
					   __in_opt  PTOKEN_PRIVILEGES NewState,
					   __in      DWORD BufferLength,
					   __out_bcount_part_opt(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
					   __out_opt PDWORD ReturnLength
					   );

typedef LSTATUS (APIENTRY *PROTO_RegOpenKeyExW) (
			   __in HKEY hKey,
			   __in_opt LPCWSTR lpSubKey,
			   __reserved DWORD ulOptions,
			   __in REGSAM samDesired,
			   __out PHKEY phkResult
			   );

typedef LSTATUS (APIENTRY *PROTO_RegQueryValueExW) (
				  __in HKEY hKey,
				  __in_opt LPCWSTR lpValueName,
				  __reserved LPDWORD lpReserved,
				  __out_opt LPDWORD lpType,
				  __out_bcount_part_opt(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
				  __inout_opt LPDWORD lpcbData
				  );

typedef LSTATUS (APIENTRY *PROTO_RegCloseKey) (
			 __in HKEY hKey
			 );

typedef BOOL (WINAPI *PROTO_GetSecurityDescriptorSacl) (
						   __in        PSECURITY_DESCRIPTOR pSecurityDescriptor,
						   __out       LPBOOL lpbSaclPresent,
						   __deref_out PACL *pSacl,
						   __out       LPBOOL lpbSaclDefaulted
						   );

typedef BOOL (WINAPI *PROTO_ConvertStringSecurityDescriptorToSecurityDescriptorA)(
	IN  LPCSTR StringSecurityDescriptor,
	IN  DWORD StringSDRevision,
	OUT PSECURITY_DESCRIPTOR  *SecurityDescriptor,
	OUT PULONG  SecurityDescriptorSize OPTIONAL
	);

typedef BOOL (WINAPI *PROTO_SetSecurityDescriptorDacl) (
						   __inout  PSECURITY_DESCRIPTOR pSecurityDescriptor,
						   __in     BOOL bDaclPresent,
						   __in_opt PACL pDacl,
						   __in     BOOL bDaclDefaulted
						   );

typedef BOOL (WINAPI *PROTO_InitializeSecurityDescriptor) (
							  __out PSECURITY_DESCRIPTOR pSecurityDescriptor,
							  __in  DWORD dwRevision
							  );

typedef BOOL (WINAPI *PROTO_CloseEventLog) (
			   __in HANDLE hEventLog
			   );

typedef HANDLE (WINAPI *PROTO_OpenEventLogA) (
			   __in_opt LPCSTR lpUNCServerName,
			   __in     LPCSTR lpSourceName
			   );

typedef BOOL (WINAPI *PROTO_GetOldestEventLogRecord) (
						 __in  HANDLE hEventLog,
						 __out PDWORD OldestRecord
						 );

typedef BOOL (WINAPI *PROTO_GetNumberOfEventLogRecords) (
							__in  HANDLE hEventLog,
							__out PDWORD NumberOfRecords
							);

typedef BOOL (WINAPI *PROTO_ReadEventLogA) (
			   __in  HANDLE     hEventLog,
			   __in  DWORD      dwReadFlags,
			   __in  DWORD      dwRecordOffset,
			   __out_bcount_part(nNumberOfBytesToRead, *pnBytesRead) LPVOID     lpBuffer,
			   __in  DWORD      nNumberOfBytesToRead,
			   __out DWORD      *pnBytesRead,
			   __out DWORD      *pnMinNumberOfBytesNeeded
			   );

typedef BOOL (WINAPI *PROTO_CloseServiceHandle)(
									   __in        SC_HANDLE   hSCObject
									   );

typedef SC_HANDLE (WINAPI *PROTO_OpenSCManagerA)(
			   __in_opt        LPCSTR                lpMachineName,
			   __in_opt        LPCSTR                lpDatabaseName,
			   __in            DWORD                   dwDesiredAccess
			   );

typedef BOOL (WINAPI *PROTO_StartServiceA)(
			  __in            SC_HANDLE            hService,
			  __in            DWORD                dwNumServiceArgs,
			  __in_ecount_opt(dwNumServiceArgs)       
			  LPCSTR             *lpServiceArgVectors
			  );

typedef SC_HANDLE (WINAPI *PROTO_CreateServiceW)(
			   __in        SC_HANDLE    hSCManager,
			   __in        LPCWSTR     lpServiceName,
			   __in_opt    LPCWSTR     lpDisplayName,
			   __in        DWORD        dwDesiredAccess,
			   __in        DWORD        dwServiceType,
			   __in        DWORD        dwStartType,
			   __in        DWORD        dwErrorControl,
			   __in_opt    LPCWSTR     lpBinaryPathName,
			   __in_opt    LPCWSTR     lpLoadOrderGroup,
			   __out_opt   LPDWORD      lpdwTagId,
			   __in_opt    LPCWSTR     lpDependencies,
			   __in_opt    LPCWSTR     lpServiceStartName,
			   __in_opt    LPCWSTR     lpPassword
			   );

typedef LSTATUS (APIENTRY *PROTO_RegOpenKeyExA)(
			   __in HKEY hKey,
			   __in_opt LPCSTR lpSubKey,
			   __reserved DWORD ulOptions,
			   __in REGSAM samDesired,
			   __out PHKEY phkResult
			   );

typedef LSTATUS (APIENTRY *PROTO_RegEnumValueA) (
			   __in HKEY hKey,
			   __in DWORD dwIndex,
			   __out_ecount_part_opt(*lpcchValueName, *lpcchValueName + 1) LPSTR lpValueName,
			   __inout LPDWORD lpcchValueName,
			   __reserved LPDWORD lpReserved,
			   __out_opt LPDWORD lpType,
			   __out_bcount_part_opt(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
			   __inout_opt LPDWORD lpcbData
			   );

typedef LSTATUS (APIENTRY *PROTO_RegEnumKeyExA) (
			   __in HKEY hKey,
			   __in DWORD dwIndex,
			   __out_ecount_part_opt(*lpcchName, *lpcchName + 1) LPSTR lpName,
			   __inout LPDWORD lpcchName,
			   __reserved LPDWORD lpReserved,
			   __out_ecount_part_opt(*lpcchClass,*lpcchClass + 1) LPSTR lpClass,
			   __inout_opt LPDWORD lpcchClass,
			   __out_opt PFILETIME lpftLastWriteTime
			   );

typedef LSTATUS (APIENTRY *PROTO_RegDeleteValueA) (
				 __in HKEY hKey,
				 __in_opt LPCSTR lpValueName
				 );

typedef PDWORD (WINAPI *PROTO_GetSidSubAuthority) (
					__in PSID pSid,
					__in DWORD nSubAuthority
					);


typedef PUCHAR (WINAPI *PROTO_GetSidSubAuthorityCount) (
						 __in PSID pSid
						 );

typedef BOOL (WINAPI *PROTO_GetTokenInformation) (
					 __in      HANDLE TokenHandle,
					 __in      TOKEN_INFORMATION_CLASS TokenInformationClass,
					 __out_bcount_part_opt(TokenInformationLength, *ReturnLength) LPVOID TokenInformation,
					 __in      DWORD TokenInformationLength,
					 __out     PDWORD ReturnLength
					 );

typedef BOOL (WINAPI *PROTO_ConvertSidToStringSidW)(
					   IN  PSID     Sid,
					   __out_ecount(1) LPWSTR  *StringSid
					   );

typedef LSTATUS (APIENTRY *PROTO_RegSetValueExW) (
				__in HKEY hKey,
				__in_opt LPCWSTR lpValueName,
				__reserved DWORD Reserved,
				__in DWORD dwType,
				__in_bcount_opt(cbData) CONST BYTE* lpData,
				__in DWORD cbData
				);

typedef BOOL (WINAPI *PROTO_GetUserNameW) (
			  __out_ecount_part_opt(*pcbBuffer, *pcbBuffer) LPWSTR lpBuffer,
			  __inout LPDWORD pcbBuffer
			  );

typedef LSTATUS (APIENTRY *PROTO_RegEnumKeyExW) (
			   __in HKEY hKey,
			   __in DWORD dwIndex,
			   __out_ecount_part_opt(*lpcchName, *lpcchName + 1) LPWSTR lpName,
			   __inout LPDWORD lpcchName,
			   __reserved LPDWORD lpReserved,
			   __out_ecount_part_opt(*lpcchClass,*lpcchClass + 1) LPWSTR lpClass,
			   __inout_opt LPDWORD lpcchClass,
			   __out_opt PFILETIME lpftLastWriteTime
			   );

typedef BOOL (WINAPI *PROTO_ConvertSidToStringSidA)(
					   IN  PSID     Sid,
					   __out_ecount(1) LPSTR  *StringSid
					   );

/************************************************************************/
/* SHELL32.dll                                                          */
/************************************************************************/

typedef BOOL (WINAPI *PROTO_SHGetSpecialFolderPathW)(
						HWND hwnd, 
						__out_ecount(MAX_PATH) LPWSTR pszPath, 
						int csidl, 
						BOOL fCreate);

/************************************************************************/
/* OLE32.dll                                                            */
/************************************************************************/

typedef HRESULT (WINAPI *PROTO_CreateStreamOnHGlobal) (IN HGLOBAL hGlobal, IN BOOL fDeleteOnRelease,
										 OUT LPSTREAM FAR* ppstm);

#endif // prototypes_h__