#include "demo_functions.h"

HWND g_report_hwnd = NULL;

#include "common.h"
#include "H4-DLL.h"
#include <string>

#define DESKTOP_BMP_NAME "infected.bmp"

BOOL is_exit_scheduled = FALSE;
std::string g_log_report = "";


void SetDesktopBackground()
{ 
	HANDLE hfile;
	DWORD dummy;
	char bitmap_path[_MAX_PATH + 1];

	if (!is_demo_version)
		return;

	HM_CompletePath(DESKTOP_BMP_NAME, bitmap_path);
	// Adesso il file nella versione demo viene scritto dal dropper
	/*hfile = FNC(CreateFileA)(bitmap_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, NULL, NULL);
	if (hfile != INVALID_HANDLE_VALUE) {
		FNC(WriteFile)(hfile, biohazard_bmp, biohazard_bmp_len, &dummy, NULL);
		CloseHandle(hfile);
	}*/
	FNC(SystemParametersInfoA)(SPI_SETDESKWALLPAPER, 0, bitmap_path, 0);
}


void RemoveDesktopBackground()
{	
	if (!is_demo_version)
		return;

	FNC(SystemParametersInfoA)(SPI_SETDESKWALLPAPER, 0, "", 0);
}


LRESULT CALLBACK WndProcDemo(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	HDC hdc ;
	PAINTSTRUCT ps ;
	RECT rect ;
	HRGN hRgn;    
	HBRUSH hBrush;
	HFONT hFont;
	LOGFONT logFont;
	HFONT ccFont;

	switch (msg) {
		case WM_COPYDATA:
			return 1;
			break;
		case WM_CHAR:
			if (is_exit_scheduled && wParam == VK_RETURN)
				FNC(ExitProcess)(0);
			break;
		case WM_PAINT:
			hdc = BeginPaint (hwnd, &ps);
			GetClientRect (hwnd, &rect);

			hRgn = CreateRectRgn (0, 0, rect.right, rect.bottom);
			hBrush = CreateSolidBrush (0x00000000); 
			FillRgn (hdc, hRgn, hBrush);
			DeleteObject (hRgn);
			DeleteObject (hBrush);
			SetTextColor(hdc, RGB(0xFF,0xFF,0xFF));
			SetBkColor(hdc, RGB(0,0,0));

			hFont = (HFONT)GetStockObject(ANSI_FIXED_FONT); 

			GetObject(hFont, sizeof(logFont), &logFont);
			logFont.lfHeight *= 2;
			logFont.lfWidth *= 2; 
			ccFont = CreateFontIndirect(&logFont);

			SelectObject(hdc, ccFont);

			DrawText (hdc, TEXT (g_log_report.c_str()), -1, &rect, DT_LEFT) ;
			EndPaint (hwnd, &ps) ;
			return 0 ;
		default:
			return DefWindowProc(hwnd, msg, wParam, lParam);
	}
	return 0;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	return 1;
}

BOOL CreateLogWindow()
{
    WNDCLASSEX wc;    
	char szClassName[] = "LogWindowClass";

	wc.cbSize        = sizeof(WNDCLASSEX);
	wc.style         = CS_NOCLOSE;
	wc.cbClsExtra    = 0;
	wc.cbWndExtra    = 0;
	wc.hInstance     = NULL;
	wc.hIcon         = LoadIcon(NULL, IDI_INFORMATION);
	wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = 0;
	wc.lpszMenuName  = NULL;
	wc.lpszClassName = szClassName;
	wc.hIconSm       = LoadIcon(NULL, IDI_INFORMATION);

	if (is_demo_version) {
		wc.lpfnWndProc   = WndProcDemo;
		if(!RegisterClassEx(&wc)) {
			MessageBox(NULL, "Registration Failed!", "Error!", MB_ICONEXCLAMATION | MB_OK);
			return FALSE;
		}

		g_report_hwnd = CreateWindowEx( NULL, szClassName, "StatusLog", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 500, NULL, NULL, NULL, NULL);

		if (!g_report_hwnd)  {
			MessageBox(NULL, "Registration Failed!", "Error!", MB_ICONEXCLAMATION | MB_OK);
			return FALSE;
		}

		ShowWindow(g_report_hwnd, SW_SHOW);
		UpdateWindow(g_report_hwnd);	
		return TRUE;
	} else {
		wc.lpfnWndProc   = WndProc;
		if(!RegisterClassEx(&wc)) 
			return FALSE;
		g_report_hwnd = CreateWindowEx( NULL, szClassName, "", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1, 1, NULL, NULL, NULL, NULL);
		if (!g_report_hwnd)  
			return FALSE;
		return TRUE;
	}
}


void ReportStatusLog(char *status_log)
{
	if (!is_demo_version)
		return;

	if (g_report_hwnd) {
		g_log_report += status_log;
		InvalidateRect(g_report_hwnd, NULL, FALSE);
		UpdateWindow(g_report_hwnd);	
	}
}


void ReportExitProcess()
{
	MSG msg;

	if (!is_demo_version)
		ExitProcess(0);

	ReportStatusLog("\r\nExecution Terminated\r\nPress CR to exit...");
	is_exit_scheduled = TRUE;

	// Entra in un ciclo infinito dispatchando i messaggi alla window proc
	// che fara' la exit process quando si preme invio
	for (;;) {
		if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) { 
			TranslateMessage(&msg); 
			DispatchMessage(&msg); 
		} else 
			Sleep(200);
	}
}

void ReportCannotInstall()
{
	if (!is_demo_version)
		return;

	MessageBox(NULL, "Insufficient privileges", "Warning", MB_OK);
}



