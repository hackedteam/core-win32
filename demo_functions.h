#include <windows.h>

extern void SetDesktopBackground();
extern void RemoveDesktopBackground();
extern void ReportExitProcess();
extern BOOL CreateLogWindow();
extern void ReportCannotInstall();

extern HWND g_report_hwnd;

#define HANDLE_SENT_MESSAGES(x,y) if (PeekMessage(&x, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&x); DispatchMessage(&x); } else Sleep(y);

#define REPORT_STATUS_LOG(x) ReportStatusLog(x)
extern void ReportStatusLog(char *);
