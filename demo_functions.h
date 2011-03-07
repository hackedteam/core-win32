#define DEMO_VERSION 

#include <windows.h>

extern void SetDesktopBackground();
extern void RemoveDesktopBackground();
extern void ReportExitProcess();
extern BOOL CreateLogWindow();
extern void ReportCannotInstall();


#ifdef DEMO_VERSION
#define REPORT_STATUS_LOG(x) ReportStatusLog(x)
extern void ReportStatusLog(char *);

#define HANDLE_SENT_MESSAGES(x,y) if (PeekMessage(&x, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&x); DispatchMessage(&x); } else Sleep(y);
#else
#define REPORT_STATUS_LOG(x) 
#define HANDLE_SENT_MESSAGES(x,y) PeekMessage(&x, NULL, 0, 0, PM_REMOVE); Sleep(y);
#endif