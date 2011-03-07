extern BOOL IsX64Process(DWORD InProcessId);
extern BOOL IsX64System(void);
extern void Run64Core(void);
extern void Kill64Core(void);
extern DWORD Find32BitProcess(void);
extern void RevertWow64Fs(PVOID OldValue);
extern PVOID DisableWow64Fs();