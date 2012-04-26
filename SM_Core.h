extern void SM_StartMonitorEvents(void);
extern void SM_EventTableState(DWORD event_id, BOOL state);
extern void CreateRepeatThread(DWORD event_id, DWORD repeat_action, DWORD count, DWORD delay);
extern void StopRepeatThread(DWORD event_id);


typedef struct {
	DWORD start_action;
	DWORD stop_action;
	DWORD repeat_action;
	DWORD count;
	DWORD delay;
} event_param_struct;