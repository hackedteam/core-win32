typedef struct {
	DWORD InLoadNext;
	DWORD InLoadPrev;
	DWORD InMemNext;
	DWORD InMemPrev;
	DWORD InInitNext;
	DWORD InInitPrev;
	DWORD ImageBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} PEB_LIST_ENTRY, *PPEB_LIST_ENTRY;

PEB_LIST_ENTRY *GetPEBAdd()
{
	DWORD Loaded_Head;
	DWORD **pPEB;
	DWORD *Ldr;

	__asm {
		MOV EAX,30h
		MOV EAX,DWORD PTR FS:[EAX]
		ADD EAX, 08h
		MOV SS:[pPEB], EAX
	}

	Ldr = *(pPEB + 1);
	Loaded_Head = *(Ldr + 3);
	return (PEB_LIST_ENTRY *)Loaded_Head;
}


// Elimina il modulo hMod
void HidePEB(HMODULE hMod)
{
	PEB_LIST_ENTRY *Depends_List, *List_Head;
	PEB_LIST_ENTRY *prev, *next;

	Depends_List = List_Head = GetPEBAdd();

	do {
		// Ha trovato il modulo
		if (Depends_List->ImageBase == (DWORD)hMod) {
			prev = (PEB_LIST_ENTRY *) Depends_List->InLoadPrev;
			next = (PEB_LIST_ENTRY *) Depends_List->InLoadNext;
			if (prev)
				prev->InLoadNext = (DWORD)next;
			if (next)
				next->InLoadPrev = (DWORD)prev;

			prev = (PEB_LIST_ENTRY *) (Depends_List->InMemPrev - 8);
			next = (PEB_LIST_ENTRY *) (Depends_List->InMemNext - 8);

			if (Depends_List->InMemPrev) {
				if (Depends_List->InMemNext)
					prev->InMemNext = ((DWORD)next) + 8;
				else
					prev->InMemNext = NULL;
			}

			if (Depends_List->InMemNext) {
				if (Depends_List->InMemPrev)
					next->InMemPrev = ((DWORD)prev) + 8;
				else 
					next->InMemPrev = NULL;
			}

			prev = (PEB_LIST_ENTRY *) (Depends_List->InInitPrev - 16);
			next = (PEB_LIST_ENTRY *) (Depends_List->InInitNext - 16);

			if (Depends_List->InInitPrev) {
				if (Depends_List->InInitNext)
					prev->InInitNext = ((DWORD)next) + 16;
				else
					prev->InInitNext = NULL;
			}

			if (Depends_List->InInitNext) {
				if (Depends_List->InInitPrev)
					next->InInitPrev = ((DWORD)prev) + 16;
				else 
					next->InInitPrev = NULL;
			}

			break;			
		}
		Depends_List = (PEB_LIST_ENTRY *)Depends_List->InLoadNext;
	} while(List_Head != Depends_List); 
}



