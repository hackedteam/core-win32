extern BOOL ExploreDirectory(HANDLE hdest, WCHAR *start_path, DWORD depth);
extern WCHAR *CompleteDirectoryPath(WCHAR *start_path, WCHAR *file_name, WCHAR *dest_path);
extern BOOL CopyDownloadFile(WCHAR *src_path, WCHAR *display_name);