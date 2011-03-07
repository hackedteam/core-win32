#include <stdlib.h>
#include <stdio.h>
#include <Tlhelp32.h>
#include <ntsecapi.h>

#define FileDirectoryInformation 1
#define FileFullDirectoryInformation 2
#define FileBothDirectoryInformation 3
#define FileNamesInformation 12
#define FileIdBothDirInformation 37
#define FileIdFullDirectoryInformation 38

typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
		ULONG NextEntryOffset;
		ULONG FileIndex;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize; 
        ULONG FileAttributes;
        ULONG FileNameLength;
		ULONG EaSize;
		CCHAR ShortNameLength;
		WCHAR ShortName[12];
		LARGE_INTEGER FileId;
		WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;


typedef struct _FILE_DIRECTORY_INFORMATION { 
        ULONG NextEntryOffset;
        ULONG Unknown;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize; 
        ULONG FileAttributes;
        ULONG FileNameLength;
        WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_FULL_DIRECTORY_INFORMATION {
        ULONG NextEntryOffset;
        ULONG Unknown;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize;
        ULONG FileAttributes;
        ULONG FileNameLength;
        ULONG EaInformationLength;
        WCHAR FileName[1];
} FILE_FULL_DIRECTORY_INFORMATION, *PFILE_FULL_DIRECTORY_INFORMATION;

typedef struct _FILE_BOTH_DIRECTORY_INFORMATION { 
        ULONG NextEntryOffset;
        ULONG Unknown;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER EndOfFile;
        LARGE_INTEGER AllocationSize;
        ULONG FileAttributes;
        ULONG FileNameLength;
        ULONG EaInformationLength;
        UCHAR AlternateNameLength;
        WCHAR AlternateName[12];
        WCHAR FileName[1];
} FILE_BOTH_DIRECTORY_INFORMATION, *PFILE_BOTH_DIRECTORY_INFORMATION; 


typedef struct _FILE_NAMES_INFORMATION {
        ULONG NextEntryOffset;
        ULONG Unknown;
        ULONG FileNameLength;
        WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

typedef struct _FILE_ID_FULL_DIR_INFORMATION {
	    ULONG NextEntryOffset;
	    ULONG FileIndex;
	    LARGE_INTEGER CreationTime;
	    LARGE_INTEGER LastAccessTime;
	    LARGE_INTEGER LastWriteTime;
	    LARGE_INTEGER ChangeTime;
	    LARGE_INTEGER EndOfFile;
	    LARGE_INTEGER AllocationSize;
	    ULONG FileAttributes;
	    ULONG FileNameLength;
	    ULONG EaSize;
	    LARGE_INTEGER FileId;
	    WCHAR FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;


typedef enum SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    Unknown1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3, /* was SystemTimeInformation */
    Unknown4,
    SystemProcessInformation = 5,
    Unknown6,
    Unknown7,
    SystemProcessorPerformanceInformation = 8,
    Unknown9,
    Unknown10,
    SystemDriverInformation,
    Unknown12,
    Unknown13,
    Unknown14,
    Unknown15,
    SystemHandleList,
    Unknown17,
    Unknown18,
    Unknown19,
    Unknown20,
    SystemCacheInformation,
    Unknown22,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct  {
    ULONG NextEntryOffset;
    ULONG           ThreadCount;            // number of threads
    ULONG           Reserved1[6];           // reserved
    LARGE_INTEGER   CreateTime;             // process creation time
    LARGE_INTEGER   UserTime;               // time spent in user mode
    LARGE_INTEGER   KernelTime;             // time spent in kernel mode
    UNICODE_STRING  ProcessName;            // process name
    DWORD           BasePriority;           // base process priority
    DWORD UniqueProcessId;
    DWORD ParentProcessId;
    ULONG HandleCount;
    BYTE Reserved4[4];
    PVOID Reserved5[11];
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION;


typedef struct _MIB_TCPROW 
{  DWORD dwState;  
   DWORD dwLocalAddr;  
   DWORD dwLocalPort;  
   DWORD dwRemoteAddr;  
   DWORD dwRemotePort;
} MIB_TCPROW, *PMIB_TCPROW;

typedef struct _MIB_TCPROW_EX
{
      DWORD dwState; 
      DWORD dwLocalAddr;
      DWORD dwLocalPort;
      DWORD dwRemoteAddr;
      DWORD dwRemotePort;
      DWORD dwProcessId;
} MIB_TCPROW_EX, *PMIB_TCPROW_EX;

typedef struct _MIB_TCPROW_SUP 
{  DWORD dwTot;  
   DWORD dwState;  
   DWORD dwLocalAddr;
   DWORD dwLocalPort;
   DWORD dwRemoteAddr;  
   DWORD dwRemotePort;
   DWORD dwProcessId;
} MIB_TCPROW_SUP, *PMIB_TCPROW_SUP;

typedef struct _TCP_VISTA_ROW 
{	
	WORD filler1;
	WORD local_port;
	DWORD local_address;
	BYTE filler2[22];
	WORD remote_port;
	DWORD remote_address;
	BYTE filler[20];
} TCP_VISTA_ROW, *PTCP_VISTA_ROW;

typedef struct _TCP_VISTA_STATUS
{
	DWORD status;
	BYTE filler[8];
} TCP_VISTA_STATUS, *PTCP_VISTA_STATUS;

typedef struct _NSI_PARAMS
{
	BYTE filler1[24];
	TCP_VISTA_ROW *row;
	DWORD type;
	BYTE filler2[8];
	TCP_VISTA_STATUS *status;
	BYTE filler3[12];
	DWORD count;
} NSI_PARAMS, *PNSI_PARAMS;


typedef struct _IO_STATUS_BLOCK {
	DWORD dummy;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
	ULONG TitleIndex;
	ULONG Type;
	ULONG NameLength;
	WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_FULL_INFORMATION {
  LARGE_INTEGER  LastWriteTime;
  ULONG  TitleIndex;
  ULONG  ClassOffset;
  ULONG  ClassLength;
  ULONG  SubKeys;
  ULONG  MaxNameLen;
  ULONG  MaxClassLen;
  ULONG  Values;
  ULONG  MaxValueNameLen;
  ULONG  MaxValueDataLen;
  WCHAR  Class[1];
} KEY_FULL_INFORMATION;

typedef struct _KEY_STR_INFORMATION {
  DWORD dw1;
  DWORD dw2;
  DWORD dw3;
  DWORD dw4;
  DWORD dw5;
  ULONG Values;
} KEY_STR_INFORMATION;

typedef enum _KEY_INFORMATION_CLASS {
  KeyBasicInformation,
  KeyNodeInformation,
  KeyFullInformation 
} KEY_INFORMATION_CLASS;
