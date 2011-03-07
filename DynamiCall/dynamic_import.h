#ifndef dynamic_import_h__
#define dynamic_import_h__

#include <Windows.h>
#include "obfuscated_calls.h"

typedef struct _XREF_CALLS
{
	char* name;
	ULONG_PTR ptr;
} XREFCALL;

typedef struct _XREF_DLL
{
	char *name;
	XREFCALL calls[256];
} XREFDLL;

#define STRINGIFY(x) #x
#define OBFUSCATED(x) obfuscated_##x

#define IMPORT_DLL(n) { OBFUSCATED(n), {
#define IMPORT_CALL(n) { OBFUSCATED(n), NULL },
#define NULL_IMPORT_CALL { NULL, NULL },
#define END_DLL NULL_IMPORT_CALL } },

#define END_IMPORTING { NULL, { NULL } }

ULONG_PTR dynamic_call(TCHAR* name);

// #define FNC(x) ((PROTO_##x) dynamic_call( STRINGIFY(x) ))
#define FNC(x) ((PROTO_##x) dynamic_call( OBFUSCATED(x) ))

extern void shiftBy1(char *str);

#endif // dynamic_import_h__