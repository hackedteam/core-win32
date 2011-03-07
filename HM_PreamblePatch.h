#pragma once
#include <windows.h>
#include <new>
#include <Imagehlp.h>
#include "HM_Reloc.h"
#include "HM_CodeAlign.h"

#define BYTE_READ_THRESHOLD 10
#define HM_WINAPI(X){				\
						__asm leave \
						__asm jmp X \
					}

int HM_LoadLibrary(PCHAR pPath);
int HM_FreeLibrary(PVOID pPtr);
UINT HM_ReadFunction(PCHAR pDll, PCHAR pFunc, UINT uToRead, PBYTE *pStub);
BOOL HM_AssembleReturnJump(PCHAR pDll, PCHAR pFunc, UINT uDisp, PBYTE pCode);
BOOL HM_IsWrapped(PCHAR pDll, PCHAR pFunc);