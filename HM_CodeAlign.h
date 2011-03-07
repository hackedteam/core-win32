#pragma once 

#include <Windows.h>

#define BYTE_READ_THRESHOLD 10

#define C_MEM1   0x0001
#define C_MEM2   0x0002
#define C_MEM4   0x0004
#define C_DATA1  0x0100
#define C_DATA2  0x0200
#define C_DATA4  0x0400
#define C_67     0x0010
#define C_MEM67  0x0020
#define C_66     0x1000
#define C_DATA66 0x2000
#define C_PREFIX 0x0008
#define C_MODRM  0x4000
#define C_DATAW0 0x8000


#define XC_MEM1   0001h
#define XC_MEM2   0002h
#define XC_MEM4   0004h
#define XC_DATA1  0100h
#define XC_DATA2  0200h
#define XC_DATA4  0400h
#define XC_67     0010h
#define XC_MEM67  0020h
#define XC_66     1000h
#define XC_DATA66 2000h
#define XC_PREFIX 0008h
#define XC_MODRM  4000h
#define XC_DATAW0 8000h            

extern int HM_sCodeAlign(PBYTE Opcode);