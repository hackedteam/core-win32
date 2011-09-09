/**********************************************************
 *	KeyGen_SBOX
 *	Skype 5.3.0.130
 *	cod
 *********************************************************/

#include <windows.h>

#include "KeyGen_SBOX.h"

#define	KEY00		0x00
#define	KEY04		0x01
#define	KEY08		0x02
#define	KEY0C		0x03
#define	KEY10		0x04
#define	KEY14		0x05
#define	KEY18		0x06
#define	KEY1C		0x07
#define	KEY20		0x08
#define	KEY24		0x09
#define	KEY28		0x0a
#define	KEY2C		0x0b
#define	KEY30		0x0c
#define	KEY34		0x0d
#define	KEY38		0x0e
#define	KEY3C		0x0f
#define	KEY40		0x10
#define	KEY44		0x11
#define	KEY48		0x12
#define	KEY4C		0x13
#define	KEY50		0x14
#define	KEY54		0x15
#define	KEY58		0x16
#define	KEY5C		0x17
#define	KEY60		0x18
#define	KEY64		0x19
#define	KEY68		0x1a
#define	KEY6C		0x1b
#define	KEY70		0x1c
#define	KEY74		0x1d
#define	KEY78		0x1e
#define	KEY7C		0x1f
#define	KEY80		0x20

#define DWORD_BITS	32

DWORD rol(DWORD value, DWORD places)
{
	return ((value << places) | (value >> (DWORD_BITS - places)));
}

DWORD ror(DWORD value, DWORD places)
{
	return ((value >> places) | (value << (DWORD_BITS - places)));
}


void sub_5e6c10(LPDWORD sbox)
{
	sbox[KEY08] += sbox[KEY1C] * 0x0EA2D3D5D;
}

// address 70b2b9: edx = 258A329D
void sub_5b4f30(LPDWORD sbox, DWORD dwConst)
{
	sbox[KEY34] ^= (dwConst < 0x2E0AF4F7) ? sbox[KEY3C] : dwConst;
}

// address 70b29b: edx = E4E7C9DD
void sub_5d28d0(LPDWORD sbox, DWORD dwConst)
{
	DWORD dwKEY04 = sbox[KEY04];
	DWORD dwKEY24 = sbox[KEY24];

	__asm
	{	// ROL IMPLEMENTATION
		push eax
		push ecx
		mov ecx, dwKEY04
		mov eax, dwKEY24
		rol ecx, 0x8e
		rol eax, cl
		mov dwKEY24, eax
		pop ecx
		pop eax
	}

	sbox[KEY24] = dwKEY24;

	if (dwKEY24 & 0x01)
	{
		sbox[KEY50] = dwConst + 0x3708DA;
		sbox[KEY54] = 0x01;
	}
}


void sub_5f20e0(LPDWORD sbox)
{
	// TODO!
}

void sub_5f8570(LPDWORD sbox)
{
	sbox[KEY18] = sbox[KEY2C] * sbox[KEY18] * 0x1304694A;
}

void sub_62e0f0(LPDWORD sbox)
{
	sbox[KEY28] ^= sbox[KEY1C] - 0x354C1FF2;
}

void sub_640e10(LPDWORD sbox)
{
	// TODO!
}

void sub_641f10(LPDWORD sbox)
{
	DWORD dwKey34 = sbox[KEY34] & 0x0ff;
	DWORD dwKey18 = sbox[KEY18];

	dwKey34 += 0x0e;

	__asm
	{
		push	edx
		push	ecx
		mov		edx, dwKey18
		mov		ecx, dwKey34

		rol		edx, cl
		mov		dwKey18, edx

		pop		ecx
		pop		edx
	}

	sbox[KEY18] = dwKey18;
}

void sub_66e940(LPDWORD sbox)
{
	sbox[KEY3C] ^= (sbox[KEY38] < 0x291B9650) ? sbox[KEY08] : sbox[KEY38];
}

void sub_689020(LPDWORD sbox)
{
	sbox[KEY0C] ^= sbox[KEY00];
}

void sub_6b4ed0()
{
	// TODO!
}

void sub_68c9d0(LPDWORD sbox)
{
	DWORD orKey = 0x1510A109;

	// TODO ! on EDX value
	if (false)
	{
		orKey = sbox[KEY38];
	}

	sbox[KEY34] |= orKey;
}

void sub_6a9490(LPDWORD sbox)
{
	// TODO!
}

void sub_6ab880(LPDWORD sbox)
{
	// TODO!
}

void sub_6bc810(LPDWORD sbox)
{
	sbox[KEY44] += sbox[KEY34] - 0x292C1156;
}

void sub_6e66d0(LPDWORD sbox)
{
	DWORD orKey = 0x1AB1E599;

	// TODO ! on EDX value
	if (false)
	{
		orKey = sbox[KEY48];
	}

	sbox[KEY18] |= orKey;

}

void sub_6fcce0(LPDWORD sbox)
{
	sbox[KEY2C] ^= sbox[KEY3C] | 0x11273409;
}

void sub_725a80(LPDWORD sbox)
{
	// todo!
}

void sub_740dc0(LPDWORD sbox)
{
	//TODO!
}

void sub_7565d0(LPDWORD sbox)
{
	sbox[KEY14] += sbox[KEY2C] | 0x0EA02A83;
}


// Generate random salt - Return CONST 0 now!
DWORD SALT()
{
	return 0x00000000;
}

void SBOX_Encrypt(LPBYTE lpOutBuffer, const char* username, int length)
{
	// INTERNAL SBOX is 0x00000000

	///////////////////////////////////////////
	/*
		0012F730  00 00 00 00 80 BE 16 63 65 7A 13 DE 08 01 24 00  ....€¾cezÞ$.
		0012F740  28 46 67 DF 02 80 0A 03 00 00 00 00 0E 43 B9 79  (Fgß€.....C¹y
		0012F750  00 00 00 00 63 FB D9 0A 60 75 03 00 0A 63 F9 4B  ....cûÙ.`u..cùK
		0012F760  D1 F0 98 80 C9 BF B6 3D 00 00 00 00 49 F5 09 D9  Ñð˜€É¿¶=....Iõ.Ù
		0012F770  E2 BB 03 3B 06 BF 10 6D D3 59 B0 64 45 EC DD 94  â»;¿mÓY°dEìÝ”
		0012F780  31 E5 C8 28 00 00 00 00 20 00 00 00 70 E0 83 2D  1åÈ(.... ...pàƒ-
	*/

	BYTE sbox[] = {
		0x00, 0x00, 0x00, 0x00, 0x80, 0xBE, 0x16, 0x63, 
		0x65, 0x7A, 0x13, 0xDE, 0x08, 0x01, 0x24, 0x00,
		0x28, 0x46, 0x67, 0xDF, 0x02, 0x80, 0x0A, 0x03,
		0x00, 0x00, 0x00, 0x00, 0x0E, 0x43, 0xB9, 0x79,
		0x00, 0x00, 0x00, 0x00, 0x63, 0xFB, 0xD9, 0x0A,
		0x60, 0x75, 0x03, 0x00, 0x0A, 0x63, 0xF9, 0x4B,
		0xD1, 0xF0, 0x98, 0x80, 0xC9, 0xBF, 0xB6, 0x3D,
		0x00, 0x00, 0x00, 0x00, 0x49, 0xF5, 0x09, 0xD9,
		0xE2, 0xBB, 0x03, 0x3B, 0x06, 0xBF, 0x10, 0x6D,
		0xD3, 0x59, 0xB0, 0x64, 0x45, 0xEC, 0xDD, 0x94
	};

	// initialize sbox
	for(int i=0; i < length && i < sizeof(sbox) ; i++)
	{
		sbox[i] ^= username[i];
	}


	lpOutBuffer[0x100] = 0x00;
	lpOutBuffer[0x101] = 0x00;

	for(int i=0; i < 0x100; i++)
		lpOutBuffer[i] = i;

	for(int i = 0, y = 0, z = 0; i < 0x100; i++)
	{
		BYTE a = lpOutBuffer[i];
		BYTE b = sbox[y];
		
		b += a;

		z += b;
		z &= 0xFF;

		b = lpOutBuffer[z];

		lpOutBuffer[i] = b;
		lpOutBuffer[z] = a;

		y++;
		if (y == sizeof(sbox))
			y = 0;
	}
}

void SBOX_Encrypt2(LPBYTE lpOutBuffer, LPBYTE lpInSbox, DWORD dwLength)
{
	BYTE sbox100 = lpInSbox[0x100];
	BYTE sbox101 = lpInSbox[0x101];

	DWORD x = (DWORD) lpOutBuffer;

	if ((x & 0x03) != 0)
	{	// process ???
		DWORD dwBlockSize = 0x04;

		dwBlockSize -= (x & 0x03);

		if (dwBlockSize > dwLength)
			dwBlockSize = dwLength;

		DWORD dwRemainBlock = dwLength - dwBlockSize;

/*
loc_5F6E31:                             ; CODE XREF: TRANSFORM_sub_5F6DF0+8Aj
.text:005F6E31                 inc     ecx
.text:005F6E32                 and     ecx, 0FFh
.text:005F6E38                 movzx   edx, byte ptr [ecx+eax] ; edx = byte sbox[ecx]
.text:005F6E3C                 mov     ebp, edx
.text:005F6E3E                 add     ebp, [esp+24h+dw_var14]
.text:005F6E42                 mov     [esp+24h+lpBuffer], edx ; save in varX value
.text:005F6E46                 and     ebp, 0FFh
.text:005F6E4C                 movzx   edx, byte ptr [eax+ebp] ; edx = byte sbox[ebp]
.text:005F6E50                 mov     [ecx+eax], dl   ; sbox[ecx] = edx
.text:005F6E53                 mov     [esp+24h+dw_var_C], edx
.text:005F6E57                 movzx   edx, byte ptr [esp+24h+lpBuffer]
.text:005F6E5C                 mov     [eax+ebp], dl   ; sbox[ebp] = varX
.text:005F6E5F                 mov     edx, [esp+24h+dw_var_C]
.text:005F6E63                 add     edx, [esp+24h+lpBuffer]
.text:005F6E67                 inc     esi             ; increase pointer to next element of [buffer]
.text:005F6E68                 and     edx, 0FFh
.text:005F6E6E                 movzx   edx, byte ptr [edx+eax] ; edx = byte sbox[edx]
.text:005F6E72                 xor     [esi-1], dl     ; xor previous element of buffer with dl
.text:005F6E75                 dec     edi
.text:005F6E76                 mov     [esp+24h+dw_var14], ebp
.text:005F6E7A                 jnz     short loc_5F6E31
*/

		for(int i=0; i < dwBlockSize; i++)
		{	
			BYTE a, b, c;

			sbox100++;			// 005F6E31 INC ECX 
			sbox100 &= 0xff;	// 005F6E32 AND ECX, 0xff

			a = (lpInSbox[sbox100]);
			b = (a + sbox101) & 0xff;
			c = (lpInSbox[b]);
			
			lpInSbox[sbox100] = (lpInSbox[b]);
			lpInSbox[b] = a;
			lpOutBuffer++;
			a = a+c;
			a &= 0xff;

			lpOutBuffer[-1] ^= lpInSbox[a];

			sbox101 = b;
		}

		// dwRemainBlock
		DWORD dwDwordRemainBlock = dwRemainBlock / 4;
		DWORD dwByteRemainBlock  = dwRemainBlock % 4;

		// ecx is sbox100
		for(int i =0; i < dwDwordRemainBlock; i++)
		{	// sbox100 + for each byte (4 byte for iteration!)
			sbox100++;
			sbox100 &= 0xff;
			BYTE rECX = lpInSbox[sbox100];
			
			BYTE rEDI = rECX + sbox101;
			rEDI &= 0xff;

			BYTE rEDX = lpInSbox[rEDI];

			lpInSbox[sbox100] = rEDX;
			lpInSbox[rEDI] = rECX;
			
			rEDX += rECX;

			sbox100++;
			sbox100 &= 0xff;

			rECX = lpInSbox[sbox100];
			BYTE rEBP = lpInSbox[rEDX];
			rEDI += rECX;
			rEDI &= 0xff;

			rEDX = lpInSbox[rEDI];

			lpInSbox[sbox100] = rEDX;
			lpInSbox[rEDI] = rECX;
			rEDX += rECX;
			rEDX &= 0xff;

			rECX = lpInSbox[rEDX];

			DWORD dwEBP = (rEBP | (rECX << 8));

			sbox100++;
			sbox100 &= 0xff;
			rECX = lpInSbox[sbox100];
			rEDI += rECX;
			rEDI &= 0xff;
			rEDX = lpInSbox[rEDI];
			lpInSbox[sbox100] = rEDX;
			rEDX += rECX;
			rEDX &= 0xff;
			lpInSbox[rEDI] = rECX;
			rEDX = lpInSbox[rEDX];

			dwEBP |= (rEDX << 16);

			sbox100++;
			sbox100 &= 0xff;

			rEDX = lpInSbox[sbox100];

			BYTE rESI = rEDX + rEDI;
			rESI &= 0xff;
			BYTE rEBX = lpInSbox[rESI];

			lpInSbox[sbox100] = rEBX;
			lpInSbox[rESI] = rEDX;

			rEDX = rEDX + rEBX;
			rEDX &= 0xff;

			sbox101 = rESI;

			rESI = lpInSbox[rEDX];

			LPDWORD lpDwordOutBuffer = (LPDWORD) lpOutBuffer;
			
			dwEBP |= (rESI << 24);
			
			lpDwordOutBuffer[0] ^= dwEBP;
			lpOutBuffer += 4;

		}
		
		for(int i=0; i < dwByteRemainBlock; i++)
		{
			BYTE rEDI = sbox101;
			sbox100++;
			sbox100 &= 0xff;

			BYTE rEDX = lpInSbox[sbox100];

			rEDI += rEDX;
			rEDI &= 0xff;

			BYTE r2EDX = rEDX;

			rEDX = lpInSbox[rEDI];

			lpInSbox[sbox100] = rEDX;
			BYTE r3EDX = rEDX;

			rEDX = lpInSbox[r2EDX];
			lpInSbox[rEDI] = rEDX;

			rEDX = r3EDX;
			rEDX += r2EDX;
			rEDX &= 0xff;

			lpOutBuffer++;
			
			rEDX = lpInSbox[rEDX];

			lpOutBuffer[-1] ^= rEDX;

			sbox101 = rEDI;
		}

		lpInSbox[0x100] = sbox100;
		lpInSbox[0x101] = sbox101;
	}

}
void FAST_SBOX_Encrypt2(LPBYTE lpOutBuffer, LPBYTE lpInSbox, int dwLength)
{
	BYTE key00 = lpInSbox[0x100];
	BYTE key01 = lpInSbox[0x101];

	for(int i=0; i < dwLength; i++)
	{
		BYTE a, b, c;

		key00++;			// 005F6E31 INC ECX 
		
		a = (lpInSbox[key00]);
		b = (a + key01) & 0xff;
		c = (lpInSbox[b]);

		lpInSbox[key00] = (lpInSbox[b]);
		lpInSbox[b] = a;
		a = a+c;
		a &= 0xff;

		*lpOutBuffer ^= lpInSbox[a];

		lpOutBuffer++;
		key01 = b;
	}

	lpInSbox[0x100] = key00;
	lpInSbox[0x101] = key01;
	return;


}

char *Encrypt(char *lpUsername, char *lpMessage)
{
	const char *hex = "0123456789ABCDEF";
	
	BYTE sbox[0x102];

	int size = strlen(lpMessage) + 9 + 1;	// 9 of extra data + 1 of TERMINATION

	char *buffer = (char *) malloc(size);
	char *hexbuffer = (char *) malloc(size * 2);

	memset(buffer, 0x00, size);
	memset(hexbuffer, 0x00, size*2);

	buffer[0] = 0x01;

	LPDWORD lpDword = (LPDWORD) &buffer[1];	// after 1 they are DWORD
	lpDword[0] = 0x00000000;
	lpDword[1] = 0x00000000;

	memcpy(&buffer[9], lpMessage, strlen(lpMessage));	// transfer message in ....
	memset(&sbox, 0x00, sizeof(sbox));

	SBOX_Encrypt(sbox, lpUsername, strlen(lpUsername));
	
	FAST_SBOX_Encrypt2((LPBYTE) &buffer[5], sbox, strlen(lpMessage) + 4);

	// final transformation
	int h = 0;
	int a = 0;
	size--;	// don't transform string terminator :)
	while(size > 0)
	{
		BYTE value = (BYTE) buffer[a++];
		hexbuffer[h] = hex[(value >> 4)];
		hexbuffer[h+1] = hex[value & 0x0f];
		h+=2;
		size--;
	}

	free(buffer);

	return hexbuffer;
}