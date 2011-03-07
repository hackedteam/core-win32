#include "HM_CodeAlign.h"

int table_1[] = { 
	C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_DATAW0             
	, C_DATAW0             
	, 0                    
	, 0                    
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_DATAW0             
	, C_DATAW0             
	, 0                    
	, 0                    
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_DATAW0             
	, C_DATAW0             
	, 0                    
	, 0                    
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_DATAW0             
	, C_DATAW0             
	, 0                    
	, 0                    
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_DATAW0             
	, C_DATAW0             
	, C_PREFIX             
	, 0                    
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_DATAW0             
	, C_DATAW0             
	, C_PREFIX             
	, 0                    
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_DATAW0             
	, C_DATAW0             
	, C_PREFIX             
	, 0                    
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_DATAW0             
	, C_DATAW0             
	, C_PREFIX             
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, C_MODRM              
	, C_MODRM              
	, C_PREFIX             
	, C_PREFIX             
	, C_PREFIX+C_66        
	, C_PREFIX+C_67        
	, C_DATA66             
	, C_MODRM+C_DATA66     
	, C_DATA1              
	, C_MODRM+C_DATA1      
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_MODRM+C_DATA1      
	, C_MODRM+C_DATA66     
	, C_MODRM+C_DATA1      
	, C_MODRM+C_DATA1      
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, C_DATA66+C_MEM2      
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, C_MEM67              
	, C_MEM67              
	, C_MEM67              
	, C_MEM67              
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, C_DATA1              
	, C_DATA66             
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA66             
	, C_DATA66             
	, C_DATA66             
	, C_DATA66             
	, C_DATA66             
	, C_DATA66             
	, C_DATA66             
	, C_DATA66             
	, C_MODRM+C_DATA1      
	, C_MODRM+C_DATA1      
	, C_DATA2              
	, 0                    
	, C_MODRM              
	, C_MODRM              
	, C_MODRM+C_DATA1      
	, C_MODRM+C_DATA66     
	, C_DATA2+C_DATA1      
	, 0                    
	, C_DATA2              
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_DATA1              
	, C_DATA1              
	, 0                    
	, 0                    
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_MODRM              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA1              
	, C_DATA66             
	, C_DATA66             
	, C_DATA66+C_MEM2      
	, C_DATA1              
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, C_PREFIX             
	, 0                    
	, C_PREFIX             
	, C_PREFIX             
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, 0                    
	, C_MODRM              
	, C_MODRM};              

	int table_0F[]= {                
		C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, -1                   
		, -1                   
		, 0                    
		, -1                   
		, 0                    
		, 0                    
		, 0                    
		, 0                    
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, C_DATA66             
		, C_DATA66             
		, C_DATA66             
		, C_DATA66             
		, C_DATA66             
		, C_DATA66             
		, C_DATA66             
		, C_DATA66             
		, C_DATA66             
		, C_DATA66             
		, C_DATA66             
		, C_DATA66             
		, C_DATA66             
		, C_DATA66             
		, C_DATA66             
		, C_DATA66             
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, 0                    
		, 0                    
		, 0                    
		, C_MODRM              
		, C_MODRM+C_DATA1      
		, C_MODRM              
		, -1                   
		, -1                   
		, 0                    
		, 0                    
		, 0                    
		, C_MODRM              
		, C_MODRM+C_DATA1      
		, C_MODRM              
		, -1                   
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, -1                   
		, -1                   
		, C_MODRM+C_DATA1      
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, C_MODRM              
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, 0                    
		, 0                    
		, 0                    
		, 0                    
		, 0                    
		, 0                    
		, 0                    
		, 0                    
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1                   
		, -1};       

int HM_sCodeAlign(PBYTE Opcode)
{
	int ret_value;

	__asm {
			mov     ecx, [Opcode]    // ECX = opcode ptr
	
			xor     edx, edx		 // flags
			xor     eax, eax

prefix:     and     dl, not XC_PREFIX

			mov     al, [ecx]
			inc     ecx

			or      edx, table_1[eax*4]

			test    dl, XC_PREFIX
			jnz     prefix

			cmp     al, 0F6h
			je      jtest
			cmp     al, 0F7h
			je      jtest

			cmp     al, 0CDh
			je      jint

			cmp     al, 0Fh
			je      jOF
cont:
			test    dh, XC_DATAW0 shr 8
			jnz     dataw0
dataw0done:
			test    dh, XC_MODRM shr 8
			jnz     modrm
exitmodrm:
			test    dl, XC_MEM67
			jnz     mem67
mem67done:
			test    dh, XC_DATA66 shr 8
			jnz     data66
data66done:
			mov     eax, ecx
			sub     eax, [Opcode]

			and     edx, XC_MEM1+XC_MEM2+XC_MEM4+XC_DATA1+XC_DATA2+XC_DATA4
			add     al, dl
			add     al, dh

			jmp		Oexit

jtest:      or      dh, XC_MODRM shr 8
			test    byte ptr [ecx], 00111000b 
			jnz     cont
			or      dh, XC_DATAW0 shr 8
			jmp     cont

jint:       or      dh, XC_DATA1 shr 8
			cmp     byte ptr [ecx], 20h
			jne     cont
			or      dh, XC_DATA4 shr 8
			jmp     cont

jOF:        mov     al, [ecx]
			inc     ecx
			or      edx, table_0F[eax*4]

			cmp     edx, -1
			jne     cont

			;error:                	
			mov     eax, edx
			jmp     Oexit

dataw0:     xor     dh, XC_DATA66 shr 8
			test    al, 00000001b
			jnz     dataw0done
			xor     dh, (XC_DATA66+XC_DATA1) shr 8
			jmp     dataw0done

mem67:     	xor     dl, XC_MEM2
			test    dl, XC_67
			jnz     mem67done
			xor     dl, XC_MEM4+XC_MEM2
			jmp     mem67done

data66:    	xor     dh, XC_DATA2 shr 8
			test    dh, XC_66 shr 8
			jnz     data66done
			xor     dh, (XC_DATA4+XC_DATA2) shr 8
			jmp     data66done

modrm:     	mov     al, [ecx]
			inc     ecx

			mov     ah, al  // ah=mod, al=rm

			and     ax, 0C007h
			cmp     ah, 0C0h
			je      exitmodrm

			test    dl, XC_67
			jnz     modrm16

			//modrm32:              	
			cmp     al, 04h
			jne     a

			mov     al, [ecx]       // sib
			inc     ecx
			and     al, 07h

a:		 	cmp     ah, 40h
			je      mem1
			cmp     ah, 80h
			je      mem4

			cmp     ax, 0005h
			jne     exitmodrm

mem4:       or      dl, XC_MEM4
			jmp     exitmodrm

mem1:       or      dl, XC_MEM1
			jmp     exitmodrm

modrm16:    cmp     ax, 0006h
			je      mem2
			cmp     ah, 40h
			je      mem1
			cmp     ah, 80h
			jne     exitmodrm

mem2:     	or      dl, XC_MEM2
			jmp     exitmodrm

Oexit:
			mov		[ret_value], eax
	};

	return ret_value;
}
