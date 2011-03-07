.586p
.MODEL FLAT, stdcall
option casemap :none   ; case sensitive
include c:\masm32\include\windows.inc
include c:\masm32\include\user32.inc
include c:\masm32\include\kernel32.inc
include c:\masm32\include\psapi.inc
.STACK
.DATA

.CODE

ASSUME fs:NOTHING

INCEAX MACRO
	db	0ebh, 0ffh, 0c0h
ENDM

PUSHEBP	MACRO
	db	0ebh, 0ffh, 0f5h
ENDM

TEST_TF MACRO param1
LOCAL dummy
	push		param1
	pushfd
	push		ss
	pop			ss
	pop			param1
	bt			param1, 8
	jnc			dummy
	mov			param1, ExitProcess
	push		param1
	push		dword ptr fs:[0]
	mov			dword ptr fs:[0], esp
	xor			param1, param1
	jmp			param1
dummy:
	pop			param1
ENDM

dll_status		dd	0

HIDING PROC
	PUSHEBP
	mov		ebp, esp
	nop
	nop
	jmp		@@1

@@1:
	pushf
	jmp		@@000
@@000:
	popf
	sub		esp, 10h
	;int		03
	call	IsDebuggerPresent
	;xor eax, eax
	push	eax
	fsetpm	; garbage jmp
	TEST_TF	eax
	;xor		eax, eax
	jmp		@@002
@@restore001:
	pop		dword ptr fs:[0]
	add		esp, 4
	jmp		@@3
@@002:
	push	offset INT03_Handler
	push	dword ptr fs:[0]
	mov		dword ptr fs:[0], esp
	
	;mov		eax, offset InternalIsDebuggerPresent
	;mov		dword ptr [eax], eax
	call    InternalIsDebuggerPresent
	jmp		@@restore001
@@3:
	;xor		eax, eax
	push	eax
	xor		eax, eax
	INCEAX
	
	test	dword ptr [esp], eax
	jnz		@@2
	jz      @@2
	pop		eax
	push	1
	pop		eax
	test	dword ptr [esp], eax
	jnz		@@2
	;pop		eax
@@DEBUG_SECTION:
	mov		eax, offset RealEntryPoint
	call	masquerade
masquerade:
	push	cs
	push	eax
	retf
@@2:
	xor			eax, eax
	mov			esp, ebp
	pop			ebp
	ret
	
RealEntryPoint	PROC
	call	@1
@1:
	pop		eax
	add		eax, 6
	ret
RealEntryPoint	ENDP
	nop
	jmp		Continue
	
Continue:
	ret
HIDING ENDP

INT03_Handler	PROC
	push		ebp
	mov			ebp, esp
	push		esi
	
	mov			esi, dword ptr [ebp+10h]
	xor			eax, eax
	mov			dword ptr [esi+04h], eax
	mov			dword ptr [esi+08h], eax
	mov			dword ptr [esi+0ch], eax
	mov			dword ptr [esi+10h], eax
	mov			dword ptr [esi+14h], eax
	mov			dword ptr [esi+18h], 155h

	mov			eax, dword ptr [esi+0b0h]	; EAX
	call		eax	 ; Invoke function
	mov			dword ptr [esi+0b0h], eax	; Replace exit value
	mov			eax, dword ptr [esi+0b8h]
	cmp			byte ptr [eax], 0cch		; CC ?
	jnz			@@001
	inc			dword ptr [esi+0b8h]		; EIP = EIP +1
	jmp			@@100
@@001:
	cmp			word ptr [eax], 03cdh		; EIP = EIP +1
	jnz			@@002
	inc			dword ptr [esi+0b8h]
	jmp			@@100
@@002:
	add			dword ptr [esi+0b8h], 2
	jmp			@@100
	mov			eax, offset ExitProcess
	mov			dword ptr [esi+0b8h], eax

@@100:	
	pop			esi
	mov			esp, ebp
	pop			ebp
	xor			eax, eax
	ret
INT03_Handler	ENDP

InternalIsDebuggerPresent PROC
	mov 		eax, dword ptr fs:[18h]
	mov 		eax, dword ptr [eax+30h]
	movzx 		eax, byte ptr [eax+02h]
	ret
InternalIsDebuggerPresent ENDP

END