#define TRY_BLOCK      __asm  pushad \
	                   __asm  call find_eip \
                       __asm  find_eip: \
                       __asm  pop esi \
					   __asm  add esi, 35h \
                       __asm  push esi \
                       __asm  push dword ptr fs:[0] \
                       __asm  mov dword ptr fs:[0], esp 

#define TRY_EXCEPT     __asm  jmp NoException \
                       __asm  mov esp, [esp + 8] \
                       __asm  pop dword ptr fs:[0] \
                       __asm  add esp, 4 \
                       __asm  popad 

#define TRY_END        __asm jmp ExceptionHandled \
                       __asm NoException: \
                       __asm pop dword ptr fs:[0] \
                       __asm add esp, 32 + 4 \
                       __asm ExceptionHandled:
