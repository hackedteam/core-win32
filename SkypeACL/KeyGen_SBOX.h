/**********************************************************
 *	KeyGen_SBOX
 *	Skype 5.3.0.130
 *	cod
 *********************************************************/

#ifndef __KEYGEN_SBOX_H__
	#define __KEYGEN_SBOX_H__


void SBOX_Encrypt(LPBYTE lpOutBuffer, const char* username, int length);
char *Encrypt(char *lpUsername, char *lpMessage);

#endif
