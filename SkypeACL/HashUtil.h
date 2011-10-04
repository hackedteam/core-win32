#ifndef __HASHUTIL_H__
#define __HASHUTIL_H__

// Return SHA256 string of block
BOOL SHA256_Array(char *lpOutChecksum, void *array, int size);
// Return MD5 string of block
BOOL MD5_Array(char *lpOutChecksum, char *array, int size);

// Return MD5 string of file content
BOOL MD5_Plugin(char *lpFileName, char *lpOutChecksum);
BOOL SHA256_Plugin(char *lpFileName, char *lpOutChecksum, BOOL isOld);

#define SHA256_DIGEST_SIZE 32
#define MD5_DIGEST_SIZE 16

#endif
