/* Sha256.h -- SHA-256 Hash
2010-06-11 : Igor Pavlov : Public domain */

#ifndef __CRYPTO_SHA256_H
#define __CRYPTO_SHA256_H

typedef unsigned __int64 ulong64;
typedef unsigned __int32 ulong32;
typedef unsigned char byte;

#define SHA256_DIGEST_SIZE 32

typedef struct
{
  ulong32 state[8];
  ulong64 count;
  byte buffer[64];
} SHA256Context;

void Sha256_Init(SHA256Context *p);
void Sha256_Update(SHA256Context *p, const byte *data, size_t size);
void Sha256_Final(SHA256Context *p, byte *digest);


#endif