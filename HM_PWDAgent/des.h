
#define DES_LONG unsigned int

#define ITERATIONS 16
#define HALF_ITERATIONS 8

#define	ROTATE(a,n)	(((a)>>(n))+((a)<<(32-(n))))

#define c2l(c,l)	(l =((DES_LONG)(*((c)++)))    , \
	l|=((DES_LONG)(*((c)++)))<< 8L, \
	l|=((DES_LONG)(*((c)++)))<<16L, \
	l|=((DES_LONG)(*((c)++)))<<24L)

#define l2c(l,c)	(*((c)++)=(unsigned char)(((l)     )&0xff), \
	*((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
	*((c)++)=(unsigned char)(((l)>>16L)&0xff), \
	*((c)++)=(unsigned char)(((l)>>24L)&0xff))

#define c2ln(c,l1,l2,n)	{ \
	c+=n; \
	l1=l2=0; \
	switch (n) { \
		case 8: l2 =((DES_LONG)(*(--(c))))<<24L; \
		case 7: l2|=((DES_LONG)(*(--(c))))<<16L; \
		case 6: l2|=((DES_LONG)(*(--(c))))<< 8L; \
		case 5: l2|=((DES_LONG)(*(--(c))));     \
		case 4: l1 =((DES_LONG)(*(--(c))))<<24L; \
		case 3: l1|=((DES_LONG)(*(--(c))))<<16L; \
		case 2: l1|=((DES_LONG)(*(--(c))))<< 8L; \
		case 1: l1|=((DES_LONG)(*(--(c))));     \
			} \
		}

#define l2cn(l1,l2,c,n)	{ \
	c+=n; \
	switch (n) { \
		case 8: *(--(c))=(unsigned char)(((l2)>>24L)&0xff); \
		case 7: *(--(c))=(unsigned char)(((l2)>>16L)&0xff); \
		case 6: *(--(c))=(unsigned char)(((l2)>> 8L)&0xff); \
		case 5: *(--(c))=(unsigned char)(((l2)     )&0xff); \
		case 4: *(--(c))=(unsigned char)(((l1)>>24L)&0xff); \
		case 3: *(--(c))=(unsigned char)(((l1)>>16L)&0xff); \
		case 2: *(--(c))=(unsigned char)(((l1)>> 8L)&0xff); \
		case 1: *(--(c))=(unsigned char)(((l1)     )&0xff); \
			} \
		}

#define PERM_OP(a,b,t,n,m) ((t)=((((a)>>(n))^(b))&(m)), (b)^=(t), (a)=((a)^((t)<<(n))))

#define HPERM_OP(a,t,n,m) ((t)=((((a)<<(16-(n)))^(a))&(m)),	(a)=(a)^(t)^(t>>(16-(n))))

#define IP(l,r) \
	{ \
	register DES_LONG tt; \
	PERM_OP(r,l,tt, 4,0x0f0f0f0fL); \
	PERM_OP(l,r,tt,16,0x0000ffffL); \
	PERM_OP(r,l,tt, 2,0x33333333L); \
	PERM_OP(l,r,tt, 8,0x00ff00ffL); \
	PERM_OP(r,l,tt, 1,0x55555555L); \
	}

#define FP(l,r) \
	{ \
	register DES_LONG tt; \
	PERM_OP(l,r,tt, 1,0x55555555L); \
	PERM_OP(r,l,tt, 8,0x00ff00ffL); \
	PERM_OP(l,r,tt, 2,0x33333333L); \
	PERM_OP(r,l,tt,16,0x0000ffffL); \
	PERM_OP(l,r,tt, 4,0x0f0f0f0fL); \
	}

#define LOAD_DATA_tmp(a,b,c,d,e,f) LOAD_DATA(a,b,c,d,e,f,g)
#define LOAD_DATA(R,S,u,t,E0,E1,tmp) \
	u=R^s[S  ]; \
	t=R^s[S+1]

#define D_ENCRYPT(LL,R,S) {\
	LOAD_DATA_tmp(R,S,u,t,E0,E1); \
	t=ROTATE(t,4); \
	LL^=\
	DES_SPtrans[0][(u>> 2L)&0x3f]^ \
	DES_SPtrans[2][(u>>10L)&0x3f]^ \
	DES_SPtrans[4][(u>>18L)&0x3f]^ \
	DES_SPtrans[6][(u>>26L)&0x3f]^ \
	DES_SPtrans[1][(t>> 2L)&0x3f]^ \
	DES_SPtrans[3][(t>>10L)&0x3f]^ \
	DES_SPtrans[5][(t>>18L)&0x3f]^ \
	DES_SPtrans[7][(t>>26L)&0x3f]; }

extern const DES_LONG DES_SPtrans[8][64];

typedef unsigned char DES_cblock[8];
typedef /* const */ unsigned char const_DES_cblock[8];

typedef struct DES_ks
{
	union
	{
		DES_cblock cblock;
		/* make sure things are correct size on machines with
		* 8 byte longs */
		DES_LONG deslong[2];
	} ks[16];
} DES_key_schedule;

#define DES_KEY_SZ 	(sizeof(DES_cblock))
#define DES_SCHEDULE_SZ (sizeof(DES_key_schedule))

#define DES_ENCRYPT	1
#define DES_DECRYPT	0

#define DES_CBC_MODE	0
#define DES_PCBC_MODE	1

void DES_set_key_unchecked(const_DES_cblock *key,DES_key_schedule *schedule);
void DES_ede3_cbc_encrypt(const unsigned char *input,unsigned char *output, 
						  long length,
						  DES_key_schedule *ks1,DES_key_schedule *ks2,
						  DES_key_schedule *ks3,DES_cblock *ivec,int enc);