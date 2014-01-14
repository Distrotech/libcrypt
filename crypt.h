#ifndef CRYPT_H_
#define CRYPT_H_
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <mpi.h>
#include <stdint.h>

/* version */
#define CRYPT   0x0003

/* ---- ERRORS ---- */
enum {
	CRYPT_OK=0,
	CRYPT_ERROR,
};
extern char *crypt_error;

/* ---- HELPER MACROS ---- */
#define STORE32L(x, y) { (y)[3] = ((x)>>24)&255; (y)[2] = ((x)>>16)&255; (y)[1] = ((x)>>8)&255; (y)[0] = (x)&255; }
#define LOAD32L(x, y)  { x = (((unsigned long)(y)[3])<<24)|(((unsigned long)(y)[2])<<16)|(((unsigned long)(y)[1])<<8)|(((unsigned long)(y)[0])); }
#define STORE64L(x, y) { (y)[7] = ((x)>>56)&255; (y)[6] = ((x)>>48)&255; (y)[5] = ((x)>>40)&255; (y)[4] = ((x)>>32)&255; (y)[3] = ((x)>>24)&255; (y)[2] = ((x)>>16)&255; (y)[1] = ((x)>>8)&255; (y)[0] = (x)&255; }
#define LOAD64L(x, y)  { x = (((unsigned long long)((y)[7]))<<56)|(((unsigned long long)((y)[6]))<<48)|(((unsigned long long)((y)[5]))<<40)|(((unsigned long long)((y)[4]))<<32)|(((unsigned long long)((y)[3]))<<24)|(((unsigned long long)((y)[2]))<<16)|(((unsigned long long)((y)[1]))<<8)|(((unsigned long long)((y)[0]))); }
#define BSWAP(x)       ( ((x>>24)&0x000000FF)|((x<<24)&0xFF000000)|((x>>8)&0x0000FF00)|((x<<8)&0x00FF0000) )

#define ROL(x, y) ( ((x)<<((y)&31)) | ((x)>>(32-((y)&31))) )
#define ROR(x, y) ( ((x)>>((y)&31)) | ((x)<<(32-((y)&31))) )

#define MAX(x, y) ( ((x)>(y))?(x):(y) )
#define MIN(x, y) ( ((x)<(y))?(x):(y) )

/* ---- SYMMETRIC KEY STUFF -----
 *
 * We put each of the ciphers scheduled keys in their own structs then we put all of the key formats in
 * one union.  This makes the function prototypes easier to use.
 */
struct blowfish_key {
   unsigned long S[4][256];
   unsigned long K[18];
};

struct rc5_key {
   unsigned long K[50], rounds;
};

struct rc6_key {
   unsigned long K[44];
};

struct saferp_key {
   uint8_t K[33][16];
   int rounds;
};

struct serpent_key {
   unsigned long K[132];
};

union symmetric_key {
   struct blowfish_key blowfish;
   struct rc5_key      rc5;
   struct rc6_key      rc6;
   struct saferp_key   saferp;
   struct serpent_key  serpent;
};

/* A block cipher CBC structure */
struct symmetric_CBC {
   int                 cipher, blocklen;
   uint8_t       IV[32];
   union symmetric_key key;
};

/* A block cipher CTR structure */
struct symmetric_CTR {
   int                 cipher, blocklen;
   uint8_t       ctr[32];
   union symmetric_key key;
};

/* cipher descriptor table, last entry has "name == NULL" to mark the end of table */
extern  struct _cipher_descriptor {
   char *name;
   int  min_key_length, max_key_length, block_length, default_rounds;
   int  (*setup)(uint8_t *key, int keylength, int num_rounds, union symmetric_key *skey);
   void (*ecb_encrypt)(uint8_t *pt, uint8_t *ct, union symmetric_key *key);
   void (*ecb_decrypt)(uint8_t *ct, uint8_t *pt, union symmetric_key *key);
   int (*test)(void);
} cipher_descriptor[];

extern int blowfish_setup(uint8_t *key, int keylen, int num_rounds, union symmetric_key *skey);
extern void blowfish_ecb_encrypt(uint8_t *pt, uint8_t *ct, union symmetric_key *key);
extern void blowfish_ecb_decrypt(uint8_t *ct, uint8_t *pt, union symmetric_key *key);
extern int blowfish_test(void);

extern int rc5_setup(uint8_t *key, int keylen, int num_rounds, union symmetric_key *skey);
extern void rc5_ecb_encrypt(uint8_t *pt, uint8_t *ct, union symmetric_key *key);
extern void rc5_ecb_decrypt(uint8_t *ct, uint8_t *pt, union symmetric_key *key);
extern int rc5_test(void);

extern int rc6_setup(uint8_t *key, int keylen, int num_rounds, union symmetric_key *skey);
extern void rc6_ecb_encrypt(uint8_t *pt, uint8_t *ct, union symmetric_key *key);
extern void rc6_ecb_decrypt(uint8_t *ct, uint8_t *pt, union symmetric_key *key);
extern int rc6_test(void);

extern int saferp_setup(uint8_t *key, int keylen, int num_rounds, union symmetric_key *skey);
extern void saferp_ecb_encrypt(uint8_t *pt, uint8_t *ct, union symmetric_key *key);
extern void saferp_ecb_decrypt(uint8_t *ct, uint8_t *pt, union symmetric_key *key);
extern int saferp_test(void);

extern int serpent_setup(uint8_t *key, int keylen, int num_rounds, union symmetric_key *skey);
extern void serpent_ecb_encrypt(uint8_t *pt, uint8_t *ct, union symmetric_key *key);
extern void serpent_ecb_decrypt(uint8_t *ct, uint8_t *pt, union symmetric_key *key);
extern int serpent_test(void);

extern int cbc_start(int cipher, uint8_t *IV, uint8_t *key, int keylen, int num_rounds, struct symmetric_CBC *cbc);
extern void cbc_encrypt(uint8_t *pt, uint8_t *ct, struct symmetric_CBC *cbc);
extern void cbc_decrypt(uint8_t *ct, uint8_t *pt, struct symmetric_CBC *cbc);

extern int ctr_start(int cipher, uint8_t *count, uint8_t *key, int keylen, int num_rounds, struct symmetric_CTR *ctr);
extern void ctr_encrypt(uint8_t *pt, uint8_t *ct, int len, struct symmetric_CTR *ctr);
extern void ctr_decrypt(uint8_t *ct, uint8_t *pt, int len, struct symmetric_CTR *ctr);
	
extern int find_cipher(char *name);

/* ---- HASH FUNCTIONS ---- */
struct sha256_state {
    unsigned long state[8], length, curlen;
    uint8_t buf[64];
};

struct sha1_state {
    unsigned long state[5], length, curlen;
    uint8_t buf[64];
};

struct md5_state {
    unsigned long state[4], length, curlen;
    uint8_t buf[64];
};

struct tiger_state {
    unsigned long long state[3];
    unsigned long length, curlen;
    uint8_t buf[64];
};

union hash_state {
    struct sha256_state sha256;
    struct sha1_state   sha1;
    struct md5_state    md5;
    struct tiger_state  tiger;
};

extern struct _hash_descriptor {
    char *name;
    int hashsize;
    void (*init)(union hash_state *);
    void (*process)(union hash_state *, uint8_t *, int);
    void (*done)(union hash_state *, uint8_t *);
    int  (*test)(void);
} hash_descriptor[];

extern void sha256_init(union hash_state * md);
extern void sha256_process(union hash_state * md, uint8_t *buf, int len);
extern void sha256_done(union hash_state * md, uint8_t *hash);
extern int  sha256_test(void);

extern void sha1_init(union hash_state * md);
extern void sha1_process(union hash_state * md, uint8_t *buf, int len);
extern void sha1_done(union hash_state * md, uint8_t *hash);
extern int  sha1_test(void);

extern void md5_init(union hash_state * md);
extern void md5_process(union hash_state * md, uint8_t *buf, int len);
extern void md5_done(union hash_state * md, uint8_t *hash);
extern int  md5_test(void);

extern void tiger_init(union hash_state * md);
extern void tiger_process(union hash_state * md, uint8_t *buf, int len);
extern void tiger_done(union hash_state * md, uint8_t *hash);
extern int  tiger_test(void);

extern int find_hash(char *name);
extern int hash_memory(int hash, uint8_t *data, int len, uint8_t *dst);
extern int hash_file(int hash, char *fname, uint8_t *dst);

/* ---- PRNG Stuff ---- */
struct yarrow_prng {
    int                   cipher, hash, clen, hlen, bl;
    uint8_t         pool[32], buf[32];
    struct symmetric_CTR  ctr;
    union hash_state      md;
};

union prng_state {
    struct yarrow_prng    yarrow;
};

extern struct _prng_descriptor {
    char *name;
    int (*start)(union prng_state *);
    int (*add_entropy)(char *, int, union prng_state *);
    int (*ready)(union prng_state *);
    int (*read)(uint8_t *, int len, union prng_state *);
} prng_descriptor[];

extern int yarrow_start(union prng_state *prng);
extern int yarrow_add_entropy(char *buf, int len, union prng_state *prng);
extern int yarrow_ready(union prng_state *prng);
extern int yarrow_read(uint8_t *buf, int len, union prng_state *prng);

extern int find_prng(char *name);

/* ---- NUMBER THEORY ---- */
extern int is_prime(mp_int *);
extern int rand_prime(mp_int *N, int len, union prng_state *prng, int wprng);

/* ---- PUBLIC KEY CRYPTO ---- */
enum {
    PK_PRIVATE=0,
    PK_PUBLIC
};

struct rsa_key {
    int type;
    mp_int e, d, N;
};

extern int rsa_make_key(union prng_state *prng, int wprng, int size, long e, struct rsa_key *key);
extern int rsa_exptmod(uint8_t *in, int inlen, uint8_t *out, int *outlen, int which, struct rsa_key *key);
extern int rsa_pad(uint8_t *in, int inlen, uint8_t *out, int *outlen, int wprng, union prng_state *prng);
extern int rsa_depad(uint8_t *in, int inlen, uint8_t *out, int *outlen);
extern void rsa_free(struct rsa_key *key);

extern int rsa_encrypt(uint8_t *in, int len, uint8_t *out, int *outlen,
                       union prng_state *prng, int wprng, int cipher, struct rsa_key *key);

extern int rsa_decrypt(uint8_t *in, int len, uint8_t *out, int *outlen, struct rsa_key *key);

extern int rsa_sign(char *in, int inlen, uint8_t *out, int *outlen, int hash, 
                    union prng_state *prng, int wprng, struct rsa_key *key);

extern int rsa_verify(char *sig, char *msg, int inlen, int *stat, struct rsa_key *key);

extern int rsa_export(uint8_t *out, int *outlen, int type, struct rsa_key *key);
extern int rsa_import(uint8_t *in, struct rsa_key *key);

/* ---- BASE64 Routines ---- */
extern int base64_encode(uint8_t *in, int len, uint8_t *out, int *outlen);
extern int base64_decode(uint8_t *in, int len, uint8_t *out, int *outlen);

#endif /* CRYPT_H_ */
