#include "crypt.h"

int ctr_start(int cipher, uint8_t *count, uint8_t *key, int keylen, int num_rounds, struct symmetric_CTR *ctr)
{
   int x;

   /* bad param? */
   if (cipher == -1) { crypt_error = "Invalid cipher id passed to ctr_start()."; return CRYPT_ERROR; }

   /* setup cipher */
   if (cipher_descriptor[cipher].setup(key, keylen, num_rounds, &ctr->key) == CRYPT_ERROR) return CRYPT_ERROR;

   /* copy ctr */
   ctr->blocklen = cipher_descriptor[cipher].block_length;
   ctr->cipher   = cipher;
   for (x = 0; x < ctr->blocklen; x++) ctr->ctr[x] = count[x];
   return CRYPT_OK;
}

void ctr_encrypt(uint8_t *pt, uint8_t *ct, int len, struct symmetric_CTR *ctr)
{
   uint8_t buf[32];
   int x;

   /* increment counter */
   for (x = 0; x < ctr->blocklen; x++) if (++ctr->ctr[x]) break;

   /* copy counter */
   for (x = 0; x < ctr->blocklen; x++) buf[x] = ctr->ctr[x];

   /* encrypt it */
   cipher_descriptor[ctr->cipher].ecb_encrypt(buf, buf, &ctr->key);
   for (x = 0; x < len; x++) ct[x] = pt[x] ^ buf[x];
   memset(buf, 0, sizeof(buf));
}

void ctr_decrypt(uint8_t *ct, uint8_t *pt, int len, struct symmetric_CTR *ctr)
{
   ctr_encrypt(ct, pt, len, ctr);
}
