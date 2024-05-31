#ifndef __DECRYPT_H_
#define __DECRTPT_H_
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/err.h>

#define error_type_message_length 100
int AES_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *plaintext);

#endif
