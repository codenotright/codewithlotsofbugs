#ifndef __ENCRYPT_H_
#define __ENCRYPT_H_
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/err.h>

#define error_type_message_length 100
int AES_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,unsigned char *iv, unsigned char *ciphertext);

#endif
