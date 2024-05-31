#include "decrypt.h"
#include "debug_tool.h"
#include <openssl/evp.h>

int AES_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    

    if(!(ctx = EVP_CIPHER_CTX_new())){
    	unsigned char error_type[error_type_message_length]="EVP_CIPHER_CTX_new_error";
    	handleErrors(error_type);
    }

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
    	unsigned char error_type[error_type_message_length]="EVP_aes_256_cbc_error";
    	handleErrors(error_type);
    }

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    	unsigned char error_type[error_type_message_length]="EVP_DecryptUpdate_error";
    	handleErrors(error_type);
    }
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    	unsigned char error_type[error_type_message_length]="EVP_DecryptFinal_ex_error";
    	handleErrors(error_type);
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}
