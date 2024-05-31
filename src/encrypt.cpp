#include"encrypt.h"
#include"debug_tool.h"


int AES_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())){ 
    	unsigned char error_type[error_type_message_length]="EVP_CIPHER_CTX_new_error";
    	handleErrors(error_type);
    }

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
    	unsigned char error_type[error_type_message_length]="EVP_EncryptInit_ex_error";
    	handleErrors(error_type);
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){ 
    	unsigned char error_type[error_type_message_length]="EVP_EncryptUpdate_error";
    	handleErrors(error_type);
    }
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    	unsigned char error_type[error_type_message_length]="EVP_EncryptFinal_ex_error";
    	handleErrors(error_type);
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}
