#include "debug_tool.h"
#include <stdio.h>
#include <openssl/err.h>

void print_hex(unsigned char* str) {
	int n=sizeof(str)/sizeof(unsigned char);
	for(int i=0;i<n;i++){
		printf("%x",str[i]>>4);
		printf("%x",str[i]%(1<<4));
	}
	printf("\n");
}

void handleErrors(unsigned char* error_type) {
	printf("while running, an error type \<%s\> occurred\n",error_type);
	ERR_print_errors_fp(stderr);
	abort();
}
