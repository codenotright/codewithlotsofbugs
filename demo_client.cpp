#include "include/socket.h"
#include "include/encrypt.h"
#include "include/decrypt.h"
#include <iostream>
#include <cstdio>

int main(int argc, char *argv[]){
	ERR_load_CRYPTO_strings();
   	OpenSSL_add_all_algorithms();
	DH_client client;
	if (client.connect2_DH_server("127.0.0.1",12000)) {
		//client.communicate();
	} else {
		std::cerr << "Failed to connect to server" << std::endl;
	}
	return 0;
}
