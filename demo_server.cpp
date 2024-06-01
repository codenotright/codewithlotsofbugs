#include "include/socket.h"
#include "include/encrypt.h"
#include "include/decrypt.h"
#include <iostream>
#include <cstdio>

int main(int argc, char *argv[]){
	ERR_load_CRYPTO_strings();
   	OpenSSL_add_all_algorithms();
	DH_server server;
	if (server.start_DH_server("127.0.0.1",12000)) {
        	std::cout << "Server started, waiting for clients..." << std::endl;
       		server.accept_DH_client();
	} else {
		std::cerr << "Failed to start server" << std::endl;
	}
	return 0;
}
