#include "include/socket.h"
#include "include/encrypt.h"
#include "include/decrypt.h"
#include <iostream>
#include <cstdio>
#include <thread>
#include <chrono>
#include <csignal>

std::atomic<bool> keep_running(true);

void signal_handler(int signal) {
    if (signal == SIGINT) {
        keep_running = false;
    }
}

int main(int argc, char *argv[]){
	ERR_load_CRYPTO_strings();
   	OpenSSL_add_all_algorithms();
   	std::signal(SIGINT, signal_handler);
	
	DH_server server;
	if (server.start_DH_server("127.0.0.1", 12000)) {
		std::cout << "Server started, waiting for clients..." << std::endl;

		while (keep_running) {
		    std::this_thread::sleep_for(std::chrono::seconds(1));
		}

		std::cout << "Shutting down server..." << std::endl;
	} else {
		std::cerr << "Failed to start server" << std::endl;
	return 1;
	}

    return 0;
}
	
//	DH_server server;
//	if (server.start_DH_server("127.0.0.1",12000)) {
 //       	std::cout << "Server started, waiting for clients..." << std::endl;
  //     		server.accept_DH_client();
//	} else {
//		std::cerr << "Failed to start server" << std::endl;
//	}
//	return 0;
//}
