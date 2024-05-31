#ifndef __SOCKET_H_
#define __SOCKET_H_

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define AUTO_ADDRESS "127.0.0.1"
#define PORT 12000
#define BUFFER_SIZE 4096
#define IV_LENGTH 16
#define AES_KEY_LENGTH 32
#define GENERATOR_LENGTH 512
// basic parameter definition

class basic_socket{
private:
	int sockfd;	
	sockadd_in addr;
	unsigned char* buffer[BUFFER_SIZE];
	int recv_len;
public:
	basic_socket():sockfd(-1),recv_len(0){
		memset(&addr, 0, sizeof(addr));
		memset(buffer,0,sizeof(buffer));
	}
	virtual ~basic_socket(){if(sockfd!=-1){close(sockfd);}}
	
	bool create(int socketfd=sockfd);
	bool bind(const std::string& address=AUTO_ADDRESS,int port=PORT,int socketfd=sockfd);
	bool connect(const std::string& address=AUTO_ADDRESS,int port=PORT,int socketfd=sockfd);
	bool send(const std::string& message,int socketfd=sockfd);
	bool send(unsigned char* str,int socketfd=sockfd);
	std::string receive(int socketfd=sockfd);
};

class DH_socket():public basic_socket{
private:
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *g;
	BIGNUM *tmp_bn;
	BIGNUM *pub_key_for_receive;
	BIGNUM *pub_key_for_send;
	DH *dh;
	unsigned char AES_key[AES_KEY_LENGTH];
	unsigned char iv[IV_LENGTH];
public:
	DH_socket():basic_socket(){
		dh=DH_new();
		//p=BN_new();
		//q=BN_new();
		//g=BN_new();
		//tmp_bn=BN_new();
		//pub_key_for_receive=BN_new();
		//pub_key_for_send=BN_new();
	}
	~DH_socket(){
		DH_free(dh);
		//DH_free(p);
		//DH_free(q);
		//DH_free(g);
		//DH_free(tmp_bn);
		//DH_free(pub_key_for_receive);
		//DH_free(pub_key_for_send);
	}
public:
	bool send(BIGNUM *tmp,int socketfd=sockfd);
	bool BN_receive(int socketfd=sockfd);
private:
	bool AES_key_generator(BIGNUM *k,DH *dh);
};

class client_socket : public basic_socket {
public:
    	bool connect2server(const std::string& address=AUTO_ADDRESS, int port=PORT,int socketfd=sockfd);
};

class server_socket : public basic_socket {
public:
    	bool start_server(const std::string& address, int port,int socketfd=sockfd);

    	void accept_client(int socketfd=sockfd); 
};

class DH_server:public DH_socket,public server_socket{
public:
	bool start_DH_server(const std::string& address,int port,int socketfd=sockfd);
	
	void accept_DH_client(int socketfd=sockfd);

}

class DH_client:public DH_socket,public client_socket{
public:
	bool connect2_DH_server(const std::string& address=AUTO_ADDRESS, int port=PORT,int socketfd=sockfd);

}
#endif











