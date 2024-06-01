#ifndef __SOCKET_H_
#define __SOCKET_H_

#include "decrypt.h"
#include "encrypt.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/dh.h>

#define AUTO_ADDRESS "127.0.0.1"
#define PORT 12000
#define BUFFER_SIZE 4096
#define IV_LENGTH 16
#define AES_KEY_LENGTH 32
#define GENERATOR_LENGTH 512
// basic parameter definition

class basic_socket{
protected:
	int sockfd;	
	sockaddr_in addr;
	unsigned char buffer[BUFFER_SIZE];
	int recv_len;
public:
	basic_socket():sockfd(-1),recv_len(0){
		memset(&addr, 0, sizeof(addr));
		memset(buffer,0,sizeof(buffer));
	}
	virtual ~basic_socket(){if(sockfd!=-1){close(sockfd);}}
	
	bool create(int socketfd);
	bool create();
	bool bind(int socketfd,const std::string& address=AUTO_ADDRESS,int port=PORT);
	bool bind(const std::string& address=AUTO_ADDRESS,int port=PORT);
	bool connect(int socketfd,const std::string& address=AUTO_ADDRESS,int port=PORT);
	bool connect(const std::string& address=AUTO_ADDRESS,int port=PORT);
	bool send(int socketfd,const std::string& message);
	bool send(const std::string& message);
	bool send(int socketfd,unsigned char* str);
	bool send(unsigned char* str);
	bool receive(int socketfd);
	bool receive();
};

class DH_socket:virtual public basic_socket{
protected:
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
		p=BN_new();
		q=BN_new();
		g=BN_new();
		tmp_bn=BN_new();
		pub_key_for_receive=BN_new();
		pub_key_for_send=BN_new();
	}
	virtual ~DH_socket(){
		DH_free(dh);
		BN_free(p);
		BN_free(q);
		BN_free(g);
		BN_free(tmp_bn);
		BN_free(pub_key_for_receive);
		BN_free(pub_key_for_send);
	}
public:
	bool send(int socketfd,BIGNUM *tmp);
	bool send(BIGNUM *tmp);
	bool BN_receive(int socketfd);
	bool BN_receive();
protected:
	bool AES_key_generator(BIGNUM *k,DH *dh);
};

class client_socket :virtual  public basic_socket {
public:
    	bool connect2server(int socketfd,const std::string& address=AUTO_ADDRESS, int port=PORT);
    	bool connect2server(const std::string& address=AUTO_ADDRESS, int port=PORT);
};

class server_socket :virtual  public basic_socket {
public:
    	bool start_server(int socketfd,const std::string& address, int port);
    	bool start_server(const std::string& address, int port);

    	void accept_client(int socketfd); 
    	void accept_client(); 
};

class DH_server:public DH_socket,public server_socket{
public:
	bool start_DH_server(int socketfd,const std::string& address,int port);
	bool start_DH_server(const std::string& address,int port);
	
	void accept_DH_client(int socketfd);
	void accept_DH_client();

};

class DH_client:public DH_socket,public client_socket{
public:
	bool connect2_DH_server(int socketfd,const std::string& address=AUTO_ADDRESS, int port=PORT);
	bool connect2_DH_server(const std::string& address=AUTO_ADDRESS, int port=PORT);

};
#endif











