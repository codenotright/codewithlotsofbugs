#include "socket.h"
#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>


bool basic_socket::create(int socketfd)
{
	socketfd=socket(AF_INET,SOCK_STREAM,0);
	return socketfd!=-1;
}

bool basic_socket::bind(const std::string& address,int port,int socketfd)
{
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(address.c_str());
	return ::bind(socketfd, (struct sockaddr*)&addr, sizeof(addr)) != -1;
}

bool basic_socket::connect(const std::string& address=AUTO_ADDRESS,int port,int socketfd)
{
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(address.c_str());
	return ::connect(socketfd, (struct sockaddr*)&addr, sizeof(addr)) != -1;
}

bool basic_socket::send(const std::string& message,int socketfd)
{
        return ::send(socketfd, message.c_str(), message.size(), 0) != -1;
}
bool basic_socket::send(unsigned char* str,int socketfd)
{
        return ::send(socketfd, str, strlen(str), 0) != -1;
}

bool basic_socket::receive(int socketfd)
{
	recv_len = ::recv(socketfd, buffer, sizeof(buffer) - 1, 0);
	return recv_len > 0;
}

bool DH_socket::send(BIGNUM *tmp,int socketfd)
{
	int tmp_len=BN_num_bytes(tmp);
	unsigned char *str=new unsigned char[tmp_len];
	BN_bn2bin(tmp, str);
	if (::send(socketfd, str, tmp_len, 0) != -1){
		free(str);
		str=NULL;
		return 1;
	}else{
		free(str);
		str=NULL;
		return 0;
	}
}

bool DH_socket::BN_receive(int socketfd)
{
	recv_len = ::recv(socketfd, buffer, sizeof(buffer) - 1, 0);
	if (BN_bin2bn(buffer,recv_len,tmp_bn) != 0) {
	   	return 1;
	}else{
		return 0;
	}
}

bool DH_socket::AES_generator(BIGNUM *k,DH *dh)
{
	unsigned char k_str[GENERATOR_LENGTH/sizeof(unsigned char)];
	//unsigned char k2_str[GENERATOR_LENGTH/sizeof(unsigned char)];
	int k_len=BN_num_bytes(k1);
	//int k2_len=BN_num_bytes(k2);
	BN_bn2bin(k, k_str);
	//BN_bn2bin(k2, k2_str);
	unsigned char tmp[GENERATOR_LENGTH/sizeof(unsigned char)];
	int secret_size = DH_compute_key(tmp,k_str, dh);
	if (secret_size == -1) {
		perror("compute_key error");
		return 0;
	}
	for(int i=0;i<AES_LENGTH;++i){
		AES_key[i]=tmp[i];
	}
	return 1;
}

bool client_socket::connect2server()
{
    	if(!create()){
    		perror("client host - creation error");
    		return 0;
    	}
    	if(!connect(address,port)){
    		perror("client host - connection failed");
    		return 0;
    	}
        return 1;
}

bool server_socket::start_server(const std::string& address, int port,int socketfd)
{
    	if(!create()){
    		perror("server host - creation error");
    		return 0;
    	}
    	if(!bind(address,port)){
		perror("server host - bind error");
		return 0;
	}
	if(!listen()){
		perror("server host - listen error");
		return 0;
	}
        return  1;
}

void server_socket::accept_client(int socketfd)
{
        sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        int clientSock = accept(sockfd, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSock != -1){
            char buffer[1024];
            memset(buffer, 0, sizeof(buffer));
            recv(clientSock, buffer, sizeof(buffer) - 1, 0);
            send(clientSock, "Hello from server", 17, 0);
            close(clientSock);
        }
}

bool DH_server::start_server(const std::string& address, int port,int socketfd)
{
    	if(!create()){
    		perror("server host - creation error");
    		return 0;
    	}
    	if(!bind(address,port)){
		perror("server host - bind error");
		return 0;
	}
	if(!listen()){
		perror("server host - listen error");
		return 0;
	}
	//DH *dh = DH_new();
	if (!DH_generate_parameters_ex(dh, GENERATOR_LENGTH, DH_GENERATOR_2, nullptr)) {
		perror("server host - DH_generate_parameters_ex");
		return 0;
	}
	p = BN_dup(DH_get0_p(dh));
	g = BN_dup(DH_get0_g(dh));
	if (!DH_generate_key(dh)) {
		perror("server host - DH_generate_key");
		return 0;
	}
	pub_key_for_send = DH_get0_pub_key(dh);
        return  1;
}

void server_socket::accept_DH_client(int socketfd)
{
        sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        int clientSock = accept(sockfd, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSock != -1){
		memset(buffer, 0, sizeof(buffer));
		if (!send(p,clientSock)){
			perror("send p error");
			return;
		}
		if (receive(clientSock)){
			perror("receive iv error");
			return;
		}
		for(int i=0;i<recv_len;++i){
			iv[i]=buffer[i];
		}
		if (!send(g,clientSock)){
			perror("send g error");
			return;
		}
		if (BN_receive()){
			perror("receive pub key error");
			return;
		}
		pub_key_for_receive=tmp_bn;
		if (send(pub_key_for_receive,clientSock)){
			perror("send pub key error");
			return;
		}
		if (!AES_key_generator(pub_key_for_receive,dh)){
			perror("generate aes key error");
			return;
		}
		
		recv_len=receive();
		unsigned char text[BUFFER_SIZE];
		AES_decrypt(buffer,recv_len,AES_key,iv,text);
		std::cout<<text;
		//while(1){
			
		//}
		close(clientSock);
        }
}

bool connect2_DH_server(const std::string& address=AUTO_ADDRESS, int port=PORT,int socketfd=sockfd)
{
	if(!connect2server(address,port,socketfd)){
		perror("basic connection fail");
		return 0;
	}
	if (!RAND_bytes(iv, IV_LENGTH)) {
        	perror("Error generating random IV");
        	return 0;
    	}
    	if (!BN_receive()){
    		perror("receive p fail");
    		return 0;
    	}
    	p=tmp_bn;
    	if (!send(iv)){
    		perror("iv send fail");
    		return 0;
    	}
    	if (!BN_receive()){
    		perror("receive g fail");
    		return 0;
    	}
    	if (!DH_set0_pqg(dh, p, nullptr, g)) {
		perror("create dh error");
		return 0;
	}
	pub_key_for_send = DH_get0_pub_key(dh);
    	if (!send(pub_key_for_send)){
    		perror("send pub key fail");
    		return 0;
    	}
    	if (BN_receive()){
		perror("receive pub key error");
		return 0;
	}
	pub_key_for_receive=tmp_bn;
    	if (!AES_key_generator(pub_key_for_receive,dh)){
		perror("generate aes key error");
		return 0;
	}
	unsigned char text[BUFFER_SIZE];
	std::string message="an unfriendly greeting from client: ****";
	AES_encrypt((unsigned char*)message.c_str(), message.length(),AES_key,iv,text);
	send(text);
	return 1;
}



















