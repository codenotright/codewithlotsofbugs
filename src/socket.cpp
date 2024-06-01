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
bool basic_socket::create()
{
	return create(sockfd);
}

bool basic_socket::bind(int socketfd,const std::string& address,int port)
{
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(address.c_str());
	return ::bind(socketfd, (struct sockaddr*)&addr, sizeof(addr)) != -1;
}
bool basic_socket::bind(const std::string& address,int port)
{
	return bind(sockfd,address,port);
}

bool basic_socket::connect(int socketfd,const std::string& address,int port)
{
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(address.c_str());
	return ::connect(socketfd, (struct sockaddr*)&addr, sizeof(addr)) != -1;
}
bool basic_socket::connect(const std::string& address,int port)
{
	return connect(sockfd,address,port);
}

bool basic_socket::send(int socketfd,const std::string& message)
{
        return ::send(socketfd, message.c_str(), message.size(), 0) != -1;
}
bool basic_socket::send(const std::string& message)
{
	return send(sockfd,message);
}
bool basic_socket::send(int socketfd,unsigned char* str)
{
        return ::send(socketfd, str, strlen(reinterpret_cast<const char*>(str)), 0) != -1;
}
bool basic_socket::send(unsigned char* str)
{
        return send(sockfd,str);
}

bool basic_socket::receive(int socketfd)
{
	recv_len = ::recv(socketfd, buffer, sizeof(buffer) - 1, 0);
	return recv_len > 0;
}
bool basic_socket::receive()
{
	return receive(sockfd);
}

bool DH_socket::send(int socketfd,BIGNUM *tmp)
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

bool DH_socket::send(BIGNUM *tmp)
{
	return send(sockfd,tmp);
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

bool DH_socket::BN_receive()
{
	return BN_receive(sockfd);
}

bool DH_socket::AES_key_generator(BIGNUM *k,DH *dh)
{
	//unsigned char k_str[GENERATOR_LENGTH/sizeof(unsigned char)];
	//unsigned char k2_str[GENERATOR_LENGTH/sizeof(unsigned char)];
	//int k_len=BN_num_bytes(k);
	//int k2_len=BN_num_bytes(k2);
	//BN_bn2bin(k, k_str);
	//BN_bn2bin(k2, k2_str);
	unsigned char tmp[GENERATOR_LENGTH/sizeof(unsigned char)];
	int secret_size = DH_compute_key(tmp,k, dh);
	if (secret_size == -1) {
		perror("compute_key error");
		return 0;
	}
	for(int i=0;i<AES_KEY_LENGTH;++i){
		AES_key[i]=tmp[i];
	}
	return 1;
}

bool client_socket::connect2server(int socketfd,const std::string& address, int port)
{
    	if(!create(socketfd)){
    		perror("client host - creation error");
    		return 0;
    	}
    	if(!connect(address,port)){
    		perror("client host - connection failed");
    		return 0;
    	}
        return 1;
}
bool client_socket::connect2server(const std::string& address, int port)
{
	return connect2server(sockfd,address,port);
}

bool server_socket::start_server(int socketfd,const std::string& address, int port)
{
    	if(!create()){
    		perror("server host - creation error");
    		return 0;
    	}
    	if(!bind(address,port)){
		perror("server host - bind error");
		return 0;
	}
	if(!listen(socketfd,3)){
		perror("server host - listen error");
		return 0;
	}
        return  1;
}

bool server_socket::start_server(const std::string& address, int port)
{
	return start_server(sockfd,address,port);
}

void server_socket::accept_client(int socketfd)
{
        sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        int clientSock = accept(sockfd, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSock != -1){
            char buffer[1024];
            memset(buffer, 0, sizeof(buffer));
            //recv(clientSock, buffer, sizeof(buffer) - 1, 0);
            //send(clientSock, "Hello from server", 17, 0);
            /************************************
            TO BE CONTINUE
            */
            close(clientSock);
        }
}
void server_socket::accept_client()
{
	return accept_client(sockfd);
}

/********************************
血泪教训：
菱形继承的多义性
对不起于老师
我下次一定认真听课
********************************/

bool DH_server::start_DH_server(int socketfd,const std::string& address, int port)
{
    	if(!create()){
    		perror("server host - creation error");
    		return 0;
    	}
    	if(!bind(address,port)){
		perror("server host - bind error");
		return 0;
	}
	if(!listen(socketfd,3)){
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
	pub_key_for_send = const_cast<BIGNUM*>(DH_get0_pub_key(dh));
        return  1;
}

bool DH_server::start_DH_server(const std::string& address, int port)
{
	return start_DH_server(sockfd,address,port);
}

void DH_server::accept_DH_client(int socketfd)
{
        sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        int clientSock = accept(sockfd, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSock != -1){
		memset(buffer, 0, sizeof(buffer));
		if (!send(clientSock,p)){
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
		if (!send(clientSock,g)){
			perror("send g error");
			return;
		}
		if (BN_receive()){
			perror("receive pub key error");
			return;
		}
		pub_key_for_receive=tmp_bn;
		if (send(clientSock,pub_key_for_receive)){
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

void DH_server::accept_DH_client()
{
	return accept_DH_client(sockfd);
}

bool DH_client::connect2_DH_server(int socketfd,const std::string& address, int port)
{
	if(!connect2server(socketfd,address,port)){
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
    	if (!basic_socket::send(sockfd,iv)){
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
	pub_key_for_send = const_cast<BIGNUM*>(DH_get0_pub_key(dh));
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
	basic_socket::send(text);
	return 1;
}

bool DH_client::connect2_DH_server(const std::string& address, int port)
{
	return connect2_DH_server(sockfd,address,port);
}

















