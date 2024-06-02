#include "socket.h"

bool basic_socket::create()
{
	sockfd=socket(AF_INET,SOCK_STREAM,0);
	std::cout<<sockfd;
	return sockfd!=-1;
}
//bool basic_socket::create()
//{
//	return create(sockfd);
//}

bool basic_socket::bind(int socketfd,const std::string& address,int port)
{
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;//inet_addr(address.c_str());
	return ::bind(socketfd, (struct sockaddr*)&addr, sizeof(addr)) != -1;
}
bool basic_socket::bind(const std::string& address,int port)
{
	return bind(sockfd,address,port);
}

bool basic_socket::connect(int socketfd,const std::string& address,int port)
{
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (inet_pton(AF_INET, address.c_str(), &addr.sin_addr) <= 0) {
		perror("\033[31mInvalid address/ Address not supported\033[0m");
		return 0;
	}
	
	//addr.sin_addr.s_addr = inet_addr(address.c_str());
	std::cout<<socketfd<<address<<port;
	if (::connect(socketfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("\033[31mConnection Failed\033[0m");
		return 0;
	}
	smp("connection established");
	return 1;//::connect(socketfd, (struct sockaddr*)&addr, sizeof(addr)) != -1;
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
	recv_len = ::recv(socketfd, buffer, sizeof(buffer), 0);
	return recv_len > 0;
}
bool basic_socket::receive()
{
	return receive(sockfd);
}

bool DH_socket::send(int socketfd,BIGNUM *tmp)
{
	std::cout<<(tmp==nullptr);
	smp("BIGNUM send method started");
	std::cout<<(tmp==nullptr);
	int tmp_len=BN_num_bytes(tmp);
	smp("length confirmed");
	unsigned char *str=new unsigned char[tmp_len*2];
	smp("address commiitted");
	BN_bn2bin(tmp, str);
	smp("transmition completed");
	if (::send(socketfd, str, tmp_len, 0) != -1){
		free(str);
		str=NULL;
		smp("DH sent");
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
	smp("BN receive method started");
	recv_len = ::recv(socketfd, buffer, sizeof(buffer), 0);
	if (recv_len<=0){
		perror("\033[31mREAD BN Failed\033[0m");
		return 0;
	}
	if (BN_bin2bn(buffer,recv_len,tmp_bn) != 0) {
		smp("BN transmition successful");
	   	return 1;
	}else{
		std::cout<<recv_len;
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
		perror("\033[31mcompute_key error\033[0m");
		return 0;
	}
	for(int i=0;i<AES_KEY_LENGTH;++i){
		AES_key[i]=tmp[i];
	}
	return 1;
}

bool client_socket::connect2server(int socketfd,const std::string& address, int port)
{
    	if(!create()){
    		perror("\033[31mclient host - creation error\033[0m");
    		return 0;
    	}
    	smp("creat sucess");
    	if(!connect(address,port)){
    		perror("\033[31mclient host - connection failed\033[0m");
    		return 0;
    	}
    	smp("connect success");
        return 1;
}
bool client_socket::connect2server(const std::string& address, int port)
{
	return connect2server(sockfd,address,port);
}

bool server_socket::start_server(int socketfd,const std::string& address, int port)
{
    	if(!create()){
    		perror("\033[31mserver host - creation error\033[0m");
    		return 0;
    	}
    	if(!bind(address,port)){
		perror("\033[31mserver host - bind error\033[0m");
		return 0;
	}
	if(!listen(socketfd,3)){
		perror("\033[31mserver host - listen error\033[0m");
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

bool DH_server::start_DH_server(const std::string& address, int port)
{
    	std::cout<<sockfd;
    	if(!create()){
    		perror("\033[31mserver host - creation error\033[0m");
    		return 0;
    	}
    	//std::cout<<" "<<socketfd<<" "<<sockfd<<" ";
    	//std::cout<<"\033[32m\033[0m"<<std::endl;
    	smp("create succuess");
    	if(!bind(address,port)){
		perror("\033[31mserver host - bind error\033[0m");
		return 0;
	}
	smp("bind success");
	if(listen(sockfd,3)<0){
		perror("\033[31mserver host - listen error\033[0m");
		return 0;
	}
	//DH *dh = DH_new();
	if (!DH_generate_parameters_ex(dh, GENERATOR_LENGTH, DH_GENERATOR_2, nullptr)) {
		perror("\033[31mserver host - DH_generate_parameters_ex\033[0m");
		return 0;
	}
	p = BN_dup(DH_get0_p(dh));
	g = BN_dup(DH_get0_g(dh));
	if (!DH_generate_key(dh)) {
		perror("\033[31mserver host - DH_generate_key\033[0m");
		return 0;
	}
	pub_key_for_send = const_cast<BIGNUM*>(DH_get0_pub_key(dh));
	smp("generate success");
	
	running = true;
        server_thread = std::thread(&DH_server::run_DH_server, this);
        
	smp("running start");
	std::cout<<sockfd<<"listening on "<<address<<" "<<port<<std::endl;
        return  1;
}

//bool DH_server::start_DH_server(const std::string& address, int port)
//{
//	return start_DH_server(sockfd,address,port);
//}

void DH_server::accept_DH_client(int socketfd)
{
        sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        //smp("start accept");
        int clientSock = accept(socketfd, (struct sockaddr*)&clientAddr, &clientAddrLen);
        //
        if (clientSock != -1) smp(clientSock);
        if (clientSock != -1){
        	smp("connection established");
		memset(buffer, 0, sizeof(buffer));
		if (!send(clientSock,p)){
			perror("\033[31msend p error\033[0m");
			return;
		}
		smp("var p sent");
		std::cout<<"p:"<<p<<std::endl;
		if (!receive(clientSock)){
			print_hex(buffer);
			perror("\033[31mreceive iv error\033[0m");
			return;
		}
		smp("iv received");
		for(int i=0;i<recv_len;++i){
			iv[i]=buffer[i];
		}
		smp("iv copied");
		print_hex(iv);
		if (!send(clientSock,g)){
			perror("\033[31msend g error\033[0m");
			return;
		}
		smp("var g sent");
		std::cout<<"g:"<<g<<std::endl;
		if (!BN_receive(clientSock)){
			perror("\033[31mreceive pub key error\033[0m");
			return;
		}
		BN_copy(pub_key_for_receive,tmp_bn);
		smp("pub key received");
		if (!send(clientSock,pub_key_for_send)){
			perror("\033[31msend pub key error\033[0m");
			return;
		}
		smp("pub key sent");
		if (!AES_key_generator(pub_key_for_receive,dh)){
			perror("\033[31mgenerate aes key error\033[0m");
			return;
		}
		smp("key generated successfully");
		memset(buffer,0,sizeof(buffer));
		print_hex(AES_key);
		if (!receive(clientSock)){
			perror("\033[31message receive error\033[0m");
		}
		unsigned char text[BUFFER_SIZE];
		smp("decrypting...");
		//print_hex(AES_key);
		//print_hex(iv);
		std::cout<<recv_len;
		AES_decrypt(buffer,recv_len,AES_key,iv,text);
		
		smp("decrypt successfully,text below");
		printf("\033[32m%s\033[0m\n",text);
		smp("going to close present socket");
		
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
		perror("\033[31mbasic connection fail\033[0m");
		return 0;
	}
	smp("connection established");
	if (!RAND_bytes(iv, IV_LENGTH)) {
        	perror("\033[31mError generating random IV");
        	return 0;
    	}
    	smp("iv generated");
    	print_hex(iv);
    	if (!BN_receive()){
    		perror("\033[31mreceive p fail\033[0m");
    		return 0;
    	}
    	smp("var p received");
    	//*p=*tmp_bn;
    	BN_copy(p,tmp_bn);
    	//std::cout<<"p:"<<p<<std::endl;
    	//BN_free(tmp_bn);
    	//tmp_bn=nullptr;
    	//tmp_bn=BN_new();
    	
    	if (!basic_socket::send(sockfd,iv)){
    		perror("\033[31miv send fail\033[0m");
    		return 0;
    	}
    	smp("iv sent");
    	print_hex(iv);
    	if (!BN_receive()){
    		perror("\033[31mreceive g fail\033[0m");
    		return 0;
    	}
    	smp("var g received");
    	//*g=*tmp_bn;
    	BN_copy(g,tmp_bn);
    	//std::cout<<"g:"<<g<<std::endl;
    	if (!DH_set0_pqg(dh, p, nullptr, g)) {
		perror("\033[31mcreate dh error\033[0m");
		return 0;
	}
	std::cout<<(dh==nullptr);
	smp("p,g,dh ready");
	if (!DH_generate_key(dh)) {
		perror("\033[31mcreate key error\033[0m");
		return 0;
	}
	//DH_generate_key(dh);
	smp("key initialized");
	pub_key_for_send = const_cast<BIGNUM*>(DH_get0_pub_key(dh));
	std::cout<<(pub_key_for_send==nullptr);
	smp("pub key prepared");
    	if (!send(sockfd,pub_key_for_send)){
    		perror("\033[31msend pub key fail\033[0m");
    		return 0;
    	}
    	smp("pub key sent");
    	if (!BN_receive()){
		perror("\033[31mreceive pub key error\033[0m");
		return 0;
	}
	smp("pub key received");
	BN_copy(pub_key_for_receive,tmp_bn);
    	if (!AES_key_generator(pub_key_for_receive,dh)){
		perror("\033[31mgenerate aes key error\033[0m");
		return 0;
	}
	smp("key generated successfully");
	print_hex(AES_key);
	unsigned char text[BUFFER_SIZE];
	std::string message;//="an unfriendly greeting from client: ********";
	std::cout<<"please input a message below\n";
	std::getline(std::cin,message);
	smp("encrypting...");
	print_hex(AES_key);
	print_hex(iv);
	AES_encrypt((unsigned char*)message.c_str(), message.length(),AES_key,iv,text);
	std::cout<<message.length();
	smp("encrypt successfully");
	basic_socket::send(text);
	smp("encrypted message sent");
	return 1;
}

bool DH_client::connect2_DH_server(const std::string& address, int port)
{
	return connect2_DH_server(sockfd,address,port);
}

