#include<iostream>
#include<cstring>
#include<openssl/evp.h>
#include<openssl/aes.h>
#include<openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>
#define PORT 12000
#define BUFFER_SIZE 4096

unsigned char universal_key[32]="aaaabbbbccccdddd"; 

void print_hex(unsigned char* str) {
	int n=sizeof(str)/sizeof(unsigned char);
	for(int i=0;i<n;i++){
		printf("%x",str[i]>>4);
		printf("%x",str[i]%(1<<4));
	}
	printf("\n");
}

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())){
    	handleErrors();
    }

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
    	handleErrors();
    }

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    	handleErrors();
    }
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    	handleErrors();
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}


int main()
{
	int server_fd,new_socket;
	struct sockaddr_in address;
	int addrlen=sizeof(address);
	int opt=1;
	unsigned char buffer[BUFFER_SIZE];
	//unsigned char key[32];
	unsigned char iv[16];
	
	memset(buffer,0,sizeof(buffer));
	std::cout<<"start\n";
	
	// 初始化 OpenSSL
	ERR_load_CRYPTO_strings();
	OpenSSL_add_all_algorithms();
	std::cout<<"initalize complete\n";
	// 生成服务器的 DH 参数
	DH *dh = DH_new();
	if (!DH_generate_parameters_ex(dh, 512, DH_GENERATOR_2, nullptr)) {
	handleErrors();
	}
	std::cout<<"DH INIT COMPLETE\n";
	// 生成服务器的私钥和公钥对
	if (!DH_generate_key(dh)) {
		handleErrors();
	}
	std::cout<<"DH key COMPLETE\n";
	// 提取服务器的公钥
	const BIGNUM *pub_key = DH_get0_pub_key(dh);
	// 计算公钥的字节长度
	int pub_key_length = BN_num_bytes(pub_key);

	// 分配足够大小的缓冲区来存储公钥的字节数据
	unsigned char *pub_key_data = new unsigned char[pub_key_length];

	// 将公钥转换为字节数据
	BN_bn2bin(pub_key, pub_key_data);
	print_hex(pub_key_data);
	
	if((server_fd=socket(AF_INET,SOCK_STREAM,0))==0){
		perror("socket failed");
		exit(EXIT_FAILURE);
	}
	if(setsockopt(server_fd,SOL_SOCKET,SO_REUSEADDR |SO_REUSEPORT,&opt,sizeof(opt))){
		perror("setsocketopt failed");
		exit(EXIT_FAILURE);
	}
	
	address.sin_family=AF_INET;
	address.sin_addr.s_addr=INADDR_ANY;
	address.sin_port=htons(PORT);
	
	if(bind(server_fd,(struct sockaddr *)&address,sizeof(address))<0){
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	if(listen(server_fd,3)<0){
		perror("Listen");
		exit(EXIT_FAILURE);
	}
	
	while(true){
		
		std::cout<<"listening...\n";
		
		if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
			perror("Accept");
			exit(EXIT_FAILURE);
	    	}
	    	std::cout<<"new connection estabished\n";
	    	read(new_socket, iv, sizeof(iv));
	    	std::cout<<"iv received: "<<iv<<" \n";
	    	//read(new_socket, pub_key_data, sizeof(pub_key_data));
	    	int data_length=read(new_socket, buffer, BUFFER_SIZE);
	    	//std::cout << "Public key received: "<<buffer<<std::endl;
	    	send(new_socket,pub_key_data,pub_key_length,0);
	    	std::cout << "public key sent\n";
	    	BIGNUM *client_pub_key = BN_bin2bn(buffer, data_length, NULL);  // 将此替换为实际接收到的客户端公钥
		//printf("cilent public key: %s \n",buffer);
		
		int client_pub_key_length = BN_num_bytes(client_pub_key);
		unsigned char *client_pub_key_data = new unsigned char[client_pub_key_length];
		BN_bn2bin(client_pub_key, client_pub_key_data);
		//freopen("server.txt","w",stdout);
		printf("下面是服务器端本身的公钥：\n");
		print_hex(pub_key_data);
		printf("下面是服务器端接收到的来自客户端的公钥：\n");
		print_hex(client_pub_key_data);
		BIGNUM *secured_pub_key=BN_bin2bn(client_pub_key_data, data_length, NULL);
		
		// 计算共享密钥
		unsigned char shared_secret[32];
		memset(shared_secret,0,sizeof(shared_secret));
		int secret_size = DH_compute_key(shared_secret,secured_pub_key, dh);
		if (secret_size == -1) {
			handleErrors();
		}
		//std::cout<<"real key got: "<<shared_secret<<" \n";
		printf("下面是计算得到的共享秘钥,长度：%d  内容 ：\n",secret_size);
		print_hex(shared_secret);
		//fclose(stdout);
		
		int valread = read(new_socket, buffer, BUFFER_SIZE);
		
		std::cout<<"test message received\n";
		
		// Decrypt the message
		unsigned char decryptedtext[BUFFER_SIZE];
		//int decryptedtext_len = decrypt(buffer, valread, shared_secret, iv, decryptedtext);
		int decryptedtext_len = decrypt(buffer, valread, universal_key, iv, decryptedtext);
		decryptedtext[decryptedtext_len] = '\0';

		std::cout << "Decrypted message: " << decryptedtext << std::endl;
		
		//send(new_socket, buffer, strlen(buffer), 0);
		//std::cout << "Echo message sent\n";

		close(new_socket);
		
	}
	close(server_fd);
	free(pub_key_data);
	return 0;
}
