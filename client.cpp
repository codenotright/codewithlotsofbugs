#include <iostream>
#include <cstring>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>


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

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}



int main() {
	int sock = 0;
	struct sockaddr_in serv_addr;
	unsigned char buffer[BUFFER_SIZE] = {0};
	int iv_length=16;
	//unsigned char key[32];
	unsigned char iv[iv_length];
	
	std::cout<<"start\n";
	ERR_load_CRYPTO_strings();
   	OpenSSL_add_all_algorithms();
   	//初始化openSSL
   	std::cout<<"initalize complete\n";
   	
	DH *dh = DH_new();
	if (!DH_generate_parameters_ex(dh, 512, DH_GENERATOR_2, nullptr)) {
	handleErrors();
	}
	//生成客户端的DH参数
	std::cout<<"DH INIT COMPLETE\n";

	if (!DH_generate_key(dh)) {
	handleErrors();
	}
	//生成客户端的私钥和公钥对

	// 提取客户端的公钥
	const BIGNUM *pub_key = DH_get0_pub_key(dh);
	// 计算公钥的字节长度
	int pub_key_length = BN_num_bytes(pub_key);

	// 分配足够大小的缓冲区来存储公钥的字节数据
	unsigned char *pub_key_data = new unsigned char[pub_key_length];

	// 将公钥转换为字节数据
	BN_bn2bin(pub_key, pub_key_data);
	print_hex(pub_key_data);
	
	
	if (!RAND_bytes(iv, iv_length)) {
        	std::cerr << "Error generating random IV" << std::endl;
        	exit(EXIT_FAILURE);
    	}
	//生成iv
	
	
	//接下来需要从服务器端获得服务器端的公钥进行下一步操作
	

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		std::cerr << "Socket creation error" << std::endl;
		exit(EXIT_FAILURE);
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	if (inet_pton(AF_INET, "10.0.0.1", &serv_addr.sin_addr) <= 0) {
		std::cerr << "Invalid address/ Address not supported" << std::endl;
		exit(EXIT_FAILURE);
	}

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		std::cerr << "Connection Failed" << std::endl;
		exit(EXIT_FAILURE);
	}
	//连接到目标服务器，这里使用mininet模拟，因此为10.0.0.1（h1）

	std::string message = "Request for public key";
	//send(sock, message.c_str(), message.length(), 0);
	send(sock,iv,iv_length,0);
	send(sock,pub_key_data,pub_key_length,0);
	std::cout << "iv sent: "<<iv<<" \n";
	//std::cout << "public key sent: "<<pub_key_data<<" \n";
	int data_length=read(sock, buffer, BUFFER_SIZE);
	
	BIGNUM *server_pub_key = BN_bin2bn(buffer, data_length, NULL);  // 将此替换为实际接收到的客户端公钥
	//std::cout << "Public key received: "<<server_pub_key<<std::endl;
	//printf("server public key: %s \n",buffer);
	// 计算共享密钥
	
	
	int server_pub_key_length = BN_num_bytes(server_pub_key);
	unsigned char *server_pub_key_data = new unsigned char[server_pub_key_length];
	BN_bn2bin(server_pub_key, server_pub_key_data);
	//freopen("client.txt","w",stdout);
	printf("下面是客户端本身的公钥：\n");
	print_hex(pub_key_data);
	printf("下面是客户端接收到的来自服务器端的公钥：\n");
	print_hex(server_pub_key_data);
	
	BIGNUM *secured_pub_key=BN_bin2bn(server_pub_key_data, data_length, NULL);
	unsigned char shared_secret[32];
	memset(shared_secret,0,sizeof(shared_secret));
	int secret_size = DH_compute_key(shared_secret,secured_pub_key, dh);
	if (secret_size == -1) {
		handleErrors();
	}
	printf("下面是计算得到的共享秘钥,长度：%d  内容 ：\n",secret_size);
	print_hex(shared_secret);
	message = "this is a test message for AES";
	std::string ciphertext;
	//int ciphertext_len = encrypt((unsigned char*)message.c_str(), message.length(), shared_secret, iv, (unsigned char*)ciphertext.c_str());
	int ciphertext_len = encrypt((unsigned char*)message.c_str(), message.length(), universal_key, iv, (unsigned char*)ciphertext.c_str());
	std::cout<<"test message proceeded\n";
	send(sock, ciphertext.c_str(), ciphertext_len, 0);
	std::cout<<"test message sent\n";

	close(sock);
	free(pub_key_data);
	//fclose(stdout);
	return 0;
}
