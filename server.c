#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#define PORTNUM 4598
#define PASSCODE "@&asuysl*9712jayts$7"
#define MAX_NOTIFICATION_QUEUE 20
#define MAX_NOTIFICATION_SIZE 100

SSL_CTX* initSSL(){
	const SSL_METHOD *method;
	SSL_CTX *ctx;
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	method = TLSv1_2_server_method();
	ctx = SSL_CTX_new(method);
	if(ctx == NULL){
		printf("Err: %d",errno);
		return NULL;
	}
	return ctx;
}
int loadCertificates(SSL_CTX* ctx, char* certFile, char* keyFile){
	if(SSL_CTX_use_certificate_file(ctx,certFile,SSL_FILETYPE_PEM) <= 0){
		printf("Err: %d\n",errno);
		return 1;
	}
	if(SSL_CTX_use_PrivateKey_file(ctx,keyFile,SSL_FILETYPE_PEM) <= 0){
		printf("Err: %d\n",errno);
		return 2;
	}
	if(!SSL_CTX_check_private_key(ctx)){
		printf("Err: %d\n",errno);
		return 3;
	}
	return 0;
}
void handleConnection(SSL *ssl, char** notifications){
	// Accept ssl connection
	if(!SSL_accept(ssl)){
		printf("Err: %d\n",errno);
		return;
	}

	char *buffer[strlen(PASSCODE)];
	bzero(buffer,strlen(PASSCODE));
	SSL_read(ssl,&buffer,strlen(PASSCODE));
	int diff = strcmp(&buffer,PASSCODE);
	if(diff != 0){
		printf("wrong");
		int sd = SSL_get_fd(ssl);
		SSL_free(ssl);
		close(sd);
		return;
	}
	SSL_read(ssl,buffer,2);
	
	char buffer2[1];
	bzero(buffer2,1);
	SSL_read(ssl,&buffer2,1);
	if(buffer2[0] == 'a'){
		char buffer3[MAX_NOTIFICATION_SIZE];
		bzero(buffer3,MAX_NOTIFICATION_SIZE);
		SSL_read(ssl,&buffer3,MAX_NOTIFICATION_SIZE);
		char flag = 0;
		for(int i = 0; i < MAX_NOTIFICATION_QUEUE; i++){
			if(strcmp(&notifications[i],"") == 0){
				// Found an empty slot
				memcpy(&notifications[i],&buffer3,MAX_NOTIFICATION_SIZE);
				flag = 1;
				break;
			}
		}
		if(!flag){
			bzero(notifications[MAX_NOTIFICATION_QUEUE-1],MAX_NOTIFICATION_SIZE);
			for(int i = MAX_NOTIFICATION_QUEUE-1; i > 0; i--){
				memcpy(&notifications[i+1],&notifications[i],MAX_NOTIFICATION_SIZE);
				bzero(&notifications[i],MAX_NOTIFICATION_SIZE);
			}
			char *slot = notifications[0];
			memcpy(&slot,&buffer3,MAX_NOTIFICATION_SIZE);
		}
	}else{
		for(int i = 0; i < MAX_NOTIFICATION_QUEUE; i++){
			char *slot = notifications[i];
			SSL_write(ssl,&slot,strlen(&slot));
			SSL_write(ssl,"\n",1);
			bzero(&notifications[i],MAX_NOTIFICATION_SIZE);
		}
	}
	int sd = SSL_get_fd(ssl);
	SSL_free(ssl);
	close(sd);
}

int main(int count, char** args){
	if(count != 3){
		printf("Usage: %s <certfile> <keyfile>\n",args[0]);
		exit(0);
	}
	SSL_CTX* ctx = initSSL();
	loadCertificates(ctx,args[1],args[2]);

	struct sockaddr_in serv;
	int mysocket;
	socklen_t socksize = sizeof(struct sockaddr_in);
	memset(&serv,0,sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = htonl(INADDR_ANY);
	serv.sin_port = htons(PORTNUM);

	mysocket = socket(AF_INET,SOCK_STREAM,0);

	bind(mysocket,(struct sockaddr *)&serv,sizeof(struct sockaddr));
	
	if(mysocket <= 0){
		printf("Err: %d\n",errno);
		return -1;
	}
	
	char notifications[MAX_NOTIFICATION_QUEUE][MAX_NOTIFICATION_SIZE];
	for(int i = 0; i < MAX_NOTIFICATION_QUEUE; i++){
		bzero(notifications[i],MAX_NOTIFICATION_SIZE);
	}
	listen(mysocket,1);
	while(1){
		struct sockaddr_in dest;
		int consocket = accept(mysocket,(struct sockaddr *)&dest,&socksize);
		if(consocket < 0){
		       	int err = errno;
			printf("%d\n",err);
			continue;
		}
		SSL *ssl = SSL_new(ctx);
		SSL_set_fd(ssl,consocket);
		handleConnection(ssl,*notifications);
	}
	SSL_CTX_free(ctx);
	
	return 0;
}
