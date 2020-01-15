#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>

#define PORTNUM 4598
#define PASSCODE "@&asuysl*9712jayts$7"
#define MAX_NOTIFICATION_QUEUE 20
#define MAX_NOTIFICATION_SIZE 100

int main(){
	struct sockaddr_in serv;
	int mysocket;
	socklen_t socksize = sizeof(struct sockaddr_in);
	memset(&serv,0,sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = htonl(INADDR_ANY);
	serv.sin_port = htons(PORTNUM);

	mysocket = socket(AF_INET,SOCK_STREAM,0);

	bind(mysocket,(struct sockaddr *)&serv,sizeof(struct sockaddr));
	
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
		char buffer[strlen(PASSCODE)];
		bzero(buffer,strlen(PASSCODE));
		read(consocket,buffer,strlen(PASSCODE));
		if(strcmp(buffer,PASSCODE) != 0){
			printf("wrong");
			close(consocket);
			continue;
		}
		read(consocket,buffer,2);
		
		char buffer2[1];
		bzero(buffer2,1);
		read(consocket,buffer2,1);
		if(buffer2[0] == 0){
			char buffer3[MAX_NOTIFICATION_SIZE];
			bzero(buffer3,MAX_NOTIFICATION_SIZE);
			read(consocket,buffer3,MAX_NOTIFICATION_SIZE);
			char flag = 0;
			for(int i = 0; MAX_NOTIFICATION_QUEUE; i++){
				if(strcmp(notifications[i],"")){
					// Found an empty slot
					char* slot = notifications[i];
					memcpy(&slot,&buffer3,MAX_NOTIFICATION_SIZE);
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
				if(strcmp(slot,"")) break;
				send(consocket,slot,MAX_NOTIFICATION_SIZE,0);
				send(consocket,"\n",1,0);
			}
		}
		close(consocket);
		printf("closed");
	}
	
	return 0;
}
