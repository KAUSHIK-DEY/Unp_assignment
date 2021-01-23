# include<stdio.h>
# include<stdlib.h>
# include<unistd.h>
# include<sys/socket.h>
# include<sys/types.h>
# include<netdb.h>
# include<netinet/in.h>
# include<arpa/inet.h>
# include<string.h>
# include<strings.h>
# include "aes.h"
void error(char * msg)
{
	perror(msg);
	exit(1);
}

int main(int argc,char *argv[])
{
	int sockfd,newsockfd,clilen;
	char buffer[2000];
	struct sockaddr_in serv_addr,cli_addr;
        int n;
        uint8_t *w; 
	uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b,
		0x1c, 0x1d, 0x1e, 0x1f};
if(argc<2)
{
	fprintf(stderr,"error!! no port provided\n");
	exit(1);
}
	sockfd=socket(AF_INET,SOCK_STREAM,0);
	if(sockfd<0)
	{
		error("ERROR opening socket");
	}
	bzero((char *) &serv_addr,sizeof(serv_addr));
	serv_addr.sin_family=AF_INET;
	serv_addr.sin_addr.s_addr=INADDR_ANY;
	serv_addr.sin_port=htons(atoi(argv[1]));
	if(bind(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr))<0)
	{
		error("ERROR on binding");
		exit(1);
	}
	listen(sockfd,5);	
		clilen=sizeof(cli_addr);
		newsockfd=accept(sockfd,(struct sockaddr *)&cli_addr,&clilen);
		if(newsockfd<0)
		{
			error("ERROR on accept");
			exit(1);
		}
		printf("New client connected from port no %d and IP %s \n",ntohs(cli_addr.sin_port),inet_ntoa(cli_addr.sin_addr));
		bzero(buffer,2000);
		n=read(newsockfd,buffer,2000);
		int m=strlen(buffer);
		w = aes_init(sizeof(key));
		aes_key_expansion(key, w);
		uint8_t *p=buffer;
		uint8_t  b[m];
		if(n<0)
		{
			error("ERROR reading from socket");		
			exit(1);
		}
		aes_inv_cipher(p, b, w);
		char *k=b;
		printf("%s",k);
		printf("Here is the message: %d\n ",strlen(buffer));
		
		n=write(newsockfd,buffer,2000);
		close(newsockfd);
		if(n<0)
		{
			error("ERROR writing to socket");
			exit(1);
		}
		
	close(sockfd);
return 0;	
}
