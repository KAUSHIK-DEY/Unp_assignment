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
#include "aes.h"
void error(char *msg)
{
	perror(msg);
	exit(1);
}
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
 
// These vars will contain the hash
uint32_t h0, h1, h2, h3;
 
void md5(uint8_t *initial_msg, size_t initial_len) {
 
    // Message (to prepare)
    uint8_t *msg = NULL;
 
    // Note: All variables are unsigned 32 bit and wrap modulo 2^32 when calculating
 
    // r specifies the per-round shift amounts
 
    uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

    // Use binary integer part of the sines of integers (in radians) as constants// Initialize variables:
    uint32_t k[] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
 
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;
 
    // Pre-processing: adding a single 1 bit
    //append "1" bit to message    
    /* Notice: the input bytes are considered as bits strings,
       where the first bit is the most significant bit of the byte.[37] */
 
    // Pre-processing: padding with zeros
    //append "0" bit until message length in bit ≡ 448 (mod 512)
    //append length mod (2 pow 64) to message
 
    int new_len = ((((initial_len + 8) / 64) + 1) * 64) - 8;
 
    msg = calloc(new_len + 64, 1); // also appends "0" bits 
                                   // (we alloc also 64 extra bytes...)
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 128; // write the "1" bit
 
    uint32_t bits_len = 8*initial_len; // note, we append the len
    memcpy(msg + new_len, &bits_len, 4);           // in bits at the end of the buffer
 
    // Process the message in successive 512-bit chunks:
    //for each 512-bit chunk of message:
    int offset;
    for(offset=0; offset<new_len; offset += (512/8)) {
 
        // break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
        uint32_t *w = (uint32_t *) (msg + offset);
 
#ifdef DEBUG
        printf("offset: %d %x\n", offset, offset);
 
        int j;
        for(j =0; j < 64; j++) printf("%x ", ((uint8_t *) w)[j]);
        puts("");
#endif
 
        // Initialize hash value for this chunk:
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
 
        // Main loop:
        uint32_t i;
        for(i = 0; i<64; i++) {

#ifdef ROUNDS
            uint8_t *p;
            printf("%i: ", i);
            p=(uint8_t *)&a;
          //  printf("%2.2x%2.2x%2.2x%2.2x ", p[0], p[1], p[2], p[3], a);
         
            p=(uint8_t *)&b;
            printf("%2.2x%2.2x%2.2x%2.2x ", p[0], p[1], p[2], p[3], b);
         //
            p=(uint8_t *)&c;
          //  printf("%2.2x%2.2x%2.2x%2.2x ", p[0], p[1], p[2], p[3], c);
         
            p=(uint8_t *)&d;
           // printf("%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3], d);
            puts("");
#endif        

 
            uint32_t f, g;
 
             if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5*i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3*i + 5) % 16;          
            } else {
                f = c ^ (b | (~d));
                g = (7*i) % 16;
            }

#ifdef ROUNDS
            printf("f=%x g=%d w[g]=%x\n", f, g, w[g]);
#endif 
            uint32_t temp = d;
            d = c;
            c = b;
        //    printf("rotateLeft(%x + %x + %x + %x, %d)\n", a, f, k[i], w[g], r[i]);
            b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
            a = temp;


 
        }
 
        // Add this chunk's hash to result so far:
 
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
 
    }
 
    // cleanup
    free(msg);
 
}
int main(int argc,char *argv[])
{
	int sockfd,n;
	struct sockaddr_in serv_addr;
	char *nr;
	char buffer[1000];
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

	if(argc <3)
	{
		fprintf(stderr,"usage %s hostname port\n",argv[0]);
		exit(0);
	}
	sockfd=socket(AF_INET,SOCK_STREAM,0);
	if(sockfd<0)
	{
		error("ERROR opening socket");
	}
	bzero((char *)&serv_addr,sizeof(serv_addr));
	serv_addr.sin_family=AF_INET;
	serv_addr.sin_port=htons(atoi(argv[2]));
	serv_addr.sin_addr.s_addr=inet_addr(argv[1]);
	if(connect(sockfd,(struct sockaddr*)&serv_addr,sizeof(serv_addr))<0)
	{
		error("ERROR connecting");
		exit(1);
	}
        printf(" connected to server from port no %d and IP %s \n",ntohs(serv_addr.sin_port),inet_ntoa(serv_addr.sin_addr));
	w = aes_init(sizeof(key));
	aes_key_expansion(key, w);
	uint8_t p[2000];
	printf("Please enter the string");
	bzero(buffer,1000);
	fgets(buffer,1000,stdin);
	md5(buffer,strlen(buffer));
	uint8_t *b=buffer;
	aes_cipher(b , p, w );
	char *d=p;
	int m=strlen(d);
	nr=(char *)malloc((m+16)*sizeof(char));
	nr=d;
	uint8_t *pr;

    // display result
 
    pr=(uint8_t *)&h0;
    
    nr[m+0]=(char)pr[0];
    nr[m+1]=(char)pr[1];
    nr[m+2]=(char)pr[2]; 
    nr[m+3]=(char)pr[3];
    pr=(uint8_t *)&h1;
    
    nr[m+4]=(char)pr[0];
    nr[m+5]=(char)pr[1];
    nr[m+6]=(char)pr[2]; 
    nr[m+7]=(char)pr[3];
    pr=(uint8_t *)&h2;
   
    nr[m+8]=(char)pr[0];
    nr[m+9]=(char)pr[1];
    nr[m+10]=(char)pr[2]; 
    nr[m+11]=(char)pr[3];
    pr=(uint8_t *)&h3;
    
    nr[m+12]=pr[0];
    nr[m+13]=pr[1];
    nr[m+14]=pr[2]; 
    nr[m+15]=pr[3];
	
	n=write(sockfd,nr,strlen(nr));
	if(n<0)
	{
		error("Error writing the socket");
	}
	printf("%s",buffer);
	bzero(buffer,256);
	n=read(sockfd,buffer,256);
	if(n<0)
	{
		error("Error reading from socket");	
		exit(1);

	}

	return 0;
}
