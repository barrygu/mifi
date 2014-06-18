/* fpont 1/00 */
/* pont.net    */
/* tcpServer.c */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h> /* close */
#include <string.h>
#include <pthread.h>
#include <stdlib.h>

//#define DEBUG
#include "tcpComm.h"
#include "tcpServer.h"

//#define END_LINE 0x0

struct receive_param {
	int sd;
};

void* control_thread(void *arg)
{
//	struct receive_param *rpar = (struct receive_param *)arg;
//	char line[MAX_MSG];

	while(1) {
		sleep(30);
	}
}

void* receive_thread(void *arg)
{
	struct receive_param *rpar = (struct receive_param *)arg;
	char line[MAX_MSG], resp[MAX_MSG];
	u8 sum;
	int len;
	
	/* init line */
	memset(line, 0x0, MAX_MSG);

	/* receive segments */
	while (read_packet(rpar->sd, (PMIFI_PACKET) line) != ERROR) {

//		printf("received from %s:TCP%d : \n",
//				inet_ntoa(cliAddr.sin_addr), ntohs(cliAddr.sin_port));

		len = get_packet_len((PMIFI_PACKET) line);
		sum = get_checksum((u8*)line, len - 1);
		DBG_OUT("len = %d, recv sum = 0x%02x, calc sum = 0x%02x\n", len, (u8)line[len - 1], sum);
		dump_packet((PMIFI_PACKET) line);

		len = server_build_response((PMIFI_PACKET)line, (PMIFI_PACKET)resp);
		printf("build response len is %d\n", len);
		if (len > 0) {
			dump_packet((PMIFI_PACKET) resp);

			printf("sending response to client...\n");
			send(rpar->sd, resp, len, 0);
			printf("sent done.\n");
		}
		/* init line */
		memset(line, 0x0, MAX_MSG);
	} /* while(read_line) */

	free(rpar);
	return NULL;
}

struct listen_param{
	int port;
	void* (*receive_thread)(void *arg);
};
void* listen_thread(void *arg)
{
	pthread_t tid;
	int sd, newSd;
	socklen_t cliLen;

	struct sockaddr_in cliAddr;
	struct sockaddr_in servAddr;
	struct listen_param *lpar = (struct listen_param*)arg;

	/* create socket */
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		perror("cannot open socket ");
		return NULL;
	}

	/* bind server port */
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(lpar->port);

	printf("bind on TCP port %u\n", lpar->port);
	if (bind(sd, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
		perror("cannot bind port ");
		return NULL;
	}

	listen(sd, 5);

	while (1) {

		printf("waiting for data on TCP port %u\n", lpar->port);

		cliLen = sizeof(cliAddr);
		newSd = accept(sd, (struct sockaddr *) &cliAddr, &cliLen);
		if (newSd < 0) {
			perror("cannot accept connection ");
			return NULL;
		}
		
		// create new thread
		struct receive_param *rpar = (struct receive_param *)malloc(sizeof(struct receive_param));
		rpar->sd = newSd;
		pthread_create(&tid, NULL, lpar->receive_thread, rpar);
	}
	return NULL;
}

int main(int UNUSED(argc), char *argv[]) 
{
	int i;
	pthread_t tid[2];
	void *status;
	struct listen_param lpar[2];
	
	lpar[0].port = SERVER_PORT;
	lpar[0].receive_thread = receive_thread;
	pthread_create(&tid[0], NULL, listen_thread, &lpar[0]);
	
	lpar[1].port = 8899;
	lpar[1].receive_thread = control_thread;
	pthread_create(&tid[1], NULL, listen_thread, &lpar[1]);
	
	for (i = 0; i < sizeof(tid)/sizeof(tid[0]); i++)
		pthread_join(tid[i],&status); 
		
	return 0;
}

int server_build_response(PMIFI_PACKET packet, PMIFI_PACKET resp)
{
	int datalen = 0, packetlen = 0;
	u8 sum;
	u16 func = packet->func; // __builtin_bswap16(packet->func);

	memcpy(resp, packet, sizeof(*packet));
	resp->func = 0x8001;  // little-endian: 0x0180

	switch (func)	{
	case MIFI_CLI_LOGIN:
	case MIFI_CLI_ALIVE:
	//case MIFI_USR_CHECK:
		datalen = 100;
		resp->datalen = __builtin_bswap16(datalen); //0x0200; // little-endian: 0x0002
		memset(resp->data, 0xcc, datalen);
		resp->data[0] = (u8)(func);
		resp->data[1] = (u8)(func >> 8);
		resp->data[2] = 'O';
		resp->data[3] = 'K';
		resp->data[98] = 'K';
		resp->data[99] = 'O';
		break;

	case MIFI_USR_CHECK:
        {
            char *purl = "http://news.baidu.com";
            datalen = strlen(purl);
            resp->datalen = __builtin_bswap16(datalen); //0x0200; // little-endian: 0x0002
            strcpy((char *)resp->data, purl);
        }
        break;

	default:
		return -1;
	}

	packetlen =  sizeof(MIFI_PACKET) + datalen;
	sum = get_checksum((u8 *)resp, packetlen);
	*(((u8 *)resp) + packetlen) = sum;
	return packetlen + 1;
}
