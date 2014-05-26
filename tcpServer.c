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

#define DEBUG
#include "tcpComm.h"
#include "tcpServer.h"

//#define END_LINE 0x0

int main(int UNUSED(argc), char *argv[]) {

	int sd, newSd, len;
	socklen_t cliLen;
	u8 sum;

	struct sockaddr_in cliAddr, servAddr;
	char line[MAX_MSG], resp[MAX_MSG];

	/* create socket */
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		perror("cannot open socket ");
		return ERROR;
	}

	/* bind server port */
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(SERVER_PORT);

	if (bind(sd, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
		perror("cannot bind port ");
		return ERROR;
	}

	listen(sd, 5);

	while (1) {

		printf("%s: waiting for data on port TCP %u\n", argv[0], SERVER_PORT);

		cliLen = sizeof(cliAddr);
		newSd = accept(sd, (struct sockaddr *) &cliAddr, &cliLen);
		if (newSd < 0) {
			perror("cannot accept connection ");
			return ERROR;
		}

		/* init line */
		memset(line, 0x0, MAX_MSG);

		/* receive segments */
		while (read_packet(newSd, (PMIFI_PACKET) line) != ERROR) {

			printf("%s: received from %s:TCP%d : \n", argv[0],
					inet_ntoa(cliAddr.sin_addr), ntohs(cliAddr.sin_port));

			len = get_packet_len((PMIFI_PACKET) line);
			sum = get_checksum((u8*)line, len - 1);
			DBG_OUT("len = %d, recv sum = 0x%02x, calc sum = 0x%02x\n", len, (u8)line[len - 1], sum);
			dump_packet((PMIFI_PACKET) line);

			len = server_build_response((PMIFI_PACKET)line, (PMIFI_PACKET)resp);
			printf("build response len is %d\n", len);
			dump_packet((PMIFI_PACKET) resp);

			printf("sending response to client...\n");
			send(newSd, resp, len, 0);
			/* init line */
			memset(line, 0x0, MAX_MSG);
		} /* while(read_line) */
	} /* while (1) */
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
		datalen = 2;
		resp->datalen = 0x0200; // little-endian: 0x0002
		resp->data[0] = 'O';
		resp->data[1] = 'K';
		break;

	default:
		return -1;
	}

	packetlen =  sizeof(MIFI_PACKET) + datalen;
	sum = get_checksum((u8 *)resp, packetlen);
	*(((u8 *)resp) + packetlen) = sum;
	return packetlen + 1;
}
