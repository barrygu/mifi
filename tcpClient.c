/* fpont 12/99 */
/* pont.net    */
/* tcpClient.c */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h> /* close */
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#include "tcpComm.h"
#include "tcpClient.h"

/*
#ifdef LOCAL_TEST
#define SERVER_ADDR "127.0.0.1"
#else
#define SERVER_ADDR "218.80.254.79"
#endif

int build_packet(PMIFI_PACKET packet, int func);
int build_response(PMIFI_PACKET packet, PMIFI_PACKET resp);
int get_device_id(u8 *pDevId);
int get_device_imsi(u8 *pImsi);
int get_device_version(u8 *pVer);
u32 get_packet_sn(void);
*/

int main(int UNUSED(argc), char *argv[]) {

	int sd, rc;
	struct sockaddr_in localAddr, servAddr;
	struct hostent *h;
	u8 sum, buff[256];
	int len;

	h = gethostbyname(SERVER_ADDR);
	if (h == NULL) {
		printf("%s: unknown host '%s'\n", argv[0], SERVER_ADDR);
		return (1);
	}

	servAddr.sin_family = h->h_addrtype;
	memcpy((char *) &servAddr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
	servAddr.sin_port = htons(SERVER_PORT);

	/* create socket */
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		perror("cannot open socket ");
		return (1);
	}

	/* bind any port number */
	localAddr.sin_family = AF_INET;
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	localAddr.sin_port = htons(0);

	rc = bind(sd, (struct sockaddr *) &localAddr, sizeof(localAddr));
	if (rc < 0) {
		printf("%s: cannot bind port TCP %u\n", argv[0], SERVER_PORT);
		perror("error ");
		return (1);
	}

	printf("connecting to server: %s\n", SERVER_ADDR);
	/* connect to server */
	rc = connect(sd, (struct sockaddr *) &servAddr, sizeof(servAddr));
	if (rc < 0) {
		perror("cannot connect ");
		return (1);
	}

	memset(buff, 0, sizeof(buff));
	len = build_packet((PMIFI_PACKET)buff, MIFI_CLI_LOGIN);
	//printf("+++ built packet len is %d\n", len);
	printf("send request packet:\n");
	dump_packet((PMIFI_PACKET)buff);
	rc = send(sd, &buff[0], len, 0);

	if (rc < 0) {
		perror("cannot send data ");
		close(sd);
		return (1);
	}

	printf("waiting for server response\n");
	read_packet(sd, (PMIFI_PACKET)buff);
	len = get_packet_len((PMIFI_PACKET)buff);
	sum = get_checksum(buff, len - 1);
	//printf("len = %d, recv sum = 0x%02x, calc sum = 0x%02x\n", len, buff[len - 1], sum);
	dump_packet((PMIFI_PACKET) buff);
	if (sum != buff[len - 1]) printf("+++++ warning: response checksum is wrong\n");

	close(sd);
	return 0;
}

int build_response(PMIFI_PACKET packet, PMIFI_PACKET resp)
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

	packetlen =  sizeof(MIFI_PACKET ) + datalen;
	sum = get_checksum((u8 *)resp, packetlen);
	*(((u8 *)resp) + packetlen) = sum;
	return packetlen + 1;
}

int build_packet(PMIFI_PACKET packet, int func)
{
	int datalen = 0, packetlen = 0;
	u8 sum;
	u32 sn_packet;

	packet->func = func; //__builtin_bswap16(func);
	sn_packet = get_packet_sn();
	packet->sn_packet = __builtin_bswap32(sn_packet);
	get_device_id(packet->id_device);
	get_device_imsi(packet->imsi);
	memset(packet->reserved, 0, sizeof(packet->reserved));

	switch (func) {
	case MIFI_CLI_LOGIN:
		datalen = 4;
		packet->datalen = 0x0400;//__builtin_bswap16(datalen);
		get_device_version(packet->data);
		break;

	default:
		return -1;
	}
	packetlen =  sizeof(MIFI_PACKET ) + datalen;
	sum = get_checksum((u8 *)packet, packetlen);
	*(((u8 *)packet) + packetlen) = sum;
	return packetlen + 1;
}

int get_device_id(u8 *pDevId)
{
	const char *myid = "18912345678";
	memcpy(pDevId, myid, strlen(myid));
	return 0;
}

int get_device_imsi(u8 *pImsi)
{
	const char *myimsi = "0123456789abcdef";
	memcpy(pImsi, myimsi, strlen(myimsi));
	return 0;
}

int get_device_version(u8 *pVer)
{
	const char myver[4] = {0x00,0x01,0x00,0x01};
	memcpy(pVer, myver, sizeof(myver));
	return 0;
}

u32 get_packet_sn(void)
{
	static u32 sn = 0;
	return ++sn;
}
