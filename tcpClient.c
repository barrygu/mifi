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
#include "linenoise.h"

//#define USED_DEV  199
#define USED_DEV  189
//#define USED_DEV  188

int main(int UNUSED(argc), char *argv[]) 
{
	int sd;
	char *line;

	sd = establish_connection(SERVER_ADDR, SERVER_PORT);
	if (sd < 0) {
		return ERROR;
	}

    linenoiseHistoryLoad("hist-cli.txt"); /* Load the history at startup */
    while((line = linenoise("mifi> ")) != NULL) {
        /* Do something with the string. */
        if (line[0] != '\0' && line[0] != '/') {
            //printf("echo: '%s'\n", line);
            cmd_handle(sd, line);
            linenoiseHistoryAdd(line); /* Add to the history. */
            linenoiseHistorySave("hist-cli.txt"); /* Save the history on disk. */
        } else if (!strncmp(line,"/q",2)) {
        	free(line);
        	break;
        } else if (!strncmp(line,"/historylen",11)) {
            /* The "/historylen" command will change the history len. */
            int len = atoi(line+11);
            linenoiseHistorySetMaxLen(len);
        } else if (line[0] == '/') {
            printf("Unreconized command: %s\r\n", line);
        } else {
        	printf("\n");
        }
        free(line);
    }

	close(sd);
	return 0;
}

static struct {
    int id;
    char *cmd;
} cmds[] = {
    {MIFI_CLI_LOGIN,   "login"},
    {MIFI_CLI_LOGOUT,  "logout"},
//    {MIFI_RPT_PARAMS,  "params"},
//    {MIFI_RPT_STATES,  "states"},
    {MIFI_CLI_ALIVE,   "alive"},
//    {MIFI_USR_OFFLINE, "offline"},
    {MIFI_USR_CHECK,   "check"},
//    {MIFI_USR_AUTH,    "auth"},
//    {MIFI_ADV_REQUEST, "adv"},
//    {MIFI_USR_GRANT,   "grant"},
    {MIFI_CMD_READ,    "read"},
    {MIFI_CMD_HELP,    "help"},
};

int get_cmdid(char *cmd)
{
	int i;

    for (i = 0; i < ARRAY_SIZE(cmds); i++)
    {
    	if (strcmp(cmds[i].cmd, cmd) == 0)
    		return cmds[i].id;
    }
    return ERROR;
}

int cmd_handle(int sd, char *cmd)
{
	int i, rc, len;
	u8 sum, *buff;
	int func;
    int argc;
    char *argv[10];
    const int buff_size = 1024;

    argc = make_argv(cmd, ARRAY_SIZE(argv), argv);
    if (argc <= 0)
        return ERROR;
        
	func = get_cmdid(argv[0]);
	if (func < 0) {
		printf("unknown command: %s\n", argv[0]);
		return ERROR;
	}

	buff = (u8*)malloc(buff_size);
	switch (func) {
	case MIFI_CLI_LOGIN:
	case MIFI_CLI_ALIVE:
	case MIFI_CLI_LOGOUT:
    case MIFI_USR_CHECK:
		memset(buff, 0, buff_size);
		len = build_packet((PMIFI_PACKET)buff, func);
		break;

    case MIFI_CMD_HELP:
        for (i = 0; i < ARRAY_SIZE(cmds); i++)
        {
            printf("  %s\r\n", cmds[i].cmd);
        }
        return 0;

    case MIFI_CMD_READ:
        break;

	default:
		printf("func isn't impletement: %d\r\n", func);
		return ERROR;
	}

    if (func != MIFI_CMD_READ) {
        DBG_OUT("send request packet:");
        dump_packet((PMIFI_PACKET)buff);
        rc = send(sd, buff, len, 0);

        if (rc < 0) {
            perror("cannot send data ");
            close(sd);
            free(buff);
            return ERROR;
        }
    }
	DBG_OUT("waiting for server response");
	rc = read_packet(sd, (PMIFI_PACKET)buff);
	if (rc != ERROR) {
		len = get_packet_len((PMIFI_PACKET)buff);
		sum = get_checksum(buff, len - 1);
		//printf("len = %d, recv sum = 0x%02x, calc sum = 0x%02x\n", len, buff[len - 1], sum);
		dump_packet((PMIFI_PACKET) buff);
		if (sum != buff[len - 1]) printf("+++++ warning: response checksum is wrong\r\n");
	}
	DBG_OUT("handle command \"%s\" end", argv[0]);
	free(buff);
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
	case MIFI_CLI_ALIVE:
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
        
	case MIFI_CLI_ALIVE:
	{
		MIFI_ALIVE alive;
		datalen = sizeof(MIFI_ALIVE);
		packet->datalen = __builtin_bswap16(datalen);
		alive.worktime = __builtin_bswap32(3600);
		alive.rssi = 78;
		alive.battery = 80;
		alive.login_users = 0;
		alive.auth_users = 0;
		alive.cellid = __builtin_bswap32(0x11223344);
		alive.used_bytes = __builtin_bswap32(1234);
		memcpy(packet->data, &alive, datalen);
		break;
	}

	case MIFI_CLI_LOGOUT:
		datalen = 0;
		packet->datalen = __builtin_bswap16(datalen);
		break;

    case MIFI_USR_CHECK:
		datalen = get_client_mac(packet->data);
		packet->datalen = __builtin_bswap16(datalen);
        break;

	default:
		return -1;
	}
	packetlen =  sizeof(MIFI_PACKET ) + datalen;
	sum = get_checksum((u8 *)packet, packetlen);
	*(((u8 *)packet) + packetlen) = sum;
	return packetlen + 1;
}

int get_client_mac(u8 *pMac)
{
    u8  mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    int len = sizeof(mac);
    
    memcpy(pMac, mac, len);
    return len;
}

int get_device_id(u8 *pDevId)
{
#if USED_DEV == 199
	const char *myid = "19912345678";
#elif USED_DEV == 189
	const char *myid = "18912345678";
#elif USED_DEV == 188
	const char *myid = "18812345678";
#endif
	memcpy(pDevId, myid, strlen(myid));
	return 0;
}

int get_device_imsi(u8 *pImsi)
{
#if USED_DEV == 199
	const char *myimsi = "1234567891abcde";
#elif USED_DEV == 189
	const char *myimsi = "0123456789abcde";
#elif USED_DEV == 188
	const char *myimsi = "1234567890abcde";
#endif
	memcpy(pImsi, myimsi, strlen(myimsi));
	return 0;
}

int get_device_version(u8 *pVer)
{
	const char myver[4] = {0x00,0x01,0x00,0x01};
	memcpy(pVer, myver, sizeof(myver));
	return 0;
}

int establish_connection(char *server, int port)
{
	int sd, rc;
	struct sockaddr_in localAddr, servAddr;
	struct hostent *h;

	h = gethostbyname(server);
	if (h == NULL) {
		printf("unknown host '%s'\r\n", server);
		return ERROR;
	}

	servAddr.sin_family = h->h_addrtype;
	memcpy((char *) &servAddr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
	servAddr.sin_port = htons(port);

	/* create socket */
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		perror("cannot open socket ");
		return ERROR;
	}

	/* bind any port number */
	localAddr.sin_family = AF_INET;
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	localAddr.sin_port = htons(0);

	rc = bind(sd, (struct sockaddr *) &localAddr, sizeof(localAddr));
	if (rc < 0) {
		DBG_OUT("cannot bind port TCP %u", port);
		perror("error ");
		return ERROR;
	}

	DBG_OUT("connecting to server: %s", server);
	/* connect to server */
	rc = connect(sd, (struct sockaddr *) &servAddr, sizeof(servAddr));
	if (rc < 0) {
		perror("cannot connect ");
		return ERROR;
	}
	return sd;
}
