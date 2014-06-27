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

static int volatile g_sd = 0;
pthread_mutex_t mtx_socket = PTHREAD_MUTEX_INITIALIZER;

struct receive_param {
	//int *sd;
	//pthread_mutex_t *mtx_socket;
};

void* receive_thread(void *arg);
int client_build_response(PMIFI_PACKET packet, PMIFI_PACKET resp);

static char svr_addr[128] = SERVER_ADDR;
static int  svr_port = SERVER_PORT;
static devid_t g_devid = "18912345678";
static imsi_t  g_imsi = "0123456789abcde";
struct mrevent mrevent;

int main(int UNUSED(argc), char *argv[]) 
{
	//int rc;
	char *line;
	const int num_threads = 2;
	pthread_t tid[num_threads];
	struct send_param send_para;
	struct receive_param rcv_para;

    //set_device_info((devid_t *)"19912345678", (imsi_t *)"1234567891abcde");
    //set_device_info((devid_t *)"18912345678", (imsi_t *)"0123456789abcde");
    //set_device_info((devid_t *)"18812345678", (imsi_t *)"1234567890abcde");
	//rc = establish_connection(svr_addr, svr_port);
	//if (rc < 0) {
	//	return ERROR;
	//}

    mrevent_init(&mrevent);
    
    que_msg = CreateQueue(100);
    sem_init(&sem_msg, 0, 0);

	send_para.que_msg = que_msg;
	send_para.mutex_msg = &mutex_msg;
	send_para.sem_msg = &sem_msg;
    pthread_create(&tid[1], NULL, send_thread, &send_para);

    //rcv_para.sd = &g_sd;
	//rcv_para.mtx_socket = &mtx_socket;
    pthread_create(&tid[0], NULL, receive_thread, &rcv_para);

    linenoiseHistoryLoad("hist-cli.txt"); /* Load the history at startup */
    while((line = linenoise("mifi> ")) != NULL) {
        /* Do something with the string. */
        if (line[0] != '\0' && line[0] != '/') {
            //printf("echo: '%s'\n", line);
            linenoiseHistoryAdd(line); /* Add to the history. */
            linenoiseHistorySave("hist-cli.txt"); /* Save the history on disk. */
            cmd_handle(g_sd, line);
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

	close(g_sd);
	return 0;
}

int is_server_response(int func)
{
	switch (func) {
	case 0x8001:
		return 1;
	}
	return 0;
}

void* receive_thread(void *arg)
{
	//struct receive_param rcv_para = *((struct receive_param *)arg);
	PMIFI_PACKET packet, resp;
	u8 sum;
	int len, sd;
	const int buff_len = 1024;

	packet = (PMIFI_PACKET)malloc(buff_len);
	resp = (PMIFI_PACKET)malloc(buff_len);
	memset(packet, 0x0, buff_len);

	while (1) {
		DBG_OUT("Waiting for packet arriving");
        sd = get_connection();
		if (read_packet(sd, packet) == ERROR) {
			printf("read packet error\r\n");
            sleep(1);
            establish_connection(svr_addr, svr_port);
			continue;
		}
		DBG_OUT("Process received packet");

		len = get_packet_len(packet);
		sum = get_checksum((u8*)packet, len - 1);
		DBG_OUT("len = %d, recv sum = 0x%02x, calc sum = 0x%02x", len, ((u8*)packet)[len - 1], sum);
		dump_packet(packet);
        if (((u8*)packet)[len - 1] != sum)
            DBG_OUT("*** check sum fail");

        if (is_server_response(packet->func) == 0) {
			//handle_packet(rcv_para.sd, packet);
			len = client_build_response(packet, resp);
			DBG_OUT("build response len is %d", len);
			if (len > 0) {
				DBG_OUT("enqueue packet to queue");
				push_data(get_connection(), (u8*)resp, len);
			}
			//handle_packet_post(rcv_para.sd, packet);
        } else {
        	DBG_OUT("It's a response from server, ignored.");
        }

		memset(packet, 0x0, buff_len);
	} /* while(read_packet) */

	DBG_OUT("terminated thread 0x%lx", (unsigned long)pthread_self());
	free(packet);
	free(resp);

	pthread_exit((void *)0);
	return NULL;
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
    {MIFI_CMD_CONNECT, "connect"},
    {MIFI_SET_DEVID,   "devid"},
    {MIFI_SET_IMSI,    "imsi"},
    {MIFI_SET_DEVINFO, "setinfo"},
    {MIFI_GET_DEVINFO, "devinfo"},
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
	int i, /*rc,*/ len;
	u8 /*sum,*/ *buff;
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
		if (argc == 1)
			len = build_packet((PMIFI_PACKET)buff, func);
		else
			len = build_packet_ex((PMIFI_PACKET)buff, func, argc, argv);
		break;

    case MIFI_CMD_HELP:
        for (i = 0; i < ARRAY_SIZE(cmds); i++)
        {
            printf("  %s\r\n", cmds[i].cmd);
        }
        return 0;

    case MIFI_CMD_READ:
        break;

    case MIFI_SET_DEVID:
        set_device_info((devid_t*)argv[1], NULL);
        break;

    case MIFI_SET_IMSI:
        set_device_info(NULL, (imsi_t*)argv[1]);
        break;

    case MIFI_SET_DEVINFO:
        set_device_info((devid_t*)argv[1], (imsi_t*)argv[2]);
        break;

    case MIFI_GET_DEVINFO:
        dump_device_info();
        break;

	case MIFI_CMD_CONNECT:
		strcpy(svr_addr, argv[1]);
		svr_port = atoi(argv[2]);
        if (mrevent_istriggered(&mrevent))
            close_connection();
        else
            establish_connection(svr_addr, svr_port);
		break;

	default:
		printf("func isn't impletement: %d\r\n", func);
		return ERROR;
	}

    if ((func & 0x00ff) != 0x0088 && (func & 0x00ff) != 0x0099) {
    	DBG_OUT("push packet:");
    	push_data(get_connection(), buff, len);
    }

	DBG_OUT("handle command \"%s\" end", argv[0]);
	free(buff);
	return 0;
}

int client_build_response(PMIFI_PACKET packet, PMIFI_PACKET resp)
{
	int datalen = 0, packetlen = 0;
	u8 sum;
	u16 func = packet->func;
	DBG_OUT("build response for func = 0x%02x", func);
	memcpy(resp, packet, sizeof(*packet));

	switch (func)	{
	case SERV_REQ_UPGRADE:
		resp->func &= 0xff00;
		datalen = 1;
		resp->datalen = htons(datalen);
		resp->data[0] = 0x00;
		break;

	case SERV_SET_PERMIT:
	case SERV_REQ_KICKCLI:
	case SERV_REQ_KICKUSR:
	case SERV_REQ_REBOOT:
	case SERV_REQ_FACTORY:
		resp->func = 0x7f00;
		datalen = 1;
		resp->datalen = htons(datalen);
		resp->data[0] = 0x00;
		break;

	default:
		return -1;
	}

	packetlen =  sizeof(MIFI_PACKET ) + datalen;
	sum = get_checksum((u8 *)resp, packetlen);
	*(((u8 *)resp) + packetlen) = sum;
	return packetlen + 1;
}

int build_packet_header(PMIFI_PACKET packet, int func)
{
	packet->func = func;
	packet->sn_packet = htonl(get_packet_sn());
	get_device_id(packet->id_device);
	get_device_imsi(packet->imsi);
	memset(packet->reserved, 0, sizeof(packet->reserved));

	return 0;
}

int build_packet(PMIFI_PACKET packet, int func)
{
	int datalen = 0, packetlen = 0;
	u8 sum;

	build_packet_header(packet, func);

	switch (func) {
	case MIFI_CLI_LOGIN:
		datalen = 4;
		packet->datalen = htons(datalen);
		get_device_version(packet->data);
		break;
        
	case MIFI_CLI_ALIVE:
	{
		MIFI_ALIVE alive;
		datalen = sizeof(MIFI_ALIVE);
		packet->datalen = htons(datalen);
		alive.worktime = htonl(3600);
		alive.rssi = 78;
		alive.battery = 80;
		alive.login_users = 0;
		alive.auth_users = 0;
		alive.cellid = htonl(get_cell_id());
		alive.used_bytes = htonl(1234);
		memcpy(packet->data, &alive, datalen);
		break;
	}

	case MIFI_CLI_LOGOUT:
		datalen = 0;
		packet->datalen = htons(datalen);
		break;

    case MIFI_USR_CHECK:
		datalen = get_user_mac(packet->data);
		packet->datalen = htons(datalen);
        break;

	default:
		return -1;
	}
	packetlen =  sizeof(MIFI_PACKET ) + datalen;
	sum = get_checksum((u8 *)packet, packetlen);
	*(((u8 *)packet) + packetlen) = sum;
	return packetlen + 1;
}

int build_packet_ex(PMIFI_PACKET packet, int func, int argc, char *argv[])
{
	int datalen = 0, packetlen = 0;
	u8 sum;

	build_packet_header(packet, func);

	switch (func) {
    case MIFI_USR_CHECK:
		datalen = 6;
		hex2bin((u8 *)argv[1], packet->data, datalen);
		packet->datalen = htons(datalen);
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
    macadr_t mac = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    const int len = sizeof(mac);
    
    memcpy(pMac, mac, len);
    return len;
}

int get_user_mac(u8 *pMac)
{
    macadr_t mac = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    const int len = sizeof(mac);

    memcpy(pMac, mac, len);
    return len;
}

int set_device_info(devid_t *pdevid, imsi_t *pimsi)
{
    if (pdevid) {
        memcpy(g_devid, pdevid, sizeof(devid_t));
    }
    
    if (pimsi) {
        memcpy(g_imsi, pimsi, sizeof(imsi_t));
    }
    return 0;
}

void dump_device_info(void)
{
    int i;

    printf("DevID: ");
    for (i = 0; i < sizeof(devid_t); i++)
    {
    }

    printf("IMSI: ");
    for (i = 0; i < sizeof(imsi_t); i++)
    {
    }
}

int get_device_id(u8 *pDevId)
{
	memcpy(pDevId, &g_devid, sizeof(devid_t));
	return 0;
}

int get_device_imsi(u8 *pImsi)
{
	memcpy(pImsi, g_imsi, sizeof(imsi_t));
	return 0;
}

int get_device_version(u8 *pVer)
{
	const char myver[4] = {0x00,0x01,0x00,0x01};
	memcpy(pVer, myver, sizeof(myver));
	return 0;
}

int get_cell_id(void)
{
	return 0x11223344;
}

int get_connection(void)
{
    mrevent_wait(&mrevent);
	return g_sd;
}

void close_connection(void)
{
    mrevent_reset(&mrevent);
    if (g_sd);
        close(g_sd);
    g_sd = 0;
}

int establish_connection(char *server, int port)
{
	int sd = -1, rc;
	struct sockaddr_in localAddr, servAddr;
	struct hostent *h;

    mrevent_reset(&mrevent);
	h = gethostbyname(server);
	if (h == NULL) {
		printf("unknown host '%s'\r\n", server);
		goto End;
	}

	servAddr.sin_family = h->h_addrtype;
	memcpy((char *) &servAddr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
	servAddr.sin_port = htons(port);

	/* create socket */
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		perror("cannot open socket ");
		goto End;
	}

	/* bind any port number */
	localAddr.sin_family = AF_INET;
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	localAddr.sin_port = htons(0);

	rc = bind(sd, (struct sockaddr *) &localAddr, sizeof(localAddr));
	if (rc < 0) {
		DBG_OUT("cannot bind port TCP %u", port);
		perror("error ");
		goto End;
	}

	DBG_OUT("connecting to server: %s", server);
	/* connect to server */
	rc = connect(sd, (struct sockaddr *) &servAddr, sizeof(servAddr));
	if (rc < 0) {
		perror("cannot connect ");
		goto End;
	}

	//pthread_mutex_lock(&mtx_socket);
	if (g_sd > 0)
		close(g_sd);
	g_sd = sd;
	//pthread_mutex_unlock(&mtx_socket);
End:
    mrevent_trigger(&mrevent);
	return sd;
}
