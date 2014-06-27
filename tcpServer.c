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
#include <semaphore.h>
#include <termios.h>
//#include <mcheck.h>

//#define DEBUG
#include "tcpComm.h"
#include "tcpServer.h"
#include "queue.h"
#include "linenoise.h"

typedef struct dev_info{
    int  sd;
    int  valid;
    devid_t devid;
    imsi_t imsi;
    macadr_t users[20];
} dev_info_t;
dev_info_t dev_map[15];

struct listen_param{
	int port;
	void* (*receive_thread)(void *arg);
};

void* listen_thread(void *arg);
void* receive_thread(void *arg);
int cmd_handle(int sd, char *cmd);
int handle_packet(int sd, PMIFI_PACKET packet);
int handle_packet_post(int sd, PMIFI_PACKET packet);

int main(int UNUSED(argc), char *argv[]) 
{
//	int i;
    const int num_threads = 2;
	pthread_t tid[num_threads];
//	void *status;
	struct listen_param lis_para;
	struct send_param send_para;
    char *line;

    //mtrace();
    que_msg = CreateQueue(100);
    sem_init(&sem_msg, 0, 0);

	memset(&dev_map, 0, sizeof(dev_map));

	lis_para.port = SERVER_PORT;
	lis_para.receive_thread = receive_thread;
	pthread_create(&tid[0], NULL, listen_thread, &lis_para);
	
	send_para.que_msg = que_msg;
	send_para.mutex_msg = &mutex_msg;
	send_para.sem_msg = &sem_msg;
    pthread_create(&tid[1], NULL, send_thread, &send_para);

    linenoiseHistoryLoad("hist-srv.txt"); /* Load the history at startup */
    while((line = linenoise("srv> ")) != NULL) {
        /* Do something with the string. */
        if (line[0] != '\0' && line[0] != '/') {
            //printf("echo: '%s'\n", line);
            linenoiseHistoryAdd(line); /* Add to the history. */
            linenoiseHistorySave("hist-srv.txt"); /* Save the history on disk. */
            cmd_handle(0, line);
        } else if (!strncmp(line,"/q",2)) {
        	free(line);
        	break;
        } else if (!strncmp(line,"/historylen",11)) {
            /* The "/historylen" command will change the history len. */
            int len = atoi(line+11);
            linenoiseHistorySetMaxLen(len);
        } else if (line[0] == '/') {
            printf("Unreconized command: %s\n", line);
        } else {
        	printf("\n");
        }
        free(line);
    }

//	for (i = 0; i < num_threads; i++)
//		pthread_join(tid[i],&status); 
		
	return 0;
}

struct receive_param {
	int sd;
};

int is_client_response(int func)
{
	switch (func) {
	case 0x3000:
	case 0x3100:
	case 0x3200:
	case 0x7100:
	case 0x7f00:
		return 1;
	}
	return 0;
}

void* receive_thread(void *arg)
{
	struct receive_param rcv_para = *((struct receive_param *)arg);
	PMIFI_PACKET packet, resp;
	u8 sum;
	int len;
	const int buff_len = 1024;
	
	packet = (PMIFI_PACKET)malloc(buff_len);
	resp = (PMIFI_PACKET)malloc(buff_len);
	memset(packet, 0x0, buff_len);

	while (read_packet(rcv_para.sd, packet) != ERROR) {
		DBG_OUT("Process received packet");

		len = get_packet_len(packet);
		sum = get_checksum((u8*)packet, len - 1);
		DBG_OUT("len = %d, recv sum = 0x%02x, calc sum = 0x%02x", len, ((u8*)packet)[len - 1], sum);
		dump_packet(packet);
        if (((u8*)packet)[len - 1] != sum)
            DBG_OUT("*** check sum fail");

        if (is_client_response(packet->func) == 0) {
			handle_packet(rcv_para.sd, packet);
			len = server_build_response(packet, resp);
			DBG_OUT("build response len is %d", len);
			if (len > 0) {
				DBG_OUT("enqueue packet to queue");
				push_data(rcv_para.sd, (u8*)resp, len);
			}
			handle_packet_post(rcv_para.sd, packet);
        } else {
        	DBG_OUT("It's a response packet from client, ignored.");
        }

		memset(packet, 0x0, buff_len);
	} /* while(read_packet) */

	DBG_OUT("terminated thread 0x%lx", (unsigned long)pthread_self());
	free(packet);
	free(resp);
	pthread_exit((void *)0);
	return NULL;
}

void* listen_thread(void *arg)
{
	pthread_t tid;
	int sd, newSd;
	socklen_t cliLen;

	struct sockaddr_in cliAddr;
	struct sockaddr_in servAddr;
	struct listen_param *lis_para = (struct listen_param*)arg;

	/* create socket */
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		perror("cannot open socket ");
		return NULL;
	}

	/* bind server port */
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(lis_para->port);

	printf("bind on TCP port %u\n", lis_para->port);
	if (bind(sd, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
		perror("cannot bind port ");
		return NULL;
	}

	listen(sd, 5);

	while (1) {

		DBG_OUT("waiting connection on TCP port %u", lis_para->port);

		cliLen = sizeof(cliAddr);
		newSd = accept(sd, (struct sockaddr *) &cliAddr, &cliLen);
		if (newSd < 0) {
			perror("cannot accept connection ");
			return NULL;
		}
		
		// create new thread
		struct receive_param rcv_para ={0};
		rcv_para.sd = newSd;
		pthread_create(&tid, NULL, lis_para->receive_thread, &rcv_para);
		pthread_detach(tid);
	}
	pthread_exit((void *)0);
	return NULL;
}

dev_info_t * get_device(int index)
{
	return &dev_map[index];
}

int find_free_device(void)
{
    int i;
    dev_info_t *pdev;

    for (i = 0; i < ARRAY_SIZE(dev_map); i++)
    {
    	pdev = get_device(i);
        if (pdev->valid == 0)
            return i;
    }
    return -1;
}

int find_device(/*int sd,*/ PMIFI_PACKET packet)
{
    int i;
    dev_info_t *pdev;

    for (i = 0; i < ARRAY_SIZE(dev_map); i++)
    {
    	pdev = get_device(i);
        if (pdev->valid == 1 /*&& pdev->sd == sd*/) {
            if (memcmp(pdev->devid, packet->id_device, sizeof(devid_t)) == 0 &&
            		memcmp(pdev->imsi, packet->imsi, sizeof(imsi_t)) == 0)
                return i;
        }
    }
    return -1;
}

int find_free_user(dev_info_t *pdev)
{
    int i;
    macadr_t freeuser = {0};
    for (i = 0; i < ARRAY_SIZE(pdev->users); i++)
    {
        if (memcmp(pdev->users[i], &freeuser, sizeof(macadr_t)) == 0)
            return i;
    }
    return -1;
}

int find_user(dev_info_t *pdev, macadr_t *user)
{
    int i;
    for (i = 0; i < ARRAY_SIZE(pdev->users); i++)
    {
        if (memcmp(&pdev->users[i], user, sizeof(macadr_t)) == 0)
            return i;
    }
    return -1;
}

void clean_user(macadr_t *user)
{
    memset(user, 0, sizeof(macadr_t));
}

int remove_user(dev_info_t *pdev, macadr_t *user)
{
    int i;
    i = find_user(pdev, user);
    clean_user(&pdev->users[i]);
    return 0;
}

int find_first_valid_user(dev_info_t *pdev)
{
    int i;
    macadr_t freeuser = {0};
    for (i = 0; i < ARRAY_SIZE(pdev->users); i++)
    {
        if (memcmp(&pdev->users[i], &freeuser, sizeof(macadr_t)) != 0)
            return i;
    }
    return -1;
}

void copy_devinfo(dev_info_t *pdev, PMIFI_PACKET packet)
{
    memcpy(pdev->devid, packet->id_device, sizeof(devid_t));
    memcpy(pdev->imsi, packet->imsi, sizeof(imsi_t));
}

int handle_packet(int sd, PMIFI_PACKET packet)
{
    int n;
    dev_info_t *pdev;
    u16 func = packet->func;
    
    switch (func) {
    case MIFI_CLI_LOGIN:
        n = find_free_device();
        pdev = get_device(n);
        pdev->sd = sd;
        pdev->valid = 1;
        copy_devinfo(pdev, packet);
        break;
        
    case MIFI_CLI_LOGOUT:
        n = find_device(/*sd,*/ packet);
        pdev = get_device(n);
        pdev->valid = 0;
        break;

    case MIFI_USR_CHECK:
    	n = find_device(/*sd,*/ packet);
    	pdev = get_device(n);
        n = find_free_user(pdev);
    	memcpy(pdev->users[n], packet->data, sizeof(macadr_t));
    	break;
    }
    return 0;
}

int handle_packet_post(int sd, PMIFI_PACKET packet)
{
    int /*n,*/ datalen, packetlen;
    u16 func = packet->func;
    PMIFI_PACKET p;
    u8 sum;
    
    switch (func) {
    case MIFI_USR_CHECK:
        {
            //char *url = "http://baike.baidu.com/";
            struct PACK_ALIGN(1) {
                u16 bytes;
                u32 time;
            } allow;

            //n = find_device(/*sd,*/ packet);

            datalen = sizeof(macadr_t) + sizeof(allow);
            packetlen =  sizeof(MIFI_PACKET ) + datalen;
            p = (PMIFI_PACKET)malloc(packetlen + 1);

            memcpy(p, packet, sizeof(MIFI_PACKET));

            p->func = SERV_SET_PERMIT;
            p->sn_packet = htonl(get_packet_sn());
            p->datalen = htons(datalen);
            memcpy(p->data, packet->data, sizeof(macadr_t));

            allow.bytes = htons(50); // 50M
            allow.time = htons(3600); // 1 hours
            memcpy(p->data + sizeof(macadr_t), &allow, sizeof(allow));

            sum = get_checksum((u8 *)p, packetlen);
            *(((u8 *)p) + packetlen) = sum;
            push_data(sd, (u8 *)p, packetlen + 1);
        }
        break;
    }
    return 0;
}

int server_build_response(PMIFI_PACKET packet, PMIFI_PACKET resp)
{
	int datalen = 0, packetlen = 0;
	u8 sum;
	u16 func = packet->func;

	memcpy(resp, packet, sizeof(*packet));
	resp->func = 0x8001;  // little-endian: 0x0180

	switch (func)	{
	case MIFI_CLI_LOGIN:
	case MIFI_CLI_ALIVE:
	case MIFI_CLI_LOGOUT:
		datalen = 100;
		resp->datalen = htons(datalen);
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
            resp->datalen = htons(datalen);
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

static struct {
    int id;
    char *cmd;
} cmds[] = {
    {SERV_REQ_PARAMS,  "param"},
    {SERV_REQ_STATES,  "status"},
    {SERV_REQ_TRUSTS,  "trust"},
    {SERV_REQ_KICKCLI, "kill"},
    {SERV_REQ_KICKUSR, "kick"},
    {SERV_REQ_REBOOT,  "reboot"},
    {SERV_REQ_FACTORY, "reset"},
    {SERV_SET_PARAMS,  "setpara"},
    {SERV_SET_TRUSTS,  "setrust"},
    {SERV_REQ_UPGRADE, "upgrade"},
    {MIFI_CMD_LUSER,   "luser"},
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

int build_packet_header(PMIFI_PACKET packet, dev_info_t *pdev, int func)
{
	packet->func = func;
	packet->sn_packet = htonl(get_packet_sn());
    memcpy(packet->id_device, pdev->devid, sizeof(packet->id_device));
    memcpy(packet->imsi, pdev->imsi, sizeof(packet->imsi));
    memset(packet->reserved, 0, sizeof(packet->reserved));
    return 0;
}

int cmd_handle(int UNUSED(sd), char *line)
{
    int argc, func;
    char *argv[10];
    dev_info_t *pdev;

    argc = make_argv(line, ARRAY_SIZE(argv), argv);
    if (argc <= 0)
        return ERROR;

    DBG_OUT("argc is %d", argc);
    
	func = get_cmdid(argv[0]);
	if (func < 0) {
		printf("unknown command: %s\r\n", argv[0]);
		return ERROR;
	}

	switch (func) {
	case SERV_REQ_KICKCLI:
	case SERV_REQ_REBOOT:
	case SERV_REQ_FACTORY:
    {
        PMIFI_PACKET p;
        int i, datalen, packetlen;
        u8 sum;

        i = 0;
        datalen = 0;
        packetlen =  sizeof(MIFI_PACKET ) + datalen;

		p = (PMIFI_PACKET)malloc(packetlen + 1);

		pdev = get_device(i);
		build_packet_header(p, pdev, func);
		p->datalen = htons(datalen);
		sum = get_checksum((u8 *)p, packetlen);
		*(((u8 *)p) + packetlen) = sum;

		push_data(pdev->sd, (u8 *)p, packetlen + 1);

        free(p);
    }
	break;

	case SERV_REQ_UPGRADE:
	{
		PMIFI_PACKET p;
		char *url = "http://url.cn/QyCLQu";
		int i, url_len, datalen, packetlen;
		u8 sum;

		i = 0;
		url_len = strlen(url);
		datalen = url_len + 2;
		packetlen =  sizeof(MIFI_PACKET ) + datalen;

		p = (PMIFI_PACKET)malloc(packetlen + 1);

		pdev = get_device(i);
		build_packet_header(p, pdev, func);
		p->datalen = htons(datalen);
		p->data[0] = ((u8*)&url_len)[1];
		p->data[1] = ((u8*)&url_len)[0];
		memcpy(p->data + 2, url, datalen);
		sum = get_checksum((u8 *)p, packetlen);
		*(((u8 *)p) + packetlen) = sum;

		push_data(pdev->sd, (u8 *)p, packetlen + 1);

		free(p);
	}
	break;

	case SERV_REQ_KICKUSR:
	{
		PMIFI_PACKET p;
		int i, datalen, packetlen;
		u8 sum;

		i = 0;
		datalen = sizeof(macadr_t);
		packetlen =  sizeof(MIFI_PACKET ) + datalen;

		p = (PMIFI_PACKET)malloc(packetlen + 1);

		pdev = get_device(i);
        build_packet_header(p, pdev, func);
		p->datalen = htons(datalen);
        if (argc == 1) {
            i = find_first_valid_user(pdev);
        } else {
            macadr_t user;
            hex2bin((u8 *)argv[1], (u8 *)&user, sizeof(macadr_t));
            i = find_user(pdev, &user);
        }
		memcpy(p->data, pdev->users[i], datalen);
        clean_user(&pdev->users[i]);  // should be clean after got the response from client
		sum = get_checksum((u8 *)p, packetlen);
		*(((u8 *)p) + packetlen) = sum;

		push_data(pdev->sd, (u8 *)p, packetlen + 1);

		free(p);
	}
	break;
    
    case MIFI_CMD_LUSER:
    {
        int i = 0;
        macadr_t freeuser = {0};
        pdev = get_device(i);
        for (i = 0; i < ARRAY_SIZE(pdev->users); i++)
        {
            if (memcmp(&pdev->users[i], &freeuser, sizeof(macadr_t)) != 0)
            {
                dump_data((u8 *)&pdev->users[i], sizeof(macadr_t), 0);
            }
        }
    }
    break;

	default:
		DBG_OUT("func isn't impletement: %d", func);
		return ERROR;
    }
    return 0;
}
