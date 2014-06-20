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

//#define DEBUG
#include "tcpComm.h"
#include "tcpServer.h"
#include "queue.h"
#include "linenoise.h"

//#define END_LINE 0x0

Queue que_msg;
pthread_mutex_t mutex_msg = PTHREAD_MUTEX_INITIALIZER;
sem_t sem_msg;

struct receive_param {
	int sd;
};

struct msg_packet {
    int sd;
    int len;
    u8  data[0];
};

struct dev_map{
    int sd;
    int valid;
    char devid[11+1];
    char imsi[15+1];
}dev_map[10];

void* send_thread(void *arg)
{
    struct msg_packet *msg;

	while(1) {
		sem_wait(&sem_msg);
        pthread_mutex_lock(&mutex_msg);
        msg = (struct msg_packet *)FrontAndDequeue(que_msg);
        pthread_mutex_unlock(&mutex_msg);
        DBG_OUT("sending %d bytes data to client...\n", msg->len);
        dump_packet((PMIFI_PACKET) msg->data);
        send(msg->sd, msg->data, msg->len, 0);
        DBG_OUT("sent done\n");
        free((void *)msg);
	}
}

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
    char *line;

    que_msg = CreateQueue(100);
    //mutex_msg = PTHREAD_MUTEX_INITIALIZER;
    sem_init(&sem_msg, 0, 0);

	memset(&dev_map, 0, sizeof(dev_map));

	lis_para.port = SERVER_PORT;
	lis_para.receive_thread = receive_thread;
	pthread_create(&tid[0], NULL, listen_thread, &lis_para);
	
    pthread_create(&tid[1], NULL, send_thread, &que_msg);
	
    linenoiseHistoryLoad("hist-srv.txt"); /* Load the history at startup */
    while((line = linenoise("srv> ")) != NULL) {
        /* Do something with the string. */
        if (line[0] != '\0' && line[0] != '/') {
            //printf("echo: '%s'\n", line);
            cmd_handle(0, line);
            linenoiseHistoryAdd(line); /* Add to the history. */
            linenoiseHistorySave("hist-srv.txt"); /* Save the history on disk. */
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

void push_data(int sd, u8 *data, int len)
{
    struct msg_packet *msg = (struct msg_packet *)malloc(len + sizeof(struct msg_packet));
    
    msg->sd = sd;
    msg->len = len;
    memcpy(msg->data, data, len);
    DBG_OUT("push %d bytes data to queue\n", len);
    pthread_mutex_lock(&mutex_msg);
    Enqueue((ElementType)msg, que_msg);
    pthread_mutex_unlock(&mutex_msg);
    sem_post(&sem_msg);
}

void* receive_thread(void *arg)
{
	struct receive_param *rcv_para = (struct receive_param *)arg;
	char line[MAX_MSG], resp[MAX_MSG];
	u8 sum;
	int len;
	
	/* init line */
	memset(line, 0x0, MAX_MSG);

	/* receive segments */
	while (read_packet(rcv_para->sd, (PMIFI_PACKET) line) != ERROR) {

//		printf("received from %s:TCP%d : \n",
//				inet_ntoa(cliAddr.sin_addr), ntohs(cliAddr.sin_port));

		len = get_packet_len((PMIFI_PACKET) line);
		sum = get_checksum((u8*)line, len - 1);
		DBG_OUT("len = %d, recv sum = 0x%02x, calc sum = 0x%02x\n", len, (u8)line[len - 1], sum);
		dump_packet((PMIFI_PACKET) line);
        if ((u8)line[len - 1] != sum)
            DBG_OUT("*** check sum fail\n");

        handle_packet(rcv_para->sd, (PMIFI_PACKET)line);
		len = server_build_response((PMIFI_PACKET)line, (PMIFI_PACKET)resp);
		DBG_OUT("build response len is %d\n", len);
		if (len > 0) {
			//dump_packet((PMIFI_PACKET) resp);

            DBG_OUT("enqueue packet to queue\n");
            push_data(rcv_para->sd, (u8*)resp, len);
		}
        handle_packet_post(rcv_para->sd, (PMIFI_PACKET)line);
		/* init line */
		memset(line, 0x0, MAX_MSG);
	} /* while(read_line) */

	free(rcv_para);
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

		printf("waiting for data on TCP port %u\n", lis_para->port);

		cliLen = sizeof(cliAddr);
		newSd = accept(sd, (struct sockaddr *) &cliAddr, &cliLen);
		if (newSd < 0) {
			perror("cannot accept connection ");
			return NULL;
		}
		
		// create new thread
		struct receive_param *rcv_para = (struct receive_param *)malloc(sizeof(struct receive_param));
		rcv_para->sd = newSd;
		pthread_create(&tid, NULL, lis_para->receive_thread, rcv_para);
	}
	return NULL;
}

int find_free_map(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(dev_map); i++)
    {
        if (dev_map[i].valid == 0)
            return i;
    }
    return -1;
}

int find_dev_map(int sd, PMIFI_PACKET packet)
{
    int i;
    for (i = 0; i < ARRAY_SIZE(dev_map); i++)
    {
        if (dev_map[i].valid == 1 && dev_map[i].sd == sd) {
            if (memcmp(dev_map[i].devid, packet->id_device, sizeof(packet->id_device)) == 0)
                return i;
        }
    }
    return -1;
}

int handle_packet(int sd, PMIFI_PACKET packet)
{
    int n;
    u16 func = packet->func; // __builtin_bswap16(packet->func);
    
    switch (func) {
    case MIFI_CLI_LOGIN:
        n = find_free_map();
        dev_map[n].sd = sd;
        dev_map[n].valid = 1;
        memcpy(dev_map[n].devid, packet->id_device, sizeof(packet->id_device));
        dev_map[n].devid[sizeof(packet->id_device)] = 0;
        memcpy(dev_map[n].imsi, packet->imsi, sizeof(packet->imsi));
        dev_map[n].imsi[sizeof(packet->imsi)] = 0;
        break;
        
    case MIFI_CLI_LOGOUT:
        n = find_dev_map(sd, packet);
        dev_map[n].valid = 0;
        break;
    }
    return 0;
}

int handle_packet_post(int sd, PMIFI_PACKET packet)
{
    int /*n,*/ datalen, packetlen;
    u16 func = packet->func; // __builtin_bswap16(packet->func);
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

            //n = find_dev_map(sd, packet);

            datalen = 6 + 4 + 2;
            packetlen =  sizeof(MIFI_PACKET ) + datalen;
            p = (PMIFI_PACKET)malloc(packetlen + 1);
            
            p->func = SERV_SET_PERMIT;
            p->sn_packet = __builtin_bswap32(get_packet_sn());
            memcpy(p->id_device, packet->id_device, sizeof(p->id_device));
            memcpy(p->imsi, packet->imsi, sizeof(p->imsi));
            memset(p->reserved, 0, sizeof(p->reserved));
            p->datalen = __builtin_bswap16(datalen);
            memcpy(p->data, packet->data, 6);
            allow.bytes = __builtin_bswap16(50); // 50M
            allow.time = __builtin_bswap16(3600); // 1 hours
            memcpy(p->data + 6, &allow, 6);
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
	u16 func = packet->func; // __builtin_bswap16(packet->func);

	memcpy(resp, packet, sizeof(*packet));
	resp->func = 0x8001;  // little-endian: 0x0180

	switch (func)	{
	case MIFI_CLI_LOGIN:
	case MIFI_CLI_ALIVE:
	case MIFI_CLI_LOGOUT:
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

static struct {
    int id;
    char *cmd;
} cmds[] = {
    {SERV_REQ_PARAMS,  "param"},
    {SERV_REQ_STATES,  "status"},
    {SERV_REQ_TRUSTS,  "trust"},
    {SERV_REQ_KICKOUT, "kill"},
    {SERV_REQ_KICKUSR, "kick"},
    {SERV_REQ_REBOOT,  "reboot"},
    {SERV_REQ_FACTORY, "factory"},
    {SERV_SET_PARAMS,  "setpara"},
    {SERV_SET_TRUSTS,  "setrust"},
    {SERV_REQ_UPGRADE, "upgrade"},
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

int cmd_handle(int UNUSED(sd), char *line)
{
    int argc, func;
    char *argv[10];

    argc = make_argv(line, ARRAY_SIZE(argv), argv);
    if (argc <= 0)
        return ERROR;

    DBG_OUT("argc is %d\n", argc);
    
	func = get_cmdid(argv[0]);
	if (func < 0) {
		printf("unknown command: %s\n", argv[0]);
		return ERROR;
	}

	switch (func) {
	case SERV_REQ_UPGRADE:
        {
            PMIFI_PACKET p;
            char *url = "http://url.cn/QyCLQu";
            int i, datalen, packetlen;
            u8 sum;
            
            datalen = strlen(url);
            packetlen =  sizeof(MIFI_PACKET ) + datalen;

            for (i = 0; i < ARRAY_SIZE(dev_map); i++)
            {
                if (dev_map[i].valid == 1) {
                    p = (PMIFI_PACKET)malloc(packetlen + 1);
                    
                    p->func = SERV_REQ_UPGRADE;
                    p->sn_packet = __builtin_bswap32(get_packet_sn());
                    memcpy(p->id_device, dev_map[i].devid, sizeof(p->id_device));
                    memcpy(p->imsi, dev_map[i].imsi, sizeof(p->imsi));
                    memset(p->reserved, 0, sizeof(p->reserved));
                    p->datalen = __builtin_bswap16(datalen);
                    memcpy(p->data, url, datalen);
                    sum = get_checksum((u8 *)p, packetlen);
                    *(((u8 *)p) + packetlen) = sum;

                    push_data(dev_map[i].sd, (u8 *)p, packetlen + 1);
                }
            }
            free(p);
        }
        break;

	default:
		printf("func isn't impletement: %d\n", func);
		return ERROR;
    }
    return 0;
}