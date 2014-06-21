#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h> /* close */
#include <string.h>
#include <stdlib.h>

//#define DEBUG
#include "tcpComm.h"

void dump_data(u8 *pdata, int datalen, int line_width) {
	int i;

	if (line_width != 16 && line_width != 8 && line_width != 32)
		line_width = 8;

	for (i = 0; i < datalen; i++) {
		if (i) {
			if (!(i % line_width))
				printf("\r\n");
			else if (!(i % (line_width / 2)))
				printf("- ");
		}
		printf("%02x ", *pdata++);
	}
	printf("\r\n");
}

void dump_packet(PMIFI_PACKET packet) {
	int len = __builtin_bswap16(packet->datalen);
	dump_data((u8 *) packet, sizeof(*packet) + len + 1, 16);
}

u8 get_checksum(u8 *pdata, int datalen) {
	u8 *pend = pdata + datalen;
	u8 sum = 0;
	for (; pdata < pend; pdata++) {
		sum ^= *pdata;
	}
	return sum;
}

int get_packet_len(PMIFI_PACKET packet)
{
	u16 datalen = packet->datalen;
	datalen = __builtin_bswap16(datalen);
	datalen +=  sizeof(MIFI_PACKET) + 1;
	return datalen;
}

int read_packet(int sd, PMIFI_PACKET packet) {
	int rcv_ptr = 0;
	char *rcv_msg;
	int rcv_len = 0, tmp;
	int offset = 0, datalen = 0;
	const int sizeof_fixlen = sizeof(MIFI_PACKET);
	const int buff_len = 1024;

	char *rcv_buff = (char *) packet;

	offset = 0;
	rcv_msg = (char *)malloc(buff_len);

	while (1) {
		rcv_ptr = 0;
		/* read data from socket */
		memset(rcv_msg, 0x0, buff_len); /* init buffer */
		rcv_len = recv(sd, rcv_msg, buff_len, 0); /* wait for data */
		if (rcv_len < 0) {
			perror(" cannot receive data ");
			free(rcv_msg);
			return ERROR;
		} else if (rcv_len == 0) {
			DBG_OUT(" connection closed by client");
			close(sd);
			free(rcv_msg);
			return ERROR;
		}

		//DBG_OUT("fixlen = %d, offset = %d, rcv_len = %d",
		//		sizeof_fixlen, offset, rcv_len);
		if (offset < sizeof_fixlen) {
			if (offset + rcv_len < sizeof_fixlen) {
				memcpy(rcv_buff + offset, rcv_msg, rcv_len);
				offset += rcv_len;
				rcv_ptr += rcv_len;
				//DBG_OUT("offset = %d, rcv_ptr = %d", offset, rcv_ptr);
				continue;
			} else {
				tmp = sizeof_fixlen - offset;
				memcpy(rcv_buff + offset, rcv_msg, tmp);

				// 读取数据长度
				datalen = get_packet_len((PMIFI_PACKET) rcv_buff);
				offset += tmp;
				rcv_ptr += tmp; // 移动数据指针

				//DBG_OUT("datalen = %d, rcv_ptr = %d, offset = %d",
				//		datalen, rcv_ptr, offset);
				if (rcv_len < datalen) {
					DBG_OUT("offset = %d, rcv_ptr = %d", offset, rcv_ptr);
					rcv_len -= tmp;
					memcpy(rcv_buff + offset, rcv_msg + rcv_ptr, rcv_len);
					offset += rcv_len;
					continue; // 将接收到的剩余全部数据读入接收缓冲
				} else {
					//DBG_OUT("offset = %d, rcv_ptr = %d", offset, rcv_ptr);
					memcpy(rcv_buff + offset, rcv_msg + rcv_ptr,
							(datalen - offset));
					free(rcv_msg);
					return 0; // 将指定长度的数据读入接收缓冲
				}
			}
		} else {
			// 读取数据长度
			datalen = get_packet_len((PMIFI_PACKET) rcv_buff);

			//DBG_OUT("datalen = %d, offset = %d, rcv_ptr = %d, rcv_len = %d",
			//		datalen, offset, rcv_ptr, rcv_len);
			tmp = rcv_len - rcv_ptr;
			if (tmp < (datalen - offset)) {
				memcpy(rcv_buff + offset, rcv_msg + rcv_ptr, tmp);
				rcv_ptr += tmp;
				offset += tmp;
				DBG_OUT("offset = %d, rcv_ptr = %d", offset, rcv_ptr);
				continue; // 将接收到的剩余全部数据读入接收缓冲
			} else {
				memcpy(rcv_buff + offset, rcv_msg + rcv_ptr,
						(datalen - offset));
				//DBG_OUT(" ");
				free(rcv_msg);
				return 0; // 将指定长度的数据读入接收缓冲
			}
		}
	} // while
	free(rcv_msg);
	return 0;
}

int make_argv(char *s, int argvsz, char *argv[])
{
    int argc = 0;

    /* split into argv */
    while (argc < argvsz - 1) {

        /* skip any white space */
        while ((*s == ' ') || (*s == '\t'))
            ++s;

        if (*s == '\0') /* end of s, no more args   */
            break;

        argv[argc++] = s;   /* begin of argument string */

        /* find end of string */
        while (*s && (*s != ' ') && (*s != '\t'))
            ++s;

        if (*s == '\0')     /* end of s, no more args   */
            break;

        *s++ = '\0';        /* terminate current arg     */
    }
    argv[argc] = NULL;

    return argc;
}

u32 get_packet_sn(void)
{
	static u32 sn = 0;
	return ++sn;
}

Queue que_msg;
pthread_mutex_t mutex_msg = PTHREAD_MUTEX_INITIALIZER;
sem_t sem_msg;

void push_data(int sd, u8 *data, int len)
{
	int datalen = len + sizeof(struct msg_packet);
    struct msg_packet *msg = (struct msg_packet *)malloc(datalen);

    msg->sd = sd;
    msg->len = len;
    memcpy(msg->data, data, len);
    DBG_OUT("push %d bytes data to queue\n", len);
    pthread_mutex_lock(&mutex_msg);
    Enqueue((ElementType)msg, que_msg);
    pthread_mutex_unlock(&mutex_msg);
    sem_post(&sem_msg);
}

void* send_thread(void *arg)
{
	struct send_param *sp = (struct send_param*)arg;
    struct msg_packet *msg;

	while(1) {
		sem_wait(sp->sem_msg);
        pthread_mutex_lock(sp->mutex_msg);
        msg = (struct msg_packet *)FrontAndDequeue(sp->que_msg);
        pthread_mutex_unlock(sp->mutex_msg);
        DBG_OUT("sending %d bytes data to client...", msg->len);
        dump_packet((PMIFI_PACKET) msg->data);
        send(msg->sd, msg->data, msg->len, 0);
        DBG_OUT("sent done\n");
        free((void *)msg);
	}
	pthread_exit((void *)0);
	return NULL;
}

