#ifndef __MIFI_TCP_H__
#define __MIFI_TCP_H__

#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include "queue.h"

//#define SERVER_PORT 6588
#define SERVER_PORT 8588

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

#ifdef DEBUG
	#define DBG_OUT(x...) do { /*printf("[%s,%s(),%d]: ", __FILE__, __FUNCTION__, __LINE__);*/ printf(x); printf("\r\n");} while(0)
#else
	#define DBG_OUT(...) do {} while(0)
#endif

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define PACK_ALIGN(x) __attribute__((packed, aligned(x)))

//#define MAX_MSG 100
#define SUCCESS 0
#define ERROR   -1

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  ul;

typedef u8 macadr_t[6];
typedef u8 devid_t[11];
typedef u8 imsi_t[15];

typedef struct PACK_ALIGN(1) mifi_packet {
	u16 func;
	u32 sn_packet;
	devid_t id_device;
	imsi_t imsi;
	u8 reserved[6];
	u16 datalen;
	u8 data[0];
} MIFI_PACKET, *PMIFI_PACKET;

typedef struct PACK_ALIGN(1) mifi_alive {
  u32 worktime; // seconds
  u8  rssi;
  u8  battery;
  u8  login_users;
  u8  auth_users;
  u8  net_type;  // 3G or lan
  u32 cellid;
  u32 used_bytes; // Mega bytes
}MIFI_ALIVE;

struct msg_packet {
    int sd;
    int len;
    u8  data[0];
};

struct send_param {
	Queue que_msg;
	pthread_mutex_t *mutex_msg;
	sem_t *sem_msg;
};

struct mrevent {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool triggered;
};

extern Queue que_msg;
extern pthread_mutex_t mutex_msg;
extern sem_t sem_msg;

void dump_data(u8 *pdata, int datalen, int line_width);
void dump_packet(PMIFI_PACKET packet);
int  read_packet(int sd, PMIFI_PACKET packet);
u8   get_checksum(u8 *pdata, int datalen);
int  get_packet_len(PMIFI_PACKET packet);
int  make_argv(char *s, int argvsz, char *argv[]);
u32  get_packet_sn(void);
u8   hex2bin(u8 * p_hexstr, u8 * p_binstr, int len);
int  set_device_info(devid_t *pdevid, imsi_t *pimsi);
void dump_device_info(void);

void push_data(int sd, u8 *data, int len);
void* send_thread(void *arg);

void mrevent_init(struct mrevent *ev);
void mrevent_trigger(struct mrevent *ev);
void mrevent_reset(struct mrevent *ev);
void mrevent_wait(struct mrevent *ev);
bool mrevent_istriggered(struct mrevent *ev);

#define MIFI_CMD_HELP     0x8888
#define MIFI_CMD_READ     0x8988
#define MIFI_CMD_CONNECT  0x8a88

#define MIFI_CMD_LUSER    0x9088
#define MIFI_CMD_LDEV     0x9188

#define MIFI_SET_DEVID    0x0099
#define MIFI_SET_IMSI     0x0199
#define MIFI_SET_DEVINFO  0x0299
#define MIFI_GET_DEVINFO  0x0399

// use big-endian to define function id
#define MIFI_CLI_LOGIN    0x0100
#define MIFI_CLI_LOGOUT   0x0200
#define MIFI_RPT_PARAMS   0x0300

#define MIFI_RPT_STATES   0x0400
#define MIFI_CLI_ALIVE    0x0500
#define MIFI_USR_OFFLINE  0x0600
#define MIFI_USR_CHECK    0x0700
#define MIFI_USR_AUTH     0x0800
#define MIFI_ADV_REQUEST  0x0900
#define MIFI_USR_GRANT    0x0A00

#define SERV_REQ_PARAMS   0x3001
#define SERV_REQ_STATES   0x3101
#define SERV_REQ_TRUSTS   0x3201

#define SERV_REQ_KICKCLI  0x5001
#define SERV_REQ_KICKUSR  0x5101
#define SERV_REQ_REBOOT   0x5201
#define SERV_REQ_FACTORY  0x5301

#define SERV_SET_PARAMS   0x5401
#define SERV_SET_TRUSTS   0x5501
#define SERV_SET_PERMIT   0x5601

#define SERV_REQ_UPGRADE  0x7101

#endif // __MIFI_TCP_H__
