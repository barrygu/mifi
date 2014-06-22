#ifndef __MIFI_CLI_H__
#define __MIFI_CLI_H__

#include "tcpComm.h"

#ifdef LOCAL_TEST
#define SERVER_ADDR "127.0.0.1"
#else
//#define SERVER_ADDR "218.80.254.79"
//#define SERVER_ADDR "192.168.10.109"
#define SERVER_ADDR "116.228.171.21"
#endif

int establish_connection(char *server, int port);
int build_packet(PMIFI_PACKET packet, int func);
int build_packet_ex(PMIFI_PACKET packet, int func, int argc, char *argv[]);
int build_response(PMIFI_PACKET packet, PMIFI_PACKET resp);

int get_cmdid(char *cmd);
int cmd_handle(int sd, char *cmd);

int get_device_id(u8 *pDevId);
int get_device_imsi(u8 *pImsi);
int get_device_version(u8 *pVer);
int get_client_mac(u8 *pMac);
int get_user_mac(u8 *pMac);
int get_cell_id(void);

#endif // __MIFI_CLI_H__
