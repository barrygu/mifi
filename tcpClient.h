#ifndef __MIFI_CLI_H__
#define __MIFI_CLI_H__

#include "tcpComm.h"

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

#endif // __MIFI_CLI_H__