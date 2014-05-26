#ifndef __MIFI_SVR_H__
#define __MIFI_SVR_H__

#include "tcpComm.h"

#define END_LINE 0x0

int server_build_response(PMIFI_PACKET packet, PMIFI_PACKET resp);

#endif // __MIFI_SVR_H__
