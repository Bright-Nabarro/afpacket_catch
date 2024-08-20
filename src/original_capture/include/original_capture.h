#pragma once

#define CTH_FATAL_ERR           (int)-1
#define CTH_SUCCESS             0x0
#define CTH_SOCKET_ERR          (1 << 0)
#define CTH_BIND_ERR            (1 << 1)
#define CTH_SETMIX_MODE_ERR     (1 << 2)
#define CTH_SET_FILITER_ERR     (1 << 3)
#define CTH_SET_PACVER_ERR      (1 << 4)
#define CTH_SET_PACKET_RING_ERR (1 << 4)

int get_original_socket(int* p_sockfd, const char* ethName);

int original_main();
