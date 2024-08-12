#pragma once

#define CTH_FATAL_ERR		(int)-1
#define CTH_SUCCESS			0x0
#define CTH_SOCKET_ERR		0x1
#define CTH_BIND_ERR		0x2
#define CTH_SETMIX_MODE_ERR 0x4
#define CTH_SET_FILITER_ERR 0x8


int get_original_socket(int* p_sockfd, const char* ethName);

int original_main();
