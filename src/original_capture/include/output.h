#pragma once
#include <stddef.h>

#define CTH_MAX_BUF_SIZ 2048

///* 直接二进制输出 */
int inital_output_file(const char* path);
int close_output_file();
int output_binary_packet(char* buf, int numBytes);

/* 转换为pcap格式保存 */
int initial_pcap_file(const char* path);
int close_pcap_file();
int output_pcap_packet(char* buf, int inclLen, int origLen);

