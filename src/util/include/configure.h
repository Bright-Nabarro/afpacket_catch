#pragma once
#include <stddef.h>

void set_ethernet(const char* eth);
const char* get_ethernet();

void set_save_pcap_path(const char* savePath);
const char* get_save_pcap_path();

void set_log_output_path(const char* outputPath);
const char* get_log_output_path();

void set_bpf_argument(const char* expr);
const char* get_bpf_argument();

void set_tp_block_size(size_t);
void set_tp_block_nr(size_t);
void set_tp_frame_size(size_t);

size_t get_tp_block_size();
size_t get_tp_block_nr();
size_t get_tp_frame_size();
size_t get_tp_frame_nr();

void release_config();

