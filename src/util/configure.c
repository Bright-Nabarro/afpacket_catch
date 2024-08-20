#include "configure.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <logger.h>

#define cth_default_ethernet		"eth0"
#define cth_default_save_pcap_path	"./output.pcap"
#define cth_default_log_output_path NULL

static char* ethernet = NULL;
static char* save_pcap_path = NULL;
static char* log_output_path = NULL;
static char* bpf_argument = NULL;      //NULL即为默认值

static size_t tp_block_size = 4096;
static size_t tp_block_nr = 64;
static size_t tp_frame_size = 2048;

#define SET_STR_TEMPLATE(str, value)                                           \
    do                                                                         \
    {                                                                          \
        if (value != NULL)                                                     \
            free(value);                                                       \
        size_t strLen = strlen(str);                                           \
        value = malloc(strLen + 1);                                            \
        strncpy(value, str, strLen);                                           \
        value[strLen] = '\0';                                                  \
    } while (0)

#define GET_STR_TEMPLATE(value)                                                \
    do                                                                         \
    {                                                                          \
        if (value == NULL)                                                     \
        {                                                                      \
            printf("%s unset, use default\n", #value);                         \
            value = cth_default_##value;                                       \
            return value;                                                      \
        }                                                                      \
        return value;                                                          \
    } while (0)

void set_ethernet(const char* eth)
{
	SET_STR_TEMPLATE(eth, ethernet);
}

const char* get_ethernet()
{
	GET_STR_TEMPLATE(ethernet);
}

void set_save_pcap_path(const char* savePath)
{
	SET_STR_TEMPLATE(savePath, save_pcap_path);
}

const char* get_save_pcap_path()
{
	GET_STR_TEMPLATE(save_pcap_path);
}

void set_log_output_path(const char* outputPath)
{
	SET_STR_TEMPLATE(outputPath, log_output_path);
}

const char* get_log_output_path()
{
	GET_STR_TEMPLATE(log_output_path);
}

void set_bpf_argument(const char* expr)
{
    SET_STR_TEMPLATE(expr, bpf_argument);
}

const char* get_bpf_argument()
{
    //无默认值无需警告，是否为NULL交由上层判断
    return bpf_argument;
}

void set_tp_block_size(size_t bksz)
{
    if (bksz % 64 != 0)
    {
        cth_log(CTH_LOG_ERROR, "invalid tp_block_size, use default");
    }

    tp_block_size = bksz;
}

void set_tp_block_nr(size_t bknr)
{

    if (bknr % 64 != 0)
    {
        cth_log(CTH_LOG_ERROR, "invalid tp_block_nr, use default");
    }

    tp_block_nr = bknr;
}

void set_tp_frame_size(size_t fmsz)
{
    if (tp_block_size % fmsz != 0 || fmsz < tp_block_size)
    {
        cth_log(CTH_LOG_ERROR, "invalid tp_frame_size, use default");
    }
    tp_frame_size = fmsz;
}

size_t get_tp_block_size()
{
    return tp_block_size;
}

size_t get_tp_block_nr()
{
    return tp_block_nr;
}

size_t get_tp_frame_size()
{
    return tp_frame_size;
}

size_t get_tp_frame_nr()
{
    return (tp_block_size * tp_block_nr) / tp_frame_size;
}

void release_config()
{
	free(ethernet);
	free(save_pcap_path);
	free(log_output_path);
    free(bpf_argument);
}

