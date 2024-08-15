#include "configure.h"

#include <stdlib.h>
#include <logger.h>
#include <string.h>

#define cth_default_ethernet		"eth0"
#define cth_default_save_pcap_path	"./output.pcap"
#define cth_default_log_output_path NULL

static char* ethernet = NULL;
static char* save_pcap_path = NULL;
static char* log_output_path = NULL;
static char* bpf_argument = NULL;      //NULL即为默认值

#define SET_TEMPLATE(str, value)                                               \
	do                                                                         \
	{                                                                          \
		if (value != NULL)                                                     \
			free(value);                                                       \
		size_t strLen = strlen(str);                                           \
		value = malloc(strLen);                                                \
		strncpy(value, str, strLen);                                           \
	} while (0)

#define GET_TEMPLATE(value)                                                    \
	do                                                                         \
	{                                                                          \
		if (value == NULL)                                                     \
		{                                                                      \
			cth_log(CTH_LOG_WARNING, "%s unset, use default", #value);         \
			value = cth_default_##value;                                       \
			return value;                                                      \
		}                                                                      \
		return value;                                                          \
	} while (0)

void set_ethernet(const char* eth)
{
	SET_TEMPLATE(eth, ethernet);
}

const char* get_ethernet()
{
	GET_TEMPLATE(ethernet);
}

void set_save_pcap_path(const char* savePath)
{
	SET_TEMPLATE(savePath, save_pcap_path);
}

const char* get_save_pcap_path()
{
	GET_TEMPLATE(save_pcap_path);
}

void set_log_output_path(const char* outputPath)
{
	SET_TEMPLATE(outputPath, log_output_path);
}

const char* get_log_output_path()
{
	GET_TEMPLATE(log_output_path);
}

void set_bpf_argument(const char* expr)
{
    SET_TEMPLATE(expr, bpf_argument);
}

const char* get_bpf_argument()
{
    //无默认值无需警告，是否为NULL交由上层判断
    return bpf_argument;
}

void release_config()
{
	free(ethernet);
	free(save_pcap_path);
	free(log_output_path);
    free(bpf_argument);
}

