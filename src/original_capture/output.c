#include "output.h"

#include <net/ethernet.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "configure.h"
#include "logger.h"

static const size_t lineBreakNum = 20;
static FILE* output_file = NULL;

/* pcap全局头部 */
struct pcap_file_header
{
    uint32_t magic_number;  //魔术字, 区分大小端
    uint16_t version_major; //主版本号
    uint16_t version_minor; //次版本号
    int32_t thiszone;       //GMT
    uint32_t sigfigs;       //精确时间戳
    uint32_t snaplen;       //最长捕获字节
    uint32_t network;       //数据链路类型
};

/* pcap每个数据包长度 */
struct pcap_packet_header
{
    uint32_t ts_sec;        //数据包捕获的秒级时间戳
    uint32_t ts_usec;       //微妙级时间戳
    uint32_t incl_len;      //捕获的数据长度
    uint32_t orig_len;      //原始数据长度
};

[[maybe_unused]]
static void fprint_bits(FILE* file, const void* ptr, size_t numBytes)
{
	const uint8_t* bptr = (const uint8_t*)ptr;
	size_t counter = 0;

	for (size_t i = 0; i < numBytes; i++)
	{
		fprintf(file, "%02x ", bptr[i]);
		if (++counter == lineBreakNum)
		{
			counter = 0;
			fprintf(file, "\n");
		}
	}

	if (++counter != lineBreakNum)
		fprintf(file, "\n");
}

[[maybe_unused]]
static void fprint_mac(FILE* file, const uint8_t mac[ETH_ALEN])
{
	fprintf(file, "%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int inital_output_file(const char* path)
{
	output_file = fopen(path, "w");
	return 0;
}

int close_output_file()
{
	if (output_file == NULL)
		return 0;

	fclose(output_file);
	output_file = NULL;
	return 0;
}

int output_binary_packet(char* buf, int numBytes)
{
    
	inital_output_file(get_save_pcap_path());
	fprint_bits(output_file, buf, numBytes);
	return 0;
}

int initial_pcap_file(const char* path)
{
    output_file = fopen(path, "wb");
    if (!output_file) 
    {
        cth_log_err(CTH_LOG_FATAL, "fopen", errno);
        return -1;
    }

    struct pcap_file_header pcapHeader = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 8,
        .sigfigs = 0,
        .snaplen = CTH_MAX_BUF_SIZ - 1,
        .network = 1        //Ethernet
    };

    fwrite(&pcapHeader, sizeof pcapHeader, 1, output_file);

    return 0;
}

int close_pcap_file()
{
    //允许重复关闭
    if (output_file == NULL)
        return 0;
    fclose(output_file);
    output_file = NULL;
    return 0;
}

int output_pcap_packet(char* buf, int numBytes)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct pcap_packet_header packetHeader = {
        .ts_sec = ts.tv_sec,
        .ts_usec = ts.tv_nsec / 1000,
        .incl_len = numBytes,
        .orig_len = numBytes,
    };
    fwrite(&packetHeader, sizeof packetHeader, 1, output_file);
    fwrite(buf, numBytes, 1, output_file);
    return 0;
}

