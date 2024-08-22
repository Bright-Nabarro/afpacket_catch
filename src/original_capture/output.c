#include "output.h"

#include <net/ethernet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "configure.h"
#include "logger.h"
#include "task_scheduler.h"

#define CTH_OUTPUT_QUE_SIZ 40

static const size_t g_lineBreakNum = 20;
static FILE* output_file = NULL;
static int g_outputFd = 0;
static CthTaskScheduler* outputScheduler = NULL;
static pthread_mutex_t writeMtx;

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
		if (++counter == g_lineBreakNum)
		{
			counter = 0;
			fprintf(file, "\n");
		}
	}

	if (++counter != g_lineBreakNum)
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
    g_outputFd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (g_outputFd < 0) 
    {
        cth_log_errcode(CTH_LOG_FATAL, "open", errno);
        goto err;
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

    if (pthread_mutex_init(&writeMtx, NULL) < 0)
    {
        cth_log_errcode(CTH_LOG_FATAL, "pthread_mutex_init", errno);
        goto cleanfd;
    }

    outputScheduler = cth_task_scheduler_init(false, CTH_OUTPUT_QUE_SIZ);
    if (outputScheduler == NULL)
    {
        cth_log(CTH_LOG_FATAL, "cth_task_scheduler_init");
        goto cleanmtx;
    }

    write(g_outputFd, &pcapHeader, sizeof pcapHeader);
    return 0;

cleanmtx:
    pthread_mutex_destroy(&writeMtx);
cleanfd:
    close(g_outputFd);
err:
    return -1;
}

int close_pcap_file()
{
    pthread_mutex_destroy(&writeMtx);
    close(g_outputFd);
    if (cth_task_scheduler_destroy(outputScheduler))
    {
        cth_log(CTH_LOG_FATAL, "cth_task_scheduler_destroy");
        return -1;
    }
    return 0;
}

typedef struct
{
    char* buf;
    int inclLen;
    int origLen;
    pthread_mutex_t* writeMtx;
} CthOutputArgs;

static void callback_output_packet(void* args)
{
    CthOutputArgs* packet = args;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct pcap_packet_header packetHeader = {
        .ts_sec = ts.tv_sec,
        .ts_usec = ts.tv_nsec / 1000,
        .incl_len = packet->inclLen,
        .orig_len = packet->origLen,
    };
    pthread_mutex_lock(packet->writeMtx);
    write(g_outputFd, &packetHeader, sizeof packetHeader);
    write(g_outputFd, packet->buf, packet->inclLen);
    pthread_mutex_unlock(packet->writeMtx);
}

int output_pcap_packet(char* buf, int inclLen, int origLen)
{
    CthOutputArgs* packet = malloc(sizeof(CthOutputArgs));
    packet->buf = buf;
    packet->inclLen = inclLen;
    packet->origLen = origLen;
    packet->writeMtx = &writeMtx;

    cth_task_scheduler_add(outputScheduler, callback_output_packet, packet);
    return 0;
}

