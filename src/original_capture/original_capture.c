#include "original_capture.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <poll.h> //仅仅用于触发事件检测
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

// in extern
#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"

// in util
#include "configure.h"
#include "logger.h"
#include "output.h"
#include "signal_handle.h"

static struct tpacket_req tpReq;
static size_t MmapBufferLen;
/*
 * 绑定到指定接口, 如果出错全部返回-1
 */
static int bind_socket_eth(int sockfd, const char* ethName, struct ifreq* p_ifr)
{
	memset(p_ifr, 0, sizeof(struct ifreq));
    
    size_t strLen = strlen(ethName);
	strncpy(p_ifr->ifr_name, ethName, strLen < IFNAMSIZ-1 ? strLen : IFNAMSIZ -1);
	//获取网络接口索引
	if (ioctl(sockfd, SIOCGIFINDEX, p_ifr) < 0)
	{
		cth_log_errcode(CTH_LOG_ERROR, "ioctl", errno);
		return -1;
	}
	cth_log_digit(CTH_LOG_STATUS, "eth bind index: %d", p_ifr->ifr_ifindex);

	//链路层套接字
	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof sll);
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = p_ifr->ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);

	//绑定
	if (bind(sockfd, (struct sockaddr*)&sll, sizeof(sll)) < 0)
	{
		cth_log_errcode(CTH_LOG_ERROR, "bind", errno);
		return -1;
	}

	return CTH_SUCCESS;
}

static int set_bpf_code(struct sock_filter* bpfCode, size_t idx, const char* key, void* value)
{
    if (strcmp(key, "code") == 0)
    {
        bpfCode[idx].code = *(uint16_t*)value;
    }
    else if(strcmp(key, "jt") == 0)
    {
        bpfCode[idx].jt = *(uint8_t*)value;
    }
    else if(strcmp(key, "jf") == 0)
    {
        bpfCode[idx].jf = *(uint8_t*)value;
    }
    else if(strcmp(key, "k") == 0)
    {
        bpfCode[idx].k = *(uint32_t*)value;
    }
    else
    {
        cth_log_str(CTH_LOG_ERROR, "unexcepted key: %s", key);
        return -1;
    }
    return 0;
}

static int set_socket_filter(int sockfd, const char* bpfarg)
{
    lua_State* L = luaL_newstate();
    struct sock_filter* bpfCode = NULL;

    if (!L)
    {
        cth_log(CTH_LOG_ERROR, "failed to create Lua state");
        return -1;
    }
    luaL_openlibs(L);

    if (luaL_dofile(L, "script/get_bpf_filter.lua") != LUA_OK)
    {
        cth_log_errmsg(CTH_LOG_ERROR, "loading lua script error: %s", lua_tostring(L, -1));
        goto err;
    }

    lua_getglobal(L, "get_bpf_filter");

    if (!lua_isfunction(L, -1))
    {
        cth_log(CTH_LOG_ERROR, "function `get_bpf_filter` not found in lua script");
        goto err;
    }

    //将参数推入栈
    lua_pushstring(L, bpfarg);
    //调用函数，1个参数，2个返回值，没有错误处理函数
    //函数完成后返回值在栈顶
    if (lua_pcall(L, 1, 1, 0) != LUA_OK)
    {
        cth_log_errmsg(CTH_LOG_ERROR, "lua_pcall error: %s", lua_tostring(L, -1));
        goto err;
    }

    //先获取全局的表达式行数
    lua_getglobal(L, "LinesCount");
    if (!lua_isnumber(L, -1))
    {
        cth_log(CTH_LOG_ERROR, "global LinesCount unset");
        goto err;
    }
    size_t bpfLines = lua_tonumber(L, -1);
    bpfCode = malloc(bpfLines * sizeof(struct sock_filter));
    lua_pop(L, 1);


    if (lua_isnil(L, -1))
    {
        cth_log(CTH_LOG_ERROR, "lua function return nil, expression maybe error");
        goto err;
    }

    if (!lua_istable(L, -1))
    {
        cth_log(CTH_LOG_ERROR, "unexpected return type");
        goto err;
    }

    
    //确保从表头开始遍历
    lua_pushnil(L);
    //table的位置在栈顶之下
    for (size_t idx = 0; lua_next(L, -2) != 0; idx++)
    {
        if (idx >= bpfLines)
        {
            cth_log(CTH_LOG_FATAL, "idx >= bpfLine, maybe logic error");
            goto err;
        }
        //现在栈顶为函数返回表的子表
        if (!lua_istable(L, -1))
        {
            cth_log(CTH_LOG_ERROR, "type in table");
            goto err;
        }

        //从子表第一项开始遍历
        lua_pushnil(L);
        while(lua_next(L, -2) != 0)
        {
            int value = lua_tonumber(L, -1);
            const char* key = lua_tostring(L, -2);
            lua_pop(L, 1);
            if (set_bpf_code(bpfCode, idx, key, &value))
            {
                cth_log(CTH_LOG_ERROR, "set_bpf_code error");
                goto err;
            }
            
        }
        //弹出一个子表
        lua_pop(L, 1);
    }
    
    struct sock_fprog filter;
    filter.len = bpfLines;
    filter.filter = bpfCode;
    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof filter) < 0)
    {
        cth_log_errcode(CTH_LOG_ERROR, "setsockopt", errno);
        goto err;
    }

    free(bpfCode);
    lua_close(L);
    return 0;

err:
    if (bpfCode != NULL) free(bpfCode);
    lua_close(L);
    return -1;
}

//配置最后PACKET环形区域时开始捕获
int get_original_socket(int* p_sockfd, const char* ethName)
{
	int ret = CTH_SUCCESS;
	*p_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (*p_sockfd < 0)
	{
		cth_log_errcode(CTH_LOG_FATAL, "socket", errno);
		p_sockfd = NULL;
		return CTH_SOCKET_ERR;
	}

	//绑定到接口
	struct ifreq ifr;
	if (ethName == NULL || bind_socket_eth(*p_sockfd, ethName, &ifr) < 0)
	{
		cth_log(CTH_LOG_ERROR, "bind_socket_eth error");
		ret |= CTH_BIND_ERR;
	}

	//设置混杂模式
	struct packet_mreq mreq;
	memset(&mreq, 0, sizeof mreq);
	mreq.mr_type = PACKET_MR_PROMISC;
	mreq.mr_ifindex = ifr.ifr_ifindex; 
    if (setsockopt(*p_sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
				&mreq, sizeof mreq) < 0)
	{
		cth_log_errcode(CTH_LOG_ERROR, "setsockopt", errno);
		ret |= CTH_SETMIX_MODE_ERR;
	}
    else
    {
        cth_log(CTH_LOG_INFO, "set mix mode success");
    }

    //添加过滤
    const char* bpfarg = get_bpf_argument();
    if (bpfarg != NULL)
    {
        if (set_socket_filter(*p_sockfd, bpfarg))
        {
            cth_log(CTH_LOG_ERROR, "set_socket_filter error, use default");
            ret |= CTH_SET_FILITER_ERR;
        }
        else
        {
            cth_log(CTH_LOG_INFO, "set_socket_filter success");
        }
    }
    else
    {
        cth_log(CTH_LOG_STATUS, "filter unset, use default");
    }

    //添加环形区域
    //设置版本
    int tpacket_version = TPACKET_V1;
    if (setsockopt(*p_sockfd, SOL_PACKET, PACKET_VERSION, &tpacket_version, sizeof(int)) < 0)
    {
        cth_log_errcode(CTH_LOG_ERROR, "setsockopt", errno);
        ret |= CTH_SET_PACVER_ERR;
        goto pass;
    }

    //暂时使用固定值，后序添加配置读取
    tpReq.tp_block_size = get_tp_block_size();
    tpReq.tp_block_nr = get_tp_block_nr();
    tpReq.tp_frame_size = get_tp_frame_size();
    tpReq.tp_frame_nr = get_tp_frame_nr();
    
    if (setsockopt(*p_sockfd, SOL_PACKET, PACKET_RX_RING, (void*)&tpReq, sizeof tpReq) < 0)
    {
        cth_log_errcode(CTH_LOG_ERROR, "setsockopt", errno);
        ret |= CTH_SET_PACKET_RING_ERR;
    }

pass:
	return ret;
}

/*
 *  出错返回NULL
 */
static void* initial_mmap(int sockfd)
{
    MmapBufferLen = tpReq.tp_block_size * tpReq.tp_block_nr;
    void* mmapArea = mmap(NULL, MmapBufferLen, PROT_READ | PROT_WRITE, MAP_SHARED, sockfd, 0);
    if (mmapArea == MAP_FAILED)
    {
        cth_log_errcode(CTH_LOG_FATAL, "mmap", errno);
        goto err;
    }
    memset(mmapArea, 0, MmapBufferLen);

    return mmapArea;
err:
    return NULL;
}

static void free_mmap(void* mmapArea)
{
    munmap(mmapArea, MmapBufferLen);
}

static int original_main_loop(int sockfd, char* mmapArea)
{

    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;
    cth_log(CTH_LOG_INFO, "start capturing");

    size_t index = 0;
    size_t counter = 0;
    while (true)
    {
        struct tpacket_hdr* hdr = (struct tpacket_hdr*)(mmapArea + index * tpReq.tp_frame_size);
        
        if ((hdr->tp_status & TP_STATUS_USER) != TP_STATUS_USER)
        {
            if (poll(&pfd, 1, -1) < 0)
            {
                if (errno == EINTR)
                    break;
                cth_log_errcode(CTH_LOG_FATAL, "poll", errno);
                goto cleanmmap;
            }
            continue;
        }

        //屏蔽ctrl c
        PrevState state;
        if (block_sig(&state, SIGINT))
        {
            cth_log(CTH_LOG_FATAL, "block_sig");
            return -1;
        }
        //--

        if (g_recSigint)
            break;

        if (errno == EINTR)
            break;

        //内核设置了PACKET环后不会回写
        hdr->tp_status = TP_STATUS_KERNEL;
        index = (index + 1) % tpReq.tp_frame_nr;
        ++counter;
        output_pcap_packet((char*)hdr + hdr->tp_mac, hdr->tp_len);

        //恢复ctrlc
        if (recover_sig(&state) < 0)
        {
            cth_log(CTH_LOG_FATAL, "recover_sig error");
            goto cleanmmap;
        }
        //--
    }

    cth_log_digit(CTH_LOG_INFO, "Captured %d packets", counter);
    free_mmap(mmapArea);
    return 0;

cleanmmap:
    free_mmap(mmapArea);
    return -1;
}

int original_main()
{
	int sockfd = 0;
    const char* ethName = get_ethernet();
	int status = get_original_socket(&sockfd, ethName);
	if (status & CTH_SOCKET_ERR)
	{
		cth_log(CTH_LOG_FATAL, "cannot open sockfd, exit");
		goto err;
	}
	
	if (initial_signal())
	{
		cth_log(CTH_LOG_FATAL, "inital_signal error, exit");
		goto cleanfd;
	}

    void* mmapArea = initial_mmap(sockfd);
    if (mmapArea == NULL)
    {
        cth_log(CTH_LOG_FATAL, "set_packet_ring error");
        goto cleanfd;
    }
    
	if (initial_pcap_file(get_save_pcap_path(), mmapArea, tpReq.tp_frame_nr) < 0)
    {
        cth_log(CTH_LOG_FATAL, "initial_pcap_file error, exit");
        goto cleanfd;
    }

	original_main_loop(sockfd, mmapArea);

    close(sockfd);
	close_pcap_file();
	return 0;

cleanfd:
	if (sockfd > 0) close(sockfd);
err:
	return -1;
}
