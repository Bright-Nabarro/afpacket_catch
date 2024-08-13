#include <getopt.h>
#include <sys/socket.h>
#include <unistd.h>

#include "configure.h"
#include "original_capture.h"
#include "logger.h"

static int parse_main_args(int argc, char* argv[])
{
	int optionArg = 0;
	//关闭默认解析错误输出
	opterr = 0;

	struct option longOptions [] = {
		/* 监视网口名 */
		{"ethernet",	required_argument,	0,	'e'	},
		/* 输出pacp路径 */
		{"savepath",	required_argument,	0,	'w'	},
		/* log输出位置 */
		{"log",			required_argument,	0,	'l' },
        /* 过滤表达式 不由引号包围的规定为文件名，参数直接转发给脚本处理*/
        {"bpf",         required_argument,  0,  'b' },
		{0, 0, 0, 0},
	};

	int opt;
	while( (opt = getopt_long(argc, argv, "e:w:l:b:", longOptions, &optionArg)) != -1 )
	{
		switch(opt)
		{
		case 'e':
            set_ethernet(optarg);
			break;
		case 'w':
            set_save_pcap_path(optarg);
			break;
		case 'l':
            set_log_output_path(optarg);
			break;
        case 'b':
            set_bpf_argument(optarg);
            break;
		case '?':
            cth_log(CTH_LOG_ERROR, "excepted main argument %c", optopt);
            break;
		default:
            cth_log(CTH_LOG_FATAL, "unprocessed argument");
			return 1;
		}
	}

	return 0;
}

int main(int argc, char* argv[])
{
    parse_main_args(argc, argv);

    return original_main();
}


