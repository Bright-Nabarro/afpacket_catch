#include "logger.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "configure.h"
#include "task_scheduler.h"

#define CTH_LOG_QUE_SIZ 10

#define INVOKE_CTH_LOG_REGISTER_SCHEDULER(logType, logLevel, strdata1,         \
										  strdata2, digit)                     \
	do                                                                         \
	{                                                                          \
		if (cth_log_register_scheduler(logType, logLevel, strdata1, strdata2,  \
									   digit))                                 \
		{                                                                      \
			fprintf(stderr, "cth_log_register_scheduler error\n");             \
			return -1;                                                         \
		}                                                                      \
	} while (0)

static void cth_log_callback(void* args);

static CthTaskScheduler* logScheduler = NULL;
static FILE* logFile;

typedef struct
{
    FILE* file;
    enum CTH_LOG_LEVEL logLevel;
    enum CTH_LOG_TYPE{
        CTH_LOG_NORMAL_MSG,         //[%s] %s
        CTH_LOG_FMT_DIGITAL,        //[%s] fmt, digit
        CTH_LOG_FMT_STR,            //[%s] fmt, str
        CTH_LOG_ERROR_CODE,         //[%s] %s error: %s, *, *, strerror(errCode)
        CTH_LOG_ERROR_MSG,          //[%s] %s error: %s
    } logType;
    
    const char* strdata1;
    const char* strdata2;
    int digit;

} CthLogThdFuncArgs;

static int cth_log_register_scheduler(enum CTH_LOG_TYPE, enum CTH_LOG_LEVEL logLevel, 
        const char* strdata1, const char* strdata2, int digit);

int cth_log_init()
{
	if (get_log_output_path() == NULL)
	{
		logFile = stdout;
	}
	else
	{
		logFile = fopen(get_log_output_path(), "w");
        if (logFile == NULL)
        {
            perror("fopen");
            fprintf(stderr, "use default output\n");
            logFile = stdout;
        }
	}

    logScheduler = cth_task_scheduler_init(true, CTH_LOG_QUE_SIZ);
    if (logScheduler == NULL)
    {
        fprintf(stderr, "cth_task_scheduler_init error\n");
        return -1;
    }
	return 0;
}

void cth_log_close()
{
    fflush(logFile);
    if (logFile != stdout)
        fclose(logFile);
    if (cth_task_scheduler_destroy(logScheduler))
    {
        fprintf(stderr, "cth_task_scheduler_destroy error\n");
    }
}

const char* log_level_to_string(enum CTH_LOG_LEVEL logLevel)
{
	#define CASE_STR(X) case (X): \
		return #X
	switch (logLevel)
	{
	CASE_STR(CTH_LOG_INFO);
	CASE_STR(CTH_LOG_STATUS);
	CASE_STR(CTH_LOG_WARNING);
	CASE_STR(CTH_LOG_ERROR);
	CASE_STR(CTH_LOG_FATAL);
	default:
		return NULL;
	}
	#undef CASE_STR
}


int cth_log(enum CTH_LOG_LEVEL logLevel, const char* msg)
{
    INVOKE_CTH_LOG_REGISTER_SCHEDULER(CTH_LOG_NORMAL_MSG, logLevel, msg, NULL, 0);
    return 0;
}

int cth_log_digit(enum CTH_LOG_LEVEL logLevel, const char* fmt, int digit)
{
    INVOKE_CTH_LOG_REGISTER_SCHEDULER(CTH_LOG_FMT_DIGITAL, logLevel, fmt, NULL, digit);
    return 0;
}

int cth_log_str(enum CTH_LOG_LEVEL logLevel, const char* fmt, const char* msg)
{
    INVOKE_CTH_LOG_REGISTER_SCHEDULER(CTH_LOG_FMT_DIGITAL, logLevel, fmt, msg, 0);
    return 0;
}

int cth_log_errcode(enum CTH_LOG_LEVEL logLevel, const char* funcName, int errcode)
{
    INVOKE_CTH_LOG_REGISTER_SCHEDULER(CTH_LOG_ERROR_CODE, logLevel, funcName, NULL, errcode);
    return 0;
}

int cth_log_errmsg(enum CTH_LOG_LEVEL logLevel, const char* funcName, const char* msg)
{
    INVOKE_CTH_LOG_REGISTER_SCHEDULER(CTH_LOG_ERROR_CODE, logLevel, funcName, msg, 0);
    return 0;
}

//在线程管理中自动释放参数
static void cth_log_callback(void* args)
{
    CthLogThdFuncArgs* thdArgs = args;
    FILE* file = thdArgs->file;
 	fprintf(file, "[%s]  ", log_level_to_string(thdArgs->logLevel));
    
    switch(thdArgs->logType)
    {
    case CTH_LOG_NORMAL_MSG:
        fprintf(file, "%s", thdArgs->strdata1);
        break;
    case CTH_LOG_FMT_DIGITAL:
        fprintf(file, thdArgs->strdata1, thdArgs->digit);
        break;
    case CTH_LOG_FMT_STR:
        fprintf(file, thdArgs->strdata1, thdArgs->strdata2);
        break;
    case CTH_LOG_ERROR_CODE:
        fprintf(file, "%s error: %s", thdArgs->strdata1, strerror(thdArgs->digit));
        break;
    case CTH_LOG_ERROR_MSG:
        fprintf(file, "%s error: %s", thdArgs->strdata1, thdArgs->strdata2);
        break;
    default:
        fprintf(stderr, "except logType in cth_log_callback\n");
        return;
    }
    fprintf(file, "\n");
}

static int cth_log_register_scheduler(enum CTH_LOG_TYPE logType, enum CTH_LOG_LEVEL logLevel, 
        const char* strdata1, const char* strdata2, int digit)
{
    CthLogThdFuncArgs* args = malloc(sizeof(CthLogThdFuncArgs));

    args->file = logFile;
    args->logLevel = logLevel;
    args->logType = logType;
    args->strdata1 = strdata1;
    args->strdata2 = strdata2;
    args->digit = digit;
    
    if (cth_task_scheduler_add(logScheduler, cth_log_callback, args) < 0)
    {
        fprintf(stderr, "cth_task_scheduler_add error\n");
        free(args);
        return -1;
    }

    return 0;
}

