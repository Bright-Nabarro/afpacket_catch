#include "logger.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "configure.h"
#include "task_scheduler.h"

#define CTH_LOG_QUE_SIZ 10

static CthTaskScheduler* scheduler = NULL;

static void cth_log_callback(void* args);

static FILE* logFile;

typedef struct
{
    FILE* file;
    enum CTH_LOG_LEVEL logLevel;
    const char * fmt;
    va_list args;
} CthLogThdFuncArgs;


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

    scheduler = cth_task_scheduler_init(true, CTH_LOG_QUE_SIZ);
    if (scheduler == NULL)
    {
        fprintf(stderr, "cth_task_scheduler_init error\n");
        return -1;
    }
	return 0;
}

void cth_log_close()
{
    fclose(logFile);
    if (cth_task_scheduler_destroy(scheduler))
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

void cth_log(enum CTH_LOG_LEVEL logLevel, const char* fmt, ...)
{
	va_list args;

    CthLogThdFuncArgs* funcArgs = malloc(sizeof(CthLogThdFuncArgs));
    assert(logFile != NULL);
    funcArgs->file = logFile;
    funcArgs->logLevel = logLevel;
    funcArgs->fmt = fmt;
	va_start(args, fmt);
    va_copy(funcArgs->args, args);

    if(cth_task_scheduler_add(scheduler, cth_log_callback, funcArgs))
    {
        fprintf(stderr, "cth_task_scheduler_add error\n");
    }

	va_end(args);
}

void cth_log_err(enum CTH_LOG_LEVEL logLevel, const char* msg, int errcode)
{
	cth_log(logLevel, "%s error: %s", msg, strerror(errcode));
}

//在线程管理中自动释放参数
static void cth_log_callback(void* args)
{
    CthLogThdFuncArgs* thdArgs = args;
    FILE* file = thdArgs->file;
 	fprintf(file, "[%s]  ", log_level_to_string(thdArgs->logLevel));
	vfprintf(file, thdArgs->fmt, thdArgs->args);
	fprintf(file, "\n");
    va_end(thdArgs->args);
}

