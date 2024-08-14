#include "task_scheduler.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#ifdef NO_LOGGER

//与logger的接口统一
#define CTH_LOG_INFO    0
#define CTH_LOG_STATUS  1
#define CTH_LOG_WARNING 2
#define CTH_LOG_ERROR   3
#define CTH_LOG_FATAL   4


#define TASK_LOG(logLevel, fmt, __VA_ARGS__)                                   \
	do                                                                         \
	{                                                                          \
		if ((logLevel) == CTH_LOG_ERROR || (logLevel) == CTH_LOG_FATAL)        \
		{                                                                      \
			fprintf(stderr, (fmt), __VA_ARGS__);                               \
		}                                                                      \
		else                                                                   \
		{                                                                      \
			fprintf(stdout, (fmt), __VA_ARGS__);                               \
		}                                                                      \
	} while (0)
#else
#define TASK_LOG(logLevel, fmt, __VA_ARGS__)                                   \
	do                                                                         \
	{                                                                          \
		cth_log((logLevel), (fmt), __VA_ARGS__);                               \
	} while (0)
#endif

/*
 * 处理错误处理中的出错
 * 直接简单退出
 */
#define CTH_HANDLE_TASK_SCHEDULER_ERROR2(ret, func)                            \
	do                                                                         \
	{                                                                          \
		fprintf(stderr, #func ": %s", strerror(ret));                          \
		fprintf(stderr, "handle error function error, exit\n");                \
		_exit(-1);                                                             \
	} while (0)

/* 管理线程执行 */
static void* cth_task_scheduler_manager(void* arg);
/* 队列添加 */
static void* cth_task_scheduler_add_task(void* arg);

CthTaskScheduler* cth_task_scheduler_init(size_t queueSize)
{
    CthTaskScheduler* scheduler = calloc(1, sizeof(CthTaskScheduler));
    scheduler->queueSize = queueSize;
    scheduler->taskQueue = malloc(sizeof(CthTask) * queueSize);
    scheduler->shutdown = false;
    
    int ret;
    ret = pthread_mutex_init(&scheduler->queueMutex, NULL);
    if (ret != 0)
    {
        TASK_LOG(CTH_LOG_FATAL, "pthread_mutex_init error: %s", strerror(ret));
        return NULL;
    }

    ret = pthread_cond_init(&scheduler->queueEmpty, NULL);
    if (ret != 0)
    {
        TASK_LOG(CTH_LOG_FATAL, "pthread_cond_init error: %s", strerror(ret));
        goto clean_mutex;
        return NULL;
    }

    ret = pthread_create(&scheduler->managerThread, NULL, cth_task_scheduler_manager, scheduler);
    if (ret != 0)
    {
        TASK_LOG(CTH_LOG_FATAL, "pthread_create error: %s", strerror(ret));
        goto clean_mutex;
        return NULL;
    }

    return scheduler;

clean_mutex:
    ret = pthread_mutex_destroy(&scheduler->queueMutex);
    if(ret != 0)
    {
        CTH_HANDLE_TASK_SCHEDULER_ERROR2(ret, pthread_mutex_destroy);
    }
    return NULL;
}


typedef struct
{
    CthTaskScheduler* scheduler;
    void (*tk_func)(void*);
    void* arg;
}CthTaskSchedulerAddTaskArgs;

/* 需要优化 */
int cth_task_scheduler_add(CthTaskScheduler* scheduler, void(*func)(void*), void* arg)
{
    pthread_t addTaskThread;
    CthTaskSchedulerAddTaskArgs* args = malloc(sizeof(CthTaskSchedulerAddTaskArgs));
    args->scheduler = scheduler;
    args->tk_func = func;
    args->arg = arg;

    int ret;
    // 在线程函数中释放args 
    ret = pthread_create(&addTaskThread, NULL, cth_task_scheduler_add_task, args);
    if (ret != 0)
    {
        TASK_LOG(CTH_LOG_FATAL, "pthread_create error: %s", strerror(ret));
        return -1;
    }

    ret = pthread_detach(addTaskThread);
    if (ret != 0)
    {
        TASK_LOG(CTH_LOG_FATAL, "pthread_detach error: %s", strerror(ret));
        ret = pthread_cancel(addTaskThread);
        if (ret != 0)
        {
            CTH_HANDLE_TASK_SCHEDULER_ERROR2(ret, pthread_cancel);
        }
        ret = pthread_join(addTaskThread, NULL);
        if (ret != 0)
        {
            CTH_HANDLE_TASK_SCHEDULER_ERROR2(ret, pthread_join);
        }
        return -1;
    }

    return 0;
}


int cth_task_scheduler_destroy(CthTaskScheduler* scheduler)
{
    scheduler->shutdown = true; 
    int* managerRet;
    int ret;
    ret = pthread_join(scheduler->managerThread, (void**)&managerRet);
    if (ret)
    {
        TASK_LOG(CTH_LOG_FATAL, "pthread_join error: %s", strerror(ret));
        return -1;
    }

    ret = pthread_cond_destroy(&scheduler->queueEmpty);
    if (ret)
    {
        TASK_LOG(CTH_LOG_FATAL, "pthread_cond_destroy error: %s", strerror(ret));
        return -1;
    }
    
    ret = pthread_mutex_destroy(&scheduler->queueMutex);
    if (ret)
    {
        TASK_LOG(CTH_LOG_FATAL, "pthread_mutex_destroy error: %s", strerror(ret));
        return -1;
    }

    free(scheduler->taskQueue);
    free(scheduler);

    return 0;
}

static inline bool cth_scheduler_queue_empty(const CthTaskScheduler* scheduler)
{
    if (scheduler->queueHead == scheduler->queueTail)
        return true;
    return false;
}

/* 失败打印信息返回NULL */
static void* cth_task_scheduler_manager(void* arg)
{
    CthTaskScheduler* scheduler = arg;
    int ret;
    while(!scheduler->shutdown || !cth_scheduler_queue_empty(scheduler))
    {
        ret = pthread_mutex_lock(&scheduler->queueMutex);
        if (ret)
        {
            TASK_LOG(CTH_LOG_FATAL, "pthread_mutex_lock error: %s", strerror(ret));
            return NULL;
        }
        
        while(cth_scheduler_queue_empty(scheduler))
        {
            ret = pthread_cond_wait(&scheduler->queueEmpty, &scheduler->queueMutex);
            if (ret)
            {
                TASK_LOG(CTH_LOG_FATAL, "pthread_cond_wait error: %s", strerror(ret));
                return NULL;
            }
        }
        
        //将task弹出队列
        CthTask* currTask = &scheduler->taskQueue[scheduler->queueHead++];
        if (scheduler->queueHead == scheduler->queueSize)
        {
            scheduler->queueHead = 0;
            if (scheduler->queueTail == scheduler->queueSize)
                scheduler->queueTail = 0;
        }

        void (*tk_func)(void*) = currTask->tk_func;
        void* tk_arg = currTask->arg;

        ret = pthread_mutex_unlock(&scheduler->queueMutex);
        if (ret)
        {
            TASK_LOG(CTH_LOG_FATAL, "pthread_mutex_unlock error: %s", strerror(ret));
        }

        tk_func(tk_arg);
        free(currTask);
    }

    return NULL;
}

static void* cth_task_scheduler_add_task(void* arg)
{
}
