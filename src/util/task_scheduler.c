#include "task_scheduler.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <logger.h>
#include <signal.h>
#include <errno.h>

#define TASK_LOG(scheduler, logLevel, fmt, ...)                                \
	do                                                                         \
	{                                                                          \
		if ((scheduler)->useLogger)                                            \
		{                                                                      \
			cth_log(logLevel, (fmt), ##__VA_ARGS__);                           \
		}                                                                      \
		else if ((logLevel) == CTH_LOG_ERROR || (logLevel) == CTH_LOG_FATAL)   \
		{                                                                      \
			fprintf(stderr, (fmt), ##__VA_ARGS__);                             \
		}                                                                      \
		else                                                                   \
		{                                                                      \
			fprintf(stdout, (fmt), ##__VA_ARGS__);                             \
		}                                                                      \
	} while (0)

/*
 * 处理错误处理中的出错
 * 直接简单退出
 */
#define CTH_HANDLE_TASK_SCHEDULER_ERROR2(ret, func)                            \
	do                                                                         \
	{                                                                          \
		fprintf(stderr, #func ": %s", strerror(ret));                          \
		fprintf(stderr, "handle error function error, exit\n");                \
        _exit(1);                                                              \
	} while (0)

/* 管理线程执行 */
static void* cth_task_scheduler_manager(void* arg);
/* 队列添加 */
static void* cth_task_scheduler_add_task(void* arg);

CthTaskScheduler* cth_task_scheduler_init(bool useLogger, size_t queueSize)
{
    CthTaskScheduler* scheduler = calloc(1, sizeof(CthTaskScheduler));
    scheduler->queueSize = queueSize;
    scheduler->taskQueue = malloc(sizeof(CthTask) * queueSize);
    scheduler->shutdown = false;
    scheduler->useLogger = useLogger;
    scheduler->addTaskWorking = ATOMIC_VAR_INIT(false);
    

    int ret;
    ret = pthread_mutex_init(&scheduler->queueMutex, NULL);
    if (ret != 0)
    {
        TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_mutex_init error: %s", strerror(ret));
        return NULL;
    }

    ret = pthread_cond_init(&scheduler->condQueueEmpty, NULL);
    if (ret != 0)
    {
        TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_cond_init error: %s", strerror(ret));
        goto clean_mutex;
    }
    ret = pthread_cond_init(&scheduler->condQueueFull, NULL);
    if (ret)
    {
        TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_cond_init error: %s", strerror(ret));
        goto clean_cond_empty;
    }

    ret = pthread_create(&scheduler->managerThread, NULL, cth_task_scheduler_manager, scheduler);
    if (ret != 0)
    {
        TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_create error: %s", strerror(ret));
        goto clean_cond_full;
    }

    return scheduler;

clean_cond_full:
    ret = pthread_cond_destroy(&scheduler->condQueueFull);
    if (ret)
    {
        CTH_HANDLE_TASK_SCHEDULER_ERROR2(ret, pthread_cond_destroy);
    }
clean_cond_empty:
    ret = pthread_cond_destroy(&scheduler->condQueueEmpty);
    if (ret)
    {
        CTH_HANDLE_TASK_SCHEDULER_ERROR2(ret, pthread_cond_destroy);
    }
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
    
    atomic_store(&scheduler->addTaskWorking, true);
    // 在线程函数中释放args 
    ret = pthread_create(&addTaskThread, NULL, cth_task_scheduler_add_task, args);
    if (ret != 0)
    {
        TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_create error: %s", strerror(ret));
        return -1;
    }

    ret = pthread_detach(addTaskThread);
    if (ret != 0)
    {
        TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_detach error: %s", strerror(ret));
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
    int ret = 0;
    ret = pthread_mutex_lock(&scheduler->queueMutex);
    if (ret)
    {
        TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_mutex_lock error: %s", strerror(ret));
    }
    ret = pthread_cond_broadcast(&scheduler->condQueueEmpty);
    if (ret)
    {
        TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_cond_broadcast error: %s", strerror(ret));
    }
    ret = pthread_mutex_unlock(&scheduler->queueMutex);
    if (ret)
    {
        TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_mutex_unlock error: %s", strerror(ret));
    }

    ret = pthread_join(scheduler->managerThread, (void**)&managerRet);
    if (ret)
    {
        TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_join error: %s", strerror(ret));
    }
    ret = pthread_cond_destroy(&scheduler->condQueueFull);
    if (ret)
    {
        TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_cond_destory error: %s", strerror(ret));
    }
    ret = pthread_cond_destroy(&scheduler->condQueueEmpty);
    if (ret)
    {
        TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_cond_destroy error: %s", strerror(ret));
    }
    ret = pthread_mutex_destroy(&scheduler->queueMutex);
    if (ret)
    {
        TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_mutex_destroy error: %s", strerror(ret));
        return -1;
    }
    if (!cth_scheduler_queue_empty(scheduler))
    {
        TASK_LOG(scheduler, CTH_LOG_FATAL, "scheduler task queue not empty, may be logic error");
    }
    free(scheduler->taskQueue);
    free(scheduler);

    return ret;
}

bool cth_scheduler_queue_empty(const CthTaskScheduler* scheduler)
{
    if (!scheduler->queueFull && scheduler->queueHead == scheduler->queueTail)
        return true;
    return false;
}

static void* cth_task_scheduler_manager(void* arg)
{
    sigset_t thdSet;
    if (sigemptyset(&thdSet) < 0)
    {
        fprintf(stderr, "sigemptyset error: %s", strerror(errno));
        _exit(1);
    }
    if (sigaddset(&thdSet, SIGINT) < 0)
    {
        fprintf(stderr, "sigaddset error: %s", strerror(errno));
        _exit(1);
    }
    if (pthread_sigmask(SIG_BLOCK, &thdSet, NULL))
    {
        perror("pthread_sigmask");
        _exit(1);
    }

    CthTaskScheduler* scheduler = arg;
    int ret;
    while(!scheduler->shutdown
        || !cth_scheduler_queue_empty(scheduler)
        || atomic_load(&scheduler->addTaskWorking))
    {
        ret = pthread_mutex_lock(&scheduler->queueMutex);
        if (ret)
        {
            TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_mutex_lock error: %s", strerror(ret));
            _exit(1);
        }
        
        while(cth_scheduler_queue_empty(scheduler))
        {
            if (scheduler->shutdown
                && cth_scheduler_queue_empty(scheduler)
                && !atomic_load(&scheduler->addTaskWorking))
            {
                ret = pthread_mutex_unlock(&scheduler->queueMutex);
                if (ret)
                {
                    TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_mutex_unlock error: %s", strerror(ret));
                    _exit(1);
                }
                return NULL;
            }
            
            ret = pthread_cond_wait(&scheduler->condQueueEmpty, &scheduler->queueMutex);
            if (ret)
            {
                TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_cond_wait error: %s", strerror(ret));
                _exit(1);
            }
        }
        
        CthTask* currTask = scheduler->taskQueue[scheduler->queueHead++];
        if (scheduler->queueHead == scheduler->queueSize)
        {
            scheduler->queueHead = 0;
            if (scheduler->queueTail == scheduler->queueSize)
                scheduler->queueTail = 0;
        }

        if (scheduler->queueFull)
            scheduler->queueFull = false;

        void (*tk_func)(void*) = currTask->tk_func;
        void* tk_arg = currTask->arg;

        ret = pthread_cond_signal(&scheduler->condQueueFull);
        if (ret)
        {
            TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_cond_signal error: %s", strerror(ret));
            _exit(1);
        }

        ret = pthread_mutex_unlock(&scheduler->queueMutex);
        if (ret)
        {
            TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_mutex_unlock error: %s", strerror(ret));
            _exit(1);
        }

        tk_func(tk_arg);
        free(tk_arg);
        free(currTask);
    }

    return NULL;
}

static void* cth_task_scheduler_add_task(void* arg)
{
    sigset_t thdSet;
    if (sigemptyset(&thdSet) < 0)
    {
        fprintf(stderr, "sigemptyset error: %s", strerror(errno));
        _exit(1);
    }
    if (sigaddset(&thdSet, SIGINT) < 0)
    {
        fprintf(stderr, "sigaddset error: %s", strerror(errno));
        _exit(1);
    }
    if (pthread_sigmask(SIG_BLOCK, &thdSet, NULL))
    {
        perror("pthread_sigmask");
        _exit(1);
    }

    CthTaskSchedulerAddTaskArgs* args = arg;
    CthTaskScheduler* scheduler = args->scheduler;
    
    CthTask* task = malloc(sizeof(CthTask));
    task->tk_func = args->tk_func;
    task->arg = args->arg;

    free(args);
    
    int ret;
    ret = pthread_mutex_lock(&scheduler->queueMutex);
    if (ret)
    {
        TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_mutex_lock error: %s", strerror(ret));
        _exit(1);
    }
    
    while (scheduler->queueFull)
    {
        ret = pthread_cond_wait(&scheduler->condQueueFull, &scheduler->queueMutex);
        if (ret)
        {
            TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_cond_wait error: %s", strerror(ret));
            _exit(1);
        }
    }
    
    scheduler->taskQueue[scheduler->queueTail] = task;
    
    if (++scheduler->queueTail == scheduler->queueHead)
        scheduler->queueFull = true;
    
    ret = pthread_cond_signal(&scheduler->condQueueEmpty);
    if (ret)
    {
        TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_cond_signal error: %s", strerror(ret));
        _exit(1);
    }

    ret = pthread_mutex_unlock(&scheduler->queueMutex);
    if (ret)
    {
        TASK_LOG(scheduler, CTH_LOG_FATAL, "pthread_mutex_destroy error: %s", strerror(ret));
        _exit(1);
    }

    atomic_store(&scheduler->addTaskWorking, false);
    
    return NULL;
}

