#pragma once
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <logger.h>

typedef struct
{
    void (*tk_func)(void*);
    void* arg;
} CthTask;

/*  
 *  能同时工作的仅为一个线程
 *  如果线程异常，设置except为非0值
 *  初始化结构体时创建管理线程
 */
typedef struct
{
    CthTask** taskQueue;
    size_t queueSize;
    size_t queueHead;
    size_t queueTail;       //超尾
    bool queueFull;
    pthread_cond_t condQueueEmpty;
    pthread_cond_t condQueueFull;
    pthread_mutex_t queueMutex;

    pthread_t managerThread;
    
    //atomic_int except;
    bool shutdown;
    atomic_bool addTaskWorking;

    int (*task_log)(enum CTH_LOG_LEVEL logLevel, const char* msg);
    int (*task_log_err)(enum CTH_LOG_LEVEL logLevel, const char* funcName, int errCode);
} CthTaskScheduler;

/* return NULL if error */
CthTaskScheduler* cth_task_scheduler_init(bool useLogger, size_t queueSize);

/* 工作线程无需释放参数 */
int cth_task_scheduler_add(CthTaskScheduler* manager, void(*func)(void*), void* arg);

int cth_task_scheduler_destroy(CthTaskScheduler* manager);

bool cth_scheduler_queue_empty(const CthTaskScheduler* scheduler);

