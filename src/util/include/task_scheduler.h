#pragma once
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>


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
    bool useLogger;

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
} CthTaskScheduler;

/* return NULL if error */
CthTaskScheduler* cth_task_scheduler_init(bool useLogger, size_t queueSize);

int cth_task_scheduler_add(CthTaskScheduler* manager, void(*func)(void*), void* arg);

int cth_task_scheduler_destroy(CthTaskScheduler* manager);

bool cth_scheduler_queue_empty(const CthTaskScheduler* scheduler);
