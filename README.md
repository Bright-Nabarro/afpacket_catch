
# 待处理遗留
1. 信号处理函数出错只是简单退出
2. `task_scheduler.c`中，如果错误处理函数中再次出错只是简单退出
3. `task_scheduler.c`所有线程的回调函数中, 如果出错只是简单退出
4. `task_scheduler.h: cth_task_scheduler_add`中, 需要手动创建线程, 消耗性能
5. 大多数错误处理过于相似，需要抽象
6. `task_scheduler`的特殊日志机制需要避免 CTH_LOG_... 多次在不同模块定义
7. 没有内存分配失败的应对措施
8. `task_scheduler`为区分不同的Log输出引入了运行时开销
9. 将`log`使用的`configure`和`后台队列`隔离出来
10. 线程函数的`pthread_sigmask`错误输出不统一，与`9.`有关


