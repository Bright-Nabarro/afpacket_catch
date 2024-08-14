#include "logger.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "queue.h"

typedef struct LogEntry
{
    char* msgBuf;
    size_t msgLen;
    STAILQ_ENTRY(LogEntry) entries;
} LogEntry;

STAILQ_HEAD(LogEntryHead, LogEntry);

typedef struct
{
    struct LogEntryHead* p_head;
} LogQueArgs;


int cth_log_init()
{
	return 0;
}

void cth_log_close()
{
    
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
	va_start(args, fmt);

	printf("[%s]  ", log_level_to_string(logLevel));
	vprintf(fmt, args);
	printf("\n");

	va_end(args);
}

void cth_log_err(enum CTH_LOG_LEVEL logLevel, const char* msg)
{
	cth_log(logLevel, "%s error: %s", msg, strerror(errno));
}

