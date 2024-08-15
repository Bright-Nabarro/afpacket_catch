#pragma once
#include <stdarg.h>

enum CTH_LOG_LEVEL{
	CTH_LOG_INFO = 0,
	CTH_LOG_STATUS,
	CTH_LOG_WARNING,
	CTH_LOG_ERROR,
	CTH_LOG_FATAL
};

int cth_log_init();
void cth_log_close();

void cth_log(enum CTH_LOG_LEVEL logLevel, const char* fmt, ...);

void cth_log_err(enum CTH_LOG_LEVEL logLevel, const char* msg, int errcode);

const char* log_level_to_string(enum CTH_LOG_LEVEL logLevel);

