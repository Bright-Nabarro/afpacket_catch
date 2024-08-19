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

int cth_log(enum CTH_LOG_LEVEL logLevel, const char* msg);
int cth_log_digit(enum CTH_LOG_LEVEL logLevel, const char* fmt, int digit);
int cth_log_str(enum CTH_LOG_LEVEL logLevel, const char* fmt, const char* msg);
int cth_log_errcode(enum CTH_LOG_LEVEL logLevel, const char* funcName, int errcode);
int cth_log_errmsg(enum CTH_LOG_LEVEL logLevel, const char* funcName, const char* msg);

const char* log_level_to_string(enum CTH_LOG_LEVEL logLevel);


