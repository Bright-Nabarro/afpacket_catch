#include "signal_handle.h"

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "logger.h"

volatile bool g_recSigint = false;
int g_workSignalPipe[2];

int block_sig(PrevState* manager, int sig)
{
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, sig);
	
	if (sigprocmask(SIG_BLOCK, &mask, &manager->prevMask) < 0)
	{
		cth_log_errcode(CTH_LOG_FATAL, "sigprocmask", errno);
		return -1;
	}

	manager->olderrno = errno;

	return 0;
}

int recover_sig(PrevState* manager)
{
	errno = manager->olderrno;
	if (sigprocmask(SIG_SETMASK, &manager->prevMask, NULL) < 0)
	{
		cth_log_errcode(CTH_LOG_FATAL, "sigprocmask", errno);
		return -1;
	}
	return 0;
}

void handle_sigint(int sig)
{
	assert(sig == SIGINT);
	PrevState state;
	if (block_sig(&state, sig) < 0)
	{
		cth_log(CTH_LOG_FATAL, "block_sig error");
		//-----需要修改
		_exit(1);
		//-----
	}

	fflush(stdout);
	printf("Received signal %d\n", sig);
	g_recSigint = true;
    write(g_workSignalPipe[1], "x", 1);

	if (recover_sig(&state) < 0)
	{
		cth_log(CTH_LOG_FATAL, "recover_sig error");
		//-----需要修改
		_exit(1);
		//-----
	}
}

int initial_signal()
{
	struct sigaction sa;
	sa.sa_handler = handle_sigint;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
    pipe(g_workSignalPipe);

	if (sigaction(SIGINT, &sa, NULL) < 0)
	{
		cth_log_errcode(CTH_LOG_FATAL, "sigaction", errno);
		return -1;
	}

	return 0;
}
