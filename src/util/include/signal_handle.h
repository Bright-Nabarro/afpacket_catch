#pragma once
#include <stdbool.h>
#include <sys/types.h>

extern volatile bool g_recSigint;


typedef struct PrevState_
{
	int olderrno;
	sigset_t prevMask;

} PrevState;

int initial_signal();

int block_sig(PrevState* manager, int sig);
int recover_sig(PrevState* manager);

void handle_sigint(int sig);


