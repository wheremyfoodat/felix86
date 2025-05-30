#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include "common.h"

volatile int you_can_leave = 0;

void signal_handler(int sig, siginfo_t* info, void* ucontext) {
    printf("Alarm hit\n");
    you_can_leave = 1;
}

int main() {
    struct sigaction act;
    act.sa_sigaction = signal_handler;
    act.sa_flags = SA_SIGINFO;
    sigemptyset(&act.sa_mask);
    sigaction(SIGALRM, &act, 0);

    alarm(1);

    while (!you_can_leave) {
    }

    return FELIX86_BTEST_SUCCESS;
}