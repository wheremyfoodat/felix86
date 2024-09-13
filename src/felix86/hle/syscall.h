#pragma once

#include "felix86/felix86.h"

#ifdef __cplusplus
extern "C" {
#endif

void felix86_syscall(felix86_recompiler_t* recompiler, x86_thread_state_t* state);

#ifdef __cplusplus
}
#endif
