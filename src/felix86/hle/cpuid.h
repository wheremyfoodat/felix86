#pragma once

#include "felix86/felix86.h"

#ifdef __cplusplus
extern "C" {
#endif

void felix86_cpuid(x86_thread_state_t* state);

#ifdef __cplusplus
}
#endif