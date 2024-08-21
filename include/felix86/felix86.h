#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/frontend/instruction.h"

typedef struct {
    bool testing;
} felix86_recompiler_config_t;

typedef enum {
    OutOfCycles,
} felix86_exit_reason_e;

typedef struct felix86_recompiler_s felix86_recompiler_t;

felix86_recompiler_t* felix86_recompiler_create(felix86_recompiler_config_t* config);
void felix86_recompiler_destroy(felix86_recompiler_t* recompiler);
u64 felix86_get_guest(felix86_recompiler_t* recompiler, x86_ref_t ref);
void felix86_set_guest(felix86_recompiler_t* recompiler, x86_ref_t ref, u64 value);
felix86_exit_reason_e felix86_recompiler_run(felix86_recompiler_t* recompiler, u64 cycles);


#ifdef __cplusplus
}
#endif