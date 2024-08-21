#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/ir/emitter.h"

void frontend_compile_block(ir_emitter_state_t* state);

#ifdef __cplusplus
}
#endif