#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/frontend/instruction.h"
#include "felix86/ir/emitter.h"

typedef void (*ir_handle_fn_t)(ir_emitter_state_t* state, x86_instruction_t* inst);

#define X(opcode, name, modrm, immsize) void ir_handle_##name(ir_emitter_state_t* state, x86_instruction_t* inst);
#include "felix86/frontend/primary.inc"
#include "felix86/frontend/secondary.inc"
#undef X

#ifdef __cplusplus
}
#endif