#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/frontend/instruction.h"
#include "felix86/frontend/frontend.h"

typedef void (*ir_handle_fn_t)(frontend_state_t* state, x86_instruction_t* inst);

#define X(opcode, name, modrm, immsize) void ir_handle_##name(frontend_state_t* state, x86_instruction_t* inst);
#include "felix86/frontend/primary.inc"
#undef X

#define X(opcode, name, name_66, name_f2, name_f3, modrm, immsize) void ir_handle_##name(frontend_state_t* state, x86_instruction_t* inst); \
void ir_handle_##name_66(frontend_state_t* state, x86_instruction_t* inst); \
void ir_handle_##name_f2(frontend_state_t* state, x86_instruction_t* inst); \
void ir_handle_##name_f3(frontend_state_t* state, x86_instruction_t* inst);
#include "felix86/frontend/secondary.inc"
#undef X

#ifdef __cplusplus
}
#endif