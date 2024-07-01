#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/common/utility.h"
#include "felix86/frontend/instruction.h"
#include "felix86/ir/block.h"
#include "felix86/ir/instruction.h"

typedef struct {
    ir_block_t* block;
    u64 current_address;
    bool exit;
} ir_emitter_state_t;

ir_instruction_t* ir_emit_add(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_sub(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_left_shift(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_right_shift(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_right_shift_arithmetic(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_and(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_or(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_xor(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_popcount(ir_emitter_state_t* state, ir_instruction_t* source);
ir_instruction_t* ir_emit_equal(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_not_equal(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_greater_than(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_sext8(ir_emitter_state_t* state, ir_instruction_t* source);
ir_instruction_t* ir_emit_sext16(ir_emitter_state_t* state, ir_instruction_t* source);
ir_instruction_t* ir_emit_sext32(ir_emitter_state_t* state, ir_instruction_t* source);

ir_instruction_t* ir_emit_get_guest(ir_emitter_state_t* state, x86_ref_t ref);
ir_instruction_t* ir_emit_set_guest(ir_emitter_state_t* state, x86_ref_t ref, ir_instruction_t* source);
ir_instruction_t* ir_emit_get_flag(ir_emitter_state_t* state, x86_flag_t flag);
ir_instruction_t* ir_emit_set_flag(ir_emitter_state_t* state, x86_flag_t flag, ir_instruction_t* source);

ir_instruction_t* ir_emit_read_byte(ir_emitter_state_t* state, ir_instruction_t* address);
ir_instruction_t* ir_emit_read_word(ir_emitter_state_t* state, ir_instruction_t* address);
ir_instruction_t* ir_emit_read_dword(ir_emitter_state_t* state, ir_instruction_t* address);
ir_instruction_t* ir_emit_read_qword(ir_emitter_state_t* state, ir_instruction_t* address);
ir_instruction_t* ir_emit_write_byte(ir_emitter_state_t* state, ir_instruction_t* address, ir_instruction_t* source);
ir_instruction_t* ir_emit_write_word(ir_emitter_state_t* state, ir_instruction_t* address, ir_instruction_t* source);
ir_instruction_t* ir_emit_write_dword(ir_emitter_state_t* state, ir_instruction_t* address, ir_instruction_t* source);
ir_instruction_t* ir_emit_write_qword(ir_emitter_state_t* state, ir_instruction_t* address, ir_instruction_t* source);

// Helpers
ir_instruction_t* ir_emit_immediate(ir_emitter_state_t* state, u64 value);

ir_instruction_t* ir_emit_get_reg8(ir_emitter_state_t* state, x86_prefixes_t* prefixes, x86_operand_t* reg_operand);
ir_instruction_t* ir_emit_get_rm8(ir_emitter_state_t* state, x86_prefixes_t* prefixes, x86_operand_t* rm_operand);
ir_instruction_t* ir_emit_get_reg(ir_emitter_state_t* state, x86_prefixes_t* prefixes, x86_operand_t* reg_operand);
ir_instruction_t* ir_emit_get_rm(ir_emitter_state_t* state, x86_prefixes_t* prefixes, x86_operand_t* rm_operand);

ir_instruction_t* ir_emit_set_reg8(ir_emitter_state_t* state, x86_prefixes_t* prefixes, x86_operand_t* reg_operand, ir_instruction_t* source);
ir_instruction_t* ir_emit_set_rm8(ir_emitter_state_t* state, x86_prefixes_t* prefixes, x86_operand_t* rm_operand, ir_instruction_t* source);
ir_instruction_t* ir_emit_set_reg(ir_emitter_state_t* state, x86_prefixes_t* prefixes, x86_operand_t* reg_operand, ir_instruction_t* source);
ir_instruction_t* ir_emit_set_rm(ir_emitter_state_t* state, x86_prefixes_t* prefixes, x86_operand_t* rm_operand, ir_instruction_t* source);

ir_instruction_t* ir_emit_get_gpr8_low(ir_emitter_state_t* state, x86_ref_t reg);
ir_instruction_t* ir_emit_get_gpr8_high(ir_emitter_state_t* state, x86_ref_t reg);
ir_instruction_t* ir_emit_get_gpr16(ir_emitter_state_t* state, x86_ref_t reg);
ir_instruction_t* ir_emit_get_gpr32(ir_emitter_state_t* state, x86_ref_t reg);
ir_instruction_t* ir_emit_get_gpr64(ir_emitter_state_t* state, x86_ref_t reg);
ir_instruction_t* ir_emit_set_gpr8_low(ir_emitter_state_t* state, x86_ref_t reg, ir_instruction_t* source);
ir_instruction_t* ir_emit_set_gpr8_high(ir_emitter_state_t* state, x86_ref_t reg, ir_instruction_t* source);
ir_instruction_t* ir_emit_set_gpr16(ir_emitter_state_t* state, x86_ref_t reg, ir_instruction_t* source);
ir_instruction_t* ir_emit_set_gpr32(ir_emitter_state_t* state, x86_ref_t reg, ir_instruction_t* source);
ir_instruction_t* ir_emit_set_gpr64(ir_emitter_state_t* state, x86_ref_t reg, ir_instruction_t* source);

ir_instruction_t* ir_emit_get_parity(ir_emitter_state_t* state, ir_instruction_t* source);
ir_instruction_t* ir_emit_get_zero(ir_emitter_state_t* state, ir_instruction_t* source);

ir_instruction_t* ir_emit_set_cpazso(ir_emitter_state_t* state, ir_instruction_t* c, ir_instruction_t* p, ir_instruction_t* a, ir_instruction_t* z, ir_instruction_t* s, ir_instruction_t* o);

#ifdef __cplusplus
}
#endif