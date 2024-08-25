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
	u8 current_instruction_length;
	bool exit;
	bool testing;
	bool debug_info;
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
ir_instruction_t* ir_emit_greater_than_signed(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_less_than_signed(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_greater_than_unsigned(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_less_than_unsigned(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_lea(ir_emitter_state_t* state, x86_prefixes_t* prefixes, x86_operand_t* rm_operand);
ir_instruction_t* ir_emit_sext8(ir_emitter_state_t* state, ir_instruction_t* source);
ir_instruction_t* ir_emit_sext16(ir_emitter_state_t* state, ir_instruction_t* source);
ir_instruction_t* ir_emit_sext32(ir_emitter_state_t* state, ir_instruction_t* source);
ir_instruction_t* ir_emit_syscall(ir_emitter_state_t* state);
ir_instruction_t* ir_emit_ternary(
	ir_emitter_state_t* state, ir_instruction_t* condition, ir_instruction_t* true_value, ir_instruction_t* false_value
);
ir_instruction_t* ir_emit_insert_integer_to_vector(
	ir_emitter_state_t* state, ir_instruction_t* vector_dest, ir_instruction_t* source, u8 size, u8 index
);
ir_instruction_t* ir_emit_extract_integer_from_vector(ir_emitter_state_t* state, ir_instruction_t* vector_src, u8 size, u8 index);

ir_instruction_t* ir_emit_get_guest(ir_emitter_state_t* state, x86_ref_e ref);
ir_instruction_t* ir_emit_set_guest(ir_emitter_state_t* state, x86_ref_e ref, ir_instruction_t* source);
ir_instruction_t* ir_emit_get_flag(ir_emitter_state_t* state, x86_flag_e flag);
ir_instruction_t* ir_emit_set_flag(ir_emitter_state_t* state, x86_flag_e flag, ir_instruction_t* source);
ir_instruction_t* ir_emit_get_flag_not(ir_emitter_state_t* state, x86_flag_e flag);

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
ir_instruction_t* ir_emit_immediate_sext(ir_emitter_state_t* state, x86_operand_t* operand);

ir_instruction_t* ir_emit_get_reg(ir_emitter_state_t* state, x86_operand_t* reg_operand);
ir_instruction_t* ir_emit_get_rm(ir_emitter_state_t* state, x86_prefixes_t* prefixes, x86_operand_t* rm_operand);
ir_instruction_t* ir_emit_set_reg(ir_emitter_state_t* state, x86_operand_t* reg_operand, ir_instruction_t* source);
ir_instruction_t* ir_emit_set_rm(ir_emitter_state_t* state, x86_prefixes_t* prefixes, x86_operand_t* rm_operand, ir_instruction_t* source);

ir_instruction_t* ir_emit_write_memory(ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* address, ir_instruction_t* value);
ir_instruction_t* ir_emit_read_memory(ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* address);

ir_instruction_t* ir_emit_get_gpr8_low(ir_emitter_state_t* state, x86_ref_e reg);
ir_instruction_t* ir_emit_get_gpr8_high(ir_emitter_state_t* state, x86_ref_e reg);
ir_instruction_t* ir_emit_get_gpr16(ir_emitter_state_t* state, x86_ref_e reg);
ir_instruction_t* ir_emit_get_gpr32(ir_emitter_state_t* state, x86_ref_e reg);
ir_instruction_t* ir_emit_get_gpr64(ir_emitter_state_t* state, x86_ref_e reg);
ir_instruction_t* ir_emit_get_vector(ir_emitter_state_t* state, x86_ref_e reg);
ir_instruction_t* ir_emit_set_gpr8_low(ir_emitter_state_t* state, x86_ref_e reg, ir_instruction_t* source);
ir_instruction_t* ir_emit_set_gpr8_high(ir_emitter_state_t* state, x86_ref_e reg, ir_instruction_t* source);
ir_instruction_t* ir_emit_set_gpr16(ir_emitter_state_t* state, x86_ref_e reg, ir_instruction_t* source);
ir_instruction_t* ir_emit_set_gpr32(ir_emitter_state_t* state, x86_ref_e reg, ir_instruction_t* source);
ir_instruction_t* ir_emit_set_gpr64(ir_emitter_state_t* state, x86_ref_e reg, ir_instruction_t* source);
ir_instruction_t* ir_emit_set_vector(ir_emitter_state_t* state, x86_ref_e reg, ir_instruction_t* source);

ir_instruction_t* ir_emit_get_parity(ir_emitter_state_t* state, ir_instruction_t* source);
ir_instruction_t* ir_emit_get_zero(ir_emitter_state_t* sta32te, ir_instruction_t* source);
ir_instruction_t* ir_emit_get_sign(ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* source);
ir_instruction_t* ir_emit_get_overflow_add(
	ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* source1, ir_instruction_t* source2, ir_instruction_t* result
);
ir_instruction_t* ir_emit_get_overflow_sub(
	ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* source1, ir_instruction_t* source2, ir_instruction_t* result
);
ir_instruction_t* ir_emit_get_carry_add(
	ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* source1, ir_instruction_t* source2, ir_instruction_t* result
);
ir_instruction_t* ir_emit_get_carry_adc(ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_get_carry_sub(
	ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* source1, ir_instruction_t* source2, ir_instruction_t* result
);
ir_instruction_t* ir_emit_get_carry_sbb(ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_get_aux_add(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2);
ir_instruction_t* ir_emit_get_aux_sub(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2);

// masks 16 bit elements in a up to 512-bit vector register
// the mask has 32 bits, one for each 16-bit element
ir_instruction_t* ir_emit_vector_mask_elements(ir_emitter_state_t* state, ir_instruction_t* vector, u32 mask);

ir_instruction_t* ir_emit_set_cpazso(
	ir_emitter_state_t* state, ir_instruction_t* c, ir_instruction_t* p, ir_instruction_t* a, ir_instruction_t* z, ir_instruction_t* s,
	ir_instruction_t* o
);

ir_instruction_t* ir_emit_debug_info_compile_time(ir_emitter_state_t* state, const char* format, ...);

void ir_emit_group1_imm(ir_emitter_state_t* state, x86_instruction_t* inst);
void ir_emit_jcc(ir_emitter_state_t* state, u8 inst_length, ir_instruction_t* imm, ir_instruction_t* condition);

#ifdef __cplusplus
}
#endif