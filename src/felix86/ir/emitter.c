#include "felix86/common/log.h"
#include "felix86/frontend/instruction.h"
#include "felix86/ir/emitter.h"
#include "felix86/ir/instruction.h"
#include <stddef.h>
#include <stdio.h>

ir_instruction_t* ir_emit_two_operand(ir_emitter_state_t* state, ir_opcode_e opcode, ir_instruction_t* source1, ir_instruction_t* source2) {
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = opcode;
    instruction->type = IR_TYPE_TWO_OPERAND;
    instruction->two_operand.source1 = source1;
    instruction->two_operand.source2 = source2;
    source1->uses++;
    source2->uses++;
    return instruction;
}

ir_instruction_t* ir_emit_one_operand(ir_emitter_state_t* state, ir_opcode_e opcode, ir_instruction_t* source) {
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = opcode;
    instruction->type = IR_TYPE_ONE_OPERAND;
    instruction->one_operand.source = source;
    source->uses++;
    return instruction;
}

ir_instruction_t* ir_emit_add(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2)
{
    return ir_emit_two_operand(state, IR_ADD, source1, source2);
}

ir_instruction_t* ir_emit_sub(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2)
{
    return ir_emit_two_operand(state, IR_SUB, source1, source2);
}

ir_instruction_t* ir_emit_left_shift(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2)
{
    return ir_emit_two_operand(state, IR_LEFT_SHIFT, source1, source2);
}

ir_instruction_t* ir_emit_right_shift(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2)
{
    return ir_emit_two_operand(state, IR_RIGHT_SHIFT, source1, source2);
}

ir_instruction_t* ir_emit_right_shift_arithmetic(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2)
{
    return ir_emit_two_operand(state, IR_RIGHT_SHIFT_ARITHMETIC, source1, source2);
}

ir_instruction_t* ir_emit_and(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2)
{
    return ir_emit_two_operand(state, IR_AND, source1, source2);
}

ir_instruction_t* ir_emit_or(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2)
{
    return ir_emit_two_operand(state, IR_OR, source1, source2);
}

ir_instruction_t* ir_emit_xor(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2)
{
    return ir_emit_two_operand(state, IR_XOR, source1, source2);
}

ir_instruction_t* ir_emit_equal(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2)
{
    return ir_emit_two_operand(state, IR_EQUAL, source1, source2);
}

ir_instruction_t* ir_emit_not_equal(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2)
{
    return ir_emit_two_operand(state, IR_NOT_EQUAL, source1, source2);
}

ir_instruction_t* ir_emit_greater_than_signed(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2)
{
    return ir_emit_two_operand(state, IR_GREATER_THAN_SIGNED, source1, source2);
}

ir_instruction_t* ir_emit_less_than_signed(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2)
{
    return ir_emit_two_operand(state, IR_LESS_THAN_SIGNED, source1, source2);
}

ir_instruction_t* ir_emit_greater_than_unsigned(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2)
{
    return ir_emit_two_operand(state, IR_GREATER_THAN_UNSIGNED, source1, source2);
}

ir_instruction_t* ir_emit_less_than_unsigned(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2)
{
    return ir_emit_two_operand(state, IR_LESS_THAN_UNSIGNED, source1, source2);
}

ir_instruction_t* ir_emit_lea(ir_emitter_state_t* state, ir_instruction_t* base, ir_instruction_t* index, u8 scale, u32 displacement)
{
    if (!base && !index) {
        ir_instruction_t* rip = ir_emit_get_guest(state, X86_REF_RIP);
        base = rip;
    }

    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_LEA;
    instruction->type = IR_TYPE_LEA;
    instruction->lea.base = base;
    instruction->lea.index = index;
    instruction->lea.scale = scale;
    instruction->lea.displacement = displacement;
    if (base)
        base->uses++;
    if (index)
        index->uses++;
    return instruction;
}

ir_instruction_t* ir_emit_popcount(ir_emitter_state_t* state, ir_instruction_t* source)
{
    return ir_emit_one_operand(state, IR_POPCOUNT, source);
}

ir_instruction_t* ir_emit_sext8(ir_emitter_state_t* state, ir_instruction_t* source)
{
    return ir_emit_one_operand(state, IR_SEXT8, source);
}

ir_instruction_t* ir_emit_sext16(ir_emitter_state_t* state, ir_instruction_t* source)
{
    return ir_emit_one_operand(state, IR_SEXT16, source);
}

ir_instruction_t* ir_emit_sext32(ir_emitter_state_t* state, ir_instruction_t* source)
{
    return ir_emit_one_operand(state, IR_SEXT32, source);
}

ir_instruction_t* ir_emit_get_guest(ir_emitter_state_t* state, x86_ref_t ref)
{
    if (ref == X86_REF_COUNT) {
        ERROR("Invalid register reference");
    }

    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_GET_GUEST;
    instruction->type = IR_TYPE_GET_GUEST;
    instruction->get_guest.ref = ref;
    return instruction;
}

ir_instruction_t* ir_emit_set_guest(ir_emitter_state_t* state, x86_ref_t ref, ir_instruction_t* source)
{
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_SET_GUEST;
    instruction->type = IR_TYPE_SET_GUEST;
    instruction->set_guest.ref = ref;
    instruction->set_guest.source = source;
    source->uses++;
    return instruction;
}

ir_instruction_t* ir_emit_get_flag(ir_emitter_state_t* state, x86_flag_t flag) {
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_GET_FLAG;
    instruction->type = IR_TYPE_GET_FLAG;
    instruction->get_flag.flag = flag;
    return instruction;
}

ir_instruction_t* ir_emit_set_flag(ir_emitter_state_t* state, x86_flag_t flag, ir_instruction_t* source) {
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_SET_FLAG;
    instruction->type = IR_TYPE_SET_FLAG;
    instruction->set_flag.flag = flag;
    instruction->set_flag.source = source;
    source->uses++;
    return instruction;
}

ir_instruction_t* ir_emit_read_byte(ir_emitter_state_t* state, ir_instruction_t* address)
{
    return ir_emit_one_operand(state, IR_READ_BYTE, address);
}

ir_instruction_t* ir_emit_read_word(ir_emitter_state_t* state, ir_instruction_t* address)
{
    return ir_emit_one_operand(state, IR_READ_WORD, address);
}

ir_instruction_t* ir_emit_read_dword(ir_emitter_state_t* state, ir_instruction_t* address)
{
    return ir_emit_one_operand(state, IR_READ_DWORD, address);
}

ir_instruction_t* ir_emit_read_qword(ir_emitter_state_t* state, ir_instruction_t* address)
{
    return ir_emit_one_operand(state, IR_READ_QWORD, address);
}

ir_instruction_t* ir_emit_write_byte(ir_emitter_state_t* state, ir_instruction_t* address, ir_instruction_t* source)
{
    return ir_emit_two_operand(state, IR_WRITE_BYTE, address, source);
}

ir_instruction_t* ir_emit_write_word(ir_emitter_state_t* state, ir_instruction_t* address, ir_instruction_t* source)
{
    return ir_emit_two_operand(state, IR_WRITE_WORD, address, source);
}

ir_instruction_t* ir_emit_write_dword(ir_emitter_state_t* state, ir_instruction_t* address, ir_instruction_t* source)
{
    return ir_emit_two_operand(state, IR_WRITE_DWORD, address, source);
}

ir_instruction_t* ir_emit_write_qword(ir_emitter_state_t* state, ir_instruction_t* address, ir_instruction_t* source)
{
    return ir_emit_two_operand(state, IR_WRITE_QWORD, address, source);
}

ir_instruction_t* ir_emit_immediate(ir_emitter_state_t* state, u64 value)
{
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_IMMEDIATE;
    instruction->type = IR_TYPE_LOAD_IMMEDIATE;
    instruction->load_immediate.immediate = value;
    return instruction;
}

// ██   ██ ███████ ██      ██████  ███████ ██████  ███████
// ██   ██ ██      ██      ██   ██ ██      ██   ██ ██     
// ███████ █████   ██      ██████  █████   ██████  ███████
// ██   ██ ██      ██      ██      ██      ██   ██      ██
// ██   ██ ███████ ███████ ██      ███████ ██   ██ ███████

ir_instruction_t* ir_emit_get_reg(ir_emitter_state_t* state, x86_operand_t* reg_operand)
{
    switch (reg_operand->reg.size) {
        case BYTE_LOW: return ir_emit_get_gpr8_low(state, reg_operand->reg.ref);
        case BYTE_HIGH: return ir_emit_get_gpr8_high(state, reg_operand->reg.ref);
        case WORD: return ir_emit_get_gpr16(state, reg_operand->reg.ref);
        case DWORD: return ir_emit_get_gpr32(state, reg_operand->reg.ref);
        case QWORD: return ir_emit_get_gpr64(state, reg_operand->reg.ref);
    }
}

ir_instruction_t* ir_emit_get_rm(ir_emitter_state_t* state, x86_prefixes_t* prefixes, x86_operand_t* rm_operand)
{
    if (rm_operand->type == X86_OP_TYPE_REGISTER) {
        return ir_emit_get_reg(state, rm_operand);
    } else {
        ir_instruction_t* (*get_guest)(ir_emitter_state_t* state, x86_ref_t reg) = prefixes->address_override ? ir_emit_get_gpr32 : ir_emit_get_gpr64;
        ir_instruction_t* base = rm_operand->memory.base != X86_REF_COUNT ? get_guest(state, rm_operand->memory.base) : NULL;
        ir_instruction_t* index = rm_operand->memory.index != X86_REF_COUNT ? get_guest(state, rm_operand->memory.index) : NULL;
        ir_instruction_t* address = ir_emit_lea(state, base, index, rm_operand->memory.scale, rm_operand->memory.displacement);
        ir_instruction_t* final_address = address;

        if (prefixes->address_override) {
            ir_instruction_t* mask = ir_emit_immediate(state, 0xFFFFFFFF);
            final_address = ir_emit_and(state, address, mask);
        }

        return ir_emit_read_memory(state, prefixes, final_address);
    }
}

ir_instruction_t* ir_emit_set_reg(ir_emitter_state_t* state, x86_operand_t* reg_operand, ir_instruction_t* source)
{
    switch (reg_operand->reg.size) {
        case BYTE_LOW: return ir_emit_set_gpr8_low(state, reg_operand->reg.ref, source);
        case BYTE_HIGH: return ir_emit_set_gpr8_high(state, reg_operand->reg.ref, source);
        case WORD: return ir_emit_set_gpr16(state, reg_operand->reg.ref, source);
        case DWORD: return ir_emit_set_gpr32(state, reg_operand->reg.ref, source);
        case QWORD: return ir_emit_set_gpr64(state, reg_operand->reg.ref, source);
    }
}

ir_instruction_t* ir_emit_set_rm(ir_emitter_state_t* state, x86_prefixes_t* prefixes, x86_operand_t* rm_operand, ir_instruction_t* source)
{
    if (rm_operand->type == X86_OP_TYPE_REGISTER) {
        return ir_emit_set_reg(state, rm_operand, source);
    } else {
        ir_instruction_t* (*get_guest)(ir_emitter_state_t* state, x86_ref_t reg) = prefixes->address_override ? ir_emit_get_gpr32 : ir_emit_get_gpr64;
        ir_instruction_t* base = rm_operand->memory.base != X86_REF_COUNT ? get_guest(state, rm_operand->memory.base) : NULL;
        ir_instruction_t* index = rm_operand->memory.index != X86_REF_COUNT ? get_guest(state, rm_operand->memory.index) : NULL;
        ir_instruction_t* address = ir_emit_lea(state, base, index, rm_operand->memory.scale, rm_operand->memory.displacement);
        ir_instruction_t* final_address = address;

        if (prefixes->address_override) {
            ir_instruction_t* mask = ir_emit_immediate(state, 0xFFFFFFFF);
            final_address = ir_emit_and(state, address, mask);
        }

        return ir_emit_write_memory(state, prefixes, final_address, source);
    }
}

ir_instruction_t* ir_emit_write_memory(ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* address, ir_instruction_t* value)
{
    if (prefixes->byte_override) {
        return ir_emit_write_byte(state, address, value);
    } else if (prefixes->rex_w) {
        return ir_emit_write_qword(state, address, value);
    } else if (prefixes->operand_override) {
        return ir_emit_write_word(state, address, value);
    } else {
        return ir_emit_write_dword(state, address, value);
    }
}

ir_instruction_t* ir_emit_read_memory(ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* address)
{
    if (prefixes->byte_override) {
        return ir_emit_read_byte(state, address);
    } else if (prefixes->rex_w) {
        return ir_emit_read_qword(state, address);
    } else if (prefixes->operand_override) {
        return ir_emit_read_word(state, address);
    } else {
        return ir_emit_read_dword(state, address);
    }
}

ir_instruction_t* ir_emit_get_gpr8_low(ir_emitter_state_t* state, x86_ref_t reg)
{
    ir_instruction_t* full_reg = ir_emit_get_guest(state, reg);
    ir_instruction_t* mask = ir_emit_immediate(state, 0xFF);
    ir_instruction_t* instruction = ir_emit_and(state, full_reg, mask);

    return instruction;
}

ir_instruction_t* ir_emit_get_gpr8_high(ir_emitter_state_t* state, x86_ref_t reg)
{
    ir_instruction_t* full_reg = ir_emit_get_guest(state, reg);
    ir_instruction_t* shift = ir_emit_immediate(state, 8);
    ir_instruction_t* shifted = ir_emit_right_shift(state, full_reg, shift);
    ir_instruction_t* mask = ir_emit_immediate(state, 0xFF);
    ir_instruction_t* instruction = ir_emit_and(state, shifted, mask);

    return instruction;
}

ir_instruction_t* ir_emit_get_gpr16(ir_emitter_state_t* state, x86_ref_t reg)
{
    ir_instruction_t* full_reg = ir_emit_get_guest(state, reg);
    ir_instruction_t* mask = ir_emit_immediate(state, 0xFFFF);
    ir_instruction_t* instruction = ir_emit_and(state, full_reg, mask);

    return instruction;
}

ir_instruction_t* ir_emit_get_gpr32(ir_emitter_state_t* state, x86_ref_t reg)
{
    ir_instruction_t* full_reg = ir_emit_get_guest(state, reg);
    ir_instruction_t* mask = ir_emit_immediate(state, 0xFFFFFFFF);
    ir_instruction_t* instruction = ir_emit_and(state, full_reg, mask);

    return instruction;
}

ir_instruction_t* ir_emit_get_gpr64(ir_emitter_state_t* state, x86_ref_t reg)
{
    ir_instruction_t* instruction = ir_emit_get_guest(state, reg);

    return instruction;
}

ir_instruction_t* ir_emit_set_gpr8_low(ir_emitter_state_t* state, x86_ref_t reg, ir_instruction_t* source)
{
    ir_instruction_t* full_reg = ir_emit_get_guest(state, reg);
    ir_instruction_t* mask = ir_emit_immediate(state, 0xFFFFFFFFFFFFFF00);
    ir_instruction_t* masked = ir_emit_and(state, full_reg, mask);
    ir_instruction_t* value_mask = ir_emit_immediate(state, 0xFF);
    ir_instruction_t* value = ir_emit_and(state, source, value_mask);
    ir_instruction_t* final_value = ir_emit_or(state, masked, value);
    ir_instruction_t* instruction = ir_emit_set_guest(state, reg, final_value);

    return instruction;
}

ir_instruction_t* ir_emit_set_gpr8_high(ir_emitter_state_t* state, x86_ref_t reg, ir_instruction_t* source)
{
    ir_instruction_t* full_reg = ir_emit_get_guest(state, reg);
    ir_instruction_t* mask = ir_emit_immediate(state, 0xFFFFFFFFFFFF00FF);
    ir_instruction_t* masked = ir_emit_and(state, full_reg, mask);
    ir_instruction_t* value_mask = ir_emit_immediate(state, 0xFF);
    ir_instruction_t* value = ir_emit_and(state, source, value_mask);
    ir_instruction_t* shift = ir_emit_immediate(state, 8);
    ir_instruction_t* shifted = ir_emit_left_shift(state, value, shift);
    ir_instruction_t* final_value = ir_emit_or(state, masked, shifted);
    ir_instruction_t* instruction = ir_emit_set_guest(state, reg, final_value);

    return instruction;
}

ir_instruction_t* ir_emit_set_gpr16(ir_emitter_state_t* state, x86_ref_t reg, ir_instruction_t* source)
{
    ir_instruction_t* full_reg = ir_emit_get_guest(state, reg);
    ir_instruction_t* mask = ir_emit_immediate(state, 0xFFFFFFFFFFFF0000);
    ir_instruction_t* masked = ir_emit_and(state, full_reg, mask);
    ir_instruction_t* value_mask = ir_emit_immediate(state, 0xFFFF);
    ir_instruction_t* value = ir_emit_and(state, source, value_mask);
    ir_instruction_t* final_value = ir_emit_or(state, masked, value);
    ir_instruction_t* instruction = ir_emit_set_guest(state, reg, final_value);

    return instruction;
}

ir_instruction_t* ir_emit_set_gpr32(ir_emitter_state_t* state, x86_ref_t reg, ir_instruction_t* source)
{
    ir_instruction_t* value_mask = ir_emit_immediate(state, 0xFFFFFFFF);
    ir_instruction_t* final_value = ir_emit_and(state, source, value_mask);
    ir_instruction_t* instruction = ir_emit_set_guest(state, reg, final_value);

    return instruction;
}

ir_instruction_t* ir_emit_set_gpr64(ir_emitter_state_t* state, x86_ref_t reg, ir_instruction_t* source)
{
    ir_instruction_t* instruction = ir_emit_set_guest(state, reg, source);

    return instruction;
}

ir_instruction_t* ir_emit_get_parity(ir_emitter_state_t* state, ir_instruction_t* source)
{
    ir_instruction_t* mask = ir_emit_immediate(state, 0xFF);
    ir_instruction_t* masked = ir_emit_and(state, source, mask);
    ir_instruction_t* popcount = ir_emit_popcount(state, masked);
    ir_instruction_t* one = ir_emit_immediate(state, 1);
    ir_instruction_t* result = ir_emit_and(state, popcount, one);
    ir_instruction_t* instruction = ir_emit_xor(state, result, one);

    return instruction;
}

ir_instruction_t* ir_emit_get_zero(ir_emitter_state_t* state, ir_instruction_t* source)
{
    ir_instruction_t* zero = ir_emit_immediate(state, 0);
    ir_instruction_t* instruction = ir_emit_equal(state, source, zero);

    return instruction;
}

ir_instruction_t* ir_emit_get_sign_mask(ir_emitter_state_t* state, x86_prefixes_t* prefixes)
{
    if (prefixes->byte_override) {
        return ir_emit_immediate(state, 1ull << 7);
    } else if (prefixes->rex_w) {
        return ir_emit_immediate(state, 1ull << 63);
    } else if (prefixes->operand_override) {
        return ir_emit_immediate(state, 1ull << 15);
    } else {
        return ir_emit_immediate(state, 1ull << 31);
    }
}

ir_instruction_t* ir_emit_get_mask(ir_emitter_state_t* state, x86_prefixes_t* prefixes)
{
    if (prefixes->byte_override) {
        return ir_emit_immediate(state, 0xFF);
    } else if (prefixes->rex_w) {
        return ir_emit_immediate(state, 0xFFFFFFFFFFFFFFFF);
    } else if (prefixes->operand_override) {
        return ir_emit_immediate(state, 0xFFFF);
    } else {
        return ir_emit_immediate(state, 0xFFFFFFFF);
    }
}

ir_instruction_t* ir_emit_get_sign(ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* source)
{
    ir_instruction_t* mask = ir_emit_get_sign_mask(state, prefixes);
    ir_instruction_t* masked = ir_emit_and(state, source, mask);
    ir_instruction_t* instruction = ir_emit_equal(state, masked, mask);

    return instruction;
}

ir_instruction_t* ir_emit_get_overflow_add(ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* source1, ir_instruction_t* source2, ir_instruction_t* result)
{
    ir_instruction_t* mask = ir_emit_get_sign_mask(state, prefixes);

    // for x + y = z, overflow occurs if ((z ^ x) & (z ^ y) & mask) == mask
    // which essentially checks if the sign bits of x and y are equal, but the sign bit of z is different
    ir_instruction_t* xor1 = ir_emit_xor(state, result, source1);
    ir_instruction_t* xor2 = ir_emit_xor(state, result, source2);
    ir_instruction_t* and = ir_emit_and(state, xor1, xor2);
    ir_instruction_t* masked = ir_emit_and(state, and, mask);

    return ir_emit_equal(state, masked, mask);
}

ir_instruction_t* ir_emit_get_overflow_sub(ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* source1, ir_instruction_t* source2, ir_instruction_t* result)
{
    ir_instruction_t* mask = ir_emit_get_sign_mask(state, prefixes);

    // for x - y = z, overflow occurs if ((x ^ y) & (x ^ z) & mask) == mask
    ir_instruction_t* xor1 = ir_emit_xor(state, source1, source2);
    ir_instruction_t* xor2 = ir_emit_xor(state, source1, result);
    ir_instruction_t* and = ir_emit_and(state, xor1, xor2);
    ir_instruction_t* masked = ir_emit_and(state, and, mask);

    return ir_emit_equal(state, masked, mask);
}

ir_instruction_t* ir_emit_get_carry_add(ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* source1, ir_instruction_t* source2, ir_instruction_t* result)
{
    (void)source2; // dont need, just keeping for consistency

    // CF = result < source1, as that means that the result overflowed
    ir_instruction_t* mask = ir_emit_get_mask(state, prefixes);
    ir_instruction_t* masked_result = ir_emit_and(state, result, mask);
    return ir_emit_less_than_unsigned(state, masked_result, source1);
}

ir_instruction_t* ir_emit_get_carry_sub(ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* source1, ir_instruction_t* source2, ir_instruction_t* result)
{
    (void)result; // dont need, just keeping for consistency
    (void)prefixes;

    // CF = source1 < source2, as that means that the result would underflow
    return ir_emit_less_than_unsigned(state, source1, source2);
}

ir_instruction_t* ir_emit_get_aux_add(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2)
{
    ir_instruction_t* mask = ir_emit_immediate(state, 0xF);
    ir_instruction_t* and1 = ir_emit_and(state, source1, mask);
    ir_instruction_t* and2 = ir_emit_and(state, source2, mask);
    ir_instruction_t* result = ir_emit_add(state, and1, and2);

    return ir_emit_greater_than_unsigned(state, result, mask);
}

ir_instruction_t* ir_emit_get_aux_sub(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2)
{
    ir_instruction_t* mask = ir_emit_immediate(state, 0xF);
    ir_instruction_t* and1 = ir_emit_and(state, source1, mask);
    ir_instruction_t* and2 = ir_emit_and(state, source2, mask);

    return ir_emit_less_than_unsigned(state, and1, and2);
}

ir_instruction_t* ir_emit_set_cpazso(ir_emitter_state_t* state, ir_instruction_t* c, ir_instruction_t* p, ir_instruction_t* a, ir_instruction_t* z, ir_instruction_t* s, ir_instruction_t* o)
{
    if (c) ir_emit_set_flag(state, X86_FLAG_CF, c);
    if (p) ir_emit_set_flag(state, X86_FLAG_PF, p);
    if (a) ir_emit_set_flag(state, X86_FLAG_AF, a);
    if (z) ir_emit_set_flag(state, X86_FLAG_ZF, z);
    if (s) ir_emit_set_flag(state, X86_FLAG_SF, s);
    if (o) ir_emit_set_flag(state, X86_FLAG_OF, o);

    return NULL;
}

