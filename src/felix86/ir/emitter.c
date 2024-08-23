#include "felix86/common/log.h"
#include "felix86/frontend/instruction.h"
#include "felix86/ir/emitter.h"
#include "felix86/ir/instruction.h"
#include <stdarg.h>
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

ir_instruction_t* ir_emit_lea(ir_emitter_state_t* state, x86_prefixes_t* prefixes, x86_operand_t* rm_operand)
{
    u8 scale = rm_operand->memory.scale;
    ir_instruction_t* (*get_guest)(ir_emitter_state_t* state, x86_ref_e reg) = prefixes->address_override ? ir_emit_get_gpr32 : ir_emit_get_gpr64;

    ir_instruction_t* base;
    if (rm_operand->memory.base == X86_REF_RIP) {
        ir_instruction_t* rip = ir_emit_get_guest(state, X86_REF_RIP);
        u64 offsetWithinBlock = (state->current_address - state->block->start_address) + state->current_instruction_length;
        ir_instruction_t* offset = ir_emit_immediate(state, offsetWithinBlock);
        ir_instruction_t* currentRip = ir_emit_add(state, rip, offset);
        base = currentRip;
    } else {
        base = rm_operand->memory.base != X86_REF_COUNT ? get_guest(state, rm_operand->memory.base) : NULL;
    }

    ir_instruction_t* index = rm_operand->memory.index != X86_REF_COUNT ? get_guest(state, rm_operand->memory.index) : NULL;
    ir_instruction_t* address = ir_ilist_push_back(state->block->instructions);
    address->opcode = IR_LEA;
    address->type = IR_TYPE_LEA;
    address->lea.base = base;
    address->lea.index = index;
    address->lea.scale = scale;
    address->lea.displacement = rm_operand->memory.displacement;
    if (base)
        base->uses++;
    if (index)
        index->uses++;

    ir_instruction_t* final_address = address;
    if (prefixes->address_override) {
        ir_instruction_t* mask = ir_emit_immediate(state, 0xFFFFFFFF);
        final_address = ir_emit_and(state, address, mask);
    }

    return final_address;
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

ir_instruction_t* ir_emit_syscall(ir_emitter_state_t* state)
{
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_SYSCALL;
    instruction->type = IR_TYPE_SYSCALL;
    return instruction;
}

ir_instruction_t* ir_emit_ternary(ir_emitter_state_t* state, ir_instruction_t* condition, ir_instruction_t* true_value, ir_instruction_t* false_value)
{
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_TERNARY;
    instruction->type = IR_TYPE_TERNARY;
    instruction->ternary.condition = condition;
    instruction->ternary.true_value = true_value;
    instruction->ternary.false_value = false_value;
    condition->uses++;
    true_value->uses++;
    false_value->uses++;
    return instruction;
}

ir_instruction_t* ir_emit_get_guest(ir_emitter_state_t* state, x86_ref_e ref)
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

ir_instruction_t* ir_emit_set_guest(ir_emitter_state_t* state, x86_ref_e ref, ir_instruction_t* source)
{
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_SET_GUEST;
    instruction->type = IR_TYPE_SET_GUEST;
    instruction->set_guest.ref = ref;
    instruction->set_guest.source = source;
    source->uses++;
    return instruction;
}

ir_instruction_t* ir_emit_get_flag(ir_emitter_state_t* state, x86_flag_e flag) {
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_GET_FLAG;
    instruction->type = IR_TYPE_GET_FLAG;
    instruction->get_flag.flag = flag;
    return instruction;
}

ir_instruction_t* ir_emit_set_flag(ir_emitter_state_t* state, x86_flag_e flag, ir_instruction_t* source) {
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

ir_instruction_t* ir_emit_immediate_sext(ir_emitter_state_t* state, x86_operand_t* operand)
{
    i64 value = operand->immediate.data;
    switch (operand->immediate.size) {
        case 1: value = (i8)value; break;
        case 2: value = (i16)value; break;
        case 4: value = (i32)value; break;
    }

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
        case X86_REG_SIZE_BYTE_LOW: return ir_emit_get_gpr8_low(state, reg_operand->reg.ref);
        case X86_REG_SIZE_BYTE_HIGH: return ir_emit_get_gpr8_high(state, reg_operand->reg.ref);
        case X86_REG_SIZE_WORD: return ir_emit_get_gpr16(state, reg_operand->reg.ref);
        case X86_REG_SIZE_DWORD: return ir_emit_get_gpr32(state, reg_operand->reg.ref);
        case X86_REG_SIZE_QWORD: return ir_emit_get_gpr64(state, reg_operand->reg.ref);
    }
}

ir_instruction_t* ir_emit_get_rm(ir_emitter_state_t* state, x86_prefixes_t* prefixes, x86_operand_t* rm_operand)
{
    if (rm_operand->type == X86_OP_TYPE_REGISTER) {
        return ir_emit_get_reg(state, rm_operand);
    } else {
        ir_instruction_t* address = ir_emit_lea(state, prefixes, rm_operand);
        return ir_emit_read_memory(state, prefixes, address);
    }
}

ir_instruction_t* ir_emit_set_reg(ir_emitter_state_t* state, x86_operand_t* reg_operand, ir_instruction_t* source)
{
    switch (reg_operand->reg.size) {
        case X86_REG_SIZE_BYTE_LOW: return ir_emit_set_gpr8_low(state, reg_operand->reg.ref, source);
        case X86_REG_SIZE_BYTE_HIGH: return ir_emit_set_gpr8_high(state, reg_operand->reg.ref, source);
        case X86_REG_SIZE_WORD: return ir_emit_set_gpr16(state, reg_operand->reg.ref, source);
        case X86_REG_SIZE_DWORD: return ir_emit_set_gpr32(state, reg_operand->reg.ref, source);
        case X86_REG_SIZE_QWORD: return ir_emit_set_gpr64(state, reg_operand->reg.ref, source);
    }
}

ir_instruction_t* ir_emit_set_rm(ir_emitter_state_t* state, x86_prefixes_t* prefixes, x86_operand_t* rm_operand, ir_instruction_t* source)
{
    if (rm_operand->type == X86_OP_TYPE_REGISTER) {
        return ir_emit_set_reg(state, rm_operand, source);
    } else {
        ir_instruction_t* address = ir_emit_lea(state, prefixes, rm_operand);
        return ir_emit_write_memory(state, prefixes, address, source);
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

ir_instruction_t* ir_emit_get_gpr8_low(ir_emitter_state_t* state, x86_ref_e reg)
{
    ir_instruction_t* full_reg = ir_emit_get_guest(state, reg);
    ir_instruction_t* mask = ir_emit_immediate(state, 0xFF);
    ir_instruction_t* instruction = ir_emit_and(state, full_reg, mask);

    return instruction;
}

ir_instruction_t* ir_emit_get_gpr8_high(ir_emitter_state_t* state, x86_ref_e reg)
{
    ir_instruction_t* full_reg = ir_emit_get_guest(state, reg);
    ir_instruction_t* shift = ir_emit_immediate(state, 8);
    ir_instruction_t* shifted = ir_emit_right_shift(state, full_reg, shift);
    ir_instruction_t* mask = ir_emit_immediate(state, 0xFF);
    ir_instruction_t* instruction = ir_emit_and(state, shifted, mask);

    return instruction;
}

ir_instruction_t* ir_emit_get_gpr16(ir_emitter_state_t* state, x86_ref_e reg)
{
    ir_instruction_t* full_reg = ir_emit_get_guest(state, reg);
    ir_instruction_t* mask = ir_emit_immediate(state, 0xFFFF);
    ir_instruction_t* instruction = ir_emit_and(state, full_reg, mask);

    return instruction;
}

ir_instruction_t* ir_emit_get_gpr32(ir_emitter_state_t* state, x86_ref_e reg)
{
    ir_instruction_t* full_reg = ir_emit_get_guest(state, reg);
    ir_instruction_t* mask = ir_emit_immediate(state, 0xFFFFFFFF);
    ir_instruction_t* instruction = ir_emit_and(state, full_reg, mask);

    return instruction;
}

ir_instruction_t* ir_emit_get_gpr64(ir_emitter_state_t* state, x86_ref_e reg)
{
    ir_instruction_t* instruction = ir_emit_get_guest(state, reg);

    return instruction;
}

ir_instruction_t* ir_emit_set_gpr8_low(ir_emitter_state_t* state, x86_ref_e reg, ir_instruction_t* source)
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

ir_instruction_t* ir_emit_set_gpr8_high(ir_emitter_state_t* state, x86_ref_e reg, ir_instruction_t* source)
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

ir_instruction_t* ir_emit_set_gpr16(ir_emitter_state_t* state, x86_ref_e reg, ir_instruction_t* source)
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

ir_instruction_t* ir_emit_set_gpr32(ir_emitter_state_t* state, x86_ref_e reg, ir_instruction_t* source)
{
    ir_instruction_t* value_mask = ir_emit_immediate(state, 0xFFFFFFFF);
    ir_instruction_t* final_value = ir_emit_and(state, source, value_mask);
    ir_instruction_t* instruction = ir_emit_set_guest(state, reg, final_value);

    return instruction;
}

ir_instruction_t* ir_emit_set_gpr64(ir_emitter_state_t* state, x86_ref_e reg, ir_instruction_t* source)
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

ir_instruction_t* ir_emit_get_carry_adc(ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* source1, ir_instruction_t* source2)
{
    ir_instruction_t* carry_in = ir_emit_get_flag(state, X86_FLAG_CF);
    ir_instruction_t* sum = ir_emit_add(state, source1, source2);
    ir_instruction_t* sum_with_carry = ir_emit_add(state, sum, carry_in);

    ir_instruction_t* carry1 = ir_emit_get_carry_add(state, prefixes, source1, source2, sum);
    ir_instruction_t* carry2 = ir_emit_get_carry_add(state, prefixes, sum, carry_in, sum_with_carry);

    return ir_emit_or(state, carry1, carry2);
}

ir_instruction_t* ir_emit_get_carry_sub(ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* source1, ir_instruction_t* source2, ir_instruction_t* result)
{
    (void)result; // dont need, just keeping for consistency
    (void)prefixes;

    // CF = source1 < source2, as that means that the result would underflow
    return ir_emit_less_than_unsigned(state, source1, source2);
}

ir_instruction_t* ir_emit_get_carry_sbb(ir_emitter_state_t* state, x86_prefixes_t* prefixes, ir_instruction_t* source1, ir_instruction_t* source2)
{
    ir_instruction_t* carry_in = ir_emit_get_flag(state, X86_FLAG_CF);
    ir_instruction_t* sum = ir_emit_sub(state, source1, source2);
    ir_instruction_t* sum_with_carry = ir_emit_sub(state, sum, carry_in);

    ir_instruction_t* carry1 = ir_emit_get_carry_sub(state, prefixes, source1, source2, sum);
    ir_instruction_t* carry2 = ir_emit_get_carry_sub(state, prefixes, sum, carry_in, sum_with_carry);

    return ir_emit_or(state, carry1, carry2);
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

ir_instruction_t* ir_emit_debug_info_compile_time(ir_emitter_state_t* state, const char* format, ...)
{
    char* final = malloc(140);
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_DEBUG_COMPILETIME;
    instruction->type = IR_TYPE_DEBUG;
    instruction->debug.text = final;

    va_list args;
    va_start(args, format);
    int off = vsnprintf(final, 140, format, args);
    va_end(args);

    return instruction;
}

ir_instruction_t* ir_emit_group1_imm(ir_emitter_state_t* state, x86_instruction_t* inst) {
    x86_group1_e opcode = inst->operand_reg.reg.ref - X86_REF_RAX;

    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->prefixes, &inst->operand_rm);
    ir_instruction_t* imm = ir_emit_immediate_sext(state, &inst->operand_imm);
    ir_instruction_t* result = NULL;
    ir_instruction_t* zero = ir_emit_immediate(state, 0);
    ir_instruction_t* c = zero;
    ir_instruction_t* o = zero;
    ir_instruction_t* a = NULL;

    switch (opcode) {
        case X86_GROUP1_ADD: {
            result = ir_emit_add(state, rm, imm);
            c = ir_emit_get_carry_add(state, &inst->prefixes, rm, imm, result);
            o = ir_emit_get_overflow_add(state, &inst->prefixes, rm, imm, result);
            a = ir_emit_get_aux_add(state, rm, imm);
            break;
        }
        case X86_GROUP1_ADC: {
            ir_instruction_t* carry_in = ir_emit_get_flag(state, X86_FLAG_CF);
            ir_instruction_t* imm_carry = ir_emit_add(state, imm, carry_in);
            result = ir_emit_add(state, rm, imm_carry);
            c = ir_emit_get_carry_adc(state, &inst->prefixes, rm, imm_carry);
            o = ir_emit_get_overflow_add(state, &inst->prefixes, rm, imm_carry, result);
            a = ir_emit_get_aux_add(state, rm, imm_carry);
            break;
        }
        case X86_GROUP1_SBB: {
            ir_instruction_t* carry_in = ir_emit_get_flag(state, X86_FLAG_CF);
            ir_instruction_t* imm_carry = ir_emit_add(state, imm, carry_in);
            result = ir_emit_sub(state, rm, imm_carry);
            c = ir_emit_get_carry_sbb(state, &inst->prefixes, rm, imm_carry);
            o = ir_emit_get_overflow_sub(state, &inst->prefixes, rm, imm_carry, result);
            a = ir_emit_get_aux_sub(state, rm, imm_carry);
            break;
        }
        case X86_GROUP1_OR: {
            result = ir_emit_or(state, rm, imm);
            break;
        }
        case X86_GROUP1_AND: {
            result = ir_emit_and(state, rm, imm);
            break;
        }
        case X86_GROUP1_SUB: {
            result = ir_emit_sub(state, rm, imm);
            c = ir_emit_get_carry_sub(state, &inst->prefixes, rm, imm, result);
            o = ir_emit_get_overflow_sub(state, &inst->prefixes, rm, imm, result);
            a = ir_emit_get_aux_sub(state, rm, imm);
            break;
        }
        case X86_GROUP1_XOR: {
            result = ir_emit_xor(state, rm, imm);
            break;
        }
        case X86_GROUP1_CMP: {
            result = ir_emit_sub(state, rm, imm);
            c = ir_emit_get_carry_sub(state, &inst->prefixes, rm, imm, result);
            o = ir_emit_get_overflow_sub(state, &inst->prefixes, rm, imm, result);
            a = ir_emit_get_aux_sub(state, rm, imm);
            break;
        }
    }

    ir_instruction_t* p = ir_emit_get_parity(state, result);
    ir_instruction_t* z = ir_emit_get_zero(state, result);
    ir_instruction_t* s = ir_emit_get_sign(state, &inst->prefixes, result);

    ir_emit_set_cpazso(state, c, p, a, z, s, o);

    if (opcode != X86_GROUP1_CMP) {
        ir_emit_set_rm(state, &inst->prefixes, &inst->operand_rm, result);
    }
}