#include "felix86/common/log.h"
#include "felix86/frontend/instruction.h"
#include "felix86/ir/emitter.h"
#include "felix86/ir/instruction.h"
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

u16 get_bit_size(x86_size_e size) {
    switch (size) {
        case X86_SIZE_BYTE:
            return 8;
        case X86_SIZE_WORD:
            return 16;
        case X86_SIZE_DWORD:
            return 32;
        case X86_SIZE_QWORD:
            return 64;
        case X86_SIZE_MM:
            return 64;
        case X86_SIZE_XMM:
            return 128;
        case X86_SIZE_YMM:
            return 256;
        case X86_SIZE_ZMM:
            return 512;
    }

    ERROR("Invalid register size");
}

x86_operand_t get_full_reg(x86_ref_e ref) {
    x86_operand_t operand;
    operand.type = X86_OP_TYPE_REGISTER;
    operand.reg.ref = ref;
    operand.size = X86_SIZE_QWORD;
    return operand;
}

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

ir_instruction_t* ir_emit_two_operand_immediates(ir_emitter_state_t* state, ir_opcode_e opcode, ir_instruction_t* source1, ir_instruction_t* source2, u32 imm32_1, u32 imm32_2) {
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = opcode;
    instruction->type = IR_TYPE_TWO_OPERAND_IMMEDIATES;
    instruction->two_operand_immediates.source1 = source1;
    instruction->two_operand_immediates.source2 = source2;
    instruction->two_operand_immediates.imm32_1 = imm32_1;
    instruction->two_operand_immediates.imm32_2 = imm32_2;
    if (source1)
        source1->uses++;
    if (source2)
        source2->uses++;
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

ir_instruction_t* ir_emit_left_rotate(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2, x86_size_e size_e)
{
    u8 size = get_bit_size(size_e);
    return ir_emit_two_operand_immediates(state, IR_LEFT_ROTATE, source1, source2, size, 0);
}

ir_instruction_t* ir_emit_right_rotate(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2, x86_size_e size_e)
{
    u8 size = get_bit_size(size_e);
    return ir_emit_two_operand_immediates(state, IR_RIGHT_ROTATE, source1, source2, size, 0);
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

ir_instruction_t* ir_emit_not(ir_emitter_state_t* state, ir_instruction_t* source)
{
    return ir_emit_one_operand(state, IR_NOT, source);
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

ir_instruction_t* ir_emit_lea(ir_emitter_state_t* state, x86_operand_t* rm_operand, bool address_override)
{
    u8 scale = rm_operand->memory.scale;
    ir_instruction_t* (*get_guest)(ir_emitter_state_t* state, x86_ref_e reg) = address_override ? ir_emit_get_gpr32 : ir_emit_get_gpr64;

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
    ir_instruction_t* address = ir_emit_two_operand_immediates(state, IR_LEA, base, index, rm_operand->memory.displacement, scale);
    if (base)
        base->uses++;
    if (index)
        index->uses++;

    ir_instruction_t* final_address = address;
    if (address_override) {
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
    return ir_emit_one_operand(state, IR_SEXT_GPR8, source);
}

ir_instruction_t* ir_emit_sext16(ir_emitter_state_t* state, ir_instruction_t* source)
{
    return ir_emit_one_operand(state, IR_SEXT_GPR16, source);
}

ir_instruction_t* ir_emit_sext32(ir_emitter_state_t* state, ir_instruction_t* source)
{
    return ir_emit_one_operand(state, IR_SEXT_GPR32, source);
}

ir_instruction_t* ir_emit_syscall(ir_emitter_state_t* state)
{
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_SYSCALL;
    instruction->type = IR_TYPE_NO_OPERANDS;
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

ir_instruction_t* ir_emit_jump(ir_emitter_state_t* state, ir_instruction_t* target)
{
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_JUMP;
    instruction->type = IR_TYPE_ONE_OPERAND;
    instruction->one_operand.source = target;
    target->uses++;
    return instruction;
}

ir_instruction_t* ir_emit_jump_if_true(ir_emitter_state_t* state, ir_instruction_t* condition, ir_instruction_t* target)
{
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_JUMP_IF_TRUE;
    instruction->type = IR_TYPE_TWO_OPERAND;
    instruction->two_operand.source1 = condition;
    instruction->two_operand.source2 = target;
    condition->uses++;
    target->uses++;
    return instruction;
}

ir_instruction_t* ir_emit_insert_integer_to_vector(ir_emitter_state_t* state, ir_instruction_t* vector_dest, ir_instruction_t* source, u8 size, u8 index)
{
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_INSERT_INTEGER_TO_VECTOR;
    instruction->type = IR_TYPE_TWO_OPERAND_IMMEDIATES;
    instruction->two_operand_immediates.source1 = vector_dest;
    instruction->two_operand_immediates.source2 = source;
    instruction->two_operand_immediates.imm32_1 = index;
    instruction->two_operand_immediates.imm32_2 = size;
    vector_dest->uses++;
    source->uses++;
    return instruction;
}

ir_instruction_t* ir_emit_extract_integer_from_vector(ir_emitter_state_t* state, ir_instruction_t* vector_src, u8 size, u8 index)
{
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_EXTRACT_INTEGER_FROM_VECTOR;
    instruction->type = IR_TYPE_TWO_OPERAND_IMMEDIATES;
    instruction->two_operand_immediates.source1 = vector_src;
    instruction->two_operand_immediates.imm32_1 = index;
    instruction->two_operand_immediates.imm32_2 = size;
    vector_src->uses++;
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

ir_instruction_t* ir_emit_get_flag_not(ir_emitter_state_t* state, x86_flag_e flag) {
    ir_instruction_t* instruction = ir_emit_get_flag(state, flag);
    ir_instruction_t* one = ir_emit_immediate(state, 1);
    return ir_emit_xor(state, instruction, one);
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

ir_instruction_t* ir_emit_cpuid(ir_emitter_state_t* state)
{
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_CPUID;
    instruction->type = IR_TYPE_NO_OPERANDS;
    return instruction;
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
    switch (operand->size) {
        case X86_SIZE_BYTE: value = (i8)value; break;
        case X86_SIZE_WORD: value = (i16)value; break;
        case X86_SIZE_DWORD: value = (i32)value; break;
        case X86_SIZE_QWORD: break;
        default: ERROR("Invalid immediate size");
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
    switch (reg_operand->size) {
        case X86_SIZE_BYTE: {
            if (reg_operand->reg.high8) {
                return ir_emit_get_gpr8_high(state, reg_operand->reg.ref);
            } else {
                return ir_emit_get_gpr8_low(state, reg_operand->reg.ref);
            }
        }
        case X86_SIZE_WORD: return ir_emit_get_gpr16(state, reg_operand->reg.ref);
        case X86_SIZE_DWORD: return ir_emit_get_gpr32(state, reg_operand->reg.ref);
        case X86_SIZE_QWORD: return ir_emit_get_gpr64(state, reg_operand->reg.ref);
        case X86_SIZE_XMM:
        case X86_SIZE_YMM: 
        case X86_SIZE_ZMM: return ir_emit_get_vector(state, reg_operand->reg.ref);
        default: ERROR("Invalid register size"); return NULL;
    }
}

ir_instruction_t* ir_emit_get_rm(ir_emitter_state_t* state, x86_operand_t* rm_operand)
{
    if (rm_operand->type == X86_OP_TYPE_REGISTER) {
        return ir_emit_get_reg(state, rm_operand);
    } else {
        ir_instruction_t* address = ir_emit_lea(state, rm_operand, rm_operand->address_override);
        return ir_emit_read_memory(state, address, rm_operand->size);
    }
}

ir_instruction_t* ir_emit_set_reg(ir_emitter_state_t* state, x86_operand_t* reg_operand, ir_instruction_t* source)
{
    switch (reg_operand->size) {
        case X86_SIZE_BYTE: {
            if (reg_operand->reg.high8) {
                return ir_emit_set_gpr8_high(state, reg_operand->reg.ref, source);
            } else {
                return ir_emit_set_gpr8_low(state, reg_operand->reg.ref, source);
            }
        }
        case X86_SIZE_WORD: return ir_emit_set_gpr16(state, reg_operand->reg.ref, source);
        case X86_SIZE_DWORD: return ir_emit_set_gpr32(state, reg_operand->reg.ref, source);
        case X86_SIZE_QWORD: return ir_emit_set_gpr64(state, reg_operand->reg.ref, source);
        default: ERROR("Invalid register size"); return NULL;
    }
}

ir_instruction_t* ir_emit_set_rm(ir_emitter_state_t* state, x86_operand_t* rm_operand, ir_instruction_t* source)
{
    if (rm_operand->type == X86_OP_TYPE_REGISTER) {
        return ir_emit_set_reg(state, rm_operand, source);
    } else {
        ir_instruction_t* address = ir_emit_lea(state, rm_operand, rm_operand->address_override);
        return ir_emit_write_memory(state, address, source, rm_operand->size);
    }
}

ir_instruction_t* ir_emit_write_memory(ir_emitter_state_t* state, ir_instruction_t* address, ir_instruction_t* value, x86_size_e size)
{
    switch (size) {
        case X86_SIZE_BYTE: return ir_emit_write_byte(state, address, value);
        case X86_SIZE_WORD: return ir_emit_write_word(state, address, value);
        case X86_SIZE_DWORD: return ir_emit_write_dword(state, address, value);
        case X86_SIZE_QWORD: return ir_emit_write_qword(state, address, value);
        default: ERROR("Invalid memory size"); return NULL;
    }
}

ir_instruction_t* ir_emit_read_memory(ir_emitter_state_t* state, ir_instruction_t* address, x86_size_e size)
{
    switch (size) {
        case X86_SIZE_BYTE: return ir_emit_read_byte(state, address);
        case X86_SIZE_WORD: return ir_emit_read_word(state, address);
        case X86_SIZE_DWORD: return ir_emit_read_dword(state, address);
        case X86_SIZE_QWORD: return ir_emit_read_qword(state, address);
        default: ERROR("Invalid memory size"); return NULL;
    }
}

ir_instruction_t* ir_emit_get_gpr8_low(ir_emitter_state_t* state, x86_ref_e reg)
{
    if (reg < X86_REF_RAX || reg > X86_REF_R15) {
        ERROR("Invalid register reference");
    }

    ir_instruction_t* full_reg = ir_emit_get_guest(state, reg);
    ir_instruction_t* mask = ir_emit_immediate(state, 0xFF);
    ir_instruction_t* instruction = ir_emit_and(state, full_reg, mask);

    return instruction;
}

ir_instruction_t* ir_emit_get_gpr8_high(ir_emitter_state_t* state, x86_ref_e reg)
{
    if (reg < X86_REF_RAX || reg > X86_REF_R15) {
        ERROR("Invalid register reference");
    }

    ir_instruction_t* full_reg = ir_emit_get_guest(state, reg);
    ir_instruction_t* shift = ir_emit_immediate(state, 8);
    ir_instruction_t* shifted = ir_emit_right_shift(state, full_reg, shift);
    ir_instruction_t* mask = ir_emit_immediate(state, 0xFF);
    ir_instruction_t* instruction = ir_emit_and(state, shifted, mask);

    return instruction;
}

ir_instruction_t* ir_emit_get_gpr16(ir_emitter_state_t* state, x86_ref_e reg)
{
    if (reg < X86_REF_RAX || reg > X86_REF_R15) {
        ERROR("Invalid register reference");
    }

    ir_instruction_t* full_reg = ir_emit_get_guest(state, reg);
    ir_instruction_t* mask = ir_emit_immediate(state, 0xFFFF);
    ir_instruction_t* instruction = ir_emit_and(state, full_reg, mask);

    return instruction;
}

ir_instruction_t* ir_emit_get_gpr32(ir_emitter_state_t* state, x86_ref_e reg)
{
    if (reg < X86_REF_RAX || reg > X86_REF_R15) {
        ERROR("Invalid register reference");
    }

    ir_instruction_t* full_reg = ir_emit_get_guest(state, reg);
    ir_instruction_t* mask = ir_emit_immediate(state, 0xFFFFFFFF);
    ir_instruction_t* instruction = ir_emit_and(state, full_reg, mask);

    return instruction;
}

ir_instruction_t* ir_emit_get_gpr64(ir_emitter_state_t* state, x86_ref_e reg)
{
    if (reg < X86_REF_RAX || reg > X86_REF_R15) {
        ERROR("Invalid register reference");
    }

    ir_instruction_t* instruction = ir_emit_get_guest(state, reg);
    return instruction;
}

ir_instruction_t* ir_emit_get_vector(ir_emitter_state_t* state, x86_ref_e reg)
{
    if (reg < X86_REF_XMM0 || reg > X86_REF_XMM31) {
        ERROR("Invalid register reference");
    }

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

ir_instruction_t* ir_emit_get_size(ir_emitter_state_t* state, x86_size_e size_e)
{
    return ir_emit_immediate(state, get_bit_size(size_e));
}

ir_instruction_t* ir_emit_get_sign_mask(ir_emitter_state_t* state, x86_size_e size_e)
{
    u16 size = get_bit_size(size_e);
    return ir_emit_immediate(state, 1ull << (size - 1));
}

ir_instruction_t* ir_emit_get_shift_mask_left(ir_emitter_state_t* state, ir_instruction_t* source, x86_size_e size_e)
{
    ir_instruction_t* one = ir_emit_immediate(state, 1);
    ir_instruction_t* shiftMax = ir_emit_get_size(state, size_e);
    ir_instruction_t* shift = ir_emit_sub(state, shiftMax, source);
    ir_instruction_t* mask = ir_emit_left_shift(state, one, shift);
    return mask;
}

ir_instruction_t* ir_emit_get_mask(ir_emitter_state_t* state, x86_size_e size_e)
{
    u16 size = get_bit_size(size_e);
    return ir_emit_immediate(state, (1ull << size) - 1);
}

ir_instruction_t* ir_emit_get_sign(ir_emitter_state_t* state, ir_instruction_t* source, x86_size_e size_e)
{
    ir_instruction_t* mask = ir_emit_get_sign_mask(state, size_e);
    ir_instruction_t* masked = ir_emit_and(state, source, mask);
    ir_instruction_t* instruction = ir_emit_equal(state, masked, mask);

    return instruction;
}

ir_instruction_t* ir_emit_get_overflow_add(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2, ir_instruction_t* result, x86_size_e size_e)
{
    ir_instruction_t* mask = ir_emit_get_sign_mask(state, size_e);

    // for x + y = z, overflow occurs if ((z ^ x) & (z ^ y) & mask) == mask
    // which essentially checks if the sign bits of x and y are equal, but the sign bit of z is different
    ir_instruction_t* xor1 = ir_emit_xor(state, result, source1);
    ir_instruction_t* xor2 = ir_emit_xor(state, result, source2);
    ir_instruction_t* and = ir_emit_and(state, xor1, xor2);
    ir_instruction_t* masked = ir_emit_and(state, and, mask);

    return ir_emit_equal(state, masked, mask);
}

ir_instruction_t* ir_emit_get_overflow_sub(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2, ir_instruction_t* result, x86_size_e size_e)
{
    ir_instruction_t* mask = ir_emit_get_sign_mask(state, size_e);

    // for x - y = z, overflow occurs if ((x ^ y) & (x ^ z) & mask) == mask
    ir_instruction_t* xor1 = ir_emit_xor(state, source1, source2);
    ir_instruction_t* xor2 = ir_emit_xor(state, source1, result);
    ir_instruction_t* and = ir_emit_and(state, xor1, xor2);
    ir_instruction_t* masked = ir_emit_and(state, and, mask);

    return ir_emit_equal(state, masked, mask);
}

ir_instruction_t* ir_emit_get_carry_add(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2, ir_instruction_t* result, x86_size_e size_e)
{
    (void)source2; // dont need, just keeping for consistency

    // CF = result < source1, as that means that the result overflowed
    ir_instruction_t* mask = ir_emit_get_mask(state, size_e);
    ir_instruction_t* masked_result = ir_emit_and(state, result, mask);
    return ir_emit_less_than_unsigned(state, masked_result, source1);
}

ir_instruction_t* ir_emit_get_carry_adc(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2, x86_size_e size_e)
{
    ir_instruction_t* carry_in = ir_emit_get_flag(state, X86_FLAG_CF);
    ir_instruction_t* sum = ir_emit_add(state, source1, source2);
    ir_instruction_t* sum_with_carry = ir_emit_add(state, sum, carry_in);

    ir_instruction_t* carry1 = ir_emit_get_carry_add(state, source1, source2, sum, size_e);
    ir_instruction_t* carry2 = ir_emit_get_carry_add(state, sum, carry_in, sum_with_carry, size_e);

    return ir_emit_or(state, carry1, carry2);
}

ir_instruction_t* ir_emit_get_carry_sub(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2, ir_instruction_t* result, x86_size_e size_e)
{
    (void)result; // dont need, just keeping for consistency

    // CF = source1 < source2, as that means that the result would underflow
    return ir_emit_less_than_unsigned(state, source1, source2);
}

ir_instruction_t* ir_emit_get_carry_sbb(ir_emitter_state_t* state, ir_instruction_t* source1, ir_instruction_t* source2, x86_size_e size_e)
{
    ir_instruction_t* carry_in = ir_emit_get_flag(state, X86_FLAG_CF);
    ir_instruction_t* sum = ir_emit_sub(state, source1, source2);
    ir_instruction_t* sum_with_carry = ir_emit_sub(state, sum, carry_in);

    ir_instruction_t* carry1 = ir_emit_get_carry_sub(state, source1, source2, sum, size_e);
    ir_instruction_t* carry2 = ir_emit_get_carry_sub(state, sum, carry_in, sum_with_carry, size_e);

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

ir_instruction_t* ir_emit_vector_mask_elements(ir_emitter_state_t* state, ir_instruction_t* vector, u32 mask)
{
    ir_instruction_t* instruction = ir_ilist_push_back(state->block->instructions);
    instruction->opcode = IR_VECTOR_MASK_ELEMENTS;
    instruction->type = IR_TYPE_TWO_OPERAND_IMMEDIATES;
    instruction->two_operand_immediates.source1 = vector;
    instruction->two_operand_immediates.imm32_1 = mask;
    return instruction;
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

void ir_emit_group1_imm(ir_emitter_state_t* state, x86_instruction_t* inst) {
    x86_group1_e opcode = inst->operand_reg.reg.ref - X86_REF_RAX;

    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->operand_rm);
    ir_instruction_t* imm = ir_emit_immediate_sext(state, &inst->operand_imm);
    ir_instruction_t* result = NULL;
    ir_instruction_t* zero = ir_emit_immediate(state, 0);
    ir_instruction_t* c = zero;
    ir_instruction_t* o = zero;
    ir_instruction_t* a = NULL;

    switch (opcode) {
        case X86_GROUP1_ADD: {
            result = ir_emit_add(state, rm, imm);
            c = ir_emit_get_carry_add(state, rm, imm, result, inst->operand_rm.size);
            o = ir_emit_get_overflow_add(state, rm, imm, result, inst->operand_rm.size);
            a = ir_emit_get_aux_add(state, rm, imm);
            break;
        }
        case X86_GROUP1_ADC: {
            ir_instruction_t* carry_in = ir_emit_get_flag(state, X86_FLAG_CF);
            ir_instruction_t* imm_carry = ir_emit_add(state, imm, carry_in);
            result = ir_emit_add(state, rm, imm_carry);
            c = ir_emit_get_carry_adc(state, rm, imm_carry, inst->operand_rm.size);
            o = ir_emit_get_overflow_add(state, rm, imm_carry, result, inst->operand_rm.size);
            a = ir_emit_get_aux_add(state, rm, imm_carry);
            break;
        }
        case X86_GROUP1_SBB: {
            ir_instruction_t* carry_in = ir_emit_get_flag(state, X86_FLAG_CF);
            ir_instruction_t* imm_carry = ir_emit_add(state, imm, carry_in);
            result = ir_emit_sub(state, rm, imm_carry);
            c = ir_emit_get_carry_sbb(state, rm, imm_carry, inst->operand_rm.size);
            o = ir_emit_get_overflow_sub(state, rm, imm_carry, result, inst->operand_rm.size);
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
            c = ir_emit_get_carry_sub(state, rm, imm, result, inst->operand_rm.size);
            o = ir_emit_get_overflow_sub(state, rm, imm, result, inst->operand_rm.size);
            a = ir_emit_get_aux_sub(state, rm, imm);
            break;
        }
        case X86_GROUP1_XOR: {
            result = ir_emit_xor(state, rm, imm);
            break;
        }
        case X86_GROUP1_CMP: {
            result = ir_emit_sub(state, rm, imm);
            c = ir_emit_get_carry_sub(state, rm, imm, result, inst->operand_rm.size);
            o = ir_emit_get_overflow_sub(state, rm, imm, result, inst->operand_rm.size);
            a = ir_emit_get_aux_sub(state, rm, imm);
            break;
        }
    }

    ir_instruction_t* p = ir_emit_get_parity(state, result);
    ir_instruction_t* z = ir_emit_get_zero(state, result);
    ir_instruction_t* s = ir_emit_get_sign(state, result, inst->operand_rm.size);

    ir_emit_set_cpazso(state, c, p, a, z, s, o);

    if (opcode != X86_GROUP1_CMP) {
        ir_emit_set_rm(state, &inst->operand_rm, result);
    }
}

void ir_emit_group2_imm(ir_emitter_state_t* state, x86_instruction_t* inst) {
    x86_group2_e opcode = inst->operand_reg.reg.ref - X86_REF_RAX;

    x86_size_e size_e = inst->operand_rm.size;
    u8 shift_mask = size_e == X86_SIZE_QWORD ? 0x3F : 0x1F;
    u8 shift_amount = inst->operand_imm.immediate.data & shift_mask;
    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->operand_rm);
    ir_instruction_t* shift_imm = ir_emit_immediate(state, shift_amount);
    ir_instruction_t* result = NULL;
    ir_instruction_t* c = NULL;
    ir_instruction_t* p = NULL;
    ir_instruction_t* a = NULL;
    ir_instruction_t* z = NULL;
    ir_instruction_t* s = NULL;
    ir_instruction_t* o = NULL;

    bool update_pzs = false;

    switch (opcode) {
        case X86_GROUP2_ROL: {
            ir_instruction_t* size = ir_emit_get_size(state, size_e);
            ir_instruction_t* shift_mask = ir_emit_sub(state, size, ir_emit_immediate(state, 1));
            ir_instruction_t* shift_masked = ir_emit_and(state, shift_imm, shift_mask);
            result = ir_emit_left_rotate(state, rm, shift_masked, size_e);
            c = ir_emit_and(state, result, ir_emit_immediate(state, 1));

            if (shift_amount == 1) {
                ir_instruction_t* msb = ir_emit_get_sign(state, result, size_e);
                o = ir_emit_xor(state, c, msb);
            }
            break;
        }
        case X86_GROUP2_ROR: {
            ERROR("Unimplemented");
            break;
        }
        case X86_GROUP2_RCL: {
            ERROR("Why? :(");
            break;
        }
        case X86_GROUP2_RCR: {
            ERROR("Why? :(");
            break;
        }
        case X86_GROUP2_SAL:
        case X86_GROUP2_SHL: {
            ir_instruction_t* msb_mask = ir_emit_get_shift_mask_left(state, shift_imm, size_e);
            result = ir_emit_left_shift(state, rm, shift_imm);
            c = ir_emit_equal(state, ir_emit_and(state, rm, msb_mask), msb_mask);
            ir_instruction_t* sign = ir_emit_get_sign(state, result, size_e);
            o = ir_emit_xor(state, c, sign);

            if (shift_amount != 0) {
                update_pzs = true;
            }
            break;
        }
        case X86_GROUP2_SHR: {
            break;
        }
        case X86_GROUP2_SAR: {
            break;
        }
    }

    if (update_pzs) {
        p = ir_emit_get_parity(state, result);
        z = ir_emit_get_zero(state, result);
        s = ir_emit_get_sign(state, result, size_e);
    }

    ir_emit_set_cpazso(state, c, p, a, z, s, o);

    ir_emit_set_rm(state, &inst->operand_rm, result);
}

void ir_emit_group3_imm(ir_emitter_state_t* state, x86_instruction_t* inst) {
    x86_group3_e opcode = inst->operand_reg.reg.ref - X86_REF_RAX;

    x86_size_e size_e = inst->operand_rm.size;
    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->operand_rm);
    ir_instruction_t* result = NULL;
    ir_instruction_t* c = NULL;
    ir_instruction_t* p = NULL;
    ir_instruction_t* a = NULL;
    ir_instruction_t* z = NULL;
    ir_instruction_t* s = NULL;
    ir_instruction_t* o = NULL;

    switch (opcode) {
        case X86_GROUP3_TEST:
        case X86_GROUP3_TEST_: {
            ir_instruction_t* imm = ir_emit_immediate_sext(state, &inst->operand_imm);
            result = ir_emit_and(state, rm, imm);
            s = ir_emit_get_sign(state, result, size_e);
            z = ir_emit_get_zero(state, result);
            p = ir_emit_get_parity(state, result);
            break;
        }
        case X86_GROUP3_NOT: {
            result = ir_emit_not(state, rm);
            break;
        }
        case X86_GROUP3_NEG: {
            ERROR("Unimplemented");
            break;
        }
        case X86_GROUP3_MUL: {
            ERROR("Unimplemented");
            break;
        }
        case X86_GROUP3_IMUL: {
            ERROR("Unimplemented");
            break;
        }
        case X86_GROUP3_DIV: {
            ERROR("Unimplemented");
            break;
        }
        case X86_GROUP3_IDIV: {
            ERROR("Unimplemented");
            break;
        }
    }

    ir_emit_set_cpazso(state, c, p, a, z, s, o);

    if (opcode != X86_GROUP3_TEST && opcode != X86_GROUP3_TEST_) {
        ir_emit_set_rm(state, &inst->operand_rm, result);
    }
}

ir_instruction_t* ir_emit_get_cc(ir_emitter_state_t* state, u8 opcode) {
    switch (opcode & 0xF) {
        case 0: return ir_emit_get_flag(state, X86_FLAG_OF);
        case 1: return ir_emit_get_flag_not(state, X86_FLAG_OF);
        case 2: return ir_emit_get_flag(state, X86_FLAG_CF);
        case 3: return ir_emit_get_flag_not(state, X86_FLAG_CF);
        case 4: return ir_emit_get_flag(state, X86_FLAG_ZF);
        case 5: return ir_emit_get_flag_not(state, X86_FLAG_ZF);
        case 6: return ir_emit_or(state, ir_emit_get_flag(state, X86_FLAG_CF), ir_emit_get_flag(state, X86_FLAG_ZF));
        case 7: return ir_emit_and(state, ir_emit_get_flag_not(state, X86_FLAG_CF), ir_emit_get_flag_not(state, X86_FLAG_ZF));
        case 8: return ir_emit_get_flag(state, X86_FLAG_SF);
        case 9: return ir_emit_get_flag_not(state, X86_FLAG_SF);
        case 10: return ir_emit_get_flag(state, X86_FLAG_PF);
        case 11: return ir_emit_get_flag_not(state, X86_FLAG_PF);
        case 12: return ir_emit_not_equal(state, ir_emit_get_flag(state, X86_FLAG_SF), ir_emit_get_flag(state, X86_FLAG_OF));
        case 13: return ir_emit_equal(state, ir_emit_get_flag(state, X86_FLAG_SF), ir_emit_get_flag(state, X86_FLAG_OF));
        case 14: return ir_emit_or(state, ir_emit_equal(state, ir_emit_get_flag(state, X86_FLAG_ZF), ir_emit_immediate(state, 1)), ir_emit_not_equal(state, ir_emit_get_flag(state, X86_FLAG_SF), ir_emit_get_flag(state, X86_FLAG_OF)));
        case 15: return ir_emit_and(state, ir_emit_equal(state, ir_emit_get_flag(state, X86_FLAG_ZF), ir_emit_immediate(state, 0)), ir_emit_equal(state, ir_emit_get_flag(state, X86_FLAG_SF), ir_emit_get_flag(state, X86_FLAG_OF)));
    }

    ERROR("Invalid condition code");
}

ir_instruction_t* ir_emit_jcc(ir_emitter_state_t* state, x86_instruction_t* inst) {
    u8 inst_length = inst->length;
    ir_instruction_t* imm = ir_emit_immediate_sext(state, &inst->operand_imm);
    ir_instruction_t* condition = ir_emit_get_cc(state, inst->opcode);
    ir_instruction_t* jump_address_false = ir_emit_immediate(state, state->current_address + inst_length);
    ir_instruction_t* jump_address_true = ir_emit_add(state, jump_address_false, imm);
    ir_instruction_t* jump = ir_emit_ternary(state, condition, jump_address_true, jump_address_false);
    state->exit = true;
    return ir_emit_jump(state, jump);
}

ir_instruction_t* ir_emit_setcc(ir_emitter_state_t* state, x86_instruction_t* inst) {
    return ir_emit_set_rm(state, &inst->operand_rm, ir_emit_get_cc(state, inst->opcode));
}

ir_instruction_t* ir_emit_cmovcc(ir_emitter_state_t* state, x86_instruction_t* inst) {
    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->operand_rm);
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_instruction_t* condition = ir_emit_get_cc(state, inst->opcode);
    ir_instruction_t* value = ir_emit_ternary(state, condition, rm, reg);
    return ir_emit_set_reg(state, &inst->operand_reg, value);
}

void ir_emit_rep_start(ir_emitter_state_t* state, x86_size_e size_e) {
    state->exit = true;

    x86_operand_t rcx = get_full_reg(X86_REF_RCX);
    ir_instruction_t* condition = ir_emit_equal(state, ir_emit_get_reg(state, &rcx), ir_emit_immediate(state, 0));
    ir_instruction_t* jump_address = ir_emit_immediate(state, state->current_address + state->current_instruction_length);

    ir_emit_jump_if_true(state, condition, jump_address);
}

void ir_emit_rep_end(ir_emitter_state_t* state, bool is_nz, x86_size_e size_e) {
    x86_operand_t rcx_reg = get_full_reg(X86_REF_RCX);
    rcx_reg.size = size_e;

    ir_instruction_t* rcx = ir_emit_get_reg(state, &rcx_reg);
    ir_instruction_t* rcx_sub = ir_emit_sub(state, rcx, ir_emit_immediate(state, 1));
    ir_emit_set_reg(state, &rcx_reg, rcx_sub);

    ir_instruction_t* zero = ir_emit_immediate(state, 0);
    ir_instruction_t* zf = ir_emit_get_flag(state, X86_FLAG_ZF);
    ir_instruction_t* condition_exit_rep = is_nz ? ir_emit_not_equal(state, zf, zero) : ir_emit_equal(state, zf, zero);
    ir_instruction_t* condition_exit_c = ir_emit_equal(state, rcx, zero);
    ir_instruction_t* condition = ir_emit_or(state, condition_exit_rep, condition_exit_c);
    ir_instruction_t* jump_address_false = ir_emit_immediate(state, state->current_address); // repeat
    ir_instruction_t* jump_address_true = ir_emit_immediate(state, state->current_address + state->current_instruction_length); // exit
    ir_instruction_t* jump = ir_emit_ternary(state, condition, jump_address_true, jump_address_false);

    ir_emit_jump(state, jump);
}