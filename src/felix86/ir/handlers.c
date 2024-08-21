#include "felix86/common/log.h"
#include "felix86/ir/emitter.h"
#include "felix86/ir/instruction.h"
#include "felix86/ir/handlers.h"

#define IR_HANDLE(name) void ir_handle_##name(ir_emitter_state_t* state, x86_instruction_t* inst)

IR_HANDLE(error) {
    ERROR("Hit error instruction during: %016lx - Opcode: %02x", state->current_address, inst->opcode);
}

IR_HANDLE(add_rm8_r8) {
    ir_instruction_t* rm = ir_emit_get_rm8(state, &inst->prefixes, &inst->operand_rm);
    ir_instruction_t* reg = ir_emit_get_reg8(state, &inst->prefixes, &inst->operand_reg);
    ir_instruction_t* result = ir_emit_add(state, rm, reg);
    ir_emit_set_rm8(state, &inst->prefixes, &inst->operand_rm, result);

    ir_instruction_t* max = ir_emit_immediate(state, 0xFF);
    ir_instruction_t* p = ir_emit_get_parity(state, result);
    ir_instruction_t* z = ir_emit_get_zero(state, result);
    ir_instruction_t* c = ir_emit_greater_than(state, result, max);

    // SF = result & 0x80
    ir_instruction_t* mask = ir_emit_immediate(state, 0x80);
    ir_instruction_t* s = ir_emit_equal(state, ir_emit_and(state, result, mask), mask);

    // OF = ((result ^ rm) & (result ^ reg) & 0x80) >> 7
    ir_instruction_t* xor1 = ir_emit_xor(state, rm, result);
    ir_instruction_t* xor2 = ir_emit_xor(state, reg, result);
    ir_instruction_t* and = ir_emit_and(state, xor1, xor2);
    ir_instruction_t* masked = ir_emit_and(state, and, mask);
    ir_instruction_t* shift = ir_emit_immediate(state, 7);
    ir_instruction_t* o = ir_emit_right_shift(state, masked, shift);

    // AF = (rm & 0x0F) + (reg & 0x0F) > 0x0F
    ir_instruction_t* nibble_mask = ir_emit_immediate(state, 0x0F);
    ir_instruction_t* rm_masked = ir_emit_and(state, rm, nibble_mask);
    ir_instruction_t* reg_masked = ir_emit_and(state, reg, nibble_mask);
    ir_instruction_t* sum = ir_emit_add(state, rm_masked, reg_masked);
    ir_instruction_t* a = ir_emit_greater_than(state, sum, nibble_mask);

    ir_emit_set_cpazso(state, c, p, a, z, s, o);
}

IR_HANDLE(push_r64) {
    ir_instruction_t* rsp = ir_emit_get_gpr64(state, X86_REF_RSP);
    if (inst->prefixes.operand_override) {
        ir_instruction_t* reg = ir_emit_get_gpr16(state, inst->operand_reg.reg);
        ir_instruction_t* size = ir_emit_immediate(state, 2);
        ir_instruction_t* rsp_sub = ir_emit_sub(state, rsp, size);
        ir_emit_write_word(state, rsp_sub, reg);
        ir_emit_set_gpr64(state, X86_REF_RSP, rsp_sub);
    } else {
        ir_instruction_t* reg = ir_emit_get_gpr64(state, inst->operand_reg.reg);
        ir_instruction_t* size = ir_emit_immediate(state, 8);
        ir_instruction_t* rsp_sub = ir_emit_sub(state, rsp, size);
        ir_emit_write_qword(state, rsp_sub, reg);
        ir_emit_set_gpr64(state, X86_REF_RSP, rsp_sub);
    }
}

IR_HANDLE(pop_r64) {
    ir_instruction_t* rsp = ir_emit_get_gpr64(state, X86_REF_RSP);
    if (inst->prefixes.operand_override) {
        ir_instruction_t* size = ir_emit_immediate(state, 2);
        ir_instruction_t* rsp_add = ir_emit_add(state, rsp, size);
        ir_instruction_t* value = ir_emit_read_word(state, rsp_add);
        ir_emit_set_gpr64(state, X86_REF_RSP, rsp_add);
        ir_emit_set_gpr16(state, inst->operand_reg.reg, value);
    } else {
        ir_instruction_t* size = ir_emit_immediate(state, 8);
        ir_instruction_t* rsp_add = ir_emit_add(state, rsp, size);
        ir_instruction_t* value = ir_emit_read_qword(state, rsp_add);
        ir_emit_set_gpr64(state, X86_REF_RSP, rsp_add);
        ir_emit_set_gpr64(state, inst->operand_reg.reg, value);
    }
}

IR_HANDLE(mov_rm32_r32) {
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->prefixes, &inst->operand_reg);
    ir_emit_set_rm(state, &inst->prefixes, &inst->operand_rm, reg);
}

IR_HANDLE(lea) {
    ir_instruction_t* address = ir_emit_get_rm(state, &inst->prefixes, &inst->operand_rm);
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->prefixes, &inst->operand_reg);
    ir_emit_set_reg(state, &inst->prefixes, &inst->operand_reg, address);
}

IR_HANDLE(mov_r8_imm8) {
    if (inst->operand_imm.immediate.size != 1) {
        ERROR("Invalid immediate size for mov_r8_imm8: %d", inst->operand_imm.immediate.size);
    }

    ir_instruction_t* imm = ir_emit_immediate(state, inst->operand_imm.immediate.data);
    ir_emit_set_reg8(state, &inst->prefixes, &inst->operand_reg, imm);
}

IR_HANDLE(mov_r32_imm32) {
    ir_instruction_t* imm = ir_emit_immediate(state, inst->operand_imm.immediate.data);
    ir_emit_set_reg(state, &inst->prefixes, &inst->operand_reg, imm);
}

IR_HANDLE(mov_rm8_imm8) {
    if (inst->operand_imm.immediate.size != 1) {
        ERROR("Invalid immediate size for mov_rm8_imm8: %d", inst->operand_imm.immediate.size);
    }

    ir_instruction_t* imm = ir_emit_immediate(state, inst->operand_imm.immediate.data);
    ir_emit_set_rm8(state, &inst->prefixes, &inst->operand_rm, imm);
}

IR_HANDLE(mov_rm32_imm32) {
    ir_instruction_t* imm = ir_emit_immediate(state, inst->operand_imm.immediate.data);
    ir_emit_set_rm(state, &inst->prefixes, &inst->operand_rm, imm);
}

IR_HANDLE(call_rel32) {
    if (inst->operand_imm.immediate.size != 4) {
        ERROR("Invalid immediate size for call_rel32: %d", inst->operand_imm.immediate.size);
    }

    u64 displacement = (i64)(i32)inst->operand_imm.immediate.data;
    u64 jumpAddress = state->current_address + inst->length + displacement;
    u64 returnAddress = state->current_address + inst->length;
    ir_instruction_t* rip = ir_emit_immediate(state, jumpAddress);
    ir_instruction_t* returnRip = ir_emit_immediate(state, returnAddress);
    ir_instruction_t* rsp = ir_emit_get_gpr64(state, X86_REF_RSP);
    ir_instruction_t* size = ir_emit_immediate(state, 8);
    ir_instruction_t* rsp_sub = ir_emit_sub(state, rsp, size);
    ir_emit_write_qword(state, rsp_sub, returnRip);
    ir_emit_set_gpr64(state, X86_REF_RSP, rsp_sub);
    ir_emit_set_gpr64(state, X86_REF_RIP, rip);

    state->exit = true;
}

IR_HANDLE(hlt) {
    if (!state->testing) {
        ERROR("Hit HLT instruction during: %016lx", state->current_address);
    } else {
        state->exit = true;
    }
}