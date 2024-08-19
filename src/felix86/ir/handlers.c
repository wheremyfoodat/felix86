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

IR_HANDLE(mov_r8_imm8) {
    if (inst->operand_imm.immediate.size != 1) {
        ERROR("Invalid immediate size for mov_r8_imm8: %d", inst->operand_imm.immediate.size);
    }

    ir_instruction_t* imm = ir_emit_immediate(state, inst->operand_imm.immediate.data);
    ir_emit_set_reg8(state, &inst->prefixes, &inst->operand_reg, imm);
}

IR_HANDLE(mov_rm8_imm8) {
    if (inst->operand_imm.immediate.size != 1) {
        ERROR("Invalid immediate size for mov_rm8_imm8: %d", inst->operand_imm.immediate.size);
    }

    ir_instruction_t* imm = ir_emit_immediate(state, inst->operand_imm.immediate.data);
    ir_emit_set_rm8(state, &inst->prefixes, &inst->operand_rm, imm);
}

IR_HANDLE(hlt) {
    if (!state->testing) {
        ERROR("Hit HLT instruction during: %016lx", state->current_address);
    } else {
        state->exit = true;
    }
}