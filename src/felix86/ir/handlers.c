#include "felix86/common/log.h"
#include "felix86/ir/emitter.h"
#include "felix86/ir/instruction.h"
#include "felix86/ir/handlers.h"

#define IR_HANDLE(name) void ir_handle_##name(ir_emitter_state_t* state, x86_instruction_t* inst)

IR_HANDLE(error) {
    ERROR("Hit error instruction during: %016lx - Opcode: %02x", state->current_address, inst->opcode);
}

IR_HANDLE(add_rm8_r8) { // add rm8, r8 - 0x00
    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->prefixes, &inst->operand_rm);
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_instruction_t* result = ir_emit_add(state, rm, reg);
    ir_emit_set_rm(state, &inst->prefixes, &inst->operand_rm, result);

    ir_instruction_t* c = ir_emit_get_carry_add(state, &inst->prefixes, rm, reg, result);
    ir_instruction_t* p = ir_emit_get_parity(state, result);
    ir_instruction_t* a = ir_emit_get_aux_add(state, rm, reg);
    ir_instruction_t* z = ir_emit_get_zero(state, result);
    ir_instruction_t* s = ir_emit_get_sign(state, &inst->prefixes, result);
    ir_instruction_t* o = ir_emit_get_overflow_add(state, &inst->prefixes, rm, reg, result);

    ir_emit_set_cpazso(state, c, p, a, z, s, o);
}

IR_HANDLE(sub_rm8_r8) { // sub rm8, r8 - 0x28
    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->prefixes, &inst->operand_rm);
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_instruction_t* result = ir_emit_sub(state, rm, reg);
    ir_emit_set_rm(state, &inst->prefixes, &inst->operand_rm, result);

    ir_instruction_t* c = ir_emit_get_carry_sub(state, &inst->prefixes, rm, reg, result);
    ir_instruction_t* p = ir_emit_get_parity(state, result);
    ir_instruction_t* a = ir_emit_get_aux_sub(state, rm, reg);
    ir_instruction_t* z = ir_emit_get_zero(state, result);
    ir_instruction_t* s = ir_emit_get_sign(state, &inst->prefixes, result);
    ir_instruction_t* o = ir_emit_get_overflow_sub(state, &inst->prefixes, rm, reg, result);

    ir_emit_set_cpazso(state, c, p, a, z, s, o);
}

IR_HANDLE(add_eax_imm32) { // add ax/eax/rax, imm16/32/64 - 0x05
    ir_instruction_t* eax = ir_emit_get_reg(state, &inst->operand_reg);
    ir_instruction_t* imm = ir_emit_immediate(state, inst->operand_imm.immediate.data);
    ir_instruction_t* result = ir_emit_add(state, eax, imm);
    ir_emit_set_reg(state, &inst->operand_reg, result);

    ir_instruction_t* c = ir_emit_get_carry_add(state, &inst->prefixes, eax, imm, result);
    ir_instruction_t* p = ir_emit_get_parity(state, result);
    ir_instruction_t* a = ir_emit_get_aux_add(state, eax, imm);
    ir_instruction_t* z = ir_emit_get_zero(state, result);
    ir_instruction_t* s = ir_emit_get_sign(state, &inst->prefixes, result);
    ir_instruction_t* o = ir_emit_get_overflow_add(state, &inst->prefixes, eax, imm, result);

    ir_emit_set_cpazso(state, c, p, a, z, s, o);
}

IR_HANDLE(xor_rm32_r32) { // xor rm16/32/64, r16/32/64 - 0x31
    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->prefixes, &inst->operand_rm);
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_instruction_t* result = ir_emit_xor(state, rm, reg);
    ir_emit_set_rm(state, &inst->prefixes, &inst->operand_rm, result);

    ir_instruction_t* zero = ir_emit_immediate(state, 0);
    ir_instruction_t* p = ir_emit_get_parity(state, result);
    ir_instruction_t* z = ir_emit_get_zero(state, result);
    ir_instruction_t* s = ir_emit_get_sign(state, &inst->prefixes, result);

    ir_emit_set_cpazso(state, zero, p, NULL, z, s, zero);
}

IR_HANDLE(push_r64) { // push r16/64 - 0x50-0x57
    x86_operand_t rsp_reg;
    rsp_reg.type = X86_OP_TYPE_REGISTER;
    rsp_reg.reg.ref = X86_REF_RSP;
    rsp_reg.reg.size = QWORD;
    ir_instruction_t* rsp = ir_emit_get_reg(state, &rsp_reg);
    ir_instruction_t* size = ir_emit_immediate(state, inst->operand_reg.reg.size);
    ir_instruction_t* rsp_sub = ir_emit_sub(state, rsp, size);
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_emit_write_memory(state, &inst->prefixes, rsp_sub, reg);
    ir_emit_set_reg(state, &rsp_reg, rsp_sub);
}

IR_HANDLE(mov_rm32_r32) { // mov rm16/32/64, r16/32/64 - 0x89
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_emit_set_rm(state, &inst->prefixes, &inst->operand_rm, reg);
}

IR_HANDLE(lea) { // lea r32/64, m - 0x8d
    x86_operand_t* rm_operand = &inst->operand_rm;
    x86_prefixes_t* prefixes = &inst->prefixes;
    ir_instruction_t* (*get_guest)(ir_emitter_state_t* state, x86_ref_t reg) = prefixes->address_override ? ir_emit_get_gpr32 : ir_emit_get_gpr64;
    ir_instruction_t* base = rm_operand->memory.base != X86_REF_COUNT ? get_guest(state, rm_operand->memory.base) : NULL;
    ir_instruction_t* index = rm_operand->memory.index != X86_REF_COUNT ? get_guest(state, rm_operand->memory.index) : NULL;
    ir_instruction_t* address = ir_emit_lea(state, base, index, rm_operand->memory.scale, rm_operand->memory.displacement);
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_emit_set_reg(state, &inst->operand_reg, address);
}

IR_HANDLE(nop) {} // nop - 0x90

IR_HANDLE(mov_r8_imm8) { // mov r8, imm8 - 0xb0-0xb7
    ir_instruction_t* imm = ir_emit_immediate(state, inst->operand_imm.immediate.data);
    ir_emit_set_reg(state, &inst->operand_reg, imm);
}

IR_HANDLE(mov_r32_imm32) { // mov r16/32/64, imm16/32/64 - 0xb8-0xbf
    ir_instruction_t* imm = ir_emit_immediate(state, inst->operand_imm.immediate.data);
    ir_emit_set_reg(state, &inst->operand_reg, imm);
}

IR_HANDLE(mov_rm8_imm8) { // mov rm8, imm8 - 0xc6
    ir_instruction_t* imm = ir_emit_immediate(state, inst->operand_imm.immediate.data);
    ir_emit_set_rm(state, &inst->prefixes, &inst->operand_rm, imm);
}

IR_HANDLE(mov_rm32_imm32) { // mov rm16/32/64, imm16/32/64 - 0xc7
    ir_instruction_t* imm = ir_emit_immediate(state, inst->operand_imm.immediate.data);
    ir_emit_set_rm(state, &inst->prefixes, &inst->operand_rm, imm);
}

IR_HANDLE(call_rel32) { // call rel32 - 0xe8
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

IR_HANDLE(hlt) { // hlt - 0xf4
    if (!state->testing) {
        ERROR("Hit HLT instruction during: %016lx", state->current_address);
    } else {
        state->exit = true;
    }
}