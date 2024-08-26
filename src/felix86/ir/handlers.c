#include "felix86/common/log.h"
#include "felix86/ir/emitter.h"
#include "felix86/ir/instruction.h"
#include "felix86/ir/handlers.h"

#define IR_HANDLE(name) void ir_handle_##name(ir_emitter_state_t* state, x86_instruction_t* inst)

IR_HANDLE(error) {
    ERROR("Hit error instruction during: %016lx - Opcode: %02x", state->current_address, inst->opcode);
}

// ██████  ██████  ██ ███    ███  █████  ██████  ██    ██ 
// ██   ██ ██   ██ ██ ████  ████ ██   ██ ██   ██  ██  ██  
// ██████  ██████  ██ ██ ████ ██ ███████ ██████    ████   
// ██      ██   ██ ██ ██  ██  ██ ██   ██ ██   ██    ██    
// ██      ██   ██ ██ ██      ██ ██   ██ ██   ██    ██    

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

IR_HANDLE(add_r32_rm32) { // add r16/32/64, rm16/32/64 - 0x03
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->prefixes, &inst->operand_rm);
    ir_instruction_t* result = ir_emit_add(state, reg, rm);
    ir_emit_set_reg(state, &inst->operand_reg, result);

    ir_instruction_t* c = ir_emit_get_carry_add(state, &inst->prefixes, reg, rm, result);
    ir_instruction_t* p = ir_emit_get_parity(state, result);
    ir_instruction_t* a = ir_emit_get_aux_add(state, reg, rm);
    ir_instruction_t* z = ir_emit_get_zero(state, result);
    ir_instruction_t* s = ir_emit_get_sign(state, &inst->prefixes, result);
    ir_instruction_t* o = ir_emit_get_overflow_add(state, &inst->prefixes, reg, rm, result);

    ir_emit_set_cpazso(state, c, p, a, z, s, o);
}

IR_HANDLE(add_eax_imm32) { // add ax/eax/rax, imm16/32/64 - 0x05
    ir_instruction_t* eax = ir_emit_get_reg(state, &inst->operand_reg);
    ir_instruction_t* imm = ir_emit_immediate_sext(state, &inst->operand_imm);
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

IR_HANDLE(or_rm32_r32) { // or rm16/32/64, r16/32/64 - 0x09
    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->prefixes, &inst->operand_rm);
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_instruction_t* result = ir_emit_or(state, rm, reg);
    ir_emit_set_rm(state, &inst->prefixes, &inst->operand_rm, result);

    ir_instruction_t* zero = ir_emit_immediate(state, 0);
    ir_instruction_t* p = ir_emit_get_parity(state, result);
    ir_instruction_t* z = ir_emit_get_zero(state, result);
    ir_instruction_t* s = ir_emit_get_sign(state, &inst->prefixes, result);

    ir_emit_set_cpazso(state, zero, p, NULL, z, s, zero);
}

IR_HANDLE(or_r32_rm32) { // or r16/32/64, rm16/32/64 - 0x0B
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->prefixes, &inst->operand_rm);
    ir_instruction_t* result = ir_emit_or(state, reg, rm);
    ir_emit_set_reg(state, &inst->operand_reg, result);

    ir_instruction_t* zero = ir_emit_immediate(state, 0);
    ir_instruction_t* p = ir_emit_get_parity(state, result);
    ir_instruction_t* z = ir_emit_get_zero(state, result);
    ir_instruction_t* s = ir_emit_get_sign(state, &inst->prefixes, result);

    ir_emit_set_cpazso(state, zero, p, NULL, z, s, zero);
}

IR_HANDLE(and_eax_imm32) { // and ax/eax/rax, imm16/32/64 - 0x25
    ir_instruction_t* eax = ir_emit_get_reg(state, &inst->operand_reg);
    ir_instruction_t* imm = ir_emit_immediate_sext(state, &inst->operand_imm);
    ir_instruction_t* result = ir_emit_and(state, eax, imm);
    ir_emit_set_reg(state, &inst->operand_reg, result);

    ir_instruction_t* zero = ir_emit_immediate(state, 0);
    ir_instruction_t* p = ir_emit_get_parity(state, result);
    ir_instruction_t* z = ir_emit_get_zero(state, result);
    ir_instruction_t* s = ir_emit_get_sign(state, &inst->prefixes, result);

    ir_emit_set_cpazso(state, zero, p, NULL, z, s, zero);
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

IR_HANDLE(sub_rm32_r32) { // sub rm16/32/64, r16/32/64 - 0x29
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

IR_HANDLE(cmp_eax_imm32) { // cmp eax, imm32 - 0x3d
    ir_instruction_t* eax = ir_emit_get_reg(state, &inst->operand_reg);
    ir_instruction_t* imm = ir_emit_immediate_sext(state, &inst->operand_imm);
    ir_instruction_t* result = ir_emit_sub(state, eax, imm);

    ir_instruction_t* c = ir_emit_get_carry_sub(state, &inst->prefixes, eax, imm, result);
    ir_instruction_t* p = ir_emit_get_parity(state, result);
    ir_instruction_t* a = ir_emit_get_aux_sub(state, eax, imm);
    ir_instruction_t* z = ir_emit_get_zero(state, result);
    ir_instruction_t* s = ir_emit_get_sign(state, &inst->prefixes, result);
    ir_instruction_t* o = ir_emit_get_overflow_sub(state, &inst->prefixes, eax, imm, result);

    ir_emit_set_cpazso(state, c, p, a, z, s, o);
}

IR_HANDLE(push_r64) { // push r16/64 - 0x50-0x57
    x86_operand_t rsp_reg;
    rsp_reg.type = X86_OP_TYPE_REGISTER;
    rsp_reg.reg.ref = X86_REF_RSP;
    rsp_reg.reg.size = X86_REG_SIZE_QWORD;
    ir_instruction_t* rsp = ir_emit_get_reg(state, &rsp_reg);
    ir_instruction_t* size = ir_emit_immediate(state, inst->operand_reg.reg.size == X86_REG_SIZE_WORD ? 2 : 8);
    ir_instruction_t* rsp_sub = ir_emit_sub(state, rsp, size);
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_emit_write_memory(state, &inst->prefixes, rsp_sub, reg);
    ir_emit_set_reg(state, &rsp_reg, rsp_sub);
}

IR_HANDLE(pop_r64) { // pop r16/64 - 0x58-0x5f
    x86_operand_t rsp_reg;
    rsp_reg.type = X86_OP_TYPE_REGISTER;
    rsp_reg.reg.ref = X86_REF_RSP;
    rsp_reg.reg.size = X86_REG_SIZE_QWORD;
    ir_instruction_t* rsp = ir_emit_get_reg(state, &rsp_reg);
    ir_instruction_t* reg = ir_emit_read_memory(state, &inst->prefixes, rsp);
    ir_instruction_t* size = ir_emit_immediate(state, inst->operand_reg.reg.size == X86_REG_SIZE_WORD ? 2 : 8);
    ir_instruction_t* rsp_add = ir_emit_add(state, rsp, size);
    ir_emit_set_reg(state, &inst->operand_reg, reg);
    ir_emit_set_reg(state, &rsp_reg, rsp_add);
}

IR_HANDLE(movsxd) { // movsxd r32/64, rm32/64 - 0x63
    if (inst->operand_reg.reg.size != X86_REG_SIZE_QWORD) {
        ERROR("MOVSXD without 64-bit register");
    }

    x86_prefixes_t empty_prefixes = {0}; // so that we only read32

    ir_instruction_t* rm = ir_emit_get_rm(state, &empty_prefixes, &inst->operand_rm);
    ir_instruction_t* serm = ir_emit_sext32(state, rm);
    ir_emit_set_reg(state, &inst->operand_reg, serm);
    
}

IR_HANDLE(jcc_rel) { // jcc rel8 - 0x70-0x7f
    ir_emit_jcc(state, inst);
}

IR_HANDLE(group1_rm32_imm32) { // add/or/adc/sbb/and/sub/xor/cmp rm16/32/64, imm16/32/64 - 0x81
    ir_emit_group1_imm(state, inst);
}

IR_HANDLE(group1_rm32_imm8) { // add/or/adc/sbb/and/sub/xor/cmp rm16/32/64, imm8 - 0x83
    ir_emit_group1_imm(state, inst);
}

IR_HANDLE(test_rm8_r8) { // test rm8, r8 - 0x84
    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->prefixes, &inst->operand_rm);
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_instruction_t* result = ir_emit_and(state, rm, reg);

    ir_instruction_t* zero = ir_emit_immediate(state, 0);
    ir_instruction_t* p = ir_emit_get_parity(state, result);
    ir_instruction_t* z = ir_emit_get_zero(state, result);
    ir_instruction_t* s = ir_emit_get_sign(state, &inst->prefixes, result);

    ir_emit_set_cpazso(state, zero, p, NULL, z, s, zero);
}

IR_HANDLE(test_rm32_r32) { // test rm16/32/64, r/m16/32/64 - 0x85
    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->prefixes, &inst->operand_rm);
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_instruction_t* result = ir_emit_and(state, rm, reg);

    ir_instruction_t* zero = ir_emit_immediate(state, 0);
    ir_instruction_t* p = ir_emit_get_parity(state, result);
    ir_instruction_t* z = ir_emit_get_zero(state, result);
    ir_instruction_t* s = ir_emit_get_sign(state, &inst->prefixes, result);

    ir_emit_set_cpazso(state, zero, p, NULL, z, s, zero);
}

IR_HANDLE(mov_rm32_r32) { // mov rm16/32/64, r16/32/64 - 0x89
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_emit_set_rm(state, &inst->prefixes, &inst->operand_rm, reg);
}

IR_HANDLE(mov_r32_rm32) { // mov r16/32/64, rm16/32/64 - 0x8b
    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->prefixes, &inst->operand_rm);
    ir_emit_set_reg(state, &inst->operand_reg, rm);
}

IR_HANDLE(lea) { // lea r32/64, m - 0x8d
    ir_instruction_t* address = ir_emit_lea(state, &inst->prefixes, &inst->operand_rm);
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_emit_set_reg(state, &inst->operand_reg, address);
}

IR_HANDLE(nop) {} // nop - 0x90

IR_HANDLE(xchg_reg_eax) { // xchg reg, eax - 0x91-0x97
    x86_operand_t eax_reg;
    eax_reg.type = X86_OP_TYPE_REGISTER;
    eax_reg.reg.ref = X86_REF_RAX;
    eax_reg.reg.size = inst->operand_reg.reg.size;

    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_instruction_t* eax = ir_emit_get_reg(state, &eax_reg);
    ir_emit_set_reg(state, &inst->operand_reg, eax);
    ir_emit_set_reg(state, &eax_reg, reg);
}

IR_HANDLE(test_al_imm8) { // test al, imm8 - 0xa8
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_instruction_t* imm = ir_emit_immediate(state, inst->operand_imm.immediate.data);
    ir_instruction_t* result = ir_emit_and(state, reg, imm);

    ir_instruction_t* zero = ir_emit_immediate(state, 0);
    ir_instruction_t* p = ir_emit_get_parity(state, result);
    ir_instruction_t* z = ir_emit_get_zero(state, result);
    ir_instruction_t* s = ir_emit_get_sign(state, &inst->prefixes, result);

    ir_emit_set_cpazso(state, zero, p, NULL, z, s, zero);
}

IR_HANDLE(stosd) { // stosd - 0xab
    x86_register_size_e size;
    int length;
    if (inst->prefixes.rex_w) {
        size = X86_REG_SIZE_QWORD;
        length = 8;
    } else if (inst->prefixes.operand_override) {
        size = X86_REG_SIZE_WORD;
        length = 2;
    } else {
        size = X86_REG_SIZE_DWORD;
        length = 4;
    }

    x86_operand_t rdi_reg;
    rdi_reg.type = X86_OP_TYPE_REGISTER;
    rdi_reg.reg.ref = X86_REF_RDI;
    rdi_reg.reg.size = inst->prefixes.address_override ? X86_REG_SIZE_DWORD : X86_REG_SIZE_QWORD;

    x86_operand_t rax_reg;
    rax_reg.type = X86_OP_TYPE_REGISTER;
    rax_reg.reg.ref = X86_REF_RAX;
    rax_reg.reg.size = size;

    ir_instruction_t* rdi = ir_emit_get_reg(state, &rdi_reg);
    ir_instruction_t* rax = ir_emit_get_reg(state, &rax_reg);
    
    ir_emit_write_memory(state, &inst->prefixes, rdi, rax);
    
    // Assume DF is 0 for now
    ir_instruction_t* rdi_add = ir_emit_add(state, rdi, ir_emit_immediate(state, length));
    ir_emit_set_reg(state, &rdi_reg, rdi_add);
    
    if (inst->prefixes.rep_z_f3) {
        x86_operand_t rcx_reg;
        rcx_reg.type = X86_OP_TYPE_REGISTER;
        rcx_reg.reg.ref = X86_REF_RCX;
        rcx_reg.reg.size = size;

        ir_instruction_t* rcx = ir_emit_get_reg(state, &rcx_reg);
        ir_instruction_t* zero = ir_emit_immediate(state, 0);
        ir_instruction_t* condition = ir_emit_equal(state, rcx, zero);
        ir_instruction_t* jump_address_false = ir_emit_immediate(state, state->current_address); // jump to start of instruction
        ir_instruction_t* jump_address_true = ir_emit_add(state, jump_address_false, ir_emit_immediate(state, inst->length)); // jump to next instruction
        ir_instruction_t* jump = ir_emit_ternary(state, condition, jump_address_true, jump_address_false);

        ir_instruction_t* one = ir_emit_immediate(state, 1);
        ir_instruction_t* rcx_sub = ir_emit_sub(state, rcx, ir_emit_xor(state, condition, one)); // sub one if condition is false
        ir_emit_set_reg(state, &rcx_reg, rcx_sub);

        ir_emit_set_guest(state, X86_REF_RIP, jump);

        state->exit = true;
    } else {
        ERROR("Unimplemented REP mode for STOSD");
    }
}

IR_HANDLE(mov_r8_imm8) { // mov r8, imm8 - 0xb0-0xb7
    ir_instruction_t* imm = ir_emit_immediate(state, inst->operand_imm.immediate.data);
    ir_emit_set_reg(state, &inst->operand_reg, imm);
}

IR_HANDLE(mov_r32_imm32) { // mov r16/32/64, imm16/32/64 - 0xb8-0xbf
    ir_instruction_t* imm = ir_emit_immediate(state, inst->operand_imm.immediate.data);
    ir_emit_set_reg(state, &inst->operand_reg, imm);
}

IR_HANDLE(group2_rm8_imm8) { // rol/ror/rcl/rcr/shl/shr/sal/sar rm8, imm8 - 0xc0
    ir_emit_group2_imm(state, inst);
}

IR_HANDLE(ret) { // ret - 0xc3
    ir_instruction_t* rsp = ir_emit_get_guest(state, X86_REF_RSP);
    ir_instruction_t* size = ir_emit_immediate(state, 8);
    ir_instruction_t* rip = ir_emit_read_qword(state, rsp);
    ir_instruction_t* rsp_add = ir_emit_add(state, rsp, size);
    ir_emit_set_guest(state, X86_REF_RSP, rsp_add);
    ir_emit_set_guest(state, X86_REF_RIP, rip);

    state->exit = true;
}

IR_HANDLE(mov_rm8_imm8) { // mov rm8, imm8 - 0xc6
    ir_instruction_t* imm = ir_emit_immediate(state, inst->operand_imm.immediate.data);
    ir_emit_set_rm(state, &inst->prefixes, &inst->operand_rm, imm);
}

IR_HANDLE(mov_rm32_imm32) { // mov rm16/32/64, imm16/32/64 - 0xc7
    ir_instruction_t* imm = ir_emit_immediate_sext(state, &inst->operand_imm);
    ir_emit_set_rm(state, &inst->prefixes, &inst->operand_rm, imm);
}

IR_HANDLE(leave) { // leave - 0xc9
    x86_register_size_e size = X86_REG_SIZE_QWORD;
    if (inst->prefixes.operand_override) {
        size = X86_REG_SIZE_WORD;
    }

    x86_operand_t rbp_reg;
    rbp_reg.type = X86_OP_TYPE_REGISTER;
    rbp_reg.reg.ref = X86_REF_RBP;
    rbp_reg.reg.size = size;

    x86_operand_t rsp_reg;
    rsp_reg.type = X86_OP_TYPE_REGISTER;
    rsp_reg.reg.ref = X86_REF_RSP;
    rsp_reg.reg.size = size;

    ir_instruction_t* rbp = ir_emit_get_reg(state, &rbp_reg);

    ir_instruction_t* popped_value = size == X86_REG_SIZE_WORD ? ir_emit_read_word(state, rbp) : ir_emit_read_qword(state, rbp);
    ir_instruction_t* imm = ir_emit_immediate(state, size == X86_REG_SIZE_WORD ? 2 : 8);
    ir_instruction_t* rbp_add = ir_emit_add(state, rbp, imm);

    if (size == X86_REG_SIZE_WORD) {
        ir_emit_set_gpr16(state, X86_REF_RBP, popped_value);
        ir_emit_set_gpr16(state, X86_REF_RSP, rbp_add);
    } else {
        ir_emit_set_gpr64(state, X86_REF_RBP, popped_value);
        ir_emit_set_gpr64(state, X86_REF_RSP, rbp_add);
    }
}

IR_HANDLE(call_rel32) { // call rel32 - 0xe8
    u64 displacement = (i64)(i32)inst->operand_imm.immediate.data;
    u64 jump_address = state->current_address + inst->length + displacement;
    u64 returnAddress = state->current_address + inst->length;
    ir_instruction_t* rip = ir_emit_immediate(state, jump_address);
    ir_instruction_t* returnRip = ir_emit_immediate(state, returnAddress);
    ir_instruction_t* rsp = ir_emit_get_guest(state, X86_REF_RSP);
    ir_instruction_t* size = ir_emit_immediate(state, 8);
    ir_instruction_t* rsp_sub = ir_emit_sub(state, rsp, size);
    ir_emit_write_qword(state, rsp_sub, returnRip);
    ir_emit_set_guest(state, X86_REF_RSP, rsp_sub);
    ir_emit_set_guest(state, X86_REF_RIP, rip);

    state->exit = true;
}

IR_HANDLE(jmp_rel32) { // jmp rel32 - 0xe9
    u64 displacement = (i64)(i32)inst->operand_imm.immediate.data;
    u64 jump_address = state->current_address + inst->length + displacement;
    ir_instruction_t* rip = ir_emit_immediate(state, jump_address);
    ir_emit_set_guest(state, X86_REF_RIP, rip);

    state->exit = true;
}

IR_HANDLE(jmp_rel8) { // jmp rel8 - 0xeb
    u64 displacement = (i64)(i8)inst->operand_imm.immediate.data;
    u64 jump_address = state->current_address + inst->length + displacement;
    ir_instruction_t* rip = ir_emit_immediate(state, jump_address);
    ir_emit_set_guest(state, X86_REF_RIP, rip);

    state->exit = true;
}

IR_HANDLE(hlt) { // hlt - 0xf4
    if (!state->testing) {
        ERROR("Hit HLT instruction during: %016lx", state->current_address);
    } else {
        state->exit = true;
    }
}

IR_HANDLE(group3_rm8) { // test/not/neg/mul/imul/div/idiv rm8, imm8 - 0xf6
    ir_emit_group3_imm(state, inst);
}

IR_HANDLE(group3_rm32) { // test/not/neg/mul/imul/div/idiv rm16/32/64, imm32 - 0xf7
    ir_emit_group3_imm(state, inst);
}

IR_HANDLE(inc_dec_rm8) { // inc/dec rm8 - 0xfe
    u8 opcode = inst->operand_reg.reg.ref - X86_REF_RAX;

    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->prefixes, &inst->operand_rm);
    ir_instruction_t* one = ir_emit_immediate(state, 1);
    ir_instruction_t* result = NULL;
    ir_instruction_t* c = NULL;
    ir_instruction_t* o = NULL;
    ir_instruction_t* a = NULL;

    if (opcode == 0) {
        result = ir_emit_add(state, rm, one);
        o = ir_emit_get_overflow_add(state, &inst->prefixes, rm, one, result);
        a = ir_emit_get_aux_add(state, rm, one);
    } else if (opcode == 1) {
        result = ir_emit_sub(state, rm, one);
        o = ir_emit_get_overflow_sub(state, &inst->prefixes, rm, one, result);
        a = ir_emit_get_aux_sub(state, rm, one);
    } else {
        ERROR("Unknown opcode for inc_dec_rm8: %02x", opcode);
    }

    ir_instruction_t* p = ir_emit_get_parity(state, result);
    ir_instruction_t* z = ir_emit_get_zero(state, result);
    ir_instruction_t* s = ir_emit_get_sign(state, &inst->prefixes, result);

    ir_emit_set_cpazso(state, c, p, a, z, s, o);
    ir_emit_set_rm(state, &inst->prefixes, &inst->operand_rm, result);
}

// ███████ ███████  ██████  ██████  ███    ██ ██████   █████  ██████  ██    ██ 
// ██      ██      ██      ██    ██ ████   ██ ██   ██ ██   ██ ██   ██  ██  ██  
// ███████ █████   ██      ██    ██ ██ ██  ██ ██   ██ ███████ ██████    ████   
//      ██ ██      ██      ██    ██ ██  ██ ██ ██   ██ ██   ██ ██   ██    ██    
// ███████ ███████  ██████  ██████  ██   ████ ██████  ██   ██ ██   ██    ██    

IR_HANDLE(syscall) { // syscall - 0x0f 0x05
    ir_emit_syscall(state);
}

IR_HANDLE(cmovcc) { // cmovcc - 0x0f 0x40-0x4f
    ir_emit_cmovcc(state, inst);
}

IR_HANDLE(movq_xmm_rm32) { // movq xmm, rm32 - 0x0f 0x6e
    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->prefixes, &inst->operand_rm);
    ir_instruction_t* reg = ir_emit_get_reg(state, &inst->operand_reg);
    ir_instruction_t* vector = ir_emit_insert_integer_to_vector(state, reg, rm, inst->prefixes.rex_w ? X86_REG_SIZE_QWORD : X86_REG_SIZE_DWORD, 0);
    ir_emit_set_guest(state, inst->operand_reg.reg.ref, vector);
}

IR_HANDLE(setcc) { // setcc - 0x0f 0x90-0x9f
    ir_emit_setcc(state, inst);
}

IR_HANDLE(cpuid) { // cpuid - 0x0f 0xa2
    ir_emit_cpuid(state);
}

IR_HANDLE(movzx_r32_rm8) { // movzx r32/64, rm8 - 0x0f 0xb6
    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->prefixes, &inst->operand_rm);
    ir_emit_set_gpr64(state, inst->operand_reg.reg.ref, rm);
}

IR_HANDLE(movzx_r32_rm16) { // movzx r32/64, rm16 - 0x0f 0xb7
    ir_instruction_t* rm = ir_emit_get_rm(state, &inst->prefixes, &inst->operand_rm);
    ir_emit_set_gpr64(state, inst->operand_reg.reg.ref, rm);
}