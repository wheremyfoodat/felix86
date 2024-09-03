#include "felix86/ir/print.h"
#include "felix86/common/log.h"

#include <stdio.h>

void print_guest(x86_ref_e guest) {
    switch (guest) {
        case X86_REF_RAX: printf("rax"); break;
        case X86_REF_RCX: printf("rcx"); break;
        case X86_REF_RDX: printf("rdx"); break;
        case X86_REF_RBX: printf("rbx"); break;
        case X86_REF_RSP: printf("rsp"); break;
        case X86_REF_RBP: printf("rbp"); break;
        case X86_REF_RSI: printf("rsi"); break;
        case X86_REF_RDI: printf("rdi"); break;
        case X86_REF_R8: printf("r8"); break;
        case X86_REF_R9: printf("r9"); break;
        case X86_REF_R10: printf("r10"); break;
        case X86_REF_R11: printf("r11"); break;
        case X86_REF_R12: printf("r12"); break;
        case X86_REF_R13: printf("r13"); break;
        case X86_REF_R14: printf("r14"); break;
        case X86_REF_R15: printf("r15"); break;
        case X86_REF_CF: printf("cf"); break;
        case X86_REF_PF: printf("pf"); break;
        case X86_REF_AF: printf("af"); break;
        case X86_REF_ZF: printf("zf"); break;
        case X86_REF_SF: printf("sf"); break;
        case X86_REF_OF: printf("of"); break;
        case X86_REF_RIP: printf("rip"); break;
        case X86_REF_FS: printf("fs"); break;
        case X86_REF_GS: printf("gs"); break;
        case X86_REF_XMM0 ... X86_REF_XMM31: printf("xmm%d", guest - X86_REF_XMM0); break;
        default: printf("Unknown guest"); break;
    }
}

void print_one_op(ir_instruction_t* instruction, const char* op) {
    printf("t%d = %s t%d", instruction->name, op, instruction->one_operand.source->name);
}

void print_two_op(ir_instruction_t* instruction, const char* op) {
    printf("t%d = t%d %s t%d", instruction->name, instruction->two_operand.source1->name, op, instruction->two_operand.source2->name);
}

void ir_print_instruction(ir_instruction_t* instruction, ir_block_t* block) {
    switch (instruction->opcode) {
        case IR_IMMEDIATE: {
            printf("t%d = 0x%0llx", instruction->name, (unsigned long long)instruction->load_immediate.immediate);
            break;
        }
        case IR_ADD: {
            print_two_op(instruction, "+");
            break;
        }
        case IR_SUB: {
            print_two_op(instruction, "-");
            break;
        }
        case IR_LEFT_SHIFT: {
            print_two_op(instruction, "<<");
            break;
        }
        case IR_RIGHT_SHIFT: {
            print_two_op(instruction, ">>");
            break;
        }
        case IR_RIGHT_SHIFT_ARITHMETIC: {
            print_two_op(instruction, ">>");
            break;
        }
        case IR_AND: {
            print_two_op(instruction, "&");
            break;
        }
        case IR_OR: {
            print_two_op(instruction, "|");
            break;
        }
        case IR_XOR: {
            print_two_op(instruction, "^");
            break;
        }
        case IR_POPCOUNT: {
            print_one_op(instruction, "popcount");
            break;
        }
        case IR_EQUAL: {
            print_two_op(instruction, "==");
            break;
        }
        case IR_NOT_EQUAL: {
            print_two_op(instruction, "!=");
            break;
        }
        case IR_GREATER_THAN_SIGNED: {
            print_two_op(instruction, "s>");
            break;
        }
        case IR_LESS_THAN_SIGNED: {
            print_two_op(instruction, "s<");
            break;
        }
        case IR_GREATER_THAN_UNSIGNED: {
            print_two_op(instruction, "u>");
            break;
        }
        case IR_LESS_THAN_UNSIGNED: {
            print_two_op(instruction, "u<");
            break;
        }
        case IR_MOV: {
            printf("t%d = t%d", instruction->name, instruction->one_operand.source->name);
            break;
        }
        case IR_SEXT_GPR8: {
            print_one_op(instruction, "sext8");
            break;
        }
        case IR_SEXT_GPR16: {
            print_one_op(instruction, "sext16");
            break;
        }
        case IR_SEXT_GPR32: {
            print_one_op(instruction, "sext32");
            break;
        }
        case IR_LEA: {
            printf("t%d = [", instruction->name);
            if (instruction->two_operand_immediates.source1) {
                printf("t%d", instruction->two_operand_immediates.source1->name);

                if (instruction->two_operand_immediates.source2 || instruction->two_operand_immediates.imm64_1 != 0) {
                    printf(" + ");
                }
            }

            if (instruction->two_operand_immediates.source2) {
                printf("t%d * %d", instruction->two_operand_immediates.source2->name, instruction->two_operand_immediates.imm64_2);

                if (instruction->two_operand_immediates.imm64_1 != 0) {
                    printf(" + ");
                }
            }

            if (instruction->two_operand_immediates.imm64_1 != 0) {
                printf("%lld", (long long)(i64)(i32)instruction->two_operand_immediates.imm64_1);
            }
            
            printf("]");

            break;
        }
        case IR_GET_GUEST: {
            printf("t%d = get_guest ", instruction->name);
            print_guest(instruction->get_guest.ref);
            break;
        }
        case IR_SET_GUEST: {
            printf("t%d = set_guest ", instruction->name);
            print_guest(instruction->set_guest.ref);
            printf(", t%d", instruction->set_guest.source->name);
            break;
        }
        case IR_READ_BYTE: {
            printf("t%d = byte[t%d]", instruction->name, instruction->one_operand.source->name);
            break;
        }
        case IR_READ_WORD: {
            printf("t%d = word[t%d]", instruction->name, instruction->one_operand.source->name);
            break;
        }
        case IR_READ_DWORD: {
            printf("t%d = dword[t%d]", instruction->name, instruction->one_operand.source->name);
            break;
        }
        case IR_READ_QWORD: {
            printf("t%d = qword[t%d]", instruction->name, instruction->one_operand.source->name);
            break;
        }
        case IR_WRITE_BYTE: {
            printf("byte[t%d] = t%d", instruction->two_operand.source1->name, instruction->two_operand.source2->name);
            break;
        }
        case IR_WRITE_WORD: {
            printf("word[t%d] = t%d", instruction->two_operand.source1->name, instruction->two_operand.source2->name);
            break;
        }
        case IR_WRITE_DWORD: {
            printf("dword[t%d] = t%d", instruction->two_operand.source1->name, instruction->two_operand.source2->name);
            break;
        }
        case IR_WRITE_QWORD: {
            printf("qword[t%d] = t%d", instruction->two_operand.source1->name, instruction->two_operand.source2->name);
            break;
        }
        case IR_START_OF_BLOCK: {
            break;
        }
        case IR_SYSCALL: {
            printf("syscall");
            break;
        }
        case IR_CPUID: {
            printf("cpuid");
            break;
        }
        case IR_JUMP: {
            printf("jump %016lx", instruction->jump.target->start_address);
            break;
        }
        case IR_EXIT: {
            printf("exit");
            break;
        }
        case IR_PHI: {
            printf("t%d = φ<", instruction->name);
            ir_phi_node_t* node = instruction->phi.list;
            while (node) {
                if (!node->value || !node->block) {
                    printf("NULL");
                } else {
                    printf("t%d @ %016lx", node->value->name, node->block->start_address);
                }
                node = node->next;
                if (node) {
                    printf(", ");
                }
            }
            printf(">");
            break;
        }
        case IR_JUMP_CONDITIONAL: {
            printf("jump t%d ? %016lx : %016lx", instruction->jump_conditional.condition->name, instruction->jump_conditional.target_true->start_address, instruction->jump_conditional.target_false->start_address);
            break;
        }
        case IR_INSERT_INTEGER_TO_VECTOR: {
            printf("x%d = insert_integer_to_vector(t%d, index=%d, size=%d)", instruction->two_operand_immediates.source1->name, instruction->two_operand_immediates.source2->name, instruction->two_operand_immediates.imm64_1, instruction->two_operand_immediates.imm64_2);
            break;
        }
        case IR_LOAD_GUEST_FROM_MEMORY: {
            printf("t%d = load_guest_from_memory ", instruction->name);
            print_guest(instruction->get_guest.ref);
            break;
        }
        case IR_STORE_GUEST_TO_MEMORY: {
            printf("store_guest_to_memory ");
            print_guest(instruction->set_guest.ref);
            printf(", t%d", instruction->set_guest.source->name);
            break;
        }
        default: {
            printf("Unknown opcode: %d", instruction->opcode);
            break;
        }
    }

    printf("\t\t\t\t(uses: %d)", instruction->uses);
    printf("\n");
}

void ir_print_block(ir_block_t* block) {
    ir_instruction_list_t* node = block->instructions;
    while (node) {
        ir_print_instruction(&node->instruction, block);
        node = node->next;
    }
}

void ir_print_function_uml(ir_function_t* function) {
    printf("@startuml\n");
    ir_block_list_t* block = function->first;
    while (block) {
        printf("class block_%016lx {\n", block->block->start_address);
        ir_block_t* b = block->block;
        ir_print_block(b);
        printf("}\n");
        ir_block_list_t* successor = b->successors;
        while (successor) {
            printf("block_%016lx --> block_%016lx\n", b->start_address, successor->block->start_address);
            successor = successor->next;
        }
        block = block->next;
    }
    printf("hide class circle\n");
    printf("@enduml\n");
}