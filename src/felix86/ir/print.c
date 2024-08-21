#include "felix86/ir/print.h"

#include <stdio.h>

void print_guest(x86_ref_t guest) {
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
        case X86_REF_FLAGS: printf("flags"); break;
        case X86_REF_RIP: printf("rip"); break;
        case X86_REF_FS: printf("fs"); break;
        case X86_REF_GS: printf("gs"); break;
        default: printf("Unknown guest"); break;
    }
}

void print_flag(x86_flag_t flag) {
    switch (flag) {
        case X86_FLAG_CF: printf("CF"); break;
        case X86_FLAG_PF: printf("PF"); break;
        case X86_FLAG_AF: printf("AF"); break;
        case X86_FLAG_ZF: printf("ZF"); break;
        case X86_FLAG_SF: printf("SF"); break;
        case X86_FLAG_OF: printf("OF"); break;
    }
}

void print_one_op(ir_instruction_t* instruction, const char* op) {
    printf("t%d = %s(t%d)", instruction->name, op, instruction->one_operand.source->name);
}

void print_two_op(ir_instruction_t* instruction, const char* op) {
    printf("t%d = t%d %s t%d", instruction->name, instruction->two_operand.source1->name, op, instruction->two_operand.source2->name);
}

void ir_print_instruction(ir_instruction_t* instruction) {
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
        case IR_GREATER_THAN: {
            print_two_op(instruction, ">");
            break;
        }
        case IR_MOV: {
            printf("t%d = t%d", instruction->name, instruction->one_operand.source->name);
            break;
        }
        case IR_SEXT8: {
            print_one_op(instruction, "sext8");
            break;
        }
        case IR_SEXT16: {
            print_one_op(instruction, "sext16");
            break;
        }
        case IR_SEXT32: {
            print_one_op(instruction, "sext32");
            break;
        }
        case IR_LEA: {
            printf("t%d = [", instruction->name);
            if (instruction->lea.base) {
                printf("t%d", instruction->lea.base->name);

                if (instruction->lea.index || instruction->lea.displacement != 0) {
                    printf(" + ");
                }
            }

            if (instruction->lea.index) {
                printf("t%d * %d", instruction->lea.index->name, instruction->lea.scale);

                if (instruction->lea.displacement != 0) {
                    printf(" + ");
                }
            }

            if (instruction->lea.displacement != 0) {
                printf("0x%x", instruction->lea.displacement);
            }
            
            printf("]");

            break;
        }
        case IR_GET_GUEST: {
            printf("t%d = get_guest(", instruction->name);
            print_guest(instruction->get_guest.ref);
            printf(")");
            break;
        }
        case IR_SET_GUEST: {
            printf("set_guest(");
            print_guest(instruction->set_guest.ref);
            printf(", t%d)", instruction->set_guest.source->name);
            break;
        }
        case IR_GET_FLAG: {
            printf("t%d = get_flag(", instruction->name);
            print_flag(instruction->get_flag.flag);
            printf(")");
            break;
        }
        case IR_SET_FLAG: {
            printf("set_flag(");
            print_flag(instruction->set_flag.flag);
            printf(", t%d)", instruction->set_flag.source->name);
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
            printf("start_of_block");
            break;
        }
        default: {
            printf("Unknown opcode: %d", instruction->opcode);
            break;
        }
    }

    // printf("\t\t(uses: %d)", instruction->uses);
    printf("\n");
}

void ir_print_block(ir_block_t* block) {
    ir_instruction_list_t* node = block->instructions;
    while (node) {
        ir_print_instruction(&node->instruction);
        node = node->next;
    }
}