#include "felix86/ir/interpreter.h"
#include "felix86/common/log.h"
#include "felix86/common/utility.h"
#include <string.h>

static u64 temps[4096] = {0};

void ir_interpret_instruction(ir_instruction_t* instruction, x86_state_t* state)
{
    switch (instruction->opcode) {
        case IR_NULL: {
            ERROR("Interpreting null, this should not happen\n");
            break;
        }
        case IR_GET_GUEST: {
            switch (instruction->get_guest.ref) {
                case X86_REF_RAX ... X86_REF_R15: {
                    temps[instruction->name] = state->gprs[instruction->get_guest.ref - X86_REF_RAX];
                    break;
                }
                case X86_REF_RIP: {
                    temps[instruction->name] = state->rip;
                    break;
                }
                case X86_REF_FLAGS: {
                    temps[instruction->name] = state->flags;
                    break;
                }
                case X86_REF_FS: {
                    temps[instruction->name] = state->fs;
                    break;
                }
                case X86_REF_GS: {
                    temps[instruction->name] = state->gs;
                    break;
                }
                default: {
                    ERROR("Invalid GPR reference");
                    break;
                }
            }
            break;
        }
        case IR_SET_GUEST: {
            switch (instruction->set_guest.ref) {
                case X86_REF_RAX ... X86_REF_R15: {
                    state->gprs[instruction->set_guest.ref - X86_REF_RAX] = temps[instruction->set_guest.source->name];
                    break;
                }
                case X86_REF_RIP: {
                    state->rip = temps[instruction->name];
                    break;
                }
                case X86_REF_FLAGS: {
                    state->flags = temps[instruction->name];
                    break;
                }
                case X86_REF_FS: {
                    state->fs = temps[instruction->name];
                    break;
                }
                case X86_REF_GS: {
                    state->gs = temps[instruction->name];
                    break;
                }
                default: {
                    ERROR("Invalid GPR reference");
                    break;
                }
            }
            break;
        }
        case IR_ADD: {
            temps[instruction->name] = temps[instruction->two_operand.source1->name] + temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_SUB: {
            temps[instruction->name] = temps[instruction->two_operand.source1->name] - temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_AND: {
            temps[instruction->name] = temps[instruction->two_operand.source1->name] & temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_OR: {
            temps[instruction->name] = temps[instruction->two_operand.source1->name] | temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_XOR: {
            temps[instruction->name] = temps[instruction->two_operand.source1->name] ^ temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_LEFT_SHIFT: {
            temps[instruction->name] = temps[instruction->two_operand.source1->name] << temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_RIGHT_SHIFT: {
            temps[instruction->name] = temps[instruction->two_operand.source1->name] >> temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_RIGHT_SHIFT_ARITHMETIC: {
            temps[instruction->name] = (i64)temps[instruction->two_operand.source1->name] >> temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_EQUAL: {
            temps[instruction->name] = temps[instruction->two_operand.source1->name] == temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_NOT_EQUAL: {
            temps[instruction->name] = temps[instruction->two_operand.source1->name] != temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_GREATER_THAN_SIGNED: {
            temps[instruction->name] = (i64)temps[instruction->two_operand.source1->name] > (i64)temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_LESS_THAN_SIGNED: {
            temps[instruction->name] = (i64)temps[instruction->two_operand.source1->name] < (i64)temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_GREATER_THAN_UNSIGNED: {
            temps[instruction->name] = temps[instruction->two_operand.source1->name] > temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_LESS_THAN_UNSIGNED: {
            temps[instruction->name] = temps[instruction->two_operand.source1->name] < temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_LEA: {
            u64 base = instruction->lea.base ? temps[instruction->lea.base->name] : 0;
            u64 index = instruction->lea.index ? temps[instruction->lea.index->name] : 0;
            u64 scale = instruction->lea.scale;
            u64 displacement = instruction->lea.displacement;
            temps[instruction->name] = base + index * scale + displacement;
            break;
        }
        case IR_READ_BYTE: {
            temps[instruction->name] = *(u8*)(temps[instruction->one_operand.source->name]);
            break;
        }
        case IR_READ_WORD: {
            temps[instruction->name] = *(u16*)(temps[instruction->one_operand.source->name]);
            break;
        }
        case IR_READ_DWORD: {
            temps[instruction->name] = *(u32*)(temps[instruction->one_operand.source->name]);
            break;
        }
        case IR_READ_QWORD: {
            temps[instruction->name] = *(u64*)(temps[instruction->one_operand.source->name]);
            break;
        }
        case IR_WRITE_BYTE: {
            *(u8*)(temps[instruction->one_operand.source->name]) = temps[instruction->one_operand.source->name];
            break;
        }
        case IR_WRITE_WORD: {
            *(u16*)(temps[instruction->one_operand.source->name]) = temps[instruction->one_operand.source->name];
            break;
        }
        case IR_WRITE_DWORD: {
            *(u32*)(temps[instruction->one_operand.source->name]) = temps[instruction->one_operand.source->name];
            break;
        }
        case IR_WRITE_QWORD: {
            *(u64*)(temps[instruction->one_operand.source->name]) = temps[instruction->one_operand.source->name];
            break;
        }
        case IR_START_OF_BLOCK: {
            break;
        }
        case IR_SEXT8: {
            temps[instruction->name] = (i64)(i8)temps[instruction->one_operand.source->name];
            break;
        }
        case IR_SEXT16: {
            temps[instruction->name] = (i64)(i16)temps[instruction->one_operand.source->name];
            break;
        }
        case IR_SEXT32: {
            temps[instruction->name] = (i64)(i32)temps[instruction->one_operand.source->name];
            break;
        }
        case IR_POPCOUNT: {
            temps[instruction->name] = __builtin_popcountll(temps[instruction->one_operand.source->name]);
            break;
        }
        case IR_GET_FLAG: {
            temps[instruction->name] = (state->flags >> instruction->get_flag.flag) & 1;
            break;
        }
        case IR_MOV: {
            ERROR("Interpreting MOV, this should not happen\n");
            break;
        }
        case IR_IMMEDIATE: {
            temps[instruction->name] = instruction->load_immediate.immediate;
            break;
        }
        case IR_SET_FLAG: {
            if (temps[instruction->set_flag.source->name] & ~1) {
                ERROR("Invalid flag value");
            }

            state->flags &= ~(1 << instruction->set_flag.flag);
            state->flags |= temps[instruction->set_flag.source->name] << instruction->set_flag.flag;
            break;
        }
        default: {
            ERROR("Invalid opcode");
            break;
        }
    }
    // printf("t%d = %016lx\n", instruction->name, temps[instruction->name]);
}

void ir_interpret_block(ir_block_t* block, x86_state_t* state)
{
    memset(temps, 0, sizeof(temps));
    ir_instruction_list_t* current = block->instructions;
    while (current) {
        ir_interpret_instruction(&current->instruction, state);
        current = current->next;
    }
}