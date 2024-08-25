#include "felix86/ir/interpreter.h"
#include "felix86/common/log.h"
#include "felix86/common/utility.h"
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static u64 temps[4096] = {0};
static xmm_reg_t xmm_temps[256] = {0};

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
                case X86_REF_XMM0 ... X86_REF_XMM31: {
                    xmm_temps[instruction->name] = state->xmm[instruction->get_guest.ref - X86_REF_XMM0];
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
                case X86_REF_XMM0 ... X86_REF_XMM31: {
                    state->xmm[instruction->set_guest.ref - X86_REF_XMM0] = xmm_temps[instruction->set_guest.source->name];
                    break;
                }
                case X86_REF_RIP: {
                    state->rip = temps[instruction->set_guest.source->name];
                    break;
                }
                case X86_REF_FLAGS: {
                    state->flags = temps[instruction->set_guest.source->name];
                    break;
                }
                case X86_REF_FS: {
                    state->fs = temps[instruction->set_guest.source->name];
                    break;
                }
                case X86_REF_GS: {
                    state->gs = temps[instruction->set_guest.source->name];
                    break;
                }
                default: {
                    ERROR("Invalid GPR reference");
                    break;
                }
            }
            break;
        }
        case IR_INSERT_INTEGER_TO_VECTOR: {
            xmm_reg_t xmm = xmm_temps[instruction->two_operand_immediates.source1->name];
            u32 index = instruction->two_operand_immediates.imm32_1;
            switch (instruction->two_operand_immediates.imm32_2) {
                case X86_REG_SIZE_BYTE_LOW: {
                    if (index > 63) {
                        ERROR("Invalid index");
                    }

                    u8* data = (u8*)&xmm.data[index];
                    *data = (u8)temps[instruction->two_operand_immediates.source2->name];
                    xmm_temps[instruction->name] = xmm;
                    break;
                }
                case X86_REG_SIZE_WORD: {
                    if (index > 31) {
                        ERROR("Invalid index");
                    }

                    u16* data = (u16*)&xmm.data[index];
                    *data = (u16)temps[instruction->two_operand_immediates.source2->name];
                    xmm_temps[instruction->name] = xmm;
                    break;
                }
                case X86_REG_SIZE_DWORD: {
                    if (index > 15) {
                        ERROR("Invalid index");
                    }

                    u32* data = (u32*)&xmm.data[index];
                    *data = (u32)temps[instruction->two_operand_immediates.source2->name];
                    xmm_temps[instruction->name] = xmm;
                    break;
                }
                case X86_REG_SIZE_QWORD: {
                    if (index > 7) {
                        ERROR("Invalid index");
                    }

                    u64* data = (u64*)&xmm.data[index];
                    *data = temps[instruction->two_operand_immediates.source2->name];
                    xmm_temps[instruction->name] = xmm;
                    break;
                }
                default: ERROR("Invalid size"); break;
            }
            break;
        }
        case IR_EXTRACT_INTEGER_FROM_VECTOR: {
            xmm_reg_t xmm = xmm_temps[instruction->two_operand_immediates.source1->name];
            u32 index = instruction->two_operand_immediates.imm32_1;
            switch (instruction->two_operand_immediates.imm32_2) {
                case X86_REG_SIZE_BYTE_LOW: {
                    if (index > 63) {
                        ERROR("Invalid index");
                    }

                    u8* data = (u8*)&xmm.data[index];
                    temps[instruction->name] = *data;
                    break;
                }
                case X86_REG_SIZE_WORD: {
                    if (index > 31) {
                        ERROR("Invalid index");
                    }

                    u16* data = (u16*)&xmm.data[index];
                    temps[instruction->name] = *data;
                    break;
                }
                case X86_REG_SIZE_DWORD: {
                    if (index > 15) {
                        ERROR("Invalid index");
                    }

                    u32* data = (u32*)&xmm.data[index];
                    temps[instruction->name] = *data;
                    break;
                }
                case X86_REG_SIZE_QWORD: {
                    if (index > 7) {
                        ERROR("Invalid index");
                    }

                    u64* data = (u64*)&xmm.data[index];
                    temps[instruction->name] = *data;
                    break;
                }
                default: ERROR("Invalid size"); break;
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
            u64 base = instruction->two_operand_immediates.source1 ? temps[instruction->two_operand_immediates.source1->name] : 0;
            u64 index = instruction->two_operand_immediates.source2 ? temps[instruction->two_operand_immediates.source2->name] : 0;
            u64 displacement = (i64)(i32)instruction->two_operand_immediates.imm32_1;
            u64 scale = instruction->two_operand_immediates.imm32_2;
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
            *(u8*)(temps[instruction->two_operand.source1->name]) = temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_WRITE_WORD: {
            *(u16*)(temps[instruction->two_operand.source1->name]) = temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_WRITE_DWORD: {
            *(u32*)(temps[instruction->two_operand.source1->name]) = temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_WRITE_QWORD: {
            *(u64*)(temps[instruction->two_operand.source1->name]) = temps[instruction->two_operand.source2->name];
            break;
        }
        case IR_START_OF_BLOCK: {
            break;
        }
        case IR_SEXT_GPR8: {
            temps[instruction->name] = (i64)(i8)temps[instruction->one_operand.source->name];
            break;
        }
        case IR_SEXT_GPR16: {
            temps[instruction->name] = (i64)(i16)temps[instruction->one_operand.source->name];
            break;
        }
        case IR_SEXT_GPR32: {
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
        case IR_SYSCALL: {
            u64 opcode = state->gprs[0];
            u64 arg1 = state->gprs[X86_REF_RDI - X86_REF_RAX];
            u64 arg2 = state->gprs[X86_REF_RSI - X86_REF_RAX];
            u64 arg3 = state->gprs[X86_REF_RDX - X86_REF_RAX];
            u64 arg4 = state->gprs[X86_REF_R10 - X86_REF_RAX];
            u64 arg5 = state->gprs[X86_REF_R8 - X86_REF_RAX];
            u64 arg6 = state->gprs[X86_REF_R9 - X86_REF_RAX];
            VERBOSE("Syscall number: %016lx", opcode);
            VERBOSE("Syscall argument 1: %016lx", arg1);
            VERBOSE("Syscall argument 2: %016lx", arg2);
            VERBOSE("Syscall argument 3: %016lx", arg3);
            VERBOSE("Syscall argument 4: %016lx", arg4);
            VERBOSE("Syscall argument 5: %016lx", arg5);
            VERBOSE("Syscall argument 6: %016lx", arg6);
            syscall(opcode, arg1, arg2, arg3, arg4, arg5, arg6);
            break;
        }
        case IR_TERNARY: {
            bool condition = temps[instruction->ternary.condition->name];
            temps[instruction->name] = condition ? temps[instruction->ternary.true_value->name] : temps[instruction->ternary.false_value->name];
            break;
        }
        case IR_DEBUG_RUNTIME: {
            LOG("Debug message: %s", instruction->debug.text);
            break;
        }
        case IR_DEBUG_COMPILETIME: {
            LOG("Debug message: %s", instruction->debug.text);
            break;
        }
        default: {
            ERROR("Invalid opcode");
            break;
        }
    }
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