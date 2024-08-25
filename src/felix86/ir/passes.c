#include "felix86/common/utility.h"
#include "felix86/ir/passes.h"
#include <stddef.h>
#include <stdio.h>

void ir_naming_pass(ir_block_t* block) {
    ir_instruction_list_t* current = block->instructions->next;
    u32 name = 0;
    while (current) {
        current->instruction.name = name++;
        current = current->next;
    }
}

void ir_dead_store_elimination_pass(ir_block_t* block) {
    ir_instruction_list_t* current = block->instructions->next;

    ir_instruction_list_t* set_flags[16] = {0};
    bool set_regs_used[X86_REF_COUNT] = {0};
    ir_instruction_list_t* set_regs[X86_REF_COUNT] = {0};

    while (current) {
        ir_instruction_t* instruction = &current->instruction;
        switch (instruction->opcode) {
            case IR_SET_FLAG: {
                ir_instruction_list_t* last_store = set_flags[instruction->set_flag.flag];
                if (last_store) {
                    last_store->instruction.set_flag.source->uses--;
                    ir_ilist_remove(last_store);
                    ir_ilist_free(last_store);
                }
                set_flags[instruction->set_flag.flag] = current;
                break;
            }
            case IR_GET_FLAG: {
                set_flags[instruction->get_flag.flag] = NULL;
                break;
            }
            case IR_SET_GUEST: {
                ir_instruction_list_t* last_store = set_regs[instruction->set_guest.ref];
                bool is_used = set_regs_used[instruction->set_guest.ref];
                if (last_store && !is_used) {
                    last_store->instruction.set_guest.source->uses--;
                    ir_ilist_remove(last_store);
                    ir_ilist_free(last_store);
                }
                set_regs[instruction->set_guest.ref] = current;
                set_regs_used[instruction->set_guest.ref] = false;
                break;
            }
            case IR_GET_GUEST: {
                ir_instruction_list_t* last_store = set_regs[instruction->get_guest.ref];
                if (last_store) {
                    last_store->instruction.set_guest.source->uses++;
                    set_regs_used[instruction->get_guest.ref] = true;
                    instruction->type = IR_TYPE_ONE_OPERAND;
                    instruction->opcode = IR_MOV;
                    instruction->one_operand.source = last_store->instruction.set_guest.source;
                }
                break;
            }
            case IR_CPUID: {
                // CPUID reads these registers, so we can't eliminate them
                set_regs_used[X86_REF_RAX] = true;
                set_regs_used[X86_REF_RBX] = true;
                set_regs_used[X86_REF_RCX] = true;
                set_regs_used[X86_REF_RDX] = true;
                break;
            }
            default: {
                break;
            }
        }

        current = current->next;
    }
}

void ir_dead_code_elimination_pass(ir_block_t* block) {
    ir_instruction_list_t* current = block->instructions->next;
    ir_instruction_list_t* last = NULL;
    while (current && current->next) {
        current = current->next;
    }

    last = current;

    // Go from the end of the block to the beginning, because marking instructions as unused
    // will make the instructions above them unused as well if they have 0 uses
    while (last) {
        ir_instruction_t* instruction = &last->instruction;
        ir_instruction_list_t* previous = last->previous;
        switch (instruction->type) {
            case IR_TYPE_LOAD_IMMEDIATE: {
                if (instruction->uses == 0) {
                    ir_ilist_remove(last);
                    ir_ilist_free(last);
                }
                break;
            }
            case IR_TYPE_TWO_OPERAND: {
                if (instruction->uses == 0) {
                    if (instruction->opcode == IR_WRITE_BYTE || instruction->opcode == IR_WRITE_WORD || instruction->opcode == IR_WRITE_DWORD || instruction->opcode == IR_WRITE_QWORD) {
                        break;
                    }

                    instruction->two_operand.source1->uses--;
                    instruction->two_operand.source2->uses--;
                    ir_ilist_remove(last);
                    ir_ilist_free(last);
                }
                break;
            }
            case IR_TYPE_ONE_OPERAND: {
                if (instruction->uses == 0) {
                    instruction->one_operand.source->uses--;
                    ir_ilist_remove(last);
                    ir_ilist_free(last);
                }
                break;
            }
            case IR_TYPE_TWO_OPERAND_IMMEDIATES: {
                if (instruction->uses == 0) {
                    if (instruction->two_operand_immediates.source1) {
                        instruction->two_operand_immediates.source1->uses--;
                    }
                    if (instruction->two_operand_immediates.source2) {
                        instruction->two_operand_immediates.source2->uses--;
                    }
                    ir_ilist_remove(last);
                    ir_ilist_free(last);
                }
                break;
            }
            case IR_TYPE_TERNARY: {
                if (instruction->uses == 0) {
                    instruction->ternary.condition->uses--;
                    instruction->ternary.true_value->uses--;
                    instruction->ternary.false_value->uses--;
                    ir_ilist_remove(last);
                    ir_ilist_free(last);
                }
                break;
            }
            case IR_TYPE_GET_GUEST: {
                if (instruction->uses == 0) {
                    ir_ilist_remove(last);
                    ir_ilist_free(last);
                }
                break;
            }
            case IR_TYPE_GET_FLAG: {
                if (instruction->uses == 0) {
                    ir_ilist_remove(last);
                    ir_ilist_free(last);
                }
                break;
            }
            default: {
                break;
            }
        }

        last = previous;
    }
}