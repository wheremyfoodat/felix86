#include "felix86/common/utility.h"
#include "felix86/ir/passes.h"
#include <stddef.h>

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

    ir_instruction_list_t* set_flags[6] = {0};
    ir_instruction_list_t* set_regs[X86_REF_COUNT] = {0};

    while (current) {
        ir_instruction_t* instruction = &current->instruction;
        switch (instruction->type) {
            case IR_TYPE_SET_FLAG: {
                ir_instruction_list_t* last_store = set_flags[instruction->set_flag.flag];
                if (last_store) {
                    last_store->instruction.set_flag.source->uses--;
                    ir_ilist_remove(last_store);
                    ir_ilist_free(last_store);
                }
                set_flags[instruction->set_flag.flag] = current;
                break;
            }
            case IR_TYPE_GET_FLAG: {
                set_flags[instruction->get_flag.flag] = NULL;
                break;
            }
            case IR_TYPE_SET_GUEST: {
                ir_instruction_list_t* last_store = set_regs[instruction->set_guest.ref];
                if (last_store) {
                    last_store->instruction.set_guest.source->uses--;
                    ir_ilist_remove(last_store);
                    ir_ilist_free(last_store);
                }
                set_regs[instruction->set_guest.ref] = current;
                break;
            }
            case IR_TYPE_GET_GUEST: {
                set_regs[instruction->get_guest.ref] = NULL;
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
            case IR_TYPE_LEA: {
                if (instruction->uses == 0) {
                    if (instruction->lea.base) {
                        instruction->lea.base->uses--;
                    }
                    if (instruction->lea.index) {
                        instruction->lea.index->uses--;
                    }
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