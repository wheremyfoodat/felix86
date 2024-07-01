#include "felix86/ir/passes.h"
#include "felix86/ir/instruction.h"
#include <cstring>
#include <map>

bool operator<(const ir_instruction_t& a1, const ir_instruction_t& a2) {
    int res = memcmp(&a1, &a2, sizeof(ir_instruction_t));
    return res < 0;
}

extern "C" void ir_local_common_subexpression_elimination_pass(ir_block_t* block) {
    std::map<ir_instruction_t, ir_instruction_t*> expressions;

    ir_instruction_list_t* current = block->instructions->next;
    while (current) {
        ir_instruction_t instruction = current->instruction;
        instruction.name = 0;
        instruction.uses = 0;
        if (instruction.type != IR_TYPE_SET_GUEST && instruction.type != IR_TYPE_SET_FLAG)
        {
            if (expressions.find(instruction) != expressions.end()) {
                current->instruction.type = IR_TYPE_ONE_OPERAND;
                current->instruction.opcode = IR_MOV;
                current->instruction.one_operand.source = expressions[instruction];
            } else {
                expressions[instruction] = &current->instruction;
            }
        } else if (instruction.type == IR_TYPE_SET_FLAG) {
            // Since it's been modified we need to remove any previous get flag instructions from
            // the expressions map
            ir_instruction_t get_instruction = {0};
            get_instruction.type = IR_TYPE_GET_FLAG;
            get_instruction.opcode = IR_GET_FLAG;
            get_instruction.get_flag.flag = instruction.set_flag.flag;
            
            if (expressions.find(get_instruction) != expressions.end()) {
                expressions.erase(get_instruction);
            }
        } else if (instruction.type == IR_TYPE_SET_GUEST) {
            // Since it's been modified we need to remove any previous get guest instructions from
            // the expressions map
            ir_instruction_t get_instruction = {0};
            get_instruction.type = IR_TYPE_GET_GUEST;
            get_instruction.opcode = IR_GET_GUEST;
            get_instruction.get_guest.ref = instruction.set_guest.ref;
            
            if (expressions.find(get_instruction) != expressions.end()) {
                expressions.erase(get_instruction);
            }
        }

        current = current->next;
    }
}

extern "C" void ir_copy_propagation_pass(ir_block_t* block) {
    std::map<ir_instruction_t*, ir_instruction_t*> copies;

    ir_instruction_list_t* current = block->instructions->next;
    while (current) {
        ir_instruction_t* instruction = &current->instruction;
        if (instruction->opcode == IR_MOV) {
            if (copies.find(instruction->one_operand.source) != copies.end()) {
                copies[instruction] = copies[instruction->one_operand.source];
            } else {
                copies[instruction] = instruction->one_operand.source;
            }

            ir_instruction_list_t* next = current->next;
            ir_ilist_remove(current);

            ir_instruction_list_t* tmp = current;
            ir_ilist_free(tmp);
            current = next;
        } else {
            switch (instruction->type) {
                case IR_TYPE_TWO_OPERAND: {
                    if (copies.find(instruction->two_operand.source1) != copies.end()) {
                        instruction->two_operand.source1 = copies[instruction->two_operand.source1];
                        instruction->two_operand.source1->uses++;
                    }
                    if (copies.find(instruction->two_operand.source2) != copies.end()) {
                        instruction->two_operand.source2 = copies[instruction->two_operand.source2];
                        instruction->two_operand.source2->uses++;
                    }
                    break;
                }
                case IR_TYPE_ONE_OPERAND: {
                    if (copies.find(instruction->one_operand.source) != copies.end()) {
                        instruction->one_operand.source = copies[instruction->one_operand.source];
                        instruction->one_operand.source->uses++;
                    }
                    break;
                }
                case IR_TYPE_SET_GUEST: {
                    if (copies.find(instruction->set_guest.source) != copies.end()) {
                        instruction->set_guest.source = copies[instruction->set_guest.source];
                        instruction->set_guest.source->uses++;
                    }
                    break;
                }
                case IR_TYPE_SET_FLAG: {
                    if (copies.find(instruction->set_flag.source) != copies.end()) {
                        instruction->set_flag.source = copies[instruction->set_flag.source];
                        instruction->set_flag.source->uses++;
                    }
                    break;
                }
                case IR_TYPE_LEA: {
                    if (copies.find(instruction->lea.base) != copies.end()) {
                        instruction->lea.base = copies[instruction->lea.base];
                        instruction->lea.base->uses++;
                    }
                    if (copies.find(instruction->lea.index) != copies.end()) {
                        instruction->lea.index = copies[instruction->lea.index];
                        instruction->lea.index->uses++;
                    }
                    break;
                }
                default: {
                    break;
                }
            }
            current = current->next;
        }
    }
}
