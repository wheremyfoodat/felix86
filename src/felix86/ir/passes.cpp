#include "felix86/ir/passes.h"

#include <cstring>
#include <map>

#include "felix86/ir/instruction.h"

bool operator<(const ir_instruction_t& a1, const ir_instruction_t& a2) {
	int res = memcmp(&a1, &a2, sizeof(ir_instruction_t));
	return res < 0;
}

bool dont_subexpression_eliminate(ir_instruction_t* instruction) {
	switch (instruction->opcode) {
		// These instructions directly modify the guest state
		case IR_GET_GUEST:
		case IR_GET_FLAG:
		case IR_SET_GUEST:
		case IR_SET_FLAG:
		case IR_CPUID: {
			return true;
		}

		default: {
			return false;
		}
	}
}

extern "C" void ir_local_common_subexpression_elimination_pass(ir_block_t* block) {
	std::map<ir_instruction_t, ir_instruction_t*> expressions;

	ir_instruction_list_t* current = block->instructions->next;
	while (current) {
		ir_instruction_t instruction = current->instruction;
		instruction.name = 0;
		instruction.uses = 0;
		if (!dont_subexpression_eliminate(&instruction)) {
			if (expressions.find(instruction) != expressions.end()) {
				current->instruction.type = IR_TYPE_ONE_OPERAND;
				current->instruction.opcode = IR_MOV;
				current->instruction.one_operand.source = expressions[instruction];
			} else {
				expressions[instruction] = &current->instruction;
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
				case IR_TYPE_TWO_OPERAND_IMMEDIATES: {
					if (copies.find(instruction->two_operand_immediates.source1) != copies.end()) {
						instruction->two_operand_immediates.source1 = copies[instruction->two_operand_immediates.source1];
						instruction->two_operand_immediates.source1->uses++;
					}
					if (copies.find(instruction->two_operand_immediates.source2) != copies.end()) {
						instruction->two_operand_immediates.source2 = copies[instruction->two_operand_immediates.source2];
						instruction->two_operand_immediates.source2->uses++;
					}
					break;
				}
				case IR_TYPE_TERNARY: {
					if (copies.find(instruction->ternary.condition) != copies.end()) {
						instruction->ternary.condition = copies[instruction->ternary.condition];
						instruction->ternary.condition->uses++;
					}
					if (copies.find(instruction->ternary.true_value) != copies.end()) {
						instruction->ternary.true_value = copies[instruction->ternary.true_value];
						instruction->ternary.true_value->uses++;
					}
					if (copies.find(instruction->ternary.false_value) != copies.end()) {
						instruction->ternary.false_value = copies[instruction->ternary.false_value];
						instruction->ternary.false_value->uses++;
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
