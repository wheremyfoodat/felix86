#include "felix86/ir/passes.h"

#include <array>
#include <cstring>
#include <map>
#include <vector>

#include "felix86/common/log.h"
#include "felix86/ir/instruction.h"
#include "felix86/ir/print.h"

bool is_read_write(ir_instruction_t* instruction) {
	switch (instruction->opcode) {
		case IR_READ_BYTE:
		case IR_READ_WORD:
		case IR_READ_DWORD:
		case IR_READ_QWORD:
		case IR_WRITE_BYTE:
		case IR_WRITE_WORD:
		case IR_WRITE_DWORD:
		case IR_WRITE_QWORD: {
			return true;
		}
		default: {
			break;
		}
	}
	return false;
}
todo, start block that gets all registers, end block taht writesback all registers
using definitions_t = std::array<std::map<ir_block_t*, ir_instruction_t>, X86_REF_COUNT>;

inline void write_variable(definitions_t& definitions, x86_ref_e variable, ir_instruction_t value, ir_block_t* block) {
	definitions[variable][block] = value;
}

ir_instruction_t read_variable_recursive(definitions_t& definitions, x86_ref_e variable, ir_block_t* block);

inline ir_instruction_t read_variable(definitions_t& definitions, x86_ref_e variable, ir_block_t* block) {
	if (definitions[variable].find(block) != definitions[variable].end()) {
		return definitions[variable][block];
	} else {
		return read_variable_recursive(definitions, variable, block);
	}
}

inline ir_instruction_t read_variable_recursive(definitions_t& definitions, x86_ref_e variable, ir_block_t* block) {

}

void ir_ssa_pass_local(std::map<ir_instruction_t, std::vector<ir_block_t*>>& definitions, ir_block_t* block) {
}





bool operator<(const ir_instruction_t& a1, const ir_instruction_t& a2) {
	int res = memcmp(&a1, &a2, sizeof(ir_instruction_t));
	return res < 0;
}

bool operates_on_temporaries(ir_instruction_t* instruction) {
	switch (instruction->opcode) {
		// These instructions directly modify the guest state
		case IR_GET_GUEST:
		case IR_GET_FLAG:
		case IR_SET_GUEST:
		case IR_SET_FLAG:
		case IR_CPUID: 
		case IR_SYSCALL: {
			return false;
		}

		default: {
			return true;
		}
	}
}

extern "C" void ir_local_common_subexpression_elimination_pass_v2(ir_block_t* block) {
	std::map<ir_instruction_t, ir_instruction_t*> expressions;
	std::array<ir_instruction_t*, X86_REF_COUNT> registers = {};
	std::array<ir_instruction_t*, 16> flags = {};

	ir_instruction_list_t* current = block->instructions->next;
	while (current) {
		ir_instruction_t expression = current->instruction;
		// we dont wanna hash these in the map
		expression.name = 0;
		expression.uses = 0;
		if (operates_on_temporaries(&current->instruction)) {
			if (expressions.find(expression) != expressions.end()) {
				ir_clear_instruction(&current->instruction);
				current->instruction.type = IR_TYPE_ONE_OPERAND;
				current->instruction.opcode = IR_MOV;
				current->instruction.one_operand.source = expressions[expression];
			} else {
				expressions[expression] = &current->instruction;
			}
		} else {
			// These instructions make the temporaries have a lifetime,
			// meaning a temporary is not available again after its guest register is overwritten
			switch (current->instruction.opcode) {
				case IR_SET_GUEST: {
					registers[current->instruction.set_guest.ref] = current->instruction.set_guest.source;
					break;
				}
				case IR_GET_GUEST: {
					if (registers[current->instruction.get_guest.ref]) {
						registers[current->instruction.get_guest.ref]->uses++;
						ir_instruction_t* new_source = registers[current->instruction.get_guest.ref];
						ir_clear_instruction(&current->instruction);
						current->instruction.type = IR_TYPE_ONE_OPERAND;
						current->instruction.opcode = IR_MOV;
						current->instruction.one_operand.source = new_source;
					} else {
						registers[current->instruction.get_guest.ref] = &current->instruction;
					}
					break;
				}
				case IR_SET_FLAG: {
					flags[current->instruction.set_flag.flag] = current->instruction.set_flag.source;
					break;
				}
				case IR_GET_FLAG: {
					if (flags[current->instruction.get_flag.flag]) {
						flags[current->instruction.get_flag.flag]->uses++;
						ir_instruction_t* new_source = flags[current->instruction.get_flag.flag];
						ir_clear_instruction(&current->instruction);
						current->instruction.type = IR_TYPE_ONE_OPERAND;
						current->instruction.opcode = IR_MOV;
						current->instruction.one_operand.source = new_source;
					} else {
						flags[current->instruction.get_flag.flag] = &current->instruction;
					}
					break;
				}
				case IR_CPUID: {
					registers[X86_REF_RAX] = nullptr;
					registers[X86_REF_RBX] = nullptr;
					registers[X86_REF_RCX] = nullptr;
					registers[X86_REF_RDX] = nullptr;
					break;
				}
				case IR_SYSCALL: {
					registers[X86_REF_RAX] = nullptr;
					registers[X86_REF_RDI] = nullptr;
					registers[X86_REF_RSI] = nullptr;
					registers[X86_REF_RDX] = nullptr;
					registers[X86_REF_R10] = nullptr;
					registers[X86_REF_R8] = nullptr;
					registers[X86_REF_R9] = nullptr;
					break;
				}
				default: {
					ERROR("Unreachable");
					break;
				}
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
			ir_ilist_free(current);
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

void ir_verifier_pass(ir_block_t* block) {
	ir_instruction_list_t* current = block->instructions->next;
	while (current) {
		if ((i16)current->instruction.uses < 0) {
			ERROR("Instruction uses is negative");
		}

		current = current->next;
	}
}