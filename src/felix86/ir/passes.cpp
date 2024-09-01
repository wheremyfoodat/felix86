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

struct definitions_t {
	std::array<std::map<ir_block_t*, ir_instruction_t*>, X86_REF_COUNT> def {};
	std::map<ir_instruction_t*, ir_instruction_t*> copies;
};

inline void write_variable(definitions_t& definitions, x86_ref_e variable, ir_instruction_t* value, ir_block_t* block) {
	definitions.def[variable][block] = value;
}

ir_instruction_t* read_variable_recursive(ir_function_t* function, definitions_t& definitions, x86_ref_e variable, ir_block_t* block, ir_instruction_list_t* current);

inline ir_instruction_t* read_variable(ir_function_t* function, definitions_t& definitions, x86_ref_e variable, ir_block_t* block, ir_instruction_list_t* current) {
	if (definitions.def[variable].find(block) != definitions.def[variable].end()) {
		return definitions.def[variable][block];
	} else {
		return read_variable_recursive(function, definitions, variable, block, current);
	}
}

inline ir_instruction_t* try_remove_trivial_phi(ir_instruction_t* phi) {
	ir_instruction_t* same = nullptr;
	ir_phi_node_t* node = phi->phi.list;
	while (node) {
		if (node->value == same || node->value == phi) {
			node = node->next;
			continue;
		}

		if (same != nullptr) {
			return phi;
		}

		same = node->value;

		node = node->next;
	}

	if (same == nullptr) {
		ERROR("The phi is unreachable or in the entry block");
	}
	
	return same;
}

inline ir_instruction_t* add_phi_operands(ir_function_t* function, definitions_t& definitions, ir_block_t* block, x86_ref_e variable, ir_instruction_t* phi, ir_instruction_list_t* current) {
	ir_block_list_t* pred = block->predecessors;
	while (pred) {
		ir_instruction_t* value = read_variable(function, definitions, variable, pred->block, current);
		ir_phi_node_t* node = phi->phi.list;
		phi->phi.list = (ir_phi_node_t*)malloc(sizeof(ir_phi_node_t));
		phi->phi.list->block = pred->block;
		phi->phi.list->value = value;
		phi->phi.list->next = node;
		value->uses++;
		
		pred = pred->next;
	}

	return try_remove_trivial_phi(phi);
}

inline ir_instruction_t* read_variable_recursive(ir_function_t* function, definitions_t& definitions, x86_ref_e variable, ir_block_t* block, ir_instruction_list_t* current) {
	u8 predecessorCount = 0;
	ir_block_list_t* pred = block->predecessors;
	while (pred) {
		predecessorCount++;
		pred = pred->next;
	}

	ir_instruction_t* ret;
	if (predecessorCount == 1) {
		ret = read_variable(function, definitions, variable, block->predecessors->block, current);
	} else if (predecessorCount > 1) {
		ret = ir_ilist_insert_before(current);
		ret->type = IR_TYPE_PHI;
		ret->opcode = IR_PHI;
		ret->phi.list = nullptr;
		write_variable(definitions, variable, ret, block);
		add_phi_operands(function, definitions, block, variable, ret, current);
	} else if (predecessorCount == 0) {
		// The search has reached our empty entry block without finding a definition
		// Which means we actually need to read the guest from memory
		// We insert an instruction that reads the guest from memory right before the current instruction
		// and return that
		ret = ir_ilist_insert_before(current);
		ret->type = IR_TYPE_LOAD_GUEST_FROM_MEMORY;
		ret->opcode = IR_LOAD_GUEST_FROM_MEMORY;
		ret->get_guest.ref = variable;
	} else {
		ERROR("Unreachable");
	}

	write_variable(definitions, variable, ret, block);
	return ret;
}

void ir_ssa_pass_impl(ir_function_t* function, definitions_t& definitions, ir_block_t* block) {
	ir_instruction_list_t* current = block->instructions->next;
	while(current) {
		ir_instruction_list_t* next = current->next;
		switch(current->instruction.opcode) {
			case IR_SET_GUEST: {
				write_variable(definitions, current->instruction.set_guest.ref, &current->instruction, block);
				ir_instruction_t* source = current->instruction.set_guest.source;
				ir_clear_instruction(&current->instruction);
				current->instruction.type = IR_TYPE_ONE_OPERAND;
				current->instruction.opcode = IR_MOV;
				current->instruction.one_operand.source = source;
				break;
			}
			case IR_GET_GUEST: {
				ir_instruction_t* value = read_variable(function, definitions, current->instruction.get_guest.ref, block, current);
				ir_clear_instruction(&current->instruction);
				current->instruction.type = IR_TYPE_ONE_OPERAND;
				current->instruction.opcode = IR_MOV;
				current->instruction.one_operand.source = value;
				value->uses++;
				break;
			}
			case IR_CPUID: {
				definitions.def[X86_REF_RAX].clear();
				definitions.def[X86_REF_RCX].clear();
				definitions.def[X86_REF_RDX].clear();
				definitions.def[X86_REF_RBX].clear();
				break;
			}
			case IR_SYSCALL: {
				definitions.def[X86_REF_RAX].clear();
				break;
			}
			case IR_JUMP_REGISTER:
			case IR_EXIT: {
				// We need to emit a writeback to memory for all variables that are used
				for (u8 i = 0; i < X86_REF_COUNT; i++) {
					if (!definitions.def[i].empty()) {
						ir_instruction_t* value = read_variable(function, definitions, (x86_ref_e)i, block, current);
						ir_instruction_t* write = ir_ilist_insert_before(current);
						write->type = IR_TYPE_STORE_GUEST_TO_MEMORY;
						write->opcode = IR_STORE_GUEST_TO_MEMORY;
						write->set_guest.ref = (x86_ref_e)i;
						write->set_guest.source = value;
						value->uses++;
					}
				}
				break;
			}
			default: {
				break;
			}
		}

		current = next;
	}
}

// This and the above functions are based entirely on Simple and Efficient Construction of Static Single Assignment Form paper
extern "C" void ir_ssa_pass(ir_function_t* function) {
	definitions_t definitions = {};
	ir_block_list_t* current = function->first;
	while (current) {
		ir_ssa_pass_impl(function, definitions, current->block);
		current = current->next;
	}
}





bool operator<(const ir_instruction_t& a1, const ir_instruction_t& a2) {
	int res = memcmp(&a1, &a2, sizeof(ir_instruction_t));
	return res < 0;
}

bool operates_on_temporaries(ir_instruction_t* instruction) {
	switch (instruction->opcode) {
		// These instructions directly modify the guest state
		case IR_GET_GUEST:
		case IR_SET_GUEST:
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

extern "C" void ir_copy_propagation_pass_block(std::map<ir_instruction_t*, ir_instruction_t*> copies, ir_block_t* block) {
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
				case IR_TYPE_JUMP:
				case IR_TYPE_ONE_OPERAND: {
					if (copies.find(instruction->one_operand.source) != copies.end()) {
						instruction->one_operand.source = copies[instruction->one_operand.source];
						instruction->one_operand.source->uses++;
					}
					break;
				}
				case IR_TYPE_STORE_GUEST_TO_MEMORY:
				case IR_TYPE_SET_GUEST: {
					if (copies.find(instruction->set_guest.source) != copies.end()) {
						instruction->set_guest.source = copies[instruction->set_guest.source];
						instruction->set_guest.source->uses++;
					}
					break;
				}
				case IR_TYPE_JUMP_CONDITIONAL: {
					if (copies.find(instruction->jump_conditional.condition) != copies.end()) {
						instruction->jump_conditional.condition = copies[instruction->jump_conditional.condition];
						instruction->jump_conditional.condition->uses++;
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
				default: {
					break;
				}
			}
			current = current->next;
		}
	}

	ir_block_list_t* succ = block->successors;
	while (succ) {
		if (succ->block != block)
			ir_copy_propagation_pass_block(copies, succ->block);
		succ = succ->next;
	}
}

void ir_copy_propagation_pass(ir_function_t* function) {
	// std::map<ir_instruction_t*, ir_instruction_t*> copies;
	// ir_block_list_t* block = function->first;
	// ir_copy_propagation_pass_block(copies, block->block);
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