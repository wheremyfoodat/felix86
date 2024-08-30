#include "felix86/common/log.h"
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

void ir_dead_code_elimination_pass(ir_block_t* block) {
    ir_instruction_list_t* current = block->instructions->next;
    ir_instruction_list_t* last = NULL;
    while (current && current->next) {
        current = current->next;
    }

    last = current;

    // if a set_guest/set_flag is the last in the block don't eliminate it
    bool not_last_register[X86_REF_COUNT] = {0};
    bool not_last_flag[16] = {0};

    // Go from the end of the block to the beginning, because marking instructions as unused
    // will make the instructions above them unused as well if they have 0 uses
    while (last) {
        ir_instruction_t* instruction = &last->instruction;
        ir_instruction_list_t* previous = last->previous;

        switch (instruction->opcode) {
            case IR_WRITE_BYTE:
            case IR_WRITE_WORD:
            case IR_WRITE_DWORD:
            case IR_WRITE_QWORD:
            case IR_JUMP: 
            case IR_JUMP_IF_TRUE: {
                last = previous;
                continue;
            }
            default: {
                break;
            }
        }

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
                    instruction->two_operand.source1->uses--;

                    if (instruction->two_operand.source1 != instruction->two_operand.source2) {
                        instruction->two_operand.source2->uses--;
                    }
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
                    if (instruction->two_operand_immediates.source2 && instruction->two_operand_immediates.source1 != instruction->two_operand_immediates.source2) {
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
                    if (instruction->ternary.condition != instruction->ternary.true_value) {
                        instruction->ternary.true_value->uses--;
                    }
                    if (instruction->ternary.condition != instruction->ternary.false_value && instruction->ternary.true_value != instruction->ternary.false_value) {
                        instruction->ternary.false_value->uses--;
                    }
                    ir_ilist_remove(last);
                    ir_ilist_free(last);
                }
                break;
            }
            case IR_TYPE_GET_GUEST: {
                not_last_register[instruction->get_guest.ref] = false;
                if (instruction->uses == 0) {
                    ir_ilist_remove(last);
                    ir_ilist_free(last);
                }
                break;
            }
            case IR_TYPE_GET_FLAG: {
                not_last_flag[instruction->get_flag.flag] = false;
                if (instruction->uses == 0) {
                    ir_ilist_remove(last);
                    ir_ilist_free(last);
                }
                break;
            }
            case IR_TYPE_SET_FLAG: {
                bool not_last = not_last_flag[instruction->set_flag.flag];
                not_last_flag[instruction->set_flag.flag] = true;
                if (instruction->uses == 0 && not_last) {
                    instruction->set_flag.source->uses--;
                    ir_ilist_remove(last);
                    ir_ilist_free(last);
                }
                break;
            }
            case IR_TYPE_SET_GUEST: {
                bool not_last = not_last_register[instruction->set_guest.ref];
                not_last_register[instruction->set_guest.ref] = true;
                if (instruction->uses == 0 && not_last) {
                    instruction->set_guest.source->uses--;
                    ir_ilist_remove(last);
                    ir_ilist_free(last);
                }
                break;
            }
            default: {
                // Instructions that need special handling when it comes to optimizations
                switch (instruction->opcode) {
                    case IR_CPUID: {
                        // Makes it so that the last stores for these registers before the cpuid are not optimized away
                        // So it sort of acts like an optimization barrier for these registers, which it needs
                        not_last_register[X86_REF_RAX] = false;
                        not_last_register[X86_REF_RBX] = false;
                        not_last_register[X86_REF_RCX] = false;
                        not_last_register[X86_REF_RDX] = false;
                        break;
                    }
                    case IR_SYSCALL: {
                        // Same as cpuid
                        not_last_register[X86_REF_RAX] = false;
                        not_last_register[X86_REF_RDI] = false;
                        not_last_register[X86_REF_RSI] = false;
                        not_last_register[X86_REF_RDX] = false;
                        not_last_register[X86_REF_R10] = false;
                        not_last_register[X86_REF_R8] = false;
                        not_last_register[X86_REF_R9] = false;
                        break;
                    }
                    default: {
                        break;
                    }
                }
                break;
            }
        }

        last = previous;
    }
}

bool both_operands_immediate(ir_instruction_t* instruction) {
	if (instruction->type == IR_TYPE_TWO_OPERAND) {
        if (instruction->two_operand.source1 && instruction->two_operand.source2) {
    		return instruction->two_operand.source1->opcode == IR_IMMEDIATE && instruction->two_operand.source2->opcode == IR_IMMEDIATE;
        } else {
            return false;
        }
	} else if (instruction->type == IR_TYPE_TWO_OPERAND_IMMEDIATES) {
		if (instruction->two_operand_immediates.source1 && instruction->two_operand_immediates.source2) {
            return instruction->two_operand_immediates.source1->opcode == IR_IMMEDIATE && instruction->two_operand_immediates.source2->opcode == IR_IMMEDIATE;
        } else {
            return false;
        }
	} else {
		ERROR("Unreachable");
	}
}

bool one_operand_immediate(ir_instruction_t* instruction) {
	if (instruction->type == IR_TYPE_TWO_OPERAND) {
		if (instruction->two_operand.source1->opcode == IR_IMMEDIATE) {
			return true;
		} else if (instruction->two_operand.source2->opcode == IR_IMMEDIATE) {
			return true;
		}
	} else if (instruction->type == IR_TYPE_TWO_OPERAND_IMMEDIATES) {
		if (instruction->two_operand_immediates.source1->opcode == IR_IMMEDIATE) {
			return true;
		} else if (instruction->two_operand_immediates.source2->opcode == IR_IMMEDIATE) {
			return true;
		}
	} else {
		ERROR("Unreachable");
	}

	return false;
}

u64 get_source1(ir_instruction_t* instruction) {
	if (instruction->type == IR_TYPE_TWO_OPERAND) {
		return instruction->two_operand.source1->load_immediate.immediate;
	} else if (instruction->type == IR_TYPE_TWO_OPERAND_IMMEDIATES) {
		return instruction->two_operand_immediates.source1->load_immediate.immediate;
	} else {
		ERROR("Unreachable");
	}
}

u64 get_source2(ir_instruction_t* instruction) {
	if (instruction->type == IR_TYPE_TWO_OPERAND) {
		return instruction->two_operand.source2->load_immediate.immediate;
	} else if (instruction->type == IR_TYPE_TWO_OPERAND_IMMEDIATES) {
		return instruction->two_operand_immediates.source2->load_immediate.immediate;
	} else {
		ERROR("Unreachable");
	}
}

ir_instruction_t* get_immediate_source(ir_instruction_t* instruction) {
	if (instruction->type == IR_TYPE_TWO_OPERAND) {
		if (instruction->two_operand.source1->opcode == IR_IMMEDIATE) {
			return instruction->two_operand.source1;
		} else {
			return instruction->two_operand.source2;
		}
	} else if (instruction->type == IR_TYPE_TWO_OPERAND_IMMEDIATES) {
		if (instruction->two_operand_immediates.source1->opcode == IR_IMMEDIATE) {
			return instruction->two_operand_immediates.source1;
		} else {
			return instruction->two_operand_immediates.source2;
		}
	} else {
		ERROR("Unreachable");
	}
}

ir_instruction_t* get_non_immediate_source(ir_instruction_t* instruction) {
	if (instruction->type == IR_TYPE_TWO_OPERAND) {
		if (instruction->two_operand.source1->opcode == IR_IMMEDIATE) {
			return instruction->two_operand.source2;
		} else {
			return instruction->two_operand.source1;
		}
	} else if (instruction->type == IR_TYPE_TWO_OPERAND_IMMEDIATES) {
		if (instruction->two_operand_immediates.source1->opcode == IR_IMMEDIATE) {
			return instruction->two_operand_immediates.source2;
		} else {
			return instruction->two_operand_immediates.source1;
		}
	} else {
		ERROR("Unreachable");
	}
}

void replace_with_immediate(ir_instruction_t* instruction, u64 immediate) {
	if (instruction->type == IR_TYPE_TWO_OPERAND) {
		ir_instruction_t* source1 = instruction->two_operand.source1;
		ir_instruction_t* source2 = instruction->two_operand.source2;
		source1->uses--;
		source2->uses--;
	} else if (instruction->type == IR_TYPE_TWO_OPERAND_IMMEDIATES) {
		ir_instruction_t* source1 = instruction->two_operand_immediates.source1;
		ir_instruction_t* source2 = instruction->two_operand_immediates.source2;
		source1->uses--;
		source2->uses--;
	} else {
		ERROR("Unreachable");
	}

    ir_clear_instruction(instruction);
	instruction->type = IR_TYPE_LOAD_IMMEDIATE;
	instruction->opcode = IR_IMMEDIATE;
	instruction->load_immediate.immediate = immediate;
}

void replace_with_mov(ir_instruction_t* instruction, ir_instruction_t* source) {
    ir_clear_instruction(instruction);
    instruction->type = IR_TYPE_ONE_OPERAND;
    instruction->opcode = IR_MOV;
    instruction->one_operand.source = source;
}

#define _Src1_ (get_source1(instruction))
#define _Src2_ (get_source2(instruction))
void ir_const_propagation_pass(ir_block_t* block) {
	ir_instruction_list_t* current = block->instructions->next;
	while (current) {
		ir_instruction_t* instruction = &current->instruction;
		switch (instruction->opcode) {
			case IR_AND: {
				if (both_operands_immediate(instruction)) {
					replace_with_immediate(instruction, _Src1_ & _Src2_);
				} else if (one_operand_immediate(instruction)) {
					ir_instruction_t* imm_source = get_immediate_source(instruction);
					u64 src = imm_source->load_immediate.immediate;
					if (src == 0) {
						replace_with_immediate(instruction, 0);
					} else if (src == 0xFFFFFFFFFFFFFFFFull) {
						ir_instruction_t* source = get_non_immediate_source(instruction);
						imm_source->uses--;
                        replace_with_mov(instruction, source);
					}
				}
				break;
			}
            case IR_OR: {
                if (both_operands_immediate(instruction)) {
                    replace_with_immediate(instruction, _Src1_ | _Src2_);
                } else if (one_operand_immediate(instruction)) {
                    ir_instruction_t* imm_source = get_immediate_source(instruction);
                    u64 src = imm_source->load_immediate.immediate;
                    if (src == 0) {
                        ir_instruction_t* source = get_non_immediate_source(instruction);
                        imm_source->uses--;
                        replace_with_mov(instruction, source);
                    }
                }
                break;
            }
            case IR_XOR: {
                if (both_operands_immediate(instruction)) {
                    replace_with_immediate(instruction, _Src1_ ^ _Src2_);
                } else if (one_operand_immediate(instruction)) {
                    ir_instruction_t* imm_source = get_immediate_source(instruction);
                    u64 src = imm_source->load_immediate.immediate;
                    if (src == 0) {
                        ir_instruction_t* source = get_non_immediate_source(instruction);
						imm_source->uses--;
                        replace_with_mov(instruction, source);
                    }
                }
                break;
            }
            case IR_ADD: {
                if (both_operands_immediate(instruction)) {
                    replace_with_immediate(instruction, _Src1_ + _Src2_);
                } else if (one_operand_immediate(instruction)) {
                    ir_instruction_t* imm_source = get_immediate_source(instruction);
                    u64 src = imm_source->load_immediate.immediate;
                    if (src == 0) {
                        ir_instruction_t* source = get_non_immediate_source(instruction);
						imm_source->uses--;
                        replace_with_mov(instruction, source);
                    }
                }
                break;
            }
            case IR_SUB: {
                if (both_operands_immediate(instruction)) {
                    replace_with_immediate(instruction, _Src1_ - _Src2_);
                } else if (instruction->two_operand.source1 == instruction->two_operand.source2) {
                    replace_with_immediate(instruction, 0);
                } else if (one_operand_immediate(instruction)) {
                    ir_instruction_t* imm_source = get_immediate_source(instruction);
                    u64 src = imm_source->load_immediate.immediate;
                    if (src == 0) {
                        ir_instruction_t* source = get_non_immediate_source(instruction);
						imm_source->uses--;
                        replace_with_mov(instruction, source);
                    }
                }
                break;
            }
            case IR_LEFT_SHIFT: {
                if (both_operands_immediate(instruction)) {
                    replace_with_immediate(instruction, _Src1_ << _Src2_);
                } else if (one_operand_immediate(instruction)) {
                    ir_instruction_t* imm_source = get_immediate_source(instruction);
                    u64 src = imm_source->load_immediate.immediate;
                    if (src == 0) {
                        ir_instruction_t* source = get_non_immediate_source(instruction);
						imm_source->uses--;
                        replace_with_mov(instruction, source);
                    }
                }
                break;
            }
            case IR_RIGHT_SHIFT: {
                if (both_operands_immediate(instruction)) {
                    replace_with_immediate(instruction, _Src1_ >> _Src2_);
                } else if (one_operand_immediate(instruction)) {
                    ir_instruction_t* imm_source = get_immediate_source(instruction);
                    u64 src = imm_source->load_immediate.immediate;
                    if (src == 0) {
                        ir_instruction_t* source = get_non_immediate_source(instruction);
						imm_source->uses--;
                        replace_with_mov(instruction, source);
                    }
                }
                break;
            }
            case IR_RIGHT_SHIFT_ARITHMETIC: {
                if (both_operands_immediate(instruction)) {
                    replace_with_immediate(instruction, (i64)_Src1_ >> _Src2_);
                } else if (one_operand_immediate(instruction)) {
                    ir_instruction_t* imm_source = get_immediate_source(instruction);
                    u64 src = imm_source->load_immediate.immediate;
                    if (src == 0) {
                        ir_instruction_t* source = get_non_immediate_source(instruction);
						imm_source->uses--;
                        replace_with_mov(instruction, source);
                    }
                }
                break;
            }
            case IR_EQUAL: {
                if (both_operands_immediate(instruction)) {
                    replace_with_immediate(instruction, _Src1_ == _Src2_);
                } else if (instruction->two_operand.source1 == instruction->two_operand.source2) {
                    replace_with_immediate(instruction, 1);
                }
                break;
            }
            case IR_NOT_EQUAL: {
                if (both_operands_immediate(instruction)) {
                    replace_with_immediate(instruction, _Src1_ != _Src2_);
                } else if (instruction->two_operand.source1 == instruction->two_operand.source2) {
                    replace_with_immediate(instruction, 0);
                }
                break;
            }
            case IR_LEA: {
                if (both_operands_immediate(instruction)) {
                    i64 disp32 = (i32)instruction->two_operand_immediates.imm32_1;
                    u8 scale = instruction->two_operand_immediates.imm32_2;
                    replace_with_immediate(instruction, _Src1_ + _Src2_ * scale  + disp32);
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
#undef _Src1_
#undef _Src2_