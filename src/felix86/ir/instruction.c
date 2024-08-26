#include "felix86/ir/instruction.h"

void ir_clear_instruction(ir_instruction_t* instruction) {
    instruction->raw_data[0] = 0;
    instruction->raw_data[1] = 0;
    instruction->raw_data[2] = 0;
}