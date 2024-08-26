#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/ir/block.h"

void ir_print_instruction(ir_instruction_t* instruction);
void ir_print_block(ir_block_t* block);

#ifdef __cplusplus
}
#endif