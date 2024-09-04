#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/ir/block.h"

void ir_local_common_subexpression_elimination_pass_v2(ir_block_t* block);
void ir_const_propagation_pass(ir_block_t* block);
void ir_dead_code_elimination_pass(ir_block_t* block);
void ir_verifier_pass(ir_block_t* block);

void ir_naming_pass(ir_function_t* function);
void ir_ssa_pass(ir_function_t* function);
void ir_copy_propagation_pass(ir_function_t* function);

#ifdef __cplusplus
}
#endif