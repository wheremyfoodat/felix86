#pragma once

#include "felix86/common/state.h"
#include "felix86/ir/block.h"

void ir_interpret_block(ir_block_t* block, x86_state_t* state);