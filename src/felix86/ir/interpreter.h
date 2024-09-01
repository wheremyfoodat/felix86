#pragma once

#include "felix86/common/state.h"
#include "felix86/ir/block.h"

void ir_interpret_function(ir_function_t* function, x86_state_t* state);