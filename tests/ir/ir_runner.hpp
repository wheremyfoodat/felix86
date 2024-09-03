#include <catch2/catch_test_macros.hpp>
#include <xbyak/xbyak.h>
#include "felix86/common/utility.h"
#include "felix86/frontend/frontend.h"
#include "felix86/felix86.h"
#include "felix86/ir/emitter.h"
#include "felix86/ir/block.h"

#define START_IR_TEST() \
    ir_function_t* function = ir_function_create(0); \
    ir_block_list_t* current = function->first; \
    frontend_state_t state_s = {0}; \
    state_s.function = function; \
    state_s.current_block = current->block; \
    state_s.current_address = current->block->start_address; \
    frontend_state_t* state = &state_s;

#define SWITCH_TO_BLOCK(block) \
    state->current_block = block; \
    state->current_address = block->start_address;
