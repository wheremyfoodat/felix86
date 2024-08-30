#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/common/utility.h"
#include "felix86/ir/instruction_list.h"

typedef struct ir_block_s {
	u64 start_address;
	ir_instruction_list_t* instructions;
	struct ir_block_list_s* predecessors;
	struct ir_block_list_s* successors;
	bool compiled;
} ir_block_t;

typedef struct ir_block_list_s {
	ir_block_t* block;
	struct ir_block_list_s* next;
} ir_block_list_t;

typedef struct ir_function_t {
	ir_block_list_t* first;
	ir_block_list_t* last;
} ir_function_t;

struct ir_function_cache_s;

ir_block_t* ir_block_create(u64 address);
ir_function_t* ir_function_create(u64 address);
ir_block_t* ir_function_get_block(ir_function_t* function, ir_block_t* predecessor, u64 address);

#ifdef __cplusplus
}
#endif
