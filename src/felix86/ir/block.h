#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/common/utility.h"
#include "felix86/ir/instruction_list.h"

typedef struct {
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

#ifdef __cplusplus
}
#endif
