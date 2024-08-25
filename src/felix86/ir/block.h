#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/common/utility.h"
#include "felix86/ir/instruction_list.h"

typedef struct {
	u64 start_address;
	ir_instruction_list_t* instructions;
	bool compiled;
} ir_block_t;

#ifdef __cplusplus
}
#endif
