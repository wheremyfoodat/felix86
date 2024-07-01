#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/common/utility.h"
#include "felix86/ir/block.h"

typedef struct ir_block_metadata_s ir_block_metadata_t;

ir_block_metadata_t* ir_block_metadata_create();
void ir_block_metadata_destroy(ir_block_metadata_t* metadata);
ir_block_t* ir_block_metadata_get_block(ir_block_metadata_t* metadata, u64 address);

#ifdef __cplusplus
}
#endif