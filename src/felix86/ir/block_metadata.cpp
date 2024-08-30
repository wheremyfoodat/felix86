#include "felix86/ir/block_metadata.h"

#include <tsl/robin_map.h>

#include "felix86/common/log.h"
#include "felix86/ir/instruction_list.h"

struct ir_block_metadata_s {
	tsl::robin_map<u64, ir_block_t*> blocks;
};

ir_block_metadata_t* ir_block_metadata_create() { return new ir_block_metadata_t(); }

void ir_block_metadata_destroy(ir_block_metadata_t* metadata) {
	for (auto& block : metadata->blocks) {
		ir_ilist_free_all(block.second->instructions);
		delete block.second;
	}

	delete metadata;
}

ir_block_t* ir_block_metadata_get_block(ir_block_metadata_t* metadata, u64 address) {
	auto it = metadata->blocks.find(address);
	if (it != metadata->blocks.end()) {
		return it->second;
	}

	ir_block_t* block = new ir_block_t {};
	block->start_address = address;
	block->instructions = ir_ilist_create();
	block->compiled = false;

	metadata->blocks[address] = block;

	return block;
}