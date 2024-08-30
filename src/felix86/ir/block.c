#include "felix86/ir/block.h"
#include "felix86/ir/emitter.h"
#include <stdlib.h>

ir_block_list_t* ir_block_list_create(ir_block_t* block)
{
    ir_block_list_t* list = calloc(1, sizeof(ir_block_list_t));
    list->block = block;
    return list;
}

ir_block_t* ir_block_create(u64 address)
{
    ir_block_t* block = calloc(1, sizeof(ir_block_t));
    block->instructions = ir_ilist_create();
    block->start_address = address;
    return block;
}

ir_function_t* ir_function_create(u64 address)
{
    ir_block_list_t* list = ir_block_list_create(ir_block_create(address));

    // We add a dummy block at the start with guaranteed no predecessors
    ir_block_list_t* entry = ir_block_list_create(ir_block_create(0));

    ir_emitter_state_t state = {0};
    state.current_block = entry->block;

    list->block->predecessors = entry;

    ir_function_t* function = malloc(sizeof(ir_function_t));
    function->entry = entry;
    function->first = list;
    function->last = list;

    return function;
}

ir_block_t* ir_function_get_block(ir_function_t* function, ir_block_t* predecessor, u64 address) {
    for (ir_block_list_t* current = function->first; current; current = current->next) {
        if (current->block->start_address == address) {
            if (predecessor) {
                ir_block_list_t* list = ir_block_list_create(predecessor);
                list->next = current->block->predecessors;
                current->block->predecessors = list;

                list = ir_block_list_create(current->block);
                list->next = predecessor->successors;
                predecessor->successors = list;
            }
            return current->block;
        }
    }

    ir_block_t* block = ir_block_create(address);
    ir_block_list_t* list = ir_block_list_create(block);
    function->last->next = list;
    function->last = list;

    // Add block to predecessor's successors
    if (predecessor) {
        ir_block_list_t* list = ir_block_list_create(block);
        list->next = predecessor->successors;
        predecessor->successors = list;
        block->predecessors = ir_block_list_create(predecessor);
    }

    return block;
}
