#include "felix86/frontend/frontend.h"
#include "felix86/ir/block.h"
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

    list->block->predecessors = entry;

    ir_function_t* function = calloc(sizeof(ir_function_t), 1);
    function->entry = entry;
    function->first = list;
    function->last = list;

    return function;
}

void ir_function_destroy(ir_function_t* function)
{
    ir_block_list_t* current = function->first;
    while (current) {
        ir_block_list_t* next = current->next;
        ir_ilist_destroy(current->block->instructions);
        free(current->block);
        free(current);
        current = next;
    }

    ir_ilist_destroy(function->entry->block->instructions);
    free(function->entry->block);
    free(function->entry);
    free(function);
}

ir_block_t* ir_function_get_block(ir_function_t* function, ir_block_t* predecessor, u64 address) {
    if (address != IR_NO_ADDRESS) {
        for (ir_block_list_t* current = function->first; current; current = current->next) {
            if (current->block->start_address == address) {
                if (predecessor) {
                    ir_add_predecessor(current->block, predecessor);
                }
                return current->block;
            }
        }
    }

    ir_block_t* block = ir_block_create(address);
    ir_block_list_t* list = ir_block_list_create(block);
    function->last->next = list;
    function->last = list;

    // Add block to predecessor's successors
    if (predecessor) {
        ir_add_successor(predecessor, block);
    }

    return block;
}

void ir_add_predecessor(ir_block_t* block, ir_block_t* predecessor) {
    ir_block_list_t* list = ir_block_list_create(predecessor);
    list->next = block->predecessors;
    block->predecessors = list;
    block->predecessors_count++;
    ir_block_list_t* succ = ir_block_list_create(block);
    succ->next = predecessor->successors;
    predecessor->successors = succ;
    predecessor->successors_count++;
}

void ir_add_successor(ir_block_t* block, ir_block_t* successor) {
    ir_block_list_t* list = ir_block_list_create(successor);
    list->next = block->successors;
    block->successors = list;
    block->successors_count++;
    ir_block_list_t* pred = ir_block_list_create(block);
    pred->next = successor->predecessors;
    successor->predecessors = pred;
    successor->predecessors_count++;
}