#include "felix86/ir/passes.h"
#include <algorithm>
#include <unordered_map>
#include <vector>

/*
    This file is in C++ instead of C to not have to reimplement some very useful standard C++ containers

    This is written with my current understanding of SSA at this time, parts of it could be wrong.

    We want to convert registers (rax, rcx, ...) to SSA form. At this time we do not care about moving memory to SSA.
    This is because when there's code like this:

    mov rax, 1
    mov rax, 2

    If we emit IR like so:

    rax = 1
    rax = 2

    This is essentially code that is not in SSA, if you view these registers as variables.
    What we'd like is for them to be transformed into IR like so:

    rax_0 = 1
    rax_1 = 2
    ...
    (immediately after the last usage of rax, store it back to memory)
    
    This is not hard, but there's a tiny gotcha. Imagine the first occurence of a usage of a variable.
    Imagine that this first usage is not dominated by a definition. So for example if your very first basic
    block in a CFG started with this instruction:

    mov rbx, rax

    rax here has a usage but is not dominated by a definition. So we need to insert a definition when converting to
    SSA:

    rax_0 = load rax from memory (our actual state struct)
    rbx_0 = rax_0

    Furthermore, we need to ensure that a load like this, even though it defines a variable named rax_0, it doesn't
    actually write it back because rax is not changed.

    If these rules are ensured, then dead load/store elimination should be simple. Stores and loads with no uses will get eliminated.

    ---

    We also want to use definitions of registers from previous blocks. This will be done by inserting a phi instruction
    A phi instruction selects a value based on the block it was reached from. Phi instructions are
    something that only exists while in SSA form, and are later removed when moving out of SSA form.

    Phi instructions are not difficult to add and there's multiple algorithms such as Cytron et al. and Braun et al.
    
    Cytron describes translation to minimal SSA form to go in three steps:
        1. The dominance frontier mapping is constructed from the control flow graph
        2. Using the dominance frontiers, the locations of the phi functions for each variable
        in the original program are determined
        3. The variables are renamed by replacing each mention of an original variable V with an
        appropriate mention of a new variable Vi

    For 1. we are going to be using a different algorithm by Cooper et al. that is faster (and imo simpler) than Cytron et al.

    It's important to note that in our IR, the only variables are the registers (rax, rcx, ..., xmm0, ..., cf, zf, ...)
    and those are the ones that need to be renamed. Temporary variables produced by instructions do not need to be
    renamed as they already are in SSA form.

    So for example, when we have the following instruction:

    or eax, 1
    (more instructions that set or use rax)

    The following IR is generated:
    (note that we handle the size in the IR explicitly, there's no different instructions to deal with different GPR sizes as of this moment)

    t0 = rax
    t1 = t0 | 1
    t2 = 0xFFFFFFFF
    t3 = t1 & t2
    rax = t3
    (more IR that sets flags, uses rax or sets rax)

    t0-t3 and the rest of the temporaries down the road are in SSA form already, it's just the registers that need to be renamed
*/

struct ir_block_info_t {
    ir_block_t* actual_block = nullptr;
    std::vector<ir_block_info_t> dominators = {};
    ir_block_info_t* immediate_dominator = nullptr;

    ir_block_info_t* successor1 = nullptr;
    ir_block_info_t* successor2 = nullptr;
    bool visited = false;
};

void postorder(ir_block_info_t* block, std::vector<ir_block_info_t>& output) {
    if (block->visited) {
        return;
    }

    block->visited = true;

    if (block->successor1) {
        postorder(block->successor1, output);
    }

    if (block->successor2) {
        postorder(block->successor2, output);
    }

    output.push_back(*block);
}

void reverse_postorder_vector_creation(ir_function_t* function, std::vector<ir_block_info_t>& output) {
    std::vector<ir_block_info_t> list;
    list.resize(output.size());

    std::vector<std::pair<ir_block_t*, ir_block_t*>> successors;
    successors.resize(output.size());

    std::unordered_map<ir_block_t*, int> block_to_index;
    ir_block_list_t* block = function->list;
    size_t index = 0;
    while (block) {
        list[index].actual_block = block->block;
        list[index].visited = false;
        block_to_index[block->block] = index;
        successors[index].first = block->block->successors ? block->block->successors->block : nullptr;
        successors[index].second = block->block->successors ? block->block->successors->next ? block->block->successors->next->block : nullptr : nullptr;
        index++;
        block = block->next;
    }

    for (size_t i = 0; i < list.size(); i++) {
        list[i].successor1 = successors[i].first ? &list[block_to_index[successors[i].first]] : nullptr;
        list[i].successor2 = successors[i].second ? &list[block_to_index[successors[i].second]] : nullptr;
    }

    ir_block_info_t* entry = &list[0];
    postorder(entry, output);
    std::reverse(output.begin(), output.end());
    
    for (size_t i = 0; i < list.size(); i++) {
        output[i].visited = false;
    }
}


void ir_ssa_pass(ir_function_t* function) {
    size_t count = 0;
    ir_block_list_t* block = function->list;
    while (block) {
        count++;
        block = block->next;
    }

    std::vector<ir_block_info_t> rpo_vector;
    rpo_vector.resize(count);
    
    reverse_postorder_vector_creation(function, rpo_vector);
}