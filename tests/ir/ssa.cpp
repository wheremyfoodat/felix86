#include <catch2/catch_test_macros.hpp>
#include <xbyak/xbyak.h>
#include "felix86/common/utility.h"
#include "felix86/felix86.h"
#include "felix86/frontend/frontend.h"
#include "felix86/ir/emitter.h"
#include "felix86/ir/print.h"

using namespace Xbyak::util;

TEST_CASE("local-ssa", "[felix86]") {
    Xbyak::CodeGenerator c(0x1000, malloc(0x1000));
    c.mov(rax, 42);
    c.mov(rbx, rax);
    c.mov(rcx, rbx);
    c.add(rcx, rax);

    c.mov(rax, rcx);
    c.add(rax, 23);
    c.mov(rcx, rax);
    c.add(rcx, rdx);

    c.hlt();

    ir_block_t block = {0};
	block.start_address = c.getCode<u64>();
	block.instructions = ir_ilist_create();
	block.compiled = false;

    ir_emitter_state_t state = {0};
    state.block = &block;
    state.current_address = c.getCode<u64>();
    state.base_address = c.getCode<u64>();
    state.exit = false;
    state.testing = true;
    state.debug_info = true;
    frontend_compile_block(&state);

    ir_print_block(&block);
}