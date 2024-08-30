#include <catch2/catch_test_macros.hpp>
#include <xbyak/xbyak.h>
#include "felix86/common/utility.h"
#include "felix86/felix86.h"
#include "felix86/frontend/frontend.h"
#include "felix86/ir/emitter.h"
#include "felix86/ir/passes.h"
#include "felix86/ir/print.h"

using namespace Xbyak::util;

TEST_CASE("local-ssa", "[felix86]") {
    Xbyak::CodeGenerator c(0x1000, malloc(0x1000));
    Xbyak::Label true_label, false_label, end_label;
    c.mov(rbx, 0x3);
    c.mov(rax, 0x1);
    c.cmp(rax, 0x1);
    c.jne(false_label);
    c.jmp(true_label);

    c.L(true_label);
    c.mov(rax, rbx);
    c.jmp(end_label);

    c.L(false_label);
    c.mov(rax, 0x3);
    c.jmp(end_label);

    c.L(end_label);
    c.mov(rbx, rax);

    c.hlt();

    felix86_recompiler_config_t config = { .testing = true, .print_blocks = true, .use_interpreter = true };
    felix86_recompiler_t* recompiler = felix86_recompiler_create(&config);
    felix86_set_guest(recompiler, X86_REF_RIP, (u64)c.getCode());
    felix86_recompiler_run(recompiler);

    ir_function_t* function = felix86_get_function(recompiler, (u64)c.getCode());

    ir_ssa_pass(function);
    ir_naming_pass(function);

    ir_block_t* block = function->first->block;
    ir_print_function_uml(function);

    felix86_recompiler_destroy(recompiler);
}