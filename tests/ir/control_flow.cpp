#include "ir_runner.hpp"

TEST_CASE("simple_if", "[felix86-ir]") {
    START_IR_TEST();
    ir_block_t* target_true = CREATE_BLOCK(entry);
    ir_block_t* target_false = CREATE_BLOCK(entry);
    ir_block_t* end = CREATE_BLOCK(target_true);
    ir_add_predecessor(end, target_false);
    x86_operand_t rax = get_full_reg(X86_REF_RAX);

    SWITCH_TO_BLOCK(entry);
    ir_instruction_t* reg = ir_emit_get_reg(INSTS, &rax);
    ir_instruction_t* condition = ir_emit_equal(INSTS, reg, ir_emit_immediate(INSTS, 0));
    ir_emit_jump_conditional(INSTS, condition, target_true, target_false);

    SWITCH_TO_BLOCK(target_true);
    ir_instruction_t* true_val = ir_emit_immediate(INSTS, 20);
    ir_emit_set_reg(INSTS, &rax, true_val);
    ir_emit_jump(INSTS, end);

    SWITCH_TO_BLOCK(target_false);
    ir_instruction_t* false_val = ir_emit_immediate(INSTS, 30);
    ir_emit_set_reg(INSTS, &rax, false_val);
    ir_emit_jump(INSTS, end);

    SWITCH_TO_BLOCK(end);
    ir_emit_exit(INSTS);

    END_IR_TEST();

    x86_state_t state = {0};
    ir_interpret_function(function, &state);

    REQUIRE(state.gprs[X86_REF_RAX - X86_REF_RAX] == 20);

    ir_function_destroy(function);
}

// TEST_CASE("simple_do_while_loop", "[felix86-ir]") {
//     START_IR_TEST();
//     ir_block_t* loop = CREATE_BLOCK(entry);
//     ir_block_t* end = CREATE_BLOCK(loop);
//     x86_operand_t rax = get_full_reg(X86_REF_RAX);
//     ir_add_predecessor(loop, loop);
    
//     SWITCH_TO_BLOCK(entry);
//     ir_emit_jump(INSTS, loop);

//     SWITCH_TO_BLOCK(loop);
//     ir_instruction_t* reg = ir_emit_get_reg(INSTS, &rax);
//     ir_instruction_t* added = ir_emit_add(INSTS, reg, ir_emit_immediate(INSTS, 1));
//     ir_emit_set_reg(INSTS, &rax, added);
//     ir_instruction_t* condition = ir_emit_equal(INSTS, added, ir_emit_immediate(INSTS, 10));
//     ir_emit_jump_conditional(INSTS, condition, end, loop);

//     SWITCH_TO_BLOCK(end);
//     ir_emit_exit(INSTS);

//     END_IR_TEST();

//     ir_print_function_uml(function);

//     x86_state_t state = {0};
//     ir_interpret_function(function, &state);

//     REQUIRE(state.gprs[X86_REF_RAX - X86_REF_RAX] == 10);
// }