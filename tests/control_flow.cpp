#include "runner.hpp"

FELIX86_TEST(if_zero) {
    Label zero;
    mov(rax, 0);
    test(rax, rax);
    mov(rax, 2);
    jz(zero);
    mov(rax, 1);
    L(zero);
    hlt();

    verify(X86_REF_RAX, 2);
}

FELIX86_TEST(loop_10_times) {
    Label loop;
    mov(rax, 0);
    L(loop);
    jne(loop);
    hlt();

    verify(X86_REF_RAX, 10);
}