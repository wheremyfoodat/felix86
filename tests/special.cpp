#include "runner.hpp"

FELIX86_TEST(push_pop64) {
    mov(rax, 0x123456789bcdef0);
    push(rax);
    mov(rbx, 0);
    pop(rbx);

    mov(rcx, 0x123456789bcdef0);
    push(cx);
    mov(rdx, 0);
    pop(dx);

    verify(X86_REF_RBX, 0x123456789bcdef0);
    verify(X86_REF_RDX, 0xdef0);
}