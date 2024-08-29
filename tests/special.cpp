#include "runner.hpp"

FELIX86_TEST(cpuid_dead_store) {
    // Checks that these stores aren't optimized away
    mov(rax, 0);
    mov(rbx, 1);
    mov(rcx, 2);
    mov(rdx, 5); // should be optimized away
    mov(rdx, 3);
    cpuid();
    mov(rax, 3);
    mov(rcx, 6);
    add(rdx, 2);

    verify(X86_REF_RAX, 3);
    verify(X86_REF_RBX, 1);
    verify(X86_REF_RCX, 6);
    verify(X86_REF_RDX, 5);
}

FELIX86_TEST(push_pop64) {
    mov(rax, 0x123456789bcdef0);
    push(rax);
    mov(rbx, 0);
    pop(rbx);

    verify(X86_REF_RBX, 0x123456789bcdef0);
}