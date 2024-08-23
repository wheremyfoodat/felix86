#include "runner.hpp"

FELIX86_TEST(lea_rip_relative) {
    nop();
    nop();
    nop();
    nop();
    nop();
    lea(rax, ptr[rip + 0x12345678]);

    void* dataEnd = (void*)getCurr();
    u64 ripExpected = (u64)dataEnd + 0x12345678;

    verify(X86_REF_RAX, ripExpected);
}

FELIX86_TEST(lea_index_not_used) {
    mov(rsp, 45);
    lea(rax, ptr[rsp + 10]);

    verify(X86_REF_RAX, 55);
}

FELIX86_TEST(lea_sign_extend) {
    xor_(eax, eax);

    lea(rbx, ptr[eax - 0x12345678]); // uses 4 byte displacement
    lea(rax, ptr[eax - 5]); // uses 1 byte displacement

    verify(X86_REF_RAX, -5ull);
    verify(X86_REF_RBX, -0x12345678ull);
}

FELIX86_TEST(lea_base_not_used) {
    mov(rbx, 45);
    lea(rax, ptr[rax + rbx * 8]);
    lea(rax, ptr[rbx * 8]);

    verify(X86_REF_RAX, 8 * 45);
}

FELIX86_TEST(lea_full) {
    mov(rax, 0x12345678);
    mov(rbx, 0x87654321);

    lea(rax, ptr[rax + rbx * 8]);

    verify(X86_REF_RAX, 0x12345678ull + (0x87654321ull * 8));
}

FELIX86_TEST(lea_rbp_r13) {
    mov(rbp, 0x12345678);
    mov(r13, 0x87654321);

    lea(rax, ptr[rbp]);
    lea(rbx, ptr[r13]);

    verify(X86_REF_RAX, 0x12345678);
    verify(X86_REF_RBX, 0x87654321);
}

FELIX86_TEST(lea_rsp_r12) {
    mov(rsp, 0x12345678);
    mov(r12, 0x87654321);

    lea(rax, ptr[rsp]);
    lea(rbx, ptr[r12]);
    lea(rcx, ptr[rsp + r12]);

    verify(X86_REF_RAX, 0x12345678);
    verify(X86_REF_RBX, 0x87654321);
    verify(X86_REF_RCX, 0x12345678 + 0x87654321);
}
