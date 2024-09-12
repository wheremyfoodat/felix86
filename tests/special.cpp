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

FELIX86_TEST(stosq) {
    Xbyak::Label memory, end;
    mov(rdi, memory);
    mov(rax, 0x123456789bcdef0);
    stosq();
    jmp(end);
    L(memory);
    dq(0xdeadbeefdeadbeef);
    L(end);

    verify_memory((u64*)memory.getAddress(), 0x123456789bcdef0, sizeof(u64));
    verify(X86_REF_RDI, (u64)memory.getAddress() + 8);
}

FELIX86_TEST(stosw) {
    Xbyak::Label memory, end;
    mov(rdi, memory);
    mov(rax, 0x1234);
    stosw();
    jmp(end);
    L(memory);
    dw(0xdead);
    L(end);

    verify_memory((u16*)memory.getAddress(), 0x1234, sizeof(u16));
    verify(X86_REF_RDI, (u64)memory.getAddress() + 2);
}

FELIX86_TEST(stosd) {
    Xbyak::Label memory, end;
    mov(rdi, memory);
    mov(rax, 0x12345678);
    stosd();
    jmp(end);
    L(memory);
    dd(0xdeadbeef);
    L(end);

    verify_memory((u32*)memory.getAddress(), 0x12345678, sizeof(u32));
    verify(X86_REF_RDI, (u64)memory.getAddress() + 4);
}

FELIX86_TEST(rep_stosq) {
    Xbyak::Label memory, end;
    mov(rcx, 6);
    mov(rdi, memory);
    mov(rax, 0x123456789bcdef0);
    rep();
    stosq();
    rep();
    stosq(); // should do nothing, rcx should be zero
    jmp(end);
    L(memory);
    dq(0xdeadbeefdeadbeef);
    dq(0xdeadbeefdeadbeef);
    dq(0xdeadbeefdeadbeef);
    dq(0xdeadbeefdeadbeef);
    dq(0xdeadbeefdeadbeef);
    dq(0xdeadbeefdeadbeef);
    dq(0xdeadbeefdeadbeef);
    L(end);
    mov(rsi, 0x1234);

    for (int i = 0; i < 6; i++) {
        verify_memory((u64*)memory.getAddress() + i, 0x123456789bcdef0, sizeof(u64));
    }

    // Memory past not overwritten
    verify_memory((u64*)memory.getAddress() + 6, 0xdeadbeefdeadbeef, sizeof(u64));

    verify(X86_REF_RDI, (u64)memory.getAddress() + 8 * 6);
    verify(X86_REF_RSI, 0x1234);
}

FELIX86_TEST(cwd_sign) {
    mov(ax, 0x8123);
    cwd();

    verify(X86_REF_RAX, 0x8123);
    verify(X86_REF_RDX, 0xffff);
}

FELIX86_TEST(cwd_no_sign) {
    mov(ax, 0x0123);
    cwd();

    verify(X86_REF_RAX, 0x0123);
    verify(X86_REF_RDX, 0);
}

FELIX86_TEST(cdq_sign) {
    mov(eax, 0x81234567);
    cdq();

    verify(X86_REF_RAX, 0x81234567);
    verify(X86_REF_RDX, 0xffffffff);
}

FELIX86_TEST(cdq_no_sign) {
    mov(eax, 0x01234567);
    cdq();

    verify(X86_REF_RAX, 0x01234567);
    verify(X86_REF_RDX, 0);
}

FELIX86_TEST(cqo_sign) {
    mov(rax, 0x8123456789abcdef);
    cqo();

    verify(X86_REF_RAX, 0x8123456789abcdef);
    verify(X86_REF_RDX, 0xffffffffffffffff);
}

FELIX86_TEST(cqo_no_sign) {
    mov(rax, 0x0123456789abcdef);
    cqo();

    verify(X86_REF_RAX, 0x0123456789abcdef);
    verify(X86_REF_RDX, 0);
}

FELIX86_TEST(bsr_word) {
    mov(ax, 0x0801);
    bsr(cx, ax);

    verify(X86_REF_RCX, 11);
}

FELIX86_TEST(bsr_dword) {
    mov(eax, 0x08080000);
    bsr(ecx, eax);

    verify(X86_REF_RCX, 27);
}

FELIX86_TEST(bsr_qword) {
    mov(rax, 0x0800080000000000);
    bsr(rcx, rax);

    verify(X86_REF_RCX, 59);
}

FELIX86_TEST(stc) {
    stc();

    verify_c(true);
}