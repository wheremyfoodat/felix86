#include "runner.hpp"

FELIX86_TEST(mov_r8_imm8) {
    u8 value = 0x12;
    u8 value2 = 0x34;
    mov(al, value);
    mov(ah, value2);
    mov(bl, value);
    mov(bh, value2);
    mov(cl, value);
    mov(ch, value2);
    mov(dl, value);
    mov(dh, value2);
    mov(sil, value);
    mov(dil, value2);
    mov(bpl, value);
    mov(r8b, value);
    mov(r9b, value2);
    mov(r10b, value);
    mov(r11b, value2);
    mov(r12b, value);
    mov(r13b, value2);
    mov(r14b, value);
    mov(r15b, value2);

    verify(X86_REF_RAX, value | (value2 << 8));
    verify(X86_REF_RBX, value | (value2 << 8));
    verify(X86_REF_RCX, value | (value2 << 8));
    verify(X86_REF_RDX, value | (value2 << 8));
    verify(X86_REF_RSI, value);
    verify(X86_REF_RDI, value2);
    verify(X86_REF_RBP, value);
    verify(X86_REF_R8, value);
    verify(X86_REF_R9, value2);
    verify(X86_REF_R10, value);
    verify(X86_REF_R11, value2);
    verify(X86_REF_R12, value);
    verify(X86_REF_R13, value2);
    verify(X86_REF_R14, value);
    verify(X86_REF_R15, value2);
}

FELIX86_TEST(mov_r8_low_imm8_dont_manipulate_upper) {
    u32 value = 0x12345678;
    mov(eax, value);
    mov(al, 0x12);

    verify(X86_REF_RAX, 0x12345612);
}

FELIX86_TEST(mov_r32_high_imm8_dont_manipulate_lower) {
    u32 value = 0x12345678;
    mov(eax, value);
    mov(ah, 0x34);

    verify(X86_REF_RAX, 0x12343478);
}

FELIX86_TEST(mov_r32_imm16_dont_manipulate_upper) {
    u32 value = 0x12345678;
    mov(eax, value);
    mov(ax, 0x1234);

    verify(X86_REF_RAX, 0x12341234);
}

FELIX86_TEST(mov_r32_imm32_zero_upper) {
    u64 value = 0x12345678ABCDEF0;
    mov(rax, value);
    mov(eax, 0x12345678);

    verify(X86_REF_RAX, 0x12345678);
}

FELIX86_TEST(mov_r64_imm16_dont_manipulate_upper) {
    u64 value = 0x12345678ABCDEF0;
    mov(rax, value);
    mov(ax, 0x1234);

    verify(X86_REF_RAX, 0x12345678ABC1234);
}

FELIX86_TEST(mov_r64_imm8_low_dont_manipulate_upper) {
    u64 value = 0x12345678ABCDEF0;
    mov(rax, value);
    mov(al, 0x12);

    verify(X86_REF_RAX, 0x12345678ABCDE12);
}

FELIX86_TEST(mov_r64_imm8_high_dont_manipulate_upper) {
    u64 value = 0x12345678ABCDEF0;
    mov(rax, value);
    mov(ah, 0x12);

    verify(X86_REF_RAX, 0x12345678ABC12F0);
}

FELIX86_TEST(mov_immediate) {
    mov(al, 0x12);
    mov(ah, 0x34);
    mov(bx, 0x5678);
    mov(ecx, 0x9ABCDEF0);
    mov(rdx, 0x123456789ABCDEF0);
    mov(r8b, 0x12);
    mov(r9w, 0x1234);
    mov(r10d, 0x12345678);
    mov(r11, 0x123456789ABCDEF0);

    verify(X86_REF_RAX, 0x3412);
    verify(X86_REF_RBX, 0x5678);
    verify(X86_REF_RCX, 0x9ABCDEF0);
    verify(X86_REF_RDX, 0x123456789ABCDEF0);
    verify(X86_REF_R8, 0x12);
    verify(X86_REF_R9, 0x1234);
    verify(X86_REF_R10, 0x12345678);
    verify(X86_REF_R11, 0x123456789ABCDEF0);
}

FELIX86_TEST(movzx_r8) {
    u32 value = 0x12345678;
    mov(eax, value);
    movzx(eax, ah);

    mov(ebx, value);
    movzx(ebx, bl);

    verify(X86_REF_RAX, 0x56);
    verify(X86_REF_RBX, 0x78);
}

FELIX86_TEST(movzx_r16) {
    u32 value = 0x12345678;
    mov(eax, value);
    movzx(eax, ax);

    verify(X86_REF_RAX, 0x5678);
}

FELIX86_TEST(mov_dead_store) {
    mov(rax, 1);
    mov(rax, 2);

    mov(rbx, 0x8000'0000);
    mov(bx, 0x1234);

    verify(X86_REF_RAX, 2);
    verify(X86_REF_RBX, 0x8000'1234);
}

// FELIX86_TEST(movq_simple) {
//     mov(rax, 0xBEEFDEADDEADC0DEull);
//     movq(xmm15, rax);

//     xmm_reg_t xmm = { 0 };
//     xmm.data[0] = 0xBEEFDEADDEADC0DE;
//     verify(X86_REF_RAX, 0xBEEFDEADDEADC0DE);
//     verify_xmm(X86_REF_XMM15, xmm);
// }

FELIX86_TEST(mov_r64_rm64) {
    static u64 mem = 0x123456789ABCDEF0;
    mov(r8, (u64)&mem);
    mov(r15, qword[r8]);

    verify(X86_REF_R15, 0x123456789ABCDEF0);
}