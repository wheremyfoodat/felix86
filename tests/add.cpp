#include <catch2/catch_test_macros.hpp>
#include "runner.hpp"

using namespace Xbyak;
using namespace Xbyak::util;

FELIX86_TEST(add_rm8_r8) {
    mov(al, 1);
    mov(bl, 1);
    add(al, bl);

    verify(X86_REF_RAX, 0x02);
    verify(X86_REF_RBX, 0x01);
    verify_flag(X86_FLAG_CF, false);
    verify_flag(X86_FLAG_PF, false);
    verify_flag(X86_FLAG_AF, false);
    verify_flag(X86_FLAG_ZF, false);
    verify_flag(X86_FLAG_SF, false);
    verify_flag(X86_FLAG_OF, false);
}

FELIX86_TEST(add_rm8_r8_negative) {
    mov(al, 2);
    mov(bl, 0xFF);
    add(al, bl);

    verify(X86_REF_RAX, 0x01);
    verify(X86_REF_RBX, 0xFF);
    verify_flag(X86_FLAG_CF, true);
    verify_flag(X86_FLAG_PF, false);
    verify_flag(X86_FLAG_AF, true);
    verify_flag(X86_FLAG_ZF, false);
    verify_flag(X86_FLAG_SF, false);
    verify_flag(X86_FLAG_OF, false);
}

FELIX86_TEST(add_rm8_r8_auxiliary) {
    mov(al, 0x06);
    mov(bl, 0x0A);
    add(al, bl);

    verify(X86_REF_RAX, 0x10);
    verify(X86_REF_RBX, 0x0A);
    verify_flag(X86_FLAG_CF, false);
    verify_flag(X86_FLAG_PF, false);
    verify_flag(X86_FLAG_AF, true);
    verify_flag(X86_FLAG_ZF, false);
    verify_flag(X86_FLAG_SF, false);
    verify_flag(X86_FLAG_OF, false);
}

FELIX86_TEST(add_rm8_r8_zero) {
    mov(al, 0);
    mov(bl, 0);
    add(al, bl);

    verify(X86_REF_RAX, 0x00);
    verify(X86_REF_RBX, 0x00);
    verify_flag(X86_FLAG_CF, false);
    verify_flag(X86_FLAG_PF, true);
    verify_flag(X86_FLAG_AF, false);
    verify_flag(X86_FLAG_ZF, true);
    verify_flag(X86_FLAG_SF, false);
    verify_flag(X86_FLAG_OF, false);
}

FELIX86_TEST(add_rm8_r8_overflow) {
    mov(al, 0x7F);
    mov(bl, 0x01);
    add(al, bl);

    verify(X86_REF_RAX, 0x80);
    verify(X86_REF_RBX, 0x01);
    verify_flag(X86_FLAG_CF, false);
    verify_flag(X86_FLAG_PF, false);
    verify_flag(X86_FLAG_AF, true);
    verify_flag(X86_FLAG_ZF, false);
    verify_flag(X86_FLAG_SF, true);
    verify_flag(X86_FLAG_OF, true);
}

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
    mov(spl, value2);
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
    verify(X86_REF_RSP, value2);
    verify(X86_REF_R8, value);
    verify(X86_REF_R9, value2);
    verify(X86_REF_R10, value);
    verify(X86_REF_R11, value2);
    verify(X86_REF_R12, value);
    verify(X86_REF_R13, value2);
    verify(X86_REF_R14, value);
    verify(X86_REF_R15, value2);
}