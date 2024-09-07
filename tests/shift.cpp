#include "runner.hpp"

FELIX86_TEST(shift_left) {
    mov(rax, 0x12345678);
    shl(rax, 1);

    mov(rbx, 0x12345678);
    shl(rbx, 2);

    mov(ecx, 0x12345);
    shl(ecx, 1);

    mov(dx, 0x1234);
    shl(dx, 1);

    mov(dil, 0x12);
    shl(dil, 1);

    verify(X86_REF_RAX, 0x12345678ull << 1);
    verify(X86_REF_RBX, 0x12345678ull << 2);
    verify(X86_REF_RCX, 0x12345 << 1);
    verify(X86_REF_RDX, (u16)(0x1234 << 1));
    verify(X86_REF_RDI, (u8)(0x12 << 1));
}

FELIX86_TEST(shift_right) {
    mov(rax, 0x12345678);
    shr(rax, 1);

    mov(rbx, 0x12345678);
    shr(rbx, 2);

    mov(ecx, 0x12345);
    shr(ecx, 1);

    mov(dx, 0x1234);
    shr(dx, 1);

    mov(dil, 0x12);
    shr(dil, 1);

    verify(X86_REF_RAX, 0x12345678ull >> 1);
    verify(X86_REF_RBX, 0x12345678ull >> 2);
    verify(X86_REF_RCX, 0x12345 >> 1);
    verify(X86_REF_RDX, (u16)(0x1234 >> 1));
    verify(X86_REF_RDI, (u8)(0x12 >> 1));
}

FELIX86_TEST(shift_right_arithmetic) {
    mov(rax, 0x8000000000000000);
    sar(rax, 63);

    mov(rbx, 0x180000000);
    sar(ebx, 31);

    mov(ecx, 0x12348000);
    sar(cx, 15);

    mov(edx, 0x12345680);
    sar(dl, 7);

    mov(rbp, 0x8010000000000000);
    sar(rbp, 20);

    mov(esi, 0x80100000);
    sar(esi, 15);

    mov(r8, 0x12348010);
    sar(r8w, 6);

    mov(r9, 0x12345688);
    sar(r9b, 3);

    verify(X86_REF_RAX, -1ull);
    verify(X86_REF_RBX, (u32)-1);
    verify(X86_REF_RCX, 0x1234FFFF);
    verify(X86_REF_RDX, 0x123456FF);
    verify(X86_REF_RBP, (i64)0x8010000000000000 >> 20);
    verify(X86_REF_RSI, (u32)((i32)0x80100000 >> 15));
    verify(X86_REF_R8, (u32)(u16)((i16)0x8010 >> 6) | 0x12340000);
    verify(X86_REF_R9, (u32)(u8)((i8)0x88 >> 3) | 0x12345600);
}