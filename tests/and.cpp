#include "runner.hpp"

FELIX86_TEST(and_high) {
    mov(eax, 0xFFFFFFFF);
    and_(ah, 0x12);
    and_(rbx, 0);

    verify(X86_REF_RAX, 0xFFFF12FF);
}

FELIX86_TEST(and_rex_low) {
    mov(r15, 0xFFFFFFFF);
    and_(r15b, 0x12);

    verify(X86_REF_R15, 0xFFFFFF12);
}