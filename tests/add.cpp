#include "runner.hpp"

#define TEST_ADD(x, y) FELIX86_TEST(add_##x##_##y) { \
    uint8_t ux = x, uy = y; \
    int8_t sx = ux, sy = uy; \
    mov(al, ux); mov(bl, uy); add(al, bl); \
    verify(X86_REF_RAX, (uint8_t)(x + y)); \
    uint8_t result; int8_t sresult; \
    bool overflow = __builtin_add_overflow(sx, sy, &sresult); \
    bool carry = __builtin_add_overflow(ux, uy, &result); \
    verify_c(carry); \
    verify_o(overflow); \
}

TEST_ADD(1, 5)
TEST_ADD(127, 1)
TEST_ADD(255, 1)
TEST_ADD(255, 255)
TEST_ADD(127, 127)
TEST_ADD(255, 0)
TEST_ADD(0, 255)
TEST_ADD(127, 0)
TEST_ADD(0, 127)

FELIX86_TEST(add_sign_extend) {
    xor_(ebx, ebx);
    add(ebx, -1); // encoded as add rm32, imm8 - gets sign extended

    verify(X86_REF_RBX, (uint32_t)-1ull);
}