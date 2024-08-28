#include "runner.hpp"

#define TEST_SUB(x, y) FELIX86_TEST(sub_##x##_##y) { \
    uint8_t ux = x, uy = y; \
    int8_t sx = ux, sy = uy; \
    mov(al, ux); mov(bl, uy); sub(al, bl); \
    verify(X86_REF_RAX, (uint8_t)(x - y)); \
    uint8_t result; int8_t sresult; \
    bool overflow = __builtin_sub_overflow(sx, sy, &sresult); \
    bool carry = __builtin_sub_overflow(ux, uy, &result); \
    verify_c(carry); \
    verify_o(overflow); \
    int a_1 = ux & 0xF, a_2 = uy & 0xF; \
    int a = a_1 - a_2; \
    verify_a(a < 0); \
}

TEST_SUB(1, 5)
TEST_SUB(127, 1)
TEST_SUB(255, 1)
TEST_SUB(255, 255)
TEST_SUB(127, 127)
TEST_SUB(255, 0)
TEST_SUB(0, 255)
TEST_SUB(127, 0)
TEST_SUB(0, 127)
TEST_SUB(0, 128)
TEST_SUB(128, 0)
TEST_SUB(128, 128)
TEST_SUB(128, 127)
TEST_SUB(127, 128)
TEST_SUB(10, 0xE0)
TEST_SUB(0xE0, 10)
TEST_SUB(0xE0, 0xF0)
TEST_SUB(0xF0, 0xE0)
TEST_SUB(0xF0, 0xF0)
TEST_SUB(0x0F, 0x0F)
TEST_SUB(0x0F, 0x0E)
TEST_SUB(0x0E, 0x0F)
TEST_SUB(0, 0x0F)