#include "runner.hpp"

#define AUX_TEST_SUB(x, y) FELIX86_TEST(aux_sub_##x##_##y) { mov(al, x); mov(bl, y); sub(al, bl); verify(X86_REF_RAX, (uint8_t)(x - y)); verify_a((x & 0xF) < (y & 0xF)); }

#define PACK_SUB(x) \
    AUX_TEST_SUB(x, 0) \
    AUX_TEST_SUB(x, 1) \
    AUX_TEST_SUB(x, 2) \
    AUX_TEST_SUB(x, 3) \
    AUX_TEST_SUB(x, 4) \
    AUX_TEST_SUB(x, 5) \
    AUX_TEST_SUB(x, 6) \
    AUX_TEST_SUB(x, 7) \
    AUX_TEST_SUB(x, 8) \
    AUX_TEST_SUB(x, 9) \
    AUX_TEST_SUB(x, 10) \
    AUX_TEST_SUB(x, 11) \
    AUX_TEST_SUB(x, 12) \
    AUX_TEST_SUB(x, 13) \
    AUX_TEST_SUB(x, 14) \
    AUX_TEST_SUB(x, 15)

PACK_SUB(0)
PACK_SUB(1)
PACK_SUB(2)
PACK_SUB(3)
PACK_SUB(4)
PACK_SUB(5)
PACK_SUB(6)
PACK_SUB(7)
PACK_SUB(8)
PACK_SUB(9)
PACK_SUB(10)
PACK_SUB(11)
PACK_SUB(12)
PACK_SUB(13)
PACK_SUB(14)
PACK_SUB(15)