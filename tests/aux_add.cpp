#include "runner.hpp"

#define AUX_TEST_ADD(x, y) FELIX86_TEST(aux_add_##x##_##y) { mov(al, x); mov(bl, y); add(al, bl); verify(X86_REF_RAX, (uint8_t)(x + y)); verify_a(((x & 0xF) + (y & 0xF)) > 0xF); }

#define PACK_ADD(x) \
    AUX_TEST_ADD(x, 0) \
    AUX_TEST_ADD(x, 1) \
    AUX_TEST_ADD(x, 2) \
    AUX_TEST_ADD(x, 3) \
    AUX_TEST_ADD(x, 4) \
    AUX_TEST_ADD(x, 5) \
    AUX_TEST_ADD(x, 6) \
    AUX_TEST_ADD(x, 7) \
    AUX_TEST_ADD(x, 8) \
    AUX_TEST_ADD(x, 9) \
    AUX_TEST_ADD(x, 10) \
    AUX_TEST_ADD(x, 11) \
    AUX_TEST_ADD(x, 12) \
    AUX_TEST_ADD(x, 13) \
    AUX_TEST_ADD(x, 14) \
    AUX_TEST_ADD(x, 15)

PACK_ADD(0)
PACK_ADD(1)
PACK_ADD(2)
PACK_ADD(3)
PACK_ADD(4)
PACK_ADD(5)
PACK_ADD(6)
PACK_ADD(7)
PACK_ADD(8)
PACK_ADD(9)
PACK_ADD(10)
PACK_ADD(11)
PACK_ADD(12)
PACK_ADD(13)
PACK_ADD(14)
PACK_ADD(15)