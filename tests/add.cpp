#include <catch2/catch_test_macros.hpp>
#include "runner.hpp"

using namespace Xbyak;
using namespace Xbyak::util;

FELIX86_TEST(add_rm8_r8) {
    mov(bl, 0x13);
    hlt();
}