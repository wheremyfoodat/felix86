#include "runner.hpp"

FELIX86_TEST(lea_rip_relative) {
    mov(al, 0);
    mov(al, 0);
    mov(al, 0);
    mov(al, 0);
    lea(rax, ptr[rip + 0x12345678]);

    void* dataEnd = (void*)getCurr();
    u64 ripExpected = (u64)dataEnd + 0x12345678;

    verify(X86_REF_RAX, ripExpected);
}