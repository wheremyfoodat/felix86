#include <catch2/catch_test_macros.hpp>
#include <xbyak/xbyak.h>
#include "felix86/common/utility.h"
#include "felix86/felix86.h"

using namespace Xbyak;
using namespace Xbyak::util;

static u8 read8(void* context, u64 address) {
    u8* data = (u8*)context;
    return data[address];
}

static u16 read16(void* context, u64 address) {
    u8* data = (u8*)context;
    return *(u16*)&data[address];
}

static u32 read32(void* context, u64 address) {
    u8* data = (u8*)context;
    return *(u32*)&data[address];
}

static u64 read64(void* context, u64 address) {
    u8* data = (u8*)context;
    return *(u64*)&data[address];
}

static void write8(void* context, u64 address, u8 value) {
    u8* data = (u8*)context;
    data[address] = value;
}

static void write16(void* context, u64 address, u16 value) {
    u8* data = (u8*)context;
    *(u16*)&data[address] = value;
}

static void write32(void* context, u64 address, u32 value) {
    u8* data = (u8*)context;
    *(u32*)&data[address] = value;
}

static void write64(void* context, u64 address, u64 value) {
    u8* data = (u8*)context;
    *(u64*)&data[address] = value;
}

static u8* get_pointer(void* context, u64 address) {
    return (u8*)context + address;
}

static void interrupt(void* context, u8 vector) {}

#define FELIX86_TEST(name) struct Code_##name final : Xbyak::CodeGenerator { \
    Code_##name(); \
    ~Code_##name() { free(data); } \
    void verify(x86_ref_e ref, u64 value) { checks.push_back({ ref, value }); } \
    void verify_c(bool value) { c = value; } \
    void verify_p(bool value) { p = value; } \
    void verify_a(bool value) { a = value; } \
    void verify_z(bool value) { z = value; } \
    void verify_s(bool value) { s = value; } \
    void verify_o(bool value) { o = value; } \
    u8* data; \
private: \
    void emit_code(); \
    void verify_checks() { \
        for (auto& check : checks) { \
            REQUIRE(felix86_get_guest(recompiler, check.first) == check.second); \
        } \
        if (c.has_value()) REQUIRE(!!(felix86_get_guest(recompiler, X86_REF_FLAGS) & (1 << X86_FLAG_CF)) == c.value()); \
        if (p.has_value()) REQUIRE(!!(felix86_get_guest(recompiler, X86_REF_FLAGS) & (1 << X86_FLAG_PF)) == p.value()); \
        if (a.has_value()) REQUIRE(!!(felix86_get_guest(recompiler, X86_REF_FLAGS) & (1 << X86_FLAG_AF)) == a.value()); \
        if (z.has_value()) REQUIRE(!!(felix86_get_guest(recompiler, X86_REF_FLAGS) & (1 << X86_FLAG_ZF)) == z.value()); \
        if (s.has_value()) REQUIRE(!!(felix86_get_guest(recompiler, X86_REF_FLAGS) & (1 << X86_FLAG_SF)) == s.value()); \
        if (o.has_value()) REQUIRE(!!(felix86_get_guest(recompiler, X86_REF_FLAGS) & (1 << X86_FLAG_OF)) == o.value()); \
    } \
    felix86_recompiler_t* recompiler; \
    std::vector<std::pair<x86_ref_e, u64>> checks; \
    std::optional<bool> c,p,a,z,s,o; \
}; \
TEST_CASE(#name, "[felix86]") { \
    Code_##name c; \
} \
Code_##name::Code_##name() : Xbyak::CodeGenerator(0x1000, malloc(0x2000)) { \
    data = (u8*)getCode(); \
    emit_code(); \
    hlt(); /* emit a hlt instruction to stop the recompiler */ \
    felix86_recompiler_config_t config = { .testing = true }; \
    recompiler = felix86_recompiler_create(&config); \
    felix86_set_guest(recompiler, X86_REF_RIP, (u64)data); \
    felix86_recompiler_run(recompiler, 0); \
    verify_checks(); \
    felix86_recompiler_destroy(recompiler); \
} \
void Code_##name::emit_code()
