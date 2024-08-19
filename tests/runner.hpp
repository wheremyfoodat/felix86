#include <xbyak/xbyak.h>
#include "felix86/common/utility.h"
#include "felix86.h"

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

#define FELIX86_TEST(name) struct Code_##name : Xbyak::CodeGenerator { \
    Code_##name(); \
    ~Code_##name() { free(data); } \
    void verify(x86_ref_t ref, u64 value) { checks.push_back({ ref, value }); } \
    void verify_flag(x86_flag_t flag, bool value) { switch (flag) { \
        case X86_FLAG_CF: flag_check &= ~(1 << 0); flag_check |= value << 0; break; \
        case X86_FLAG_PF: flag_check &= ~(1 << 2); flag_check |= value << 2; break; \
        case X86_FLAG_AF: flag_check &= ~(1 << 4); flag_check |= value << 4; break; \
        case X86_FLAG_ZF: flag_check &= ~(1 << 6); flag_check |= value << 6; break; \
        case X86_FLAG_SF: flag_check &= ~(1 << 7); flag_check |= value << 7; break; \
        case X86_FLAG_OF: flag_check &= ~(1 << 11); flag_check |= value << 11; break; \
        default: REQUIRE(false); break; \
    } } \
    u8* data; \
private: \
    void emit_code(); \
    void verify_checks() { \
        for (auto& check : checks) { \
            REQUIRE(felix86_get_guest(recompiler, check.first) == check.second); \
        } \
        REQUIRE(felix86_get_guest(recompiler, X86_REF_FLAGS) == flag_check); \
    } \
    environment_t env; \
    felix86_recompiler_t* recompiler; \
    std::vector<std::pair<x86_ref_t, u64>> checks; \
    u64 flag_check = 0; \
}; \
TEST_CASE(#name, "[felix86]") { \
    Code_##name c; \
} \
Code_##name::Code_##name() : Xbyak::CodeGenerator(0x1000, malloc(0x2000)) { \
    data = (u8*)getCode(); \
    env.read8 = read8; \
    env.read16 = read16; \
    env.read32 = read32; \
    env.read64 = read64; \
    env.write8 = write8; \
    env.write16 = write16; \
    env.write32 = write32; \
    env.write64 = write64; \
    env.get_pointer = get_pointer; \
    env.context = data; \
    emit_code(); \
    hlt(); /* emit a hlt instruction to stop the recompiler */ \
    felix86_recompiler_config_t config = { .env = &env, .testing = true }; \
    recompiler = felix86_recompiler_create(&config); \
    felix86_recompiler_run(recompiler, 0); \
    verify_checks(); \
    felix86_recompiler_destroy(recompiler); \
} \
void Code_##name::emit_code()
