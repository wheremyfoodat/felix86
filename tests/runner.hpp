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
    void emit_code(); \
    environment_t env; \
    felix86_recompiler_t* recompiler; \
    u8* data; \
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
    felix86_recompiler_config_t config = { .env = &env }; \
    recompiler = felix86_recompiler_create(&config); \
    felix86_recompiler_run(recompiler, 0); \
    felix86_recompiler_destroy(recompiler); \
} \
void Code_##name::emit_code()
