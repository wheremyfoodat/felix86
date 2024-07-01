#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/common/utility.h"

typedef struct {
    u8 (*read8)(void* context, u64 address);
    u16 (*read16)(void* context, u64 address);
    u32 (*read32)(void* context, u64 address);
    u64 (*read64)(void* context, u64 address);
    void (*write8)(void* context, u64 address, u8 value);
    void (*write16)(void* context, u64 address, u16 value);
    void (*write32)(void* context, u64 address, u32 value);
    void (*write64)(void* context, u64 address, u64 value);
    u8* (*get_pointer)(void* context, u64 address);
    void (*interrupt)(void* context, u8 vector);

    void* context;
} environment_t;

#ifdef __cplusplus
}
#endif