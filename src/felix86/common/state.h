#pragma once

#include "felix86/common/utility.h"

typedef struct {
    u64 gprs[16];
    u64 flags;
    u64 rip;
    u16 gs;
    u16 fs;
} x86_state_t;