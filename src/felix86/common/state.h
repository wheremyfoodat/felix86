#pragma once

#include "felix86/common/utility.h"

typedef struct {
    u64 data[8]; // surely one day we'll support >= AVX right? :cluegi:
} mm_reg_t;

typedef struct {
    u64 gprs[16];
    u64 flags;
    u64 rip;
    u16 gs;
    u16 fs;
    mm_reg_t mm[32];
} x86_state_t;