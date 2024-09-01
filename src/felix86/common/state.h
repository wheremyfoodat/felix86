#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/common/utility.h"

typedef struct {
	u64 data[8];
} xmm_reg_t;

typedef struct {
	u64 gprs[16];
	u64 rip;
	u64 mm[8];
	xmm_reg_t xmm[16];
	u16 gs;
	u16 fs;
	bool cf;
	bool pf;
	bool af;
	bool zf;
	bool sf;
	bool of;
} x86_state_t;

#ifdef __cplusplus
}
#endif