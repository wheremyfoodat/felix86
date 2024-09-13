#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/common/utility.h"

void felix86_fs_init();
u32 felix86_fs_readlinkat(u32 dirfd, const char* pathname, char* buf, u32 bufsiz);

#ifdef __cplusplus
}
#endif
