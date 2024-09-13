#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/common/utility.h"
#include <linux/limits.h>

extern char sandbox_path[PATH_MAX];

int felix86_make_path_safe(char* buffer, u32 buffer_size, const char* path);

void felix86_fs_init(const char* squashfs_path);
void felix86_fs_cleanup();
u32 felix86_fs_readlinkat(u32 dirfd, const char* pathname, char* buf, u32 bufsiz);

#ifdef __cplusplus
}
#endif
