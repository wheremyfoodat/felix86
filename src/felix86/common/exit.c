#include "felix86/common/exit.h"
#include "felix86/hle/filesystem.h"
#include <stdlib.h>

void felix86_exit()
{
    felix86_fs_cleanup();
    exit(0);
}