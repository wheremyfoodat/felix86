#include "felix86/loader/loader.h"
#include <stdio.h>

int main(int argc, const char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <elf-executable>\n", argv[0]);
        return 1;
    }

    loader_set_args(1, argv);
    loader_run_elf(argv[1]);
    return 0;
}