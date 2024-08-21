#include "felix86/loader/elf.h"
#include "felix86/common/log.h"

void loader_run_elf(const char* path) {
    elf_t* elf = elf_load(path, NULL);

    elf_destroy(elf);
}