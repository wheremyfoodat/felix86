#include "felix86/loader/elf.h"
#include "felix86/common/log.h"

void loader_run_elf(const char* path) {
    elf_t* elf = elf_load(path, NULL);
    if (!elf) {
        ERROR("Failed to load ELF\n");
        return;
    }

    if (elf->interpreter) {
        ERROR("Interpreter not implemented\n");
    } else {
        printf("Entry: %p\n", (void*)elf->entry);
    }

    elf_destroy(elf);
}