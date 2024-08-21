#include "felix86/loader/elf.h"
#include "felix86/common/log.h"
#include "felix86/felix86.h"

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

    felix86_recompiler_config_t config = { .testing = true };
    felix86_recompiler_t* recompiler = felix86_recompiler_create(&config);
    felix86_set_guest(recompiler, X86_REF_RIP, (u64)elf->program + elf->entry);
    felix86_set_guest(recompiler, X86_REF_RSP, (u64)elf->stackPointer);
    felix86_recompiler_run(recompiler, 0);
    felix86_recompiler_destroy(recompiler);

    elf_destroy(elf);
}