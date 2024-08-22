#include "felix86/loader/elf.h"
#include "felix86/common/log.h"
#include "felix86/felix86.h"
#include <string.h>
#include <sys/auxv.h>

int guest_argc = 0;
const char** guest_argv = NULL;

int guest_envc = 0;
const char** guest_envp = NULL;

typedef struct
{
    int a_type;
    union {
        long a_val;
        void *a_ptr;
        void (*a_fnc)();
    } a_un;
} auxv_t;

u64 stack_push(u64 stack, u64 value) {
    stack -= 8;
    *(u64*)stack = value;
    return stack;
}

void loader_set_args(int argc, const char** argv) {
    guest_argc = argc;
    guest_argv = argv;
}

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

    // Initial process stack according to System V AMD64 ABI
    u64 rsp = (u64)elf->stackPointer;

    // To hold the addresses of the arguments for later pushing
    u64* argv_addresses = malloc(guest_argc * sizeof(u64));

    for (int i = 0; i < guest_argc; i++) {
        rsp -= strlen(guest_argv[i]) + 1;
        strcpy((char*)rsp, guest_argv[i]);
        argv_addresses[i] = rsp;
    }

    u16 aux_vector_count = 0;

    // This is the varying amount of space needed for the stack
    // past our own information block
    // It's important to calculate this because the RSP final
    // value needs to be aligned to 16 bytes
    u16 size_needed =
        8 + // null terminator
        16 * aux_vector_count + // aux vector entries
        8 + // null terminator
        guest_envc * 8 + // envp
        8 + // null terminator
        guest_argc * 8 + // argv
        8; // argc

    u64 final_rsp = rsp - size_needed;
    if (final_rsp & 0xF) {
        // The final rsp wouldn't be aligned to 16 bytes
        // so we need to add padding
        rsp = stack_push(rsp, 0);
    }

    // End of auxiliary vector entries
    rsp = stack_push(rsp, 0);

    // TODO: push auxiliary vector entries

    // End of environment variables
    rsp = stack_push(rsp, 0);

    // TODO: push environment variables

    // End of arguments
    rsp = stack_push(rsp, 0);
    for (int i = guest_argc - 1; i >= 0; i--) {
        rsp = stack_push(rsp, argv_addresses[i]);
    }

    // Argument count
    rsp = stack_push(rsp, guest_argc);

    if (rsp & 0xF) {
        ERROR("Stack not aligned to 16 bytes\n");
        return;
    }

    free(argv_addresses);

    felix86_recompiler_config_t config = { .testing = true };
    felix86_recompiler_t* recompiler = felix86_recompiler_create(&config);
    felix86_set_guest(recompiler, X86_REF_RIP, (u64)elf->program + elf->entry);
    felix86_set_guest(recompiler, X86_REF_RSP, rsp);
    felix86_recompiler_run(recompiler, 0);
    felix86_recompiler_destroy(recompiler);

    elf_destroy(elf);
}