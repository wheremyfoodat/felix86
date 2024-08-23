#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/common/utility.h"
#include "felix86/common/callbacks.h"

typedef struct {
    void* program;
    u64 entry;
    char* interpreter;
    void* stackBase;
    void* stackPointer;
    bool executableStack;

    void* phdr;
    u64 phnum;
    u64 phent;
} elf_t;

/// Load an ELF file from the given path
/// The callbacks parameter exists to allow the user to not have to use file functions and load an elf from memory instead
/// @param path The path to the ELF file
/// @param callbacks The file reading callbacks, NULL for fopen etc
/// @return The loaded ELF file
elf_t* elf_load(const char* path, file_reading_callbacks_t* callbacks);

void elf_destroy(elf_t* elf);

#ifdef __cplusplus
}
#endif