#include "felix86/loader/elf.h"
#include "felix86/common/log.h"
#include "felix86/common/file.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define ELFCLASS64 2
#define ELFDATA2LSB 1

#define ET_EXEC 2
#define ET_DYN 3

#define EM_X86_64 62 // makes you wish this was 64

#define EI_NIDENT 16

#define PN_XNUM 0xffff

#define PT_LOAD 1
#define PT_INTERP 3

#define PF_X 1
#define PF_W 2
#define PF_R 4

#define SHT_PROGBITS 1
#define SHF_EXECINSTR 4

typedef u16 Elf64_Half;
typedef u32 Elf64_Word;
typedef u64 Elf64_Off;
typedef u64 Elf64_Addr;
typedef u64 Elf64_Xword;

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;
    Elf64_Off e_phoff;
    Elf64_Off e_shoff;
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct {
  Elf64_Word p_type;    // Type of segment
  Elf64_Word p_flags;   // Segment flags
  Elf64_Off p_offset;   // File offset where segment is located, in bytes
  Elf64_Addr p_vaddr;   // Virtual address of beginning of segment
  Elf64_Addr p_paddr;   // Physical addr of beginning of segment (OS-specific)
  Elf64_Xword p_filesz; // Num. of bytes in file image of segment (may be zero)
  Elf64_Xword p_memsz;  // Num. of bytes in mem image of segment (may be zero)
  Elf64_Xword p_align;  // Segment alignment constraint
} Elf64_Phdr;

typedef struct {
  Elf64_Word sh_name;       // Section name (index into the section header string table)
  Elf64_Word sh_type;       // Section type
  Elf64_Xword sh_flags;     // Section flags
  Elf64_Addr sh_addr;       // Address where section is to be loaded
  Elf64_Off sh_offset;      // File offset of section data, in bytes
  Elf64_Xword sh_size;      // Size of section, in bytes
  Elf64_Word sh_link;       // Section type-specific header table index link
  Elf64_Word sh_info;       // Section type-specific extra information
  Elf64_Xword sh_addralign; // Section address alignment
  Elf64_Xword sh_entsize;   // Size of records contained within the section
} Elf64_Shdr;

elf_t* elf_load(const char* path, file_reading_callbacks_t* callbacks) {
    // No, I am not a K&R enthusiast, I just want to make sure they are null before they are
    // allocated so we can free them in cleanup
    elf_t elf = {0};
    u8* phdrtable = NULL;
    u8* shdrtable = NULL;
    void* file = NULL;

    void* (*fopen)(const char* path, void* user_data);
    bool (*fread)(void* handle, void* buffer, u64 offset, u64 size, void* user_data);
    void (*fclose)(void* handle, void* user_data);
    u64 (*get_size)(void* handle, void* user_data);
    void* user_data = NULL;
    if (callbacks) {
#define SET(func) if (!callbacks->func) { WARN("Callback " #func " is NULL"); goto cleanup; } func = callbacks->func
        SET(fopen);
        SET(fread);
        SET(fclose);
        SET(get_size);
        user_data = callbacks->user_data;
#undef SET
    } else {
        // User didn't provide callbacks, use fopen etc
        fopen = easy_fopen;
        fread = easy_fread;
        fclose = easy_fclose;
        get_size = easy_get_size;
    }

    file = fopen(path, user_data);
    if (!file) {
        WARN("Failed to open file %s", path);
        goto cleanup;
    }

    u64 size = get_size(file, user_data);
    if (size < sizeof(Elf64_Ehdr)) {
        WARN("File %s is too small to be an ELF file", path);
        goto cleanup;
    }

    Elf64_Ehdr ehdr;
    bool result = fread(file, &ehdr, 0, sizeof(Elf64_Ehdr), user_data);
    if (!result) {
        WARN("Failed to read ELF header from file %s", path);
        goto cleanup;
    }

    if (ehdr.e_ident[0] != 0x7F || ehdr.e_ident[1] != 'E' || ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F') {
        WARN("File %s is not an ELF file", path);
        goto cleanup;
    }

    if (ehdr.e_ident[4] != ELFCLASS64) {
        WARN("File %s is not a 64-bit ELF file", path);
        goto cleanup;
    }

    if (ehdr.e_ident[5] != ELFDATA2LSB) {
        WARN("File %s is not a little-endian ELF file", path);
        goto cleanup;
    }

    if (ehdr.e_ident[6] != 1 || ehdr.e_version != 1) {
        WARN("File %s has an invalid version", path);
        goto cleanup;
    }

    if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) {
        WARN("File %s is not an executable or shared object", path);
        goto cleanup;
    }

    if (ehdr.e_machine != EM_X86_64) {
        WARN("File %s is not an x86_64 ELF file", path);
        goto cleanup;
    }

    if (ehdr.e_entry == 0 && ehdr.e_type == ET_EXEC) {
        WARN("File %s is an executable but has no entry point", path);
        goto cleanup;
    }

    if (ehdr.e_phoff == 0) {
        WARN("File %s has no program header table, thus has no loadable segments", path);
        goto cleanup;
    }

    if (ehdr.e_phnum == 0xFFFF) {
        WARN("If the number of program headers is greater than or equal to PN_XNUM (0xffff) "
            "this member has the value PN_XNUM (0xffff). The actual number of program header "
            "table entries is contained in the sh_info field of the section header at index 0");
        goto cleanup;
    }

    if (ehdr.e_shstrndx == 0) {
        WARN("File %s has no section header string table", path);
        goto cleanup;
    }

    elf.entry = ehdr.e_entry;

    u64 phdrtable_size = ehdr.e_phnum * ehdr.e_phentsize;
    phdrtable = malloc(phdrtable_size);
    result = fread(file, phdrtable, ehdr.e_phoff, phdrtable_size, user_data);

    u64 shdrtable_size = ehdr.e_shnum * ehdr.e_shentsize;
    shdrtable = malloc(shdrtable_size);
    result = fread(file, shdrtable, ehdr.e_shoff, shdrtable_size, user_data);

    u64 lowest_vaddr = UINT64_MAX;
    u64 highest_vaddr = 0;

    for (Elf64_Half i = 0; i < phdrtable_size; i += ehdr.e_phentsize) {
        Elf64_Phdr* phdr = (Elf64_Phdr*)(phdrtable + i);
        switch (phdr->p_type) {
            case PT_INTERP: {
                elf.interpreter = malloc(phdr->p_filesz);
                result = fread(file, elf.interpreter, phdr->p_offset, phdr->p_filesz, user_data);
                if (!result) {
                    WARN("Failed to read interpreter from file %s", path);
                    goto cleanup;
                }
                break;
            }
            case PT_LOAD: {
                if (phdr->p_filesz == 0) {
                    break;
                }

                if (phdr->p_vaddr < lowest_vaddr) {
                    lowest_vaddr = phdr->p_vaddr;
                }

                if (phdr->p_vaddr + phdr->p_memsz > highest_vaddr) {
                    highest_vaddr = phdr->p_vaddr + phdr->p_memsz;
                }
                break;
            }
        }
    }

    elf.program = mmap(NULL, highest_vaddr - lowest_vaddr, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (elf.program == MAP_FAILED) {
        WARN("Failed to allocate memory for ELF file %s", path);
        goto cleanup;
    }

    for (Elf64_Half i = 0; i < phdrtable_size; i += ehdr.e_phentsize) {
        Elf64_Phdr* phdr = (Elf64_Phdr*)(phdrtable + i);
        switch (phdr->p_type) {
            case PT_LOAD: {
                if (phdr->p_filesz == 0) {
                    break;
                }

                u8 prot = 0;
                if (phdr->p_flags & PF_R) {
                    prot |= PROT_READ;
                }

                if (phdr->p_flags & PF_W) {
                    prot |= PROT_WRITE;
                }

                if (phdr->p_flags & PF_X) {
                    prot |= PROT_EXEC;
                }

                void* addr = mmap(elf.program + (phdr->p_vaddr - lowest_vaddr), phdr->p_memsz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED_NOREPLACE | MAP_ANONYMOUS, -1, 0);
                if (addr == MAP_FAILED) {
                    WARN("Failed to allocate memory for segment in file %s", path);
                    goto cleanup;
                }

                result = fread(file, addr, phdr->p_offset, phdr->p_filesz, user_data);
                if (!result) {
                    WARN("Failed to read segment from file %s", path);
                    goto cleanup;
                }

                mprotect(addr, phdr->p_memsz, prot);
                break;
            }
        }
    }

    u64 bss_offset = 0;
    u64 bss_size = 0;
    for (Elf64_Half i = 0; i < shdrtable_size; i += ehdr.e_shentsize) {
        Elf64_Shdr* shdr = (Elf64_Shdr*)(shdrtable + i);
        if (shdr->sh_type == SHT_PROGBITS) {
            char* name = (char*)(shdrtable + ehdr.e_shstrndx + shdr->sh_name);
            if (strncmp(name, ".bss", 4) == 0) {
                bss_size = shdr->sh_size;
                bss_offset = shdr->sh_addr;

                if (bss_offset + bss_size > highest_vaddr || bss_offset < lowest_vaddr) {
                    WARN("Invalid .bss section in file %s", path);
                    goto cleanup;
                }
            }
            break;
        }
    }

    if (bss_size == 0) {
        WARN("File %s has no .bss section", path);
    }

    memset(elf.program + (bss_offset - lowest_vaddr), 0, bss_size);

    // Allocate it last so we don't have to free it if we fail
    elf_t* pelf = malloc(sizeof(elf_t));
    memcpy(pelf, &elf, sizeof(elf_t));
    return pelf;

cleanup:
    if (phdrtable) free(phdrtable);
    if (shdrtable) free(shdrtable);
    if (elf.interpreter) free(elf.interpreter);
    if (elf.program) free(elf.program);
    if (file) fclose(file, user_data);
    return NULL;
}