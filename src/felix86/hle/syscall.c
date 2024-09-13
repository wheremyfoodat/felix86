#include "felix86/hle/syscall.h"
#include "felix86/common/log.h"
#include <errno.h>
#include <unistd.h>

// We add felix86_ in front of the linux related identifiers to avoid naming conflicts

#define felix86_ARCH_SET_GS 0x1001
#define felix86_ARCH_SET_FS 0x1002
#define felix86_ARCH_GET_FS 0x1003
#define felix86_ARCH_GET_GS 0x1004

enum syscall_id_e {
#define X(name, id) felix86_##name = id,
#include "felix86/hle/syscall.inc"
#undef X
};

const char* print_syscall_name(u64 syscall_number)
{
    switch (syscall_number) {
#define X(name, id) case id: return #name;
#include "felix86/hle/syscall.inc"
#undef X
    default: return "Unknown";
    }
}

void felix86_syscall(felix86_recompiler_t* recompiler, x86_thread_state_t* state)
{
    u64 syscall_number = state->gprs[X86_REF_RAX];
    u64 rdi = state->gprs[X86_REF_RDI];
    u64 rsi = state->gprs[X86_REF_RSI];
    u64 rdx = state->gprs[X86_REF_RDX];
    u64 r10 = state->gprs[X86_REF_R10];
    u64 r8 = state->gprs[X86_REF_R8];
    u64 r9 = state->gprs[X86_REF_R9];
    u64 result = 0;

    switch (syscall_number) {
        case felix86_brk: {
            if (rdi == 0) {
                result = recompiler->brk_current_address;
            } else {
                recompiler->brk_current_address = rdi;
                result = recompiler->brk_current_address;
            }
            VERBOSE("brk(%p) = %p", (void*)rdi, (void*)result);
            break;
        }
        case felix86_arch_prctl: {
            switch (rdi) {
                case felix86_ARCH_SET_GS: {
                    state->gsbase = rsi;
                    break;
                }
                case felix86_ARCH_SET_FS: {
                    state->fsbase = rsi;
                    break;
                }
                case felix86_ARCH_GET_FS: {
                    result = state->fsbase;
                    break;
                }
                case felix86_ARCH_GET_GS: {
                    result = state->gsbase;
                    break;
                }
                default: {
                    ERROR("Unimplemented arch_prctl %016lx", rdi);
                    break;
                }
            }
            VERBOSE("arch_prctl(%016lx, %016lx) = %016lx", rdi, rsi, result);
            break;
        }
        case felix86_set_tid_address: {
            state->clear_child_tid = rdi;
            result = rdi;
            VERBOSE("set_tid_address(%016lx) = %016lx", rdi, result);
            break;
        }
        case felix86_get_robust_list: {
            if (rdi != 0) {
                ERROR("get_robust_list asking for a different thread not implemented");
            }
            ERROR("get_robust_list not implemented");
            break;
        }
        case felix86_set_robust_list: {
            state->robust_futex_list = rdi;

            if (rsi != sizeof(u64) * 3) {
                WARN("Struct size is wrong during set_robust_list");
                result = EINVAL;
            }
            VERBOSE("set_robust_list(%016lx, %016lx) = %016lx", rdi, rsi, result);
            break;
        }
        case felix86_rseq: {
            // Couldn't find any solid documentation and FEX doesn't support it either
            result = -ENOSYS;
            break;
        }
        case felix86_prlimit64: {
            result = syscall(syscall_number, rdi, rsi, rdx, r10);
            VERBOSE("prlimit64(%016lx, %016lx, %016lx, %016lx) = %016lx", rdi, rsi, rdx, r10, result);
            break;
        }
        case felix86_readlinkat: {
            ERROR("readlinkat not implemented");
            break;
        }
        default: {
            ERROR("Unimplemented syscall %s (%016lx)", print_syscall_name(syscall_number), syscall_number);
            break;
        }
    }

    state->gprs[X86_REF_RAX] = result;
}