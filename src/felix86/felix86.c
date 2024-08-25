#include "felix86/felix86.h"
#include "felix86/common/log.h"
#include "felix86/common/state.h"
#include "felix86/frontend/frontend.h"
#include "felix86/ir/block_metadata.h"
#include "felix86/ir/emitter.h"
#include "felix86/ir/passes.h"
#include "felix86/ir/print.h"
#include "felix86/ir/interpreter.h"
#include <stdlib.h>

struct felix86_recompiler_s {
    ir_block_metadata_t* block_metadata;
    x86_state_t state;
    bool testing;
    bool optimize;
    bool print_blocks;
    u64 base_address;
};

felix86_recompiler_t* felix86_recompiler_create(felix86_recompiler_config_t* config) {
    felix86_recompiler_t* recompiler = calloc(1, sizeof(felix86_recompiler_t));
    recompiler->block_metadata = ir_block_metadata_create();
    recompiler->testing = config->testing;
    recompiler->optimize = config->optimize;
    recompiler->print_blocks = config->print_blocks;
    recompiler->base_address = config->base_address;

    return recompiler;
}

void felix86_recompiler_destroy(felix86_recompiler_t* recompiler) {
    ir_block_metadata_destroy(recompiler->block_metadata);
    free(recompiler);
}

u64 felix86_get_guest(felix86_recompiler_t* recompiler, x86_ref_e ref) {
    switch (ref) {
        case X86_REF_RAX:
            return recompiler->state.gprs[0];
        case X86_REF_RCX:
            return recompiler->state.gprs[1];
        case X86_REF_RDX:
            return recompiler->state.gprs[2];
        case X86_REF_RBX:
            return recompiler->state.gprs[3];
        case X86_REF_RSP:
            return recompiler->state.gprs[4];
        case X86_REF_RBP:
            return recompiler->state.gprs[5];
        case X86_REF_RSI:
            return recompiler->state.gprs[6];
        case X86_REF_RDI:
            return recompiler->state.gprs[7];
        case X86_REF_R8:
            return recompiler->state.gprs[8];
        case X86_REF_R9:
            return recompiler->state.gprs[9];
        case X86_REF_R10:
            return recompiler->state.gprs[10];
        case X86_REF_R11:
            return recompiler->state.gprs[11];
        case X86_REF_R12:
            return recompiler->state.gprs[12];
        case X86_REF_R13:
            return recompiler->state.gprs[13];
        case X86_REF_R14:
            return recompiler->state.gprs[14];
        case X86_REF_R15:
            return recompiler->state.gprs[15];
        case X86_REF_RIP:
            return recompiler->state.rip;
        case X86_REF_FLAGS:
            return recompiler->state.flags;
        case X86_REF_GS:
            return recompiler->state.gs;
        case X86_REF_FS:
            return recompiler->state.fs;
        default:
            ERROR("Invalid GPR reference");
    }
}

void felix86_set_guest(felix86_recompiler_t* recompiler, x86_ref_e ref, u64 value) {
    switch (ref) {
        case X86_REF_RAX:
            recompiler->state.gprs[0] = value;
            break;
        case X86_REF_RCX:
            recompiler->state.gprs[1] = value;
            break;
        case X86_REF_RDX:
            recompiler->state.gprs[2] = value;
            break;
        case X86_REF_RBX:
            recompiler->state.gprs[3] = value;
            break;
        case X86_REF_RSP:
            recompiler->state.gprs[4] = value;
            break;
        case X86_REF_RBP:
            recompiler->state.gprs[5] = value;
            break;
        case X86_REF_RSI:
            recompiler->state.gprs[6] = value;
            break;
        case X86_REF_RDI:
            recompiler->state.gprs[7] = value;
            break;
        case X86_REF_R8:
            recompiler->state.gprs[8] = value;
            break;
        case X86_REF_R9:
            recompiler->state.gprs[9] = value;
            break;
        case X86_REF_R10:
            recompiler->state.gprs[10] = value;
            break;
        case X86_REF_R11:
            recompiler->state.gprs[11] = value;
            break;
        case X86_REF_R12:
            recompiler->state.gprs[12] = value;
            break;
        case X86_REF_R13:
            recompiler->state.gprs[13] = value;
            break;
        case X86_REF_R14:
            recompiler->state.gprs[14] = value;
            break;
        case X86_REF_R15:
            recompiler->state.gprs[15] = value;
            break;
        case X86_REF_RIP:
            recompiler->state.rip = value;
            break;
        case X86_REF_FLAGS:
            recompiler->state.flags = value;
            break;
        case X86_REF_GS:
            recompiler->state.gs = value;
            break;
        case X86_REF_FS:
            recompiler->state.fs = value;
            break;
        default:
            ERROR("Invalid GPR reference");
    }
}

xmm_reg_t felix86_get_guest_xmm(felix86_recompiler_t* recompiler, x86_ref_e ref) {
    if (ref < X86_REF_XMM0 || ref > X86_REF_XMM31) {
        ERROR("Invalid XMM reference");
    }

    return recompiler->state.xmm[ref - X86_REF_XMM0];
}

void felix86_set_guest_xmm(felix86_recompiler_t* recompiler, x86_ref_e ref, xmm_reg_t value) {
    if (ref < X86_REF_XMM0 || ref > X86_REF_XMM31) {
        ERROR("Invalid XMM reference");
    }

    recompiler->state.xmm[ref - X86_REF_XMM0] = value;
}

felix86_exit_reason_e felix86_recompiler_run(felix86_recompiler_t* recompiler, u64 cycles) {
    // TODO: check for backend block? needs asm dispatcher
    while (true) {
        ir_block_t* block = ir_block_metadata_get_block(recompiler->block_metadata, recompiler->state.rip);

        if (!block->compiled) {
            ir_emitter_state_t state = {0};
            state.block = block;
            state.current_address = recompiler->state.rip;
            state.exit = false;
            state.testing = recompiler->testing;
            state.debug_info = recompiler->print_blocks;
            frontend_compile_block(&state);

            if (recompiler->optimize) {
                ir_local_common_subexpression_elimination_pass(block);
                ir_copy_propagation_pass(block);
                ir_dead_store_elimination_pass(block);
                ir_dead_code_elimination_pass(block);
            }
            
            ir_naming_pass(block);
            
            if (recompiler->print_blocks) {
                ir_print_block(block);
            }
        }

        ir_interpret_block(block, &recompiler->state);

        if(recompiler->testing) {
            return OutOfCycles;
        }
    }

    return OutOfCycles;
}