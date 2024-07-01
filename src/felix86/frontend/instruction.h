#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/common/utility.h"

typedef enum {
    REP_NONE = 0,
    REP_Z = 1,
    REP_NZ = 2,
} rep_type_e;

typedef enum {
    SEGMENT_NONE = 0,
    SEGMENT_FS = 1,
    SEGMENT_GS = 2,
    SEGMENT_FS_GS = 3,
} segment_override_e;


typedef enum {
    X86_REF_RAX,
    X86_REF_RCX,
    X86_REF_RDX,
    X86_REF_RBX,
    X86_REF_RSP,
    X86_REF_RBP,
    X86_REF_RSI,
    X86_REF_RDI,
    X86_REF_R8,
    X86_REF_R9,
    X86_REF_R10,
    X86_REF_R11,
    X86_REF_R12,
    X86_REF_R13,
    X86_REF_R14,
    X86_REF_R15,
    X86_REF_RIP,
    X86_REF_FLAGS,
    X86_REF_GS,
    X86_REF_FS,

    X86_REF_COUNT,
} x86_ref_t;

typedef enum {
    X86_FLAG_CF,
    X86_FLAG_PF,
    X86_FLAG_AF,
    X86_FLAG_ZF,
    X86_FLAG_SF,
    X86_FLAG_OF,
} x86_flag_t;

typedef union {
    struct {
        u16 rex_b : 1;
        u16 rex_x : 1;
        u16 rex_r : 1;
        u16 rex_w : 1;
        u16 rex : 1;
        u16 address_override : 1;
        u16 operand_override : 1;
        u16 lock : 1;
        u16 prefix_count : 2;
        u16 rep : 2;
        u16 segment_override : 2;
        u16 : 2;
    };

    u16 raw;
} x86_prefixes_t;

typedef enum {
    X86_OP_TYPE_NONE,
    X86_OP_TYPE_MEMORY,
    X86_OP_TYPE_REGISTER,
    X86_OP_TYPE_IMMEDIATE,
} x86_operand_type_e;

typedef struct {
    union {
        struct {
            u64 displacement;
            x86_ref_t base;
            x86_ref_t index;
            u8 scale;
        } memory;

        x86_ref_t reg;

        struct {
            u64 data;
            u8 size;
        } immediate;
    };

    x86_operand_type_e type;
} x86_operand_t;

typedef struct {
    x86_prefixes_t prefixes;
    x86_operand_t operand_rm;
    x86_operand_t operand_reg;
    x86_operand_t operand_imm;
    uint8_t opcode;
} x86_instruction_t;

#ifdef __cplusplus
}
#endif