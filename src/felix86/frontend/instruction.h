#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/common/utility.h"

typedef enum : u8 {
    REP_NONE = 0,
    REP_Z = 1,
    REP_NZ = 2,
} rep_type_e;

typedef enum : u8 {
    SEGMENT_NONE = 0,
    SEGMENT_FS = 1,
    SEGMENT_GS = 2,
    SEGMENT_FS_GS = 3,
} segment_override_e;

typedef enum : u8 {
    X86_GROUP1_ADD = 0,
    X86_GROUP1_OR  = 1,
    X86_GROUP1_ADC = 2,
    X86_GROUP1_SBB = 3,
    X86_GROUP1_AND = 4,
    X86_GROUP1_SUB = 5,
    X86_GROUP1_XOR = 6,
    X86_GROUP1_CMP = 7,
} x86_group1_e;

typedef enum : u8 {
    X86_GROUP2_ROL = 0,
    X86_GROUP2_ROR = 1,
    X86_GROUP2_RCL = 2,
    X86_GROUP2_RCR = 3,
    X86_GROUP2_SHL = 4,
    X86_GROUP2_SHR = 5,
    X86_GROUP2_SAL = 6,
    X86_GROUP2_SAR = 7,
} x86_group2_e;

typedef enum : u8 {
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
    X86_REF_MM0,
    X86_REF_MM1,
    X86_REF_MM2,
    X86_REF_MM3,
    X86_REF_MM4,
    X86_REF_MM5,
    X86_REF_MM6,
    X86_REF_MM7,
    X86_REF_MM8,
    X86_REF_MM9,
    X86_REF_MM10,
    X86_REF_MM11,
    X86_REF_MM12,
    X86_REF_MM13,
    X86_REF_MM14,
    X86_REF_MM15,
    X86_REF_MM16,
    X86_REF_MM17,
    X86_REF_MM18,
    X86_REF_MM19,
    X86_REF_MM20,
    X86_REF_MM21,
    X86_REF_MM22,
    X86_REF_MM23,
    X86_REF_MM24,
    X86_REF_MM25,
    X86_REF_MM26,
    X86_REF_MM27,
    X86_REF_MM28,
    X86_REF_MM29,
    X86_REF_MM30,
    X86_REF_MM31,
    X86_REF_RIP,
    X86_REF_FLAGS,
    X86_REF_GS,
    X86_REF_FS,

    X86_REF_COUNT,
} x86_ref_e;

typedef enum : u8 {
    X86_FLAG_CF = 0,
    X86_FLAG_PF = 2,
    X86_FLAG_AF = 4,
    X86_FLAG_ZF = 6,
    X86_FLAG_SF = 7,
    X86_FLAG_OF = 11,
} x86_flag_e;

typedef enum : u8 {
    X86_OP_TYPE_NONE,
    X86_OP_TYPE_MEMORY,
    X86_OP_TYPE_REGISTER,
    X86_OP_TYPE_IMMEDIATE,
} x86_operand_type_e;

typedef enum : u8 {
    X86_REG_SIZE_BYTE_LOW,
    X86_REG_SIZE_BYTE_HIGH,
    X86_REG_SIZE_WORD,
    X86_REG_SIZE_DWORD,
    X86_REG_SIZE_QWORD,
    X86_REG_SIZE_XMM,
    X86_REG_SIZE_YMM,
    X86_REG_SIZE_ZMM,
} x86_register_size_e;

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
        u16 byte_override : 1;
        u16 : 1;
    };

    u16 raw;
} x86_prefixes_t;

typedef struct {
    union {
        struct {
            u64 displacement;
            x86_ref_e base;
            x86_ref_e index;
            u8 scale;
        } memory;

        struct {
            x86_ref_e ref;
            x86_register_size_e size;
        } reg;

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
    u8 opcode;
    u8 length;
} x86_instruction_t;

#ifdef __cplusplus
}
#endif