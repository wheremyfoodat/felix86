#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/common/utility.h"
#include "felix86/frontend/instruction.h"
#include "felix86/ir/value.h"

typedef enum : u8 {
    IR_NULL,

    IR_START_OF_BLOCK,

    IR_MOV,
    IR_IMMEDIATE,
    IR_POPCOUNT,
    IR_SEXT8,
    IR_SEXT16,
    IR_SEXT32,

    IR_GET_GUEST,
    IR_SET_GUEST,
    IR_GET_FLAG,
    IR_SET_FLAG,

    IR_ADD,
    IR_SUB,
    IR_LEFT_SHIFT,
    IR_RIGHT_SHIFT,
    IR_RIGHT_SHIFT_ARITHMETIC,
    IR_AND,
    IR_OR,
    IR_XOR,
    IR_LEA,
    IR_EQUAL,
    IR_NOT_EQUAL,
    IR_GREATER_THAN_SIGNED,
    IR_LESS_THAN_SIGNED,
    IR_GREATER_THAN_UNSIGNED,
    IR_LESS_THAN_UNSIGNED,

    IR_READ_BYTE,
    IR_READ_WORD,
    IR_READ_DWORD,
    IR_READ_QWORD,
    IR_WRITE_BYTE,
    IR_WRITE_WORD,
    IR_WRITE_DWORD,
    IR_WRITE_QWORD,
} ir_opcode_e;

typedef enum : u8 {
    IR_TYPE_NULL,
    IR_TYPE_TWO_OPERAND,
    IR_TYPE_LOAD_IMMEDIATE,
    IR_TYPE_ONE_OPERAND,
    IR_TYPE_LEA,
    IR_TYPE_GET_GUEST,
    IR_TYPE_SET_GUEST,
    IR_TYPE_GET_FLAG,
    IR_TYPE_SET_FLAG,
} ir_type_e;

typedef struct ir_instruction_s {
    union {
        struct {
            struct ir_instruction_s* source1;
            struct ir_instruction_s* source2;
        } two_operand;

        struct {
            u64 immediate;
        } load_immediate;

        struct {
            struct ir_instruction_s* source;
        } one_operand;

        struct {
            struct ir_instruction_s* base;
            struct ir_instruction_s* index;
            u32 displacement;
            u8 scale;
        } lea;

        struct {
            x86_ref_e ref;
        } get_guest;

        struct {
            struct ir_instruction_s* source;
            x86_ref_e ref;
        } set_guest;

        struct {
            x86_flag_e flag;
        } get_flag;

        struct {
            x86_flag_e flag;
            struct ir_instruction_s* source;
        } set_flag;
    };

    ir_type_e type;
    ir_opcode_e opcode;
    u16 uses;
    u32 name;
} ir_instruction_t;

#ifdef __cplusplus
}
#endif