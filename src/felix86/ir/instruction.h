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
	IR_DEBUG_RUNTIME,
	IR_DEBUG_COMPILETIME,

	IR_MOV,
	IR_IMMEDIATE,
	IR_POPCOUNT,
	IR_SEXT_GPR8,
	IR_SEXT_GPR16,
	IR_SEXT_GPR32,
	IR_SYSCALL,
	IR_CPUID,
	IR_TERNARY,
	IR_JUMP,
	IR_JUMP_IF_TRUE,

	IR_VECTOR_MASK_ELEMENTS,

	IR_GET_GUEST,
	IR_SET_GUEST,
	IR_INSERT_INTEGER_TO_VECTOR,
	IR_EXTRACT_INTEGER_FROM_VECTOR,
	IR_GET_FLAG,
	IR_SET_FLAG,

	IR_ADD,
	IR_SUB,
	IR_LEFT_SHIFT,
	IR_RIGHT_SHIFT,
	IR_RIGHT_SHIFT_ARITHMETIC,
	IR_LEFT_ROTATE,
	IR_RIGHT_ROTATE,
	IR_AND,
	IR_OR,
	IR_XOR,
	IR_NOT,
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
	IR_TYPE_TWO_OPERAND_IMMEDIATES,
	IR_TYPE_GET_GUEST,
	IR_TYPE_SET_GUEST,
	IR_TYPE_GET_FLAG,
	IR_TYPE_SET_FLAG,
	IR_TYPE_NO_OPERANDS,
	IR_TYPE_TERNARY,
	IR_TYPE_DEBUG,
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
			struct ir_instruction_s* source1;
			struct ir_instruction_s* source2;
			u32 imm32_1;
			u32 imm32_2;
		} two_operand_immediates;

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

		struct {
			struct ir_instruction_s* condition;
			struct ir_instruction_s* true_value;
			struct ir_instruction_s* false_value;
		} ternary;

		struct {
			const char* text;
		} debug;

		u64 raw_data[3];
	};

	u16 uses;
	u16 name;
	ir_type_e type;
	ir_opcode_e opcode;
} ir_instruction_t;

void ir_clear_instruction(ir_instruction_t* instruction);

#ifdef __cplusplus
}
#endif