#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/ir/instruction.h"

struct ir_instruction_list_s;

typedef struct ir_instruction_list_s {
	ir_instruction_t instruction;
	struct ir_instruction_list_s* previous;
	struct ir_instruction_list_s* next;
} ir_instruction_list_t;

ir_instruction_list_t* ir_ilist_create();
ir_instruction_t* ir_ilist_push_back(ir_instruction_list_t* ilist);
void ir_ilist_remove(ir_instruction_list_t* ilist);
void ir_ilist_free(ir_instruction_list_t* ilist);
void ir_ilist_free_all(ir_instruction_list_t* ilist);

#ifdef __cplusplus
}
#endif