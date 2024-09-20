#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "felix86/common/utility.h"

// Prompt the user with a yes/no question, returns 1 if the user answers yes, 0
// otherwise
u32 prompt_yn_question(const char* question);

#ifdef __cplusplus
}
#endif