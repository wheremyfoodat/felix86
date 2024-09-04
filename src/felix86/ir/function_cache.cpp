#include "felix86/ir/function_cache.h"

#include <tsl/robin_map.h>

#include "felix86/common/log.h"

extern "C"
struct ir_function_cache_s {
	tsl::robin_map<u64, ir_function_t*> functions;
};

ir_function_cache_t* ir_function_cache_create() { return new ir_function_cache_s(); }

ir_function_t* ir_function_cache_get_function(ir_function_cache_t* metadata, u64 address) {
	auto it = metadata->functions.find(address);
	if (it != metadata->functions.end()) {
		return it->second;
	}

	ir_function_t* function = ir_function_create(address);

	metadata->functions[address] = function;

	return function;
}