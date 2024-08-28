# felix86 compilation frontend and intermediate representation
The frontend aims to decode an instruction into an `x86_instruction_t` struct, which consists of info on the prefixes, the operands, the main opcode and the length.

Then it calls a function defined in handlers.c with a pointer to this struct, and the handler emits intermediate representation.

The intermediate representation is static single assignment form, which means that every IR temporary is only assigned to once
This makes optimizations a lot easier, mostly due to the fact that you don't have to worry about a temporary being reassigned.

The handler uses functions defined in emitter.c, which construct 0 or more `ir_instruction_t` structs. Those are part of the `ir_instruction_list_s` struct, which is an intrusive linked list.

Those instructions are added to the instruction list of the current basic block.

After the basic block is done compiling (due to a control flow instruction) the block is ran through a few functions named ir_*_pass that perform optimizations.