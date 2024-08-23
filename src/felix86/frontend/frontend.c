#include "felix86/frontend/frontend.h"
#include "felix86/frontend/instruction.h"
#include "felix86/ir/handlers.h"
#include "felix86/ir/emitter.h"
#include "felix86/common/log.h"

typedef union {
    struct {
        u8 rm : 3;
        u8 reg : 3;
        u8 mod : 2;
    };

    u8 raw;
} modrm_t;

typedef union {
    struct {
        u8 base : 3;
        u8 index : 3;
        u8 scale : 2;
    };

    u8 raw;
} sib_t;

typedef enum : u8 {
    NO_IMMEDIATE,
    BYTE_IMMEDIATE = 1,
    WORD_IMMEDIATE = 2,
    UP_TO_DWORD_IMMEDIATE = 4,
    UP_TO_QWORD_IMMEDIATE = 8,
} immediate_size_e;

typedef enum : u8 {
    NO_FLAG,
    MODRM_FLAG = 1,
    OPCODE_FLAG = 2, // register encoded in the opcode itself
    BYTE_OVERRIDE_FLAG = 4,
    EAX_OVERRIDE_FLAG = 8,
} decoding_flags_e;

typedef struct {
    u8 opcode;
    ir_handle_fn_t fn;
    decoding_flags_e decoding_flags;
    immediate_size_e immediate_size;
} instruction_metadata_t;

instruction_metadata_t primary_table[] = {
#define X(opcode, name, flag, immsize) [opcode] = {opcode, ir_handle_##name, flag, immsize},
#include "felix86/frontend/primary.inc"
#undef X
};

instruction_metadata_t secondary_table[] = {
#define X(opcode, name, flag, immsize) [opcode] = {opcode, ir_handle_##name, flag, immsize},
#include "felix86/frontend/secondary.inc"
#undef X
};

bool needs_sib(modrm_t modrm) {
    return modrm.mod != 0b11 && modrm.rm == 0b100;
}

u8 decode_modrm(x86_operand_t* operand_rm, x86_operand_t* operand_reg, x86_prefixes_t prefixes, modrm_t modrm, sib_t sib) {
    u8 displacement_size = 0;

    operand_reg->type = X86_OP_TYPE_REGISTER;
    operand_rm->type = (modrm.mod == 0b11) ? X86_OP_TYPE_REGISTER : X86_OP_TYPE_MEMORY;

    operand_reg->reg.ref = X86_REF_RAX + (modrm.reg | (prefixes.rex_r << 3));
        
    operand_rm->memory.base = X86_REF_COUNT;
    operand_rm->memory.index = X86_REF_COUNT;

    if (operand_rm->type == X86_OP_TYPE_REGISTER) {
        operand_rm->reg.ref = X86_REF_RAX + (modrm.rm | (prefixes.rex_b << 3));
    } else if (operand_rm->type == X86_OP_TYPE_MEMORY) {
        bool has_sib = needs_sib(modrm);
        if (has_sib) {
            operand_rm->memory.base = X86_REF_RAX + (sib.base | (prefixes.rex_b << 3));
            operand_rm->memory.index = X86_REF_RAX + (sib.index | (prefixes.rex_x << 3));
            operand_rm->memory.scale = sib.scale;
        } else {
            operand_rm->memory.base = X86_REF_RAX + (modrm.rm | (prefixes.rex_b << 3));
        }

        if (modrm.mod == 0b00 && modrm.rm == 0b101) {
            // RIP-relative addressing
            operand_rm->memory.base = X86_REF_RIP;
            displacement_size = 4;
        } else if (modrm.mod == 0b01) {
            displacement_size = 1;
        } else if (modrm.mod == 0b10) {
            displacement_size = 4;
        }
    }

    return displacement_size;
}

void frontend_compile_instruction(ir_emitter_state_t* state)
{
    u8* data = (u8*)state->current_address;

    int index = 0;
    bool prefix = false;
    x86_prefixes_t prefixes;
    prefixes.raw = 0;
    do {
        switch (data[index]) {
            case 0x40 ... 0x4F: {
                prefixes.rex = true;
                prefixes.raw |= data[index] & 0x0F;
                prefix = true;
                index += 1;
                break;
            }

            case 0x64: {
                prefixes.segment_override = SEGMENT_FS;
                prefix = true;
                index += 1;
                break;
            }

            case 0x65: {
                prefixes.segment_override = SEGMENT_GS;
                prefix = true;
                index += 1;
                break;
            }

            case 0x66: {
                prefixes.operand_override = true;
                prefix = true;
                index += 1;
                break;
            }

            case 0x67: {
                prefixes.address_override = true;
                prefix = true;
                index += 1;
                break;
            }

            case 0xF0: {
                prefixes.lock = true;
                prefix = true;
                index += 1;
                break;
            }

            case 0xF2: {
                prefixes.rep = REP_NZ;
                prefix = true;
                index += 1;
                break;
            }

            case 0xF3: {
                prefixes.rep = REP_Z;
                prefix = true;
                index += 1;
                break;
            }

            default: {
                prefix = false;
                break;
            }
        }
    } while (prefix);

    u8 opcode = data[index++];
    instruction_metadata_t primary = primary_table[opcode];

    u8 size = X86_REG_SIZE_DWORD;
    if (primary.decoding_flags & BYTE_OVERRIDE_FLAG) {
        prefixes.byte_override = true;
        size = X86_REG_SIZE_BYTE_LOW;
    } else if (prefixes.operand_override) {
        size = X86_REG_SIZE_WORD;
    } else if (prefixes.rex_w) {
        size = X86_REG_SIZE_QWORD;
    }

    x86_instruction_t inst = {0};
    inst.opcode = opcode;
    inst.prefixes = prefixes;

    if (prefixes.operand_override && prefixes.rex_w) {
        ERROR("Both operand override and REX.W are set, which is sus");
    }
    
    if (opcode == 0x0F) {
        opcode = data[index++];
        inst.opcode = opcode;
        primary = secondary_table[opcode];
    }

    if (primary.decoding_flags & MODRM_FLAG) {
        modrm_t modrm;
        modrm.raw = data[index++];

        sib_t sib;
        if (needs_sib(modrm)) {
            sib.raw = data[index++];
        }

        u8 displacement_size = decode_modrm(&inst.operand_rm, &inst.operand_reg, prefixes, modrm, sib);
        switch (displacement_size) {
            case 1: {
                inst.operand_rm.memory.displacement = data[index];
                index += 1;
                break;
            }
            
            case 4: {
                inst.operand_rm.memory.displacement = *(u32*)&data[index];
                index += 4;
                break;
            }
        }
    } else if (primary.decoding_flags & OPCODE_FLAG) {
        inst.operand_reg.type = X86_OP_TYPE_REGISTER;
        inst.operand_reg.reg.ref = (X86_REF_RAX + (opcode & 0x07)) | (prefixes.rex_b << 3);
    } else if (primary.decoding_flags & EAX_OVERRIDE_FLAG) {
        inst.operand_rm.type = X86_OP_TYPE_REGISTER;
        inst.operand_rm.reg.ref = X86_REF_RAX;
    }

    switch (primary.immediate_size) {
        case BYTE_IMMEDIATE: {
            inst.operand_imm.immediate.data = data[index];
            inst.operand_imm.immediate.size = 1;
            index += 1;
            break;
        }

        case WORD_IMMEDIATE: {
            inst.operand_imm.immediate.data = *(u16*)&data[index];
            inst.operand_imm.immediate.size = 2;
            index += 2;
            break;
        }

        case UP_TO_DWORD_IMMEDIATE: {
            if (prefixes.operand_override) {
                inst.operand_imm.immediate.data = *(u16*)&data[index];
                inst.operand_imm.immediate.size = 2;
                index += 2;
            } else {
                inst.operand_imm.immediate.data = *(u32*)&data[index];
                inst.operand_imm.immediate.size = 4;
                index += 4;
            }
            break;
        }

        case UP_TO_QWORD_IMMEDIATE: {
            if (prefixes.operand_override) {
                inst.operand_imm.immediate.data = *(u16*)&data[index];
                inst.operand_imm.immediate.size = 2;
                index += 2;
            } else if (prefixes.rex_w) {
                inst.operand_imm.immediate.data = *(u64*)&data[index];
                inst.operand_imm.immediate.size = 8;
                index += 8;
            } else {
                inst.operand_imm.immediate.data = *(u32*)&data[index];
                inst.operand_imm.immediate.size = 4;
                index += 4;
            }
            break;
        }

        case NO_IMMEDIATE: {
            break;
        }
    }

    if (inst.operand_reg.type == X86_OP_TYPE_REGISTER) {
        inst.operand_reg.reg.size = size;

        if (!prefixes.rex && inst.operand_reg.reg.size == X86_REG_SIZE_BYTE_LOW) {
            int reg_index = (inst.operand_reg.reg.ref - X86_REF_RAX) & 0x7;
            bool high = reg_index >= 4;
            inst.operand_reg.reg.ref = X86_REF_RAX + (reg_index & 0x3);
            inst.operand_reg.reg.size = high ? X86_REG_SIZE_BYTE_HIGH : X86_REG_SIZE_BYTE_LOW;
        }
    }

    if (inst.operand_rm.type == X86_OP_TYPE_REGISTER) {
        inst.operand_rm.reg.size = size;

        if (!prefixes.rex && inst.operand_rm.reg.size == X86_REG_SIZE_BYTE_LOW) {
            int reg_index = (inst.operand_rm.reg.ref - X86_REF_RAX) & 0x7;
            bool high = reg_index >= 4;
            inst.operand_rm.reg.ref = X86_REF_RAX + (reg_index & 0x3);
            inst.operand_rm.reg.size = high ? X86_REG_SIZE_BYTE_HIGH : X86_REG_SIZE_BYTE_LOW;
        }
    }

    inst.length = index;
    state->current_instruction_length = inst.length;

    primary.fn(state, &inst);

    state->current_address += inst.length;
}

void frontend_compile_block(ir_emitter_state_t* state)
{
    while (!state->exit) {
        frontend_compile_instruction(state);
    }

    state->block->compiled = true;
}