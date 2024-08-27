#include "felix86/frontend/frontend.h"
#include "felix86/frontend/instruction.h"
#include "felix86/ir/handlers.h"
#include "felix86/ir/emitter.h"
#include "felix86/common/log.h"
#include <Zydis/Zydis.h>

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
    MUST_DWORD_IMMEDIATE,
    BYTE_IMMEDIATE_IF_REG_0_OR_1,
    UP_TO_DWORD_IMMEDIATE_IF_REG_0_OR_1,
} immediate_size_e;

typedef enum : u16 {
    NO_FLAG,
    MODRM_FLAG = 1,
    OPCODE_FLAG = 2, // register encoded in the opcode itself
    BYTE_OVERRIDE_FLAG = 4,
    RM_EAX_OVERRIDE_FLAG = 8,
    RM_ALWAYS_BYTE_FLAG = 16,
    RM_ALWAYS_WORD_FLAG = 32,
    RM_AT_LEAST_DWORD_FLAG = 64,
    REG_MM_FLAG = 128, // reg is an mm register
    RM_MM_FLAG = 256, // rm is an mm register
    REG_EAX_OVERRIDE_FLAG = 512,
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

u8 decode_modrm(x86_operand_t* operand_rm, x86_operand_t* operand_reg, bool rex_b, bool rex_x, bool rex_r, modrm_t modrm, sib_t sib) {
    operand_reg->type = X86_OP_TYPE_REGISTER;
    operand_reg->reg.ref = X86_REF_RAX + (modrm.reg | (rex_r << 3));

    if (modrm.mod != 0b11) {
        operand_rm->type = X86_OP_TYPE_MEMORY;
        operand_rm->memory.base = X86_REF_COUNT;
        operand_rm->memory.index = X86_REF_COUNT;
    }

    // https://wiki.osdev.org/X86-64_Instruction_Encoding
    switch (modrm.mod) {
        case 0b00: {
            if (modrm.rm == 0b100) {
                u8 xindex = sib.index | (rex_x << 3);
                if (xindex != 0b100) {
                    operand_rm->memory.index = X86_REF_RAX + xindex;
                    operand_rm->memory.scale = 1 << sib.scale;
                }

                if (sib.base != 0b101) {
                    operand_rm->memory.base = X86_REF_RAX + (sib.base | (rex_b << 3));
                } else {
                    return 4;
                }

                return 0;
            } else if (modrm.rm == 0b101) {
                operand_rm->memory.base = X86_REF_RIP;
                return 4;
            } else {
                operand_rm->memory.base = X86_REF_RAX + modrm.rm | (rex_b << 3);
                return 0;
            }
        }

        case 0b01: {
            if (modrm.rm == 0b100) {
                operand_rm->memory.base = X86_REF_RAX + (sib.base | (rex_b << 3));
                u8 xindex = sib.index | (rex_x << 3);
                if (xindex != 0b100) {
                    operand_rm->memory.index = X86_REF_RAX + xindex;
                    operand_rm->memory.scale = 1 << sib.scale;
                }
            } else {
                operand_rm->memory.base = X86_REF_RAX + modrm.rm | (rex_b << 3);
            }
            return 1;
        }

        case 0b10: {
            if (modrm.rm == 0b100) {
                operand_rm->memory.base = X86_REF_RAX + (sib.base | (rex_b << 3));
                u8 xindex = sib.index | (rex_x << 3);
                if (xindex != 0b100) {
                    operand_rm->memory.index = X86_REF_RAX + xindex;
                    operand_rm->memory.scale = 1 << sib.scale;
                }
            } else {
                operand_rm->memory.base = X86_REF_RAX + modrm.rm | (rex_b << 3);
            }
            return 4;
        }

        case 0b11: {
            operand_rm->type = X86_OP_TYPE_REGISTER;
            operand_rm->reg.ref = X86_REF_RAX + (modrm.rm | (rex_b << 3));
            return 0;
        }
    }

    ERROR("Unreachable");
}

void frontend_compile_instruction(ir_emitter_state_t* state)
{
    u8* data = (u8*)state->current_address;

    x86_instruction_t inst = {0};
    int index = 0;
    bool prefix = false;
    bool rex = false;
    bool rex_b = false;
    bool rex_x = false;
    bool rex_r = false;
    instruction_metadata_t* primary_map = primary_table;
    x86_prefixes_t prefixes;
    prefixes.raw = 0;
    do {
        switch (data[index]) {
            case 0x40 ... 0x4F: {
                rex = true;
                u8 opcode = data[index];
                rex_b = opcode & 0x1;
                rex_x = (opcode >> 1) & 0x1;
                rex_r = (opcode >> 2) & 0x1;
                prefixes.rex_w = (opcode >> 3) & 0x1;
                prefix = true;
                index += 1;
                break;
            }

            case 0x62: {
                ERROR("EVEX prefix not supported\n");
                break;
            }

            case 0x64: {
                ERROR("FS segment override not supported");
                prefixes.segment_override = SEGMENT_FS;
                prefix = true;
                index += 1;
                break;
            }

            case 0x65: {
                ERROR("GS segment override not supported");
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

            case 0xC4: {
                // Three-byte VEX prefix
                u8 vex1 = data[index + 1];
                u8 vex2 = data[index + 2];
                prefixes.vex = true;
                rex_r = ~((vex1 >> 7) & 0x1);
                rex_x = ~((vex1 >> 6) & 0x1);
                rex_b = ~((vex1 >> 5) & 0x1);
                prefixes.rex_w = (vex2 >> 7) & 0x1;
                prefixes.vex_l = (vex2 >> 2) & 0x1;

                u8 map_select = vex1 & 0x1F;
                switch (map_select) {
                    case 1: { // this means implicit 0F prefix
                        primary_map = secondary_table;
                        break;
                    }
                    case 2: { // this means implicit 0F 38 prefix
                        ERROR("VEX map select 2 not supported");
                        break;
                    }
                    case 3: { // this means implicit 0F 3A prefix
                        ERROR("VEX map select 3 not supported");
                        break;
                    }
                }

                u8 operand_vex = ~((vex2 >> 3) & 0b1111);
                inst.operand_vex.type = X86_OP_TYPE_REGISTER;
                inst.operand_vex.reg.ref = X86_REF_XMM0 + operand_vex;
                inst.operand_vex.reg.size = X86_REG_SIZE_VECTOR;

                // specifies implicit mandatory prefix
                u8 pp = vex2 & 0b11;
                switch (pp) {
                    case 0b01: prefixes.operand_override = 1; break;
                    case 0b10: prefixes.rep_z_f3 = 1; break;
                    case 0b11: prefixes.rep_nz_f2 = 1; break;
                }

                index += 3;
                break;
            }

            case 0xC5: {
                // Two-byte VEX prefix
                u8 vex = data[index + 1];
                prefixes.vex = true;
                rex_r = ~((vex >> 7) & 0x1);
                prefixes.vex_l = (vex >> 2) & 0x1;

                u8 operand_vex = ~((vex >> 3) & 0b1111);
                inst.operand_vex.type = X86_OP_TYPE_REGISTER;
                inst.operand_vex.reg.ref = X86_REF_XMM0 + operand_vex;
                inst.operand_vex.reg.size = X86_REG_SIZE_VECTOR;

                // specifies implicit mandatory prefix
                u8 pp = vex & 0b11;
                switch (pp) {
                    case 0b01: prefixes.operand_override = 1; break;
                    case 0b10: prefixes.rep_z_f3 = 1; break;
                    case 0b11: prefixes.rep_nz_f2 = 1; break;
                }

                index += 2;
                break;
            }

            case 0xF0: {
                prefixes.lock = true;
                prefix = true;
                index += 1;
                break;
            }

            case 0xF2: {
                prefixes.rep_nz_f2 = 1;
                prefix = true;
                index += 1;
                break;
            }

            case 0xF3: {
                prefixes.rep_z_f3 = 1;
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

    inst.opcode = opcode;
    inst.prefixes = prefixes;

    if (opcode == 0x0F) {
        if (primary_map != primary_table) {
            ERROR("Secondary opcode while VEX changed the primary map");
        }

        opcode = data[index++];
        inst.opcode = opcode;
        primary = secondary_table[opcode];
    }

    u8 size = X86_REG_SIZE_DWORD;
    if (primary.decoding_flags & BYTE_OVERRIDE_FLAG) {
        inst.prefixes.byte_override = true;
        size = X86_REG_SIZE_BYTE_LOW;
    } else if (prefixes.rex_w) {
        size = X86_REG_SIZE_QWORD;
    } else if (prefixes.operand_override) {
        size = X86_REG_SIZE_WORD;
    }

    u8 size_rm = size;
    u8 size_reg = size;

    if (primary.decoding_flags & MODRM_FLAG) {
        modrm_t modrm;
        modrm.raw = data[index++];

        sib_t sib;
        if (modrm.rm == 0b100 && modrm.mod != 0b11) {
            sib.raw = data[index++];
        }

        u8 displacement_size = decode_modrm(&inst.operand_rm, &inst.operand_reg, rex_b, rex_x, rex_r, modrm, sib);
        switch (displacement_size) {
            case 1: {
                inst.operand_rm.memory.displacement = (i32)(i8)data[index];
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
        inst.operand_reg.reg.ref = (X86_REF_RAX + (opcode & 0x07)) | (rex_b << 3);
    }
    
    if (primary.decoding_flags & RM_EAX_OVERRIDE_FLAG) {
        inst.operand_rm.type = X86_OP_TYPE_REGISTER;
        inst.operand_rm.reg.ref = X86_REF_RAX;
    } else if (primary.decoding_flags & REG_EAX_OVERRIDE_FLAG) {
        inst.operand_reg.type = X86_OP_TYPE_REGISTER;
        inst.operand_reg.reg.ref = X86_REF_RAX;
    }

    if (primary.decoding_flags & RM_ALWAYS_BYTE_FLAG) {
        inst.prefixes.byte_override = true;
        size_rm = X86_REG_SIZE_BYTE_LOW;
    } else if (primary.decoding_flags & RM_ALWAYS_WORD_FLAG) {
        size_rm = X86_REG_SIZE_WORD;
    } else if (primary.decoding_flags & RM_AT_LEAST_DWORD_FLAG && size_rm < X86_REG_SIZE_DWORD) {
        size_rm = X86_REG_SIZE_DWORD;
    }

    if (primary.decoding_flags & RM_MM_FLAG) {
        u8 reg = inst.operand_rm.reg.ref - X86_REF_RAX;

        if (prefixes.operand_override) {
            inst.operand_rm.reg.ref = X86_REF_XMM0 + reg;
            size_rm = X86_REG_SIZE_VECTOR;
        } else {
            ERROR("Operation using mm register");
        }
    } else if (primary.decoding_flags & REG_MM_FLAG) {
        u8 reg = inst.operand_reg.reg.ref - X86_REF_RAX;

        if (prefixes.operand_override) {
            inst.operand_reg.reg.ref = X86_REF_XMM0 + reg;
            size_reg = X86_REG_SIZE_VECTOR;
        } else {
            ERROR("Operation using mm register");
        }
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

        case MUST_DWORD_IMMEDIATE: {
            inst.operand_imm.immediate.data = *(u32*)&data[index];
            inst.operand_imm.immediate.size = 4;
            index += 4;
            break;
        }

        case BYTE_IMMEDIATE_IF_REG_0_OR_1: {
            if (inst.operand_reg.reg.ref == X86_REF_RAX || inst.operand_reg.reg.ref == X86_REF_RCX) {
                inst.operand_imm.immediate.data = data[index];
                inst.operand_imm.immediate.size = 1;
                index += 1;
            }
            break;
        }

        case UP_TO_DWORD_IMMEDIATE_IF_REG_0_OR_1: {
            if (inst.operand_reg.reg.ref == X86_REF_RAX || inst.operand_reg.reg.ref == X86_REF_RCX) {
                if (prefixes.operand_override) {
                    inst.operand_imm.immediate.data = *(u16*)&data[index];
                    inst.operand_imm.immediate.size = 2;
                    index += 2;
                } else {
                    inst.operand_imm.immediate.data = *(u32*)&data[index];
                    inst.operand_imm.immediate.size = 4;
                    index += 4;
                }
            }
            break;
        }

        case NO_IMMEDIATE: {
            break;
        }
    }

    if (inst.operand_reg.type == X86_OP_TYPE_REGISTER) {
        inst.operand_reg.reg.size = size_reg;

        if (!rex && inst.operand_reg.reg.size == X86_REG_SIZE_BYTE_LOW) {
            int reg_index = (inst.operand_reg.reg.ref - X86_REF_RAX) & 0x7;
            bool high = reg_index >= 4;
            inst.operand_reg.reg.ref = X86_REF_RAX + (reg_index & 0x3);
            inst.operand_reg.reg.size = high ? X86_REG_SIZE_BYTE_HIGH : X86_REG_SIZE_BYTE_LOW;
        }
    }

    if (inst.operand_rm.type == X86_OP_TYPE_REGISTER) {
        inst.operand_rm.reg.size = size_rm;

        if (!rex && inst.operand_rm.reg.size == X86_REG_SIZE_BYTE_LOW) {
            int reg_index = (inst.operand_rm.reg.ref - X86_REF_RAX) & 0x7;
            bool high = reg_index >= 4;
            inst.operand_rm.reg.ref = X86_REF_RAX + (reg_index & 0x3);
            inst.operand_rm.reg.size = high ? X86_REG_SIZE_BYTE_HIGH : X86_REG_SIZE_BYTE_LOW;
        }
    }

    inst.length = index;
    state->current_instruction_length = inst.length;

    if (state->debug_info) {
        ZydisDisassembledInstruction instruction;
        if (ZYAN_SUCCESS(ZydisDisassembleIntel(
        /* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
        /* runtime_address: */ state->current_address,
        /* buffer:          */ data,
        /* length:          */ inst.length,
        /* instruction:     */ &instruction
        )))
        {
            ir_emit_debug_info_compile_time(state, "0x%016llx: %s", state->current_address - state->base_address, instruction.text);
        }
    }

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