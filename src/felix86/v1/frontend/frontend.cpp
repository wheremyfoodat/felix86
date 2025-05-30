#include <Zydis/Zydis.h>
#include <fmt/format.h>
#include <openssl/md5.h>
#include "felix86/common/global.hpp"
#include "felix86/common/hash.hpp"
#include "felix86/common/log.hpp"
#include "felix86/common/print.hpp"
#include "felix86/common/x86.hpp"
#include "felix86/frontend/frontend.hpp"
#include "felix86/frontend/instruction.hpp"
#include "felix86/ir/handlers.hpp"

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
    RM_MM_FLAG = 256,  // rm is an mm register
    REG_EAX_OVERRIDE_FLAG = 512,
    DEFAULT_U64_FLAG = 1024,
    CAN_REP_FLAG = 2048,
    CAN_REPZ_REPNZ_FLAG = 4096,
    REG_XMM_FLAG = 8192,
    RM_XMM_FLAG = 16384,
    MANDATORY_PREFIX_FLAG = 32768,
} decoding_flags_e;

typedef struct {
    u8 opcode;
    ir_handle_fn_t fn;
    decoding_flags_e decoding_flags;
    immediate_size_e immediate_size;
} instruction_metadata_t;

instruction_metadata_t primary_table[] = {
#define X(opcode, name, flag, immsize) [opcode] = {opcode, ir_handle_##name, (decoding_flags_e)(flag), immsize},
#include "felix86/frontend/primary.inc"
#undef X
};

instruction_metadata_t secondary_table[] = {
#define X(opcode, name, flag, immsize) [opcode] = {opcode, ir_handle_##name, (decoding_flags_e)(flag), immsize},
#include "felix86/frontend/secondary.inc"
#undef X
};

instruction_metadata_t secondary_table_66[] = {
#define X(opcode, name, flag, immsize) [opcode] = {opcode, ir_handle_##name, (decoding_flags_e)(flag), immsize},
#include "felix86/frontend/secondary_66.inc"
#undef X
};

instruction_metadata_t secondary_table_f2[] = {
#define X(opcode, name, flag, immsize) [opcode] = {opcode, ir_handle_##name, (decoding_flags_e)(flag), immsize},
#include "felix86/frontend/secondary_f2.inc"
#undef X
};

instruction_metadata_t secondary_table_f3[] = {
#define X(opcode, name, flag, immsize) [opcode] = {opcode, ir_handle_##name, (decoding_flags_e)(flag), immsize},
#include "felix86/frontend/secondary_f3.inc"
#undef X
};

instruction_metadata_t tertiary_table_3a[] = {
#define X(opcode, name, flag, immsize) [opcode] = {opcode, ir_handle_##name, (decoding_flags_e)(flag), immsize},
#include "felix86/frontend/tertiary_3a.inc"
#undef X
};

instruction_metadata_t tertiary_table_3a_66[] = {
#define X(opcode, name, flag, immsize) [opcode] = {opcode, ir_handle_##name, (decoding_flags_e)(flag), immsize},
#include "felix86/frontend/tertiary_3a_66.inc"
#undef X
};

instruction_metadata_t tertiary_table_38[] = {
#define X(opcode, name, flag, immsize) [opcode] = {opcode, ir_handle_##name, (decoding_flags_e)(flag), immsize},
#include "felix86/frontend/tertiary_38.inc"
#undef X
};

instruction_metadata_t tertiary_table_38_66[] = {
#define X(opcode, name, flag, immsize) [opcode] = {opcode, ir_handle_##name, (decoding_flags_e)(flag), immsize},
#include "felix86/frontend/tertiary_38_66.inc"
#undef X
};

instruction_metadata_t tertiary_table_38_f2[] = {
#define X(opcode, name, flag, immsize) [opcode] = {opcode, ir_handle_##name, (decoding_flags_e)(flag), immsize},
#include "felix86/frontend/tertiary_38_f2.inc"
#undef X
};

void frontend_compile_block(IREmitter& ir, IRFunction* function, IRBlock* block);

u8 decode_modrm(x86_operand_t* operand_rm, x86_operand_t* operand_reg, bool rex_b, bool rex_x, bool rex_r, modrm_t modrm, sib_t sib) {
    operand_reg->type = X86_OP_TYPE_REGISTER;
    operand_reg->reg.ref = x86_ref_e(X86_REF_RAX + (modrm.reg | (rex_r << 3)));

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
                operand_rm->memory.index = x86_ref_e(X86_REF_RAX + xindex);
                operand_rm->memory.scale = sib.scale;
            }

            if (sib.base != 0b101) {
                operand_rm->memory.base = x86_ref_e(X86_REF_RAX + (sib.base | (rex_b << 3)));
            } else {
                return 4;
            }

            return 0;
        } else if (modrm.rm == 0b101) {
            operand_rm->memory.base = X86_REF_RIP;
            return 4;
        } else {
            operand_rm->memory.base = x86_ref_e(X86_REF_RAX + (modrm.rm | (rex_b << 3)));
            return 0;
        }
    }

    case 0b01: {
        if (modrm.rm == 0b100) {
            operand_rm->memory.base = x86_ref_e(X86_REF_RAX + (sib.base | (rex_b << 3)));
            u8 xindex = sib.index | (rex_x << 3);
            if (xindex != 0b100) {
                operand_rm->memory.index = x86_ref_e(X86_REF_RAX + xindex);
                operand_rm->memory.scale = sib.scale;
            }
        } else {
            operand_rm->memory.base = x86_ref_e(X86_REF_RAX + (modrm.rm | (rex_b << 3)));
        }
        return 1;
    }

    case 0b10: {
        if (modrm.rm == 0b100) {
            operand_rm->memory.base = x86_ref_e(X86_REF_RAX + (sib.base | (rex_b << 3)));
            u8 xindex = sib.index | (rex_x << 3);
            if (xindex != 0b100) {
                operand_rm->memory.index = x86_ref_e(X86_REF_RAX + xindex);
                operand_rm->memory.scale = sib.scale;
            }
        } else {
            operand_rm->memory.base = x86_ref_e(X86_REF_RAX + (modrm.rm | (rex_b << 3)));
        }
        return 4;
    }

    case 0b11: {
        operand_rm->type = X86_OP_TYPE_REGISTER;
        operand_rm->reg.ref = x86_ref_e(X86_REF_RAX + (modrm.rm | (rex_b << 3)));
        return 0;
    }
    }

    UNREACHABLE();
    return 0;
}

void frontend_compile_instruction(IREmitter& ir, MD5_CTX& ctx) {
    const u8* const data = (u8*)ir.GetCurrentAddress();

    x86_instruction_t inst = {};
    int index = 0;
    bool prefix = false;
    bool rex = false;
    bool rex_b = false;
    bool rex_x = false;
    bool rex_r = false;
    bool rex_w = false;
    bool address_override = false;
    bool operand_override = false;
    bool fs_override = false;
    bool gs_override = false;
    bool rep_nz_f2 = false;
    bool rep_z_f3 = false;
    bool lock = false;
    instruction_metadata_t* primary_map = primary_table;
    do {
        switch (data[index]) {
        case 0x26:
        case 0x2E:
        case 0x36:
        case 0x3E: {
            // Null prefixes
            prefix = true;
            index += 1;
            break;
        }

        case 0x40 ... 0x4F: {
            rex = true;
            u8 opcode = data[index];
            rex_b = opcode & 0x1;
            rex_x = (opcode >> 1) & 0x1;
            rex_r = (opcode >> 2) & 0x1;
            rex_w = (opcode >> 3) & 0x1;
            prefix = true;
            index += 1;
            break;
        }

        case 0x62: {
            ERROR("EVEX prefix not supported\n");
            break;
        }

        case 0x64: {
            fs_override = true;
            prefix = true;
            index += 1;
            break;
        }

        case 0x65: {
            gs_override = true;
            prefix = true;
            index += 1;
            break;
        }

        case 0x66: {
            operand_override = true;
            prefix = true;
            index += 1;
            break;
        }

        case 0x67: {
            address_override = true;
            prefix = true;
            index += 1;
            break;
        }

        case 0xC4: {
            ERROR("VEX prefix not supported, TODO: needs vector size prefix on "
                  "instructions");
            // Three-byte VEX prefix
            // u8 vex1 = data[index + 1];
            // u8 vex2 = data[index + 2];
            // prefixes.vex = true;
            // rex_r = ~((vex1 >> 7) & 0x1);
            // rex_x = ~((vex1 >> 6) & 0x1);
            // rex_b = ~((vex1 >> 5) & 0x1);
            // prefixes.rex_w = (vex2 >> 7) & 0x1;
            // prefixes.vex_l = (vex2 >> 2) & 0x1;

            // u8 map_select = vex1 & 0x1F;
            // switch (map_select) {
            //     case 1: { // this means implicit 0F prefix
            //         primary_map = secondary_table;
            //         break;
            //     }
            //     case 2: { // this means implicit 0F 38 prefix
            //         ERROR("VEX map select 2 not supported");
            //         break;
            //     }
            //     case 3: { // this means implicit 0F 3A prefix
            //         ERROR("VEX map select 3 not supported");
            //         break;
            //     }
            // }

            // u8 operand_vex = ~((vex2 >> 3) & 0b1111);
            // inst.operand_vex.type = X86_OP_TYPE_REGISTER;
            // inst.operand_vex.reg.ref = X86_REF_XMM0 + operand_vex;
            // inst.operand_vex.size = prefixes.vex_l ? X86_SIZE_YMM : X86_SIZE_XMM;

            // // specifies implicit mandatory prefix
            // u8 pp = vex2 & 0b11;
            // switch (pp) {
            //     case 0b01: operand_override = true; break;
            //     case 0b10: rep_z_f3 = true; break;
            //     case 0b11: rep_nz_f2 = true; break;
            // }

            // index += 3;
            break;
        }

        case 0xC5: {
            ERROR("VEX prefix not supported, TODO: needs vector size prefix on "
                  "instructions");
            // Two-byte VEX prefix
            // u8 vex = data[index + 1];
            // prefixes.vex = true;
            // rex_r = ~((vex >> 7) & 0x1);
            // prefixes.vex_l = (vex >> 2) & 0x1;

            // u8 operand_vex = ~((vex >> 3) & 0b1111);
            // inst.operand_vex.type = X86_OP_TYPE_REGISTER;
            // inst.operand_vex.reg.ref = X86_REF_XMM0 + operand_vex;
            // inst.operand_vex.size = prefixes.vex_l ? X86_SIZE_YMM : X86_SIZE_XMM;

            // // specifies implicit mandatory prefix
            // u8 pp = vex & 0b11;
            // switch (pp) {
            //     case 0b01: operand_override = true; break;
            //     case 0b10: rep_z_f3 = true; break;
            //     case 0b11: rep_nz_f2 = true; break;
            // }

            // index += 2;
            break;
        }

        case 0xF0: {
            lock = true;
            prefix = true;
            index += 1;
            break;
        }

        case 0xF2: {
            rep_nz_f2 = true;
            prefix = true;
            index += 1;
            break;
        }

        case 0xF3: {
            rep_z_f3 = true;
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
    inst.opcode = opcode;

    instruction_metadata_t primary = primary_map[opcode];
    decoding_flags_e decoding_flags = primary.decoding_flags;
    immediate_size_e immediate_size = primary.immediate_size;
    ir_handle_fn_t fn = primary.fn;

    if (opcode == 0x0F) {
        if (primary_map != primary_table) {
            ERROR("Secondary opcode while VEX changed the primary map");
        }

        instruction_metadata_t secondary;
        opcode = data[index++];

        if (opcode == 0x38) {
            opcode = data[index++];
            secondary = tertiary_table_38[opcode];

            if (secondary.decoding_flags & MANDATORY_PREFIX_FLAG) {
                if (operand_override) {
                    operand_override = false;
                    secondary = tertiary_table_38_66[opcode];
                } else if (rep_nz_f2) {
                    secondary = tertiary_table_38_f2[opcode];
                }
            }
        } else if (opcode == 0x3A) {
            opcode = data[index++];
            secondary = tertiary_table_3a[opcode];

            if (secondary.decoding_flags & MANDATORY_PREFIX_FLAG) {
                if (operand_override) {
                    secondary = tertiary_table_3a_66[opcode];
                    operand_override = false;
                }
            }
        } else {
            secondary = secondary_table[opcode];

            if (secondary.decoding_flags & MANDATORY_PREFIX_FLAG) {
                if (operand_override) {
                    secondary = secondary_table_66[opcode];
                    operand_override = false;
                } else if (rep_z_f3) {
                    secondary = secondary_table_f3[opcode];
                    rep_z_f3 = false;
                } else if (rep_nz_f2) {
                    secondary = secondary_table_f2[opcode];
                    rep_nz_f2 = false;
                }
            }
        }

        decoding_flags = secondary.decoding_flags;
        immediate_size = secondary.immediate_size;
        fn = secondary.fn;
        inst.opcode = opcode;
    }

    x86_size_e size = (decoding_flags & DEFAULT_U64_FLAG) ? X86_SIZE_QWORD : X86_SIZE_DWORD;
    if (decoding_flags & BYTE_OVERRIDE_FLAG) {
        size = X86_SIZE_BYTE;
    } else if (rex_w) {
        size = X86_SIZE_QWORD;
    } else if (operand_override) {
        size = X86_SIZE_WORD;
    }

    x86_size_e size_rm = size;
    x86_size_e size_reg = size;

    if (decoding_flags & MODRM_FLAG) {
        modrm_t modrm;
        modrm.raw = data[index++];

        sib_t sib = {};
        if (modrm.rm == 0b100 && modrm.mod != 0b11) {
            sib.raw = data[index++];
        }

        inst.modrm = modrm.raw;

        u8 displacement_size = decode_modrm(&inst.operand_rm, &inst.operand_reg, rex_b, rex_x, rex_r, modrm, sib);
        switch (displacement_size) {
        case 1: {
            inst.operand_rm.memory.displacement = (i64)(i32)(i8)data[index];
            index += 1;
            break;
        }

        case 4: {
            inst.operand_rm.memory.displacement = (i64) * (i32*)&data[index];
            index += 4;
            break;
        }
        }
    } else if (decoding_flags & OPCODE_FLAG) {
        inst.operand_reg.type = X86_OP_TYPE_REGISTER;
        inst.operand_reg.reg.ref = x86_ref_e((X86_REF_RAX + (opcode & 0x07)) | (rex_b << 3));
    }

    x86_rep_e rep_type = x86_rep_e::NONE; // TODO: use enum class for x86_rep_e
    if (rep_z_f3 && (decoding_flags & CAN_REPZ_REPNZ_FLAG)) {
        rep_type = REP_Z;
    } else if (rep_nz_f2 && (decoding_flags & CAN_REPZ_REPNZ_FLAG)) {
        rep_type = REP_NZ;
    } else if ((rep_nz_f2 || rep_z_f3) && (decoding_flags & CAN_REP_FLAG)) {
        rep_type = REP;
    }

    if (decoding_flags & RM_EAX_OVERRIDE_FLAG) {
        inst.operand_rm.type = X86_OP_TYPE_REGISTER;
        inst.operand_rm.reg.ref = X86_REF_RAX;
    } else if (decoding_flags & REG_EAX_OVERRIDE_FLAG) {
        inst.operand_reg.type = X86_OP_TYPE_REGISTER;
        inst.operand_reg.reg.ref = X86_REF_RAX;
    }

    if (decoding_flags & RM_ALWAYS_BYTE_FLAG) {
        size_rm = X86_SIZE_BYTE;
    } else if (decoding_flags & RM_ALWAYS_WORD_FLAG) {
        size_rm = X86_SIZE_WORD;
    } else if ((decoding_flags & RM_AT_LEAST_DWORD_FLAG) && size_rm < X86_SIZE_DWORD) {
        size_rm = X86_SIZE_DWORD;
    }

    if (decoding_flags & RM_MM_FLAG) {
        u8 reg = inst.operand_rm.reg.ref - X86_REF_RAX;
        if (reg > 7) {
            ERROR("Invalid MM register");
        }

        inst.operand_rm.reg.ref = x86_ref_e(X86_REF_ST0 + reg);
        size_rm = X86_SIZE_MM;
    }

    if (decoding_flags & REG_MM_FLAG) {
        u8 reg = inst.operand_reg.reg.ref - X86_REF_RAX;
        if (reg > 7) {
            ERROR("Invalid MM register");
        }

        inst.operand_reg.reg.ref = x86_ref_e(X86_REF_ST0 + reg);
        size_reg = X86_SIZE_MM;
    }

    if (decoding_flags & REG_XMM_FLAG) {
        if (inst.operand_reg.type == X86_OP_TYPE_REGISTER) {
            u8 reg = inst.operand_reg.reg.ref - X86_REF_RAX;
            if (reg > 15) {
                ERROR("Invalid XMM register");
            }

            inst.operand_reg.reg.ref = x86_ref_e(X86_REF_XMM0 + reg);
        }
        size_reg = X86_SIZE_XMM;
    }

    if (decoding_flags & RM_XMM_FLAG) {
        if (inst.operand_rm.type == X86_OP_TYPE_REGISTER) {
            u8 reg = inst.operand_rm.reg.ref - X86_REF_RAX;
            if (reg > 15) {
                ERROR("Invalid XMM register");
            }

            inst.operand_rm.reg.ref = x86_ref_e(X86_REF_XMM0 + reg);
        }
        size_rm = X86_SIZE_XMM;
    }

    switch (immediate_size) {
    case BYTE_IMMEDIATE: {
        inst.operand_imm.immediate.data = data[index];
        inst.operand_imm.size = X86_SIZE_BYTE;
        index += 1;
        break;
    }

    case WORD_IMMEDIATE: {
        inst.operand_imm.immediate.data = *(u16*)&data[index];
        inst.operand_imm.size = X86_SIZE_WORD;
        index += 2;
        break;
    }

    case UP_TO_DWORD_IMMEDIATE: {
        if (operand_override) {
            inst.operand_imm.immediate.data = *(u16*)&data[index];
            inst.operand_imm.size = X86_SIZE_WORD;
            index += 2;
        } else {
            inst.operand_imm.immediate.data = *(u32*)&data[index];
            inst.operand_imm.size = X86_SIZE_DWORD;
            index += 4;
        }
        break;
    }

    case UP_TO_QWORD_IMMEDIATE: {
        if (operand_override) {
            inst.operand_imm.immediate.data = *(u16*)&data[index];
            inst.operand_imm.size = X86_SIZE_WORD;
            index += 2;
        } else if (rex_w) {
            inst.operand_imm.immediate.data = *(u64*)&data[index];
            inst.operand_imm.size = X86_SIZE_QWORD;
            index += 8;
        } else {
            inst.operand_imm.immediate.data = *(u32*)&data[index];
            inst.operand_imm.size = X86_SIZE_DWORD;
            index += 4;
        }
        break;
    }

    case MUST_DWORD_IMMEDIATE: {
        inst.operand_imm.immediate.data = *(u32*)&data[index];
        inst.operand_imm.size = X86_SIZE_DWORD;
        index += 4;
        break;
    }

    case BYTE_IMMEDIATE_IF_REG_0_OR_1: {
        if (inst.operand_reg.reg.ref == X86_REF_RAX || inst.operand_reg.reg.ref == X86_REF_RCX) {
            inst.operand_imm.immediate.data = data[index];
            inst.operand_imm.size = X86_SIZE_BYTE;
            index += 1;
        }
        break;
    }

    case UP_TO_DWORD_IMMEDIATE_IF_REG_0_OR_1: {
        if (inst.operand_reg.reg.ref == X86_REF_RAX || inst.operand_reg.reg.ref == X86_REF_RCX) {
            if (operand_override) {
                inst.operand_imm.immediate.data = *(u16*)&data[index];
                inst.operand_imm.size = X86_SIZE_WORD;
                index += 2;
            } else {
                inst.operand_imm.immediate.data = *(u32*)&data[index];
                inst.operand_imm.size = X86_SIZE_DWORD;
                index += 4;
            }
        }
        break;
    }

    case NO_IMMEDIATE: {
        break;
    }
    }

    inst.operand_reg.size = size_reg;
    if (!rex && inst.operand_reg.size == X86_SIZE_BYTE) {
        int reg_index = (inst.operand_reg.reg.ref - X86_REF_RAX) & 0x7;
        bool high = reg_index >= 4;
        inst.operand_reg.reg.ref = x86_ref_e(X86_REF_RAX + (reg_index & 0x3));
        inst.operand_reg.reg.high8 = high;
    }

    inst.operand_rm.size = size_rm;
    if (inst.operand_rm.type == X86_OP_TYPE_REGISTER) {
        if (!rex && inst.operand_rm.size == X86_SIZE_BYTE) {
            int reg_index = (inst.operand_rm.reg.ref - X86_REF_RAX) & 0x7;
            bool high = reg_index >= 4;
            inst.operand_rm.reg.ref = x86_ref_e(X86_REF_RAX + (reg_index & 0x3));
            inst.operand_rm.reg.high8 = high;
        }
    } else if (inst.operand_rm.type == X86_OP_TYPE_MEMORY) {
        inst.operand_rm.memory.address_override = address_override;
        inst.operand_rm.memory.fs_override = fs_override;
        inst.operand_rm.memory.gs_override = gs_override;
        inst.operand_rm.memory.lock = lock;
        if (inst.operand_rm.memory.base == X86_REF_RIP) {
            // The RIP during the block is at the start of the function, so we need to add the offset
            // of the current instruction.
            // This is to be able to use the disk cache since compiled functions will be relocated
            // on different runs.
            u64 offset = ir.GetCurrentAddress() - ir.GetFunction().GetStartAddress();
            inst.operand_rm.memory.displacement += offset; // offset of current block
            inst.operand_rm.memory.displacement += index;  // offset of current instruction
        }
    } else if (inst.operand_rm.type != X86_OP_TYPE_NONE) {
        ERROR("Invalid operand type");
    }

    inst.length = index;

    // Hash every instruction that comprises the function to be able to lookup
    // the function cache
    MD5_Update(&ctx, data, inst.length);

    if (g_include_comments) {
        ZydisDisassembledInstruction zydis_inst;
        if (ZYAN_SUCCESS(ZydisDisassembleIntel(
                /* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
                /* runtime_address: */ ir.GetCurrentAddress(),
                /* buffer:          */ data,
                /* length:          */ 15,
                /* instruction:     */ &zydis_inst))) {
            std::string buffer = fmt::format("{:016x} {}", ir.GetCurrentAddress(), zydis_inst.text);
            ir.Comment(buffer);
        }
    }

    bool is_rep = rep_type != NONE;
    IRBlock* loop_block = nullptr;
    IRBlock* exit_block = nullptr;
    ir.SetInstruction(&inst);

    // TODO: Move these RepStart and RepEnd to handlers themselves
    if (is_rep) {
        loop_block = ir.CreateBlock();
        exit_block = ir.CreateBlockAt(ir.GetNextAddress());
        ir.RepStart(loop_block, exit_block);

        // Write the instruction in the loop body
        ir.SetBlock(loop_block);
    }

    // Call actual decoding function
    fn(ir, &inst);

    if (is_rep) {
        ir.RepEnd(rep_type, loop_block, exit_block);
    }

    ir.IncrementAddress(inst.length);
}

void frontend_compile_block(IREmitter& ir, IRFunction& function, IRBlock* block, MD5_CTX& ctx) {
    ASSERT(!block->IsCompiled());
    block->SetCompiled();

    // Since compiling instructions might change the current block (due to some instruction that needs multiple blocks, for example)
    // we check that the *current* block has no termination, rather than the original block
    while (ir.GetCurrentBlock()->GetTermination() == Termination::Null) {
        frontend_compile_instruction(ir, ctx);
    }

    if (g_print_state) {
        // If you use this you gotta make sure to add a GetGuest and StoreGuestToMemory for the registers
        // you want to print
        SSAInstruction* inst = ir.GetGuest(X86_REF_R9);
        ir.StoreGuestToMemory(inst, X86_REF_R9);
        ir.CallHostFunction((u64)print_gprs);
    }
}

void frontend_compile_function(IRFunction& function) {
    IREmitter ir(function);

    MD5_CTX ctx;
    MD5_Init(&ctx);

    IRBlock* block = function.GetBlockAt(function.GetStartAddress());
    ir.SetBlock(block);
    ir.SetAddress(block->GetStartAddress());
    frontend_compile_block(ir, function, block, ctx);

    IRBlock* queued_block = ir.PopQueue();
    while (queued_block) {
        if (!queued_block->IsCompiled()) {
            ir.SetBlock(queued_block);
            ir.SetAddress(queued_block->GetStartAddress());
            frontend_compile_block(ir, function, queued_block, ctx);
        }
        queued_block = ir.PopQueue();
    }

    Hash function_hash;
    MD5_Final((u8*)&function_hash, &ctx);
    function.GetHashRef() = function_hash; // TODO: change to SetHash, remove GetHashRef

    function.SetCompiled();
}