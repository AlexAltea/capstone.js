/**
 * (c) 2014-2026 Capstone.JS
 * Wrapper made by Alexandro Sanchez Bach.
 */

Object.assign(Module, {
    // cs_err
    ERR_OK: 0,
    ERR_MEM: 1,
    ERR_ARCH: 2,
    ERR_HANDLE: 3,
    ERR_CSH: 4,
    ERR_MODE: 5,
    ERR_OPTION: 6,
    ERR_DETAIL: 7,
    ERR_MEMSETUP: 8,
    ERR_VERSION: 9,
    ERR_DIET: 10,
    ERR_SKIPDATA: 11,
    ERR_X86_ATT: 12,
    ERR_X86_INTEL: 13,
    ERR_X86_MASM: 14,

    // cs_arch
    ARCH_ARM: 0,
    ARCH_ARM64: 1,
    ARCH_MIPS: 2,
    ARCH_X86: 3,
    ARCH_PPC: 4,
    ARCH_SPARC: 5,
    ARCH_SYSZ: 6,
    ARCH_XCORE: 7,
    ARCH_M68K: 8,
    ARCH_TMS320C64X: 9,
    ARCH_M680X: 10,
    ARCH_EVM: 11,
    ARCH_MOS65XX: 12,
    ARCH_WASM: 13,
    ARCH_BPF: 14,
    ARCH_RISCV: 15,
    ARCH_SH: 16,
    ARCH_TRICORE: 17,
    ARCH_MAX: 18,
    ARCH_ALL: 0xFFFF,

    // cs_mode
    MODE_LITTLE_ENDIAN: 0,
    MODE_ARM: 0,
    MODE_16: 1 << 1,
    MODE_32: 1 << 2,
    MODE_64: 1 << 3,
    MODE_THUMB: 1 << 4,
    MODE_MCLASS: 1 << 5,
    MODE_V8: 1 << 6,
    MODE_MICRO: 1 << 4,
    MODE_MIPS3: 1 << 5,
    MODE_MIPS32R6: 1 << 6,
    MODE_MIPS2: 1 << 7,
    MODE_V9: 1 << 4,
    MODE_QPX: 1 << 4,
    MODE_SPE: 1 << 5,
    MODE_BOOKE: 1 << 6,
    MODE_PS: 1 << 7,
    MODE_M68K_000: 1 << 1,
    MODE_M68K_010: 1 << 2,
    MODE_M68K_020: 1 << 3,
    MODE_M68K_030: 1 << 4,
    MODE_M68K_040: 1 << 5,
    MODE_M68K_060: 1 << 6,
    MODE_BIG_ENDIAN: 0x80000000,
    MODE_MIPS32: 1 << 2,
    MODE_MIPS64: 1 << 3,
    MODE_M680X_6301: 1 << 1,
    MODE_M680X_6309: 1 << 2,
    MODE_M680X_6800: 1 << 3,
    MODE_M680X_6801: 1 << 4,
    MODE_M680X_6805: 1 << 5,
    MODE_M680X_6808: 1 << 6,
    MODE_M680X_6809: 1 << 7,
    MODE_M680X_6811: 1 << 8,
    MODE_M680X_CPU12: 1 << 9,
    MODE_M680X_HCS08: 1 << 10,
    MODE_BPF_CLASSIC: 0,
    MODE_BPF_EXTENDED: 1 << 0,
    MODE_RISCV32: 1 << 0,
    MODE_RISCV64: 1 << 1,
    MODE_RISCVC: 1 << 2,
    MODE_MOS65XX_6502: 1 << 1,
    MODE_MOS65XX_65C02: 1 << 2,
    MODE_MOS65XX_W65C02: 1 << 3,
    MODE_MOS65XX_65816: 1 << 4,
    MODE_MOS65XX_65816_LONG_M: 1 << 5,
    MODE_MOS65XX_65816_LONG_X: 1 << 6,
    MODE_MOS65XX_65816_LONG_MX: (1 << 5) | (1 << 6),
    MODE_SH2: 1 << 1,
    MODE_SH2A: 1 << 2,
    MODE_SH3: 1 << 3,
    MODE_SH4: 1 << 4,
    MODE_SH4A: 1 << 5,
    MODE_SHFPU: 1 << 6,
    MODE_SHDSP: 1 << 7,
    MODE_TRICORE_110: 1 << 1,
    MODE_TRICORE_120: 1 << 2,
    MODE_TRICORE_130: 1 << 3,
    MODE_TRICORE_131: 1 << 4,
    MODE_TRICORE_160: 1 << 5,
    MODE_TRICORE_161: 1 << 6,
    MODE_TRICORE_162: 1 << 7,

    // cs_opt_type
    OPT_INVALID: 0,
    OPT_SYNTAX: 1,
    OPT_DETAIL: 2,
    OPT_MODE: 3,
    OPT_MEM: 4,
    OPT_SKIPDATA: 5,
    OPT_SKIPDATA_SETUP: 6,
    OPT_MNEMONIC: 7,
    OPT_UNSIGNED: 8,
    OPT_NO_BRANCH_OFFSET: 9,

    // cs_opt_value
    OPT_OFF: 0,
    OPT_ON: 3,
    OPT_SYNTAX_DEFAULT: 0,
    OPT_SYNTAX_INTEL: 1,
    OPT_SYNTAX_ATT: 2,
    OPT_SYNTAX_NOREGNAME: 3,
    OPT_SYNTAX_MASM: 4,
    OPT_SYNTAX_MOTOROLA: 5,

    // cs_op_type
    OP_INVALID: 0,
    OP_REG: 1,
    OP_IMM: 2,
    OP_MEM: 3,
    OP_FP: 4,

    // cs_ac_type
    AC_INVALID: 0,
    AC_READ: 1 << 0,
    AC_WRITE: 1 << 1,

    // cs_group_type
    GRP_INVALID: 0,
    GRP_JUMP: 1,
    GRP_CALL: 2,
    GRP_RET: 3,
    GRP_INT: 4,
    GRP_IRET: 5,
    GRP_PRIVILEGE: 6,
    GRP_BRANCH_RELATIVE: 7,

    // query id for cs_support()
    SUPPORT_DIET: 0xFFFF + 1,
    SUPPORT_X86_REDUCE: 0xFFFF + 2,

    // Maximum size of an instruction mnemonic string
    MNEMONIC_SIZE: 32,

    version: function() {
        var major_ptr = Module._malloc(4);
        var minor_ptr = Module._malloc(4);
        var ret = Module.ccall('cs_version', 'number',
            ['pointer', 'pointer'], [major_ptr, minor_ptr]);
        Module._free(major_ptr);
        Module._free(minor_ptr);
        return ret;
    },

    support: function(query) {
        var ret = Module.ccall('cs_support', 'number', ['number'], [query]);
        return ret;
    },

    strerror: function(code) {
        var ret = Module.ccall('cs_strerror', 'string', ['number'], [code]);
        return ret;
    },

    /**
     * Instruction object
     */
    Instruction: function (pointer, arch) {
        // Instruction ID
        this.id = Module.getValue(pointer, 'i32');

        // Address (EIP) of this instruction
        this.address = Module.getValue(pointer + 8, 'i64');

        // Size of this instruction
        this.size = Module.getValue(pointer + 16, 'i16');

        // Machine bytes of this instruction (length indicated by @size above)
        this.bytes = [];
        for (var i = 0; i < this.size; i++) {
            var byteValue = Module.getValue(pointer + 18 + i, 'i8');
            if (byteValue < 0) {
                byteValue = 256 + byteValue;
            }
            this.bytes.push(byteValue);
        }

        // ASCII representation of instruction mnemonic
        this.mnemonic = Module.UTF8ToString(pointer + 42);

        // ASCII representation of instruction operands
        this.op_str = Module.UTF8ToString(pointer + 74);

        // Details
        var detail = {};
        var detail_addr = Module.getValue(pointer + 236, '*');
        if (detail_addr != 0) {
            // Architecture-agnostic instruction info
            detail.op = [];
            detail.regs_read = [];
            var regs_read_count = Module.getValue(detail_addr + 24, 'i8');
            for (var i = 0; i < regs_read_count; i++) {
                detail.regs_read[i] = Module.getValue(detail_addr + 0 + i, 'i16');
            }
            detail.regs_write = [];
            var regs_write_count = Module.getValue(detail_addr + 66, 'i8');
            for (var i = 0; i < regs_write_count; i++) {
                detail.regs_write[i] = Module.getValue(detail_addr + 26 + i, 'i16');
            }
            detail.groups = [];
            var groups_count = Module.getValue(detail_addr + 75, 'i8');
            for (var i = 0; i < groups_count; i++) {
                detail.groups[i] = Module.getValue(detail_addr + 67 + i, 'i8');
            }
            // Architecture-specific instruction info
            var arch_info_addr = detail_addr + 80;
            switch (arch) {
            case Module.ARCH_ARM:
                detail.usermode = Boolean(Module.getValue(arch_info_addr + 0x00, 'i8'));
                detail.vector_size = Module.getValue(arch_info_addr + 0x04, 'i32');
                detail.vector_data = Module.getValue(arch_info_addr + 0x08, 'i32');
                detail.cps_mode = Module.getValue(arch_info_addr + 0x0C, 'i32');
                detail.cps_flag = Module.getValue(arch_info_addr + 0x10, 'i32');
                detail.cc = Module.getValue(arch_info_addr + 0x14, 'i32');
                detail.update_flags = Boolean(Module.getValue(arch_info_addr + 0x18, 'i8'));
                detail.writeback = Boolean(Module.getValue(arch_info_addr + 0x19, 'i8'));
                detail.mem_barrier = Module.getValue(arch_info_addr + 0x1C, 'i32');
                // Operands
                var op_size = 36;
                var op_count = Module.getValue(arch_info_addr + 0x20, 'i8');
                for (var i = 0; i < op_count; i++) {
                    var op = {};
                    var op_addr = arch_info_addr + 0x24 + (i * op_size);
                    op.vector_index = Module.getValue(op_addr + 0, 'i32');
                    op.shift = {
                        type:  Module.getValue(op_addr + 4, 'i32'),
                        value: Module.getValue(op_addr + 8, 'i32'),
                    };
                    op.type = Module.getValue(op_addr + 12, 'i32');
                    switch (op.type) {
                    case Module.ARM_OP_REG:
                        op.reg = Module.getValue(op_addr + 16, 'i32');
                        break;
                    case Module.ARM_OP_IMM:
                        op.imm = Module.getValue(op_addr + 16, 'i32');
                        break;
                    case Module.ARM_OP_FP:
                        op.fp = Module.getValue(op_addr + 16, 'double');
                        break;
                    case Module.ARM_OP_SETEND:
                        op.setend = Module.getValue(op_addr + 16, 'i32');
                        break;
                    case Module.ARM_OP_MEM:
                        op.mem = {
                            base:  Module.getValue(op_addr + 16, 'i32'),
                            index: Module.getValue(op_addr + 20, 'i32'),
                            scale: Module.getValue(op_addr + 24, 'i32'),
                            disp:  Module.getValue(op_addr + 28, 'i32'),
                        };
                        break;
                    }
                    op.subtracted = Boolean(Module.getValue(arch_info_addr + 32, 'i8'));
                    detail.op[i] = op;
                }
                break;

            case Module.ARCH_ARM64:
                detail.cc = Module.getValue(arch_info_addr + 0x00, 'i32');
                detail.update_flags = Boolean(Module.getValue(arch_info_addr + 0x04, 'i8'));
                detail.writeback = Boolean(Module.getValue(arch_info_addr + 0x05, 'i8'));
                // Operands
                var op_size = 40;
                var op_count = Module.getValue(arch_info_addr + 0x06, 'i8');
                for (var i = 0; i < op_count; i++) {
                    var op = {};
                    var op_addr = arch_info_addr + 0x08 + (i * op_size);
                    op.vector_index = Module.getValue(op_addr + 0, 'i32');
                    op.vas = Module.getValue(op_addr + 4, 'i32');
                    op.vess = Module.getValue(op_addr + 8, 'i32');
                    op.shift = {
                        type:  Module.getValue(op_addr + 12, 'i32'),
                        value: Module.getValue(op_addr + 16, 'i32'),
                    };
                    op.ext = Module.getValue(op_addr + 20, 'i32');
                    op.type = Module.getValue(op_addr + 24, 'i32');
                    switch (op.type) {
                    case Module.ARM64_OP_REG:
                        op.reg = Module.getValue(op_addr + 28, 'i32');
                        break;
                    case Module.ARM64_OP_IMM:
                        op.imm = Module.getValue(op_addr + 28, 'i64');
                        break;
                    case Module.ARM64_OP_FP:
                        op.fp = Module.getValue(op_addr + 28, 'double');
                        break;
                    case Module.ARM64_OP_PSTATE:
                        op.pstate = Module.getValue(op_addr + 28, 'i32');
                        break;
                    case Module.ARM64_OP_SYS:
                        op.sys = Module.getValue(op_addr + 28, 'i32');
                        break;
                    case Module.ARM64_OP_BARRIER:
                        op.barrier = Module.getValue(op_addr + 28, 'i32');
                        break;
                    case Module.ARM64_OP_PREFETCH:
                        op.prefetch = Module.getValue(op_addr + 28, 'i32');
                        break;
                    case Module.ARM64_OP_MEM:
                        op.mem = {
                            base:  Module.getValue(op_addr + 28, 'i32'),
                            index: Module.getValue(op_addr + 32, 'i32'),
                            disp:  Module.getValue(op_addr + 36, 'i32'),
                        };
                        break;
                    }
                    detail.op[i] = op;
                }
                break;

            case Module.ARCH_MIPS:
                // Operands
                var op_size = 16;
                var op_count = Module.getValue(arch_info_addr + 0x00, 'i8');
                for (var i = 0; i < op_count; i++) {
                    var op = {};
                    var op_addr = arch_info_addr + 0x04 + (i * op_size);
                    op.type = Module.getValue(op_addr + 0, 'i32');
                    switch (op.type) {
                    case Module.MIPS_OP_REG:
                        op.reg = Module.getValue(op_addr + 4, 'i32');
                        break;
                    case Module.MIPS_OP_IMM:
                        op.imm = Module.getValue(op_addr + 4, 'i64');
                        break;
                    case Module.MIPS_OP_MEM:
                        op.mem = {
                            base: Module.getValue(op_addr + 4, 'i32'),
                            disp: Module.getValue(op_addr + 8, 'i64'),
                        };
                        break;
                    }
                    detail.op[i] = op;
                }
                break;

            case Module.ARCH_X86:
                detail.prefix = [];
                detail.prefix[0] = Module.getValue(arch_info_addr + 0x00, 'i8');
                detail.prefix[1] = Module.getValue(arch_info_addr + 0x01, 'i8');
                detail.prefix[2] = Module.getValue(arch_info_addr + 0x02, 'i8');
                detail.prefix[3] = Module.getValue(arch_info_addr + 0x03, 'i8');
                detail.opcode = [];
                detail.opcode[0] = Module.getValue(arch_info_addr + 0x04, 'i8');
                detail.opcode[1] = Module.getValue(arch_info_addr + 0x05, 'i8');
                detail.opcode[2] = Module.getValue(arch_info_addr + 0x06, 'i8');
                detail.opcode[3] = Module.getValue(arch_info_addr + 0x07, 'i8');
                detail.rex = Module.getValue(arch_info_addr + 0x08, 'i8');
                detail.addr_size = Module.getValue(arch_info_addr + 0x09, 'i8');
                detail.modrm = Module.getValue(arch_info_addr + 0x0A, 'i8');
                detail.sib = Module.getValue(arch_info_addr + 0x0B, 'i8');
                detail.disp = Module.getValue(arch_info_addr + 0x10, 'i64');
                detail.sib_index = Module.getValue(arch_info_addr + 0x18, 'i32');
                detail.sib_scale = Module.getValue(arch_info_addr + 0x1C, 'i8');
                detail.sib_base = Module.getValue(arch_info_addr + 0x20, 'i32');
                detail.xop_cc = Module.getValue(arch_info_addr + 0x24, 'i32');
                detail.sse_cc = Module.getValue(arch_info_addr + 0x28, 'i32');
                detail.avx_cc = Module.getValue(arch_info_addr + 0x2C, 'i32');
                detail.avx_sae = Module.getValue(arch_info_addr + 0x30, 'i8');
                detail.avx_rm = Module.getValue(arch_info_addr + 0x34, 'i32');
                detail.eflags = Module.getValue(arch_info_addr + 0x38, 'i64');
                detail.fpu_flags = Module.getValue(arch_info_addr + 0x38, 'i64');
                // Operands
                var op_size = 48;
                var op_count = Module.getValue(arch_info_addr + 0x40, 'i8');
                for (var i = 0; i < op_count; i++) {
                    var op = {};
                    var op_addr = arch_info_addr + 0x48 + (i * op_size);
                    op.type = Module.getValue(op_addr + 0, 'i32');
                    switch (op.type) {
                    case Module.X86_OP_REG:
                        op.reg = Module.getValue(op_addr + 8, 'i32');
                        break;
                    case Module.X86_OP_IMM:
                        op.imm = Module.getValue(op_addr + 8, 'i64');
                        break;
                    case Module.X86_OP_FP:
                        op.fp = Module.getValue(op_addr + 8, 'double');
                        break;
                    case Module.X86_OP_MEM:
                        op.mem = {
                            segment:  Module.getValue(op_addr +  8, 'i32'),
                            base:     Module.getValue(op_addr + 12, 'i32'),
                            index:    Module.getValue(op_addr + 16, 'i32'),
                            scale:    Module.getValue(op_addr + 20, 'i32'),
                            disp:     Module.getValue(op_addr + 24, 'i64'),
                        };
                        break;
                    }
                    op.size = Module.getValue(op_addr + 32, 'i8');
                    op.access = Module.getValue(op_addr + 33, 'i8');
                    op.avx_bcast = Module.getValue(op_addr + 36, 'i32');
                    op.avx_zero_opmask = Module.getValue(op_addr + 40, 'i8');
                    detail.op[i] = op;
                }
                break;

            case Module.ARCH_PPC:
                detail.bc = Module.getValue(arch_info_addr + 0x00, 'i32');
                detail.bh = Module.getValue(arch_info_addr + 0x04, 'i32');
                detail.update_cr0 = Module.getValue(arch_info_addr + 0x08, 'i8');
                // Operands
                var op_size = 16;
                var op_count = Module.getValue(arch_info_addr + 0x09, 'i8');
                for (var i = 0; i < op_count; i++) {
                    var op = {};
                    var op_addr = arch_info_addr + 0x0C + (i * op_size);
                    op.type = Module.getValue(op_addr + 0, 'i32');
                    switch (op.type) {
                    case Module.PPC_OP_REG:
                        op.reg = Module.getValue(op_addr + 4, 'i32');
                        break;
                    case Module.PPC_OP_IMM:
                        op.imm = Module.getValue(op_addr + 4, 'i32');
                        break;
                    case Module.PPC_OP_CRX:
                        op.crx = {
                            scale:  Module.getValue(op_addr +  4, 'i32'),
                            reg:    Module.getValue(op_addr +  8, 'i32'),
                            cond:   Module.getValue(op_addr + 12, 'i32'),
                        };
                        break;
                    case Module.PPC_OP_MEM:
                        op.mem = {
                            base:   Module.getValue(op_addr +  4, 'i32'),
                            disp:   Module.getValue(op_addr +  8, 'i32'),
                        };
                        break;
                    }
                    detail.op[i] = op;
                }
                break;

            case Module.ARCH_SPARC:
                detail.cc = Module.getValue(arch_info_addr + 0x00, 'i32');
                detail.hint = Module.getValue(arch_info_addr + 0x04, 'i32');
                // Operands
                var op_size = 12;
                var op_count = Module.getValue(arch_info_addr + 0x08, 'i8');
                for (var i = 0; i < op_count; i++) {
                    var op = {};
                    var op_addr = arch_info_addr + 0x09 + (i * op_size);
                    op.type = Module.getValue(op_addr + 0, 'i32');
                    switch (op.type) {
                    case Module.SPARC_OP_REG:
                        op.reg = Module.getValue(op_addr + 4, 'i32');
                        break;
                    case Module.SPARC_OP_IMM:
                        op.imm = Module.getValue(op_addr + 4, 'i32');
                        break;
                    case Module.SPARC_OP_MEM:
                        op.mem = {
                            base:   Module.getValue(op_addr + 4, 'i8'),
                            index:  Module.getValue(op_addr + 5, 'i8'),
                            disp:   Module.getValue(op_addr + 8, 'i32'),
                        };
                        break;
                    }
                    detail.op[i] = op;
                }
                break;

            case Module.ARCH_SYSZ:
                detail.cc = Module.getValue(arch_info_addr + 0x00, 'i32');
                // Operands
                var op_size = 24;
                var op_count = Module.getValue(arch_info_addr + 0x04, 'i8');
                for (var i = 0; i < op_count; i++) {
                    var op = {};
                    var op_addr = arch_info_addr + 0x08 + (i * op_size);
                    op.type = Module.getValue(op_addr + 0, 'i32');
                    switch (op.type) {
                    case Module.SYSZ_OP_REG:
                        op.reg = Module.getValue(op_addr + 4, 'i32');
                        break;
                    case Module.SYSZ_OP_IMM:
                        op.imm = Module.getValue(op_addr + 4, 'i32');
                        break;
                    case Module.SYSZ_OP_MEM:
                        op.mem = {
                            base:   Module.getValue(op_addr +  4, 'i8'),
                            index:  Module.getValue(op_addr +  5, 'i8'),
                            length: Module.getValue(op_addr +  8, 'i64'),
                            disp:   Module.getValue(op_addr + 16, 'i64'),
                        };
                        break;
                    }
                    detail.op[i] = op;
                }
                break;

            case Module.ARCH_XCORE:
                // Operands
                var op_size = 16;
                var op_count = Module.getValue(arch_info_addr + 0, 'i8');
                for (var i = 0; i < op_count; i++) {
                    var op = {};
                    var op_addr = arch_info_addr + 4 + (i * op_size);
                    op.type = Module.getValue(op_addr + 0, 'i32');
                    switch (op.type) {
                    case Module.XCORE_OP_REG:
                        op.reg = Module.getValue(op_addr + 4, 'i32');
                        break;
                    case Module.XCORE_OP_IMM:
                        op.imm = Module.getValue(op_addr + 4, 'i32');
                        break;
                    case Module.XCORE_OP_MEM:
                        op.mem = {
                            base:   Module.getValue(op_addr +  4, 'i8'),
                            index:  Module.getValue(op_addr +  5, 'i8'),
                            disp:   Module.getValue(op_addr +  8, 'i32'),
                            direct: Module.getValue(op_addr + 12, 'i32'),
                        };
                        break;
                    }
                    detail.op[i] = op;
                }
                break;
            }
        }
        this.detail = detail;
    },

    /**
     * Capstone object
     */
    Capstone: function (arch, mode) {
        this.arch = arch;
        this.mode = mode;
        this.handle_ptr = Module._malloc(4);

        // Options
        this.option = function(option, value) {
            var handle = Module.getValue(this.handle_ptr, '*');
            if (!handle) {
                return;
            }
            var ret = Module.ccall('cs_option', 'number',
                ['pointer', 'number', 'number'],
                [handle, option, value]
            );
            if (ret != Module.ERR_OK) {
                var error = 'Capstone.js: Function cs_option failed with code ' + ret + ':\n' + Module.strerror(ret);
                throw error;
            }
        }

        // Disassemble
        this.disasm = function (buffer, addr, max) {
            var handle = Module.getValue(this.handle_ptr, 'i32');

            // Allocate buffer and copy data
            var buffer_len = buffer.length;
            var buffer_ptr = Module._malloc(buffer_len);
            Module.writeArrayToMemory(buffer, buffer_ptr);

            // Pointer to the instruction array
            var insn_ptr_ptr = Module._malloc(4);

            var count = Module.ccall('cs_disasm', 'number',
                ['number', 'pointer', 'number', 'number', 'number', 'pointer'],
                [handle, buffer_ptr, buffer_len, BigInt(addr || 0), max || 0, insn_ptr_ptr]
            );
            if (count == 0 && buffer_len != 0) {
                Module._free(insn_ptr_ptr);
                Module._free(buffer_ptr);

                var code = this.errno();
                var error = 'Capstone.js: Function cs_disasm failed with code ' + code + ':\n' + Module.strerror(code);
                throw error;
            }

            // Dereference intruction array
            var insn_ptr = Module.getValue(insn_ptr_ptr, 'i32');
            var insn_size = 240;
            var instructions = [];

            // Save instructions
            for (var i = 0; i < count; i++) {
                instructions.push(new Module.Instruction(insn_ptr + i * insn_size, this.arch));
            }

            var count = Module.ccall('cs_free', 'void',
                ['pointer', 'number'],
                [insn_ptr, count]
            );

            Module._free(insn_ptr_ptr);
            Module._free(buffer_ptr);
            return instructions;
        };

        // Disassemble one instruction at a time. For each decoded instruction the
        // callback receives the parsed Instruction and a pointer to the live cs_insn
        // (usable with op_count/op_index/reg_read/reg_write/insn_group/regs_access
        // below). Returning false from the callback stops iteration early.
        this.disasm_iter = function (buffer, addr, callback) {
            var handle = Module.getValue(this.handle_ptr, 'i32');

            // Input buffer, plus the in/out pointers cs_disasm_iter advances as it
            // consumes it: code (const uint8_t*), size (size_t), address (uint64_t).
            var buffer_len = buffer.length;
            var buffer_ptr = Module._malloc(buffer_len);
            Module.writeArrayToMemory(buffer, buffer_ptr);
            var code_ptr = Module._malloc(4);
            var size_ptr = Module._malloc(4);
            var addr_ptr = Module._malloc(8);
            Module.setValue(code_ptr, buffer_ptr, 'i32');
            Module.setValue(size_ptr, buffer_len, 'i32');
            Module.setValue(addr_ptr, BigInt(addr || 0), 'i64');

            // Reusable instruction cache, freed once after the loop.
            var insn_ptr = Module.ccall('cs_malloc', 'number', ['number'], [handle]);

            var count = 0;
            try {
                while (insn_ptr && Module.ccall('cs_disasm_iter', 'number',
                    ['number', 'pointer', 'pointer', 'pointer', 'number'],
                    [handle, code_ptr, size_ptr, addr_ptr, insn_ptr]
                )) {
                    count += 1;
                    var insn = new Module.Instruction(insn_ptr, this.arch);
                    if (callback(insn, insn_ptr) === false) {
                        break;
                    }
                }
            } finally {
                if (insn_ptr) {
                    Module.ccall('cs_free', 'void', ['pointer', 'number'], [insn_ptr, 1]);
                }
                Module._free(addr_ptr);
                Module._free(size_ptr);
                Module._free(code_ptr);
                Module._free(buffer_ptr);
            }
            return count;
        };

        // Allocate a cs_insn cache to drive cs_disasm_iter manually (free with free()).
        this.malloc = function() {
            var handle = Module.getValue(this.handle_ptr, 'i32');
            return Module.ccall('cs_malloc', 'number', ['number'], [handle]);
        }

        // Free count instructions allocated by malloc() (count 1) or cs_disasm().
        this.free = function(insn_ptr, count) {
            Module.ccall('cs_free', 'void', ['pointer', 'number'], [insn_ptr, count]);
        }

        // Number of operands of a given type in a live cs_insn (needs detail ON).
        this.op_count = function(insn_ptr, op_type) {
            var handle = Module.getValue(this.handle_ptr, '*');
            return Module.ccall('cs_op_count', 'number',
                ['pointer', 'pointer', 'number'], [handle, insn_ptr, op_type]);
        }

        // Index of the operand at the given position (1-based) of a given type
        // in a live cs_insn's operand array (needs detail ON).
        this.op_index = function(insn_ptr, op_type, position) {
            var handle = Module.getValue(this.handle_ptr, '*');
            return Module.ccall('cs_op_index', 'number',
                ['pointer', 'pointer', 'number', 'number'],
                [handle, insn_ptr, op_type, position]);
        }

        // Whether a live cs_insn implicitly reads the given register (needs detail ON).
        this.reg_read = function(insn_ptr, reg_id) {
            var handle = Module.getValue(this.handle_ptr, '*');
            return Boolean(Module.ccall('cs_reg_read', 'number',
                ['pointer', 'pointer', 'number'], [handle, insn_ptr, reg_id]));
        }

        // Whether a live cs_insn implicitly writes the given register (needs detail ON).
        this.reg_write = function(insn_ptr, reg_id) {
            var handle = Module.getValue(this.handle_ptr, '*');
            return Boolean(Module.ccall('cs_reg_write', 'number',
                ['pointer', 'pointer', 'number'], [handle, insn_ptr, reg_id]));
        }

        // Whether a live cs_insn belongs to the given group (needs detail ON).
        this.insn_group = function(insn_ptr, group_id) {
            var handle = Module.getValue(this.handle_ptr, '*');
            return Boolean(Module.ccall('cs_insn_group', 'number',
                ['pointer', 'pointer', 'number'], [handle, insn_ptr, group_id]));
        }

        // All registers (explicit + implicit) accessed by a live cs_insn.
        // Returns { regs_read: [...], regs_write: [...] } (needs detail ON).
        this.regs_access = function(insn_ptr) {
            var handle = Module.getValue(this.handle_ptr, '*');
            var regs_read_ptr = Module._malloc(64 * 2);
            var regs_write_ptr = Module._malloc(64 * 2);
            var read_count_ptr = Module._malloc(1);
            var write_count_ptr = Module._malloc(1);
            var ret = Module.ccall('cs_regs_access', 'number',
                ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer'],
                [handle, insn_ptr, regs_read_ptr, read_count_ptr, regs_write_ptr, write_count_ptr]
            );
            var result = { regs_read: [], regs_write: [] };
            if (ret == Module.ERR_OK) {
                var read_count = Module.getValue(read_count_ptr, 'i8');
                for (var i = 0; i < read_count; i++) {
                    result.regs_read.push(Module.getValue(regs_read_ptr + i * 2, 'i16'));
                }
                var write_count = Module.getValue(write_count_ptr, 'i8');
                for (var i = 0; i < write_count; i++) {
                    result.regs_write.push(Module.getValue(regs_write_ptr + i * 2, 'i16'));
                }
            }
            Module._free(write_count_ptr);
            Module._free(read_count_ptr);
            Module._free(regs_write_ptr);
            Module._free(regs_read_ptr);
            return result;
        }

        this.reg_name = function(reg_id) {
            var handle = Module.getValue(this.handle_ptr, '*');
            var ret = Module.ccall('cs_reg_name', 'string', ['pointer', 'number'], [handle, reg_id]);
            return ret;
        }

        this.insn_name = function(insn_id) {
            var handle = Module.getValue(this.handle_ptr, '*');
            var ret = Module.ccall('cs_insn_name', 'string', ['pointer', 'number'], [handle, insn_id]);
            return ret;
        }

        this.group_name = function(group_id) {
            var handle = Module.getValue(this.handle_ptr, '*');
            var ret = Module.ccall('cs_group_name', 'string', ['pointer', 'number'], [handle, group_id]);
            return ret;
        }

        this.errno = function() {
            var handle = Module.getValue(this.handle_ptr, '*');
            var ret = Module.ccall('cs_errno', 'number', ['pointer'], [handle]);
            return ret;
        }

        this.close = function() {
            var ret = Module.ccall('cs_close', 'number', ['pointer'], [this.handle_ptr]);
            if (ret != Module.ERR_OK) {
                var error = 'Capstone.js: Function cs_close failed with code ' + ret + ':\n' + Module.strerror(ret);
                throw error;
            }
            Module._free(this.handle_ptr);
        }


        // Constructor
        var ret = Module.ccall('cs_open', 'number',
            ['number', 'number', 'pointer'],
            [this.arch, this.mode, this.handle_ptr]
        );

        if (ret != Module.ERR_OK) {
            Module.setValue(this.handle_ptr, 0, '*');
            var error = 'Capstone.js: Function cs_open failed with code ' + ret + ':\n' + Module.strerror(ret);
            throw error;
        }
    },
});
