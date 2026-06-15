/**
 * (c) 2014-2026 Capstone.JS
 * Wrapper made by Alexandro Sanchez Bach.
 */

Object.assign(Module, {
    // Return codes
    ERR_OK: 0,         // No error: everything was fine
    ERR_MEM: 1,        // Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
    ERR_ARCH: 2,       // Unsupported architecture: cs_open()
    ERR_HANDLE: 3,     // Invalid handle: cs_op_count(), cs_op_index()
    ERR_CSH: 4,        // Invalid csh argument: cs_close(), cs_errno(), cs_option()
    ERR_MODE: 5,       // Invalid/unsupported mode: cs_open()
    ERR_OPTION: 6,     // Invalid/unsupported option: cs_option()
    ERR_DETAIL: 7,     // Information is unavailable because detail option is OFF
    ERR_MEMSETUP: 8,   // Dynamic memory management uninitialized (see OPT_MEM)
    ERR_VERSION: 9,    // Unsupported version (bindings)
    ERR_DIET: 10,      // Access irrelevant data in "diet" engine
    ERR_SKIPDATA: 11,  // Access irrelevant data for "data" instruction in SKIPDATA mode
    ERR_X86_ATT: 12,   // X86 AT&T syntax is unsupported (opt-out at compile time)
    ERR_X86_INTEL: 13, // X86 Intel syntax is unsupported (opt-out at compile time)

    // Architectures
    ARCH_ARM: 0,       // ARM architecture (including Thumb, Thumb-2)
    ARCH_ARM64: 1,     // ARM-64, also called AArch64
    ARCH_MIPS: 2,      // Mips architecture
    ARCH_X86: 3,       // X86 architecture (including x86 & x86-64)
    ARCH_PPC: 4,       // PowerPC architecture
    ARCH_SPARC: 5,     // Sparc architecture
    ARCH_SYSZ: 6,      // SystemZ architecture
    ARCH_XCORE: 7,     // XCore architecture
    ARCH_MAX: 8,
    ARCH_ALL: 0xFFFF,

    // Modes
    MODE_LITTLE_ENDIAN: 0,     // Little-Endian mode (default mode)
    MODE_ARM: 0,               // 32-bit ARM
    MODE_16: 1 << 1,           // 16-bit mode (X86)
    MODE_32: 1 << 2,           // 32-bit mode (X86)
    MODE_64: 1 << 3,           // 64-bit mode (X86, PPC)
    MODE_THUMB: 1 << 4,        // ARM's Thumb mode, including Thumb-2
    MODE_MCLASS: 1 << 5,       // ARM's Cortex-M series
    MODE_V8: 1 << 6,           // ARMv8 A32 encodings for ARM
    MODE_MICRO: 1 << 4,        // MicroMips mode (MIPS)
    MODE_MIPS3: 1 << 5,        // Mips III ISA
    MODE_MIPS32R6: 1 << 6,     // Mips32r6 ISA
    MODE_MIPSGP64: 1 << 7,     // General Purpose Registers are 64-bit wide (MIPS)
    MODE_V9: 1 << 4,           // SparcV9 mode (Sparc)
    MODE_BIG_ENDIAN: 1 << 31,  // Big-Endian mode
    MODE_MIPS32: 1 << 2,       // Mips32 ISA (Mips)
    MODE_MIPS64: 1 << 3,       // Mips64 ISA (Mips)

    // Options
    OPT_SYNTAX: 1,             // Intel X86 asm syntax (CS_ARCH_X86 arch)
    OPT_DETAIL: 2,             // Break down instruction structure into details
    OPT_MODE: 3,               // Change engine's mode at run-time
    OPT_MEM: 4,                // Change engine's mode at run-time
    OPT_SKIPDATA: 5,           // Skip data when disassembling
    OPT_SKIPDATA_SETUP: 6,     // Setup user-defined function for SKIPDATA option

    // Capstone option value
    OPT_OFF: 0,                // Turn OFF an option - default option of CS_OPT_DETAIL
    OPT_ON: 3,                 // Turn ON an option (CS_OPT_DETAIL)

    // Capstone syntax value
    OPT_SYNTAX_DEFAULT: 0,     // Default assembly syntax of all platforms (CS_OPT_SYNTAX)
    OPT_SYNTAX_INTEL: 1,       // Intel X86 asm syntax - default syntax on X86 (CS_OPT_SYNTAX, CS_ARCH_X86)
    OPT_SYNTAX_ATT: 2,         // ATT asm syntax (CS_OPT_SYNTAX, CS_ARCH_X86)
    OPT_SYNTAX_NOREGNAME: 3,   // Asm syntax prints register name with only number - (CS_OPT_SYNTAX, CS_ARCH_PPC, CS_ARCH_ARM)

    // Common instruction groups - to be consistent across all architectures.
    GRP_INVALID: 0,            // uninitialized/invalid group.
    GRP_JUMP: 1,               // all jump instructions (conditional+direct+indirect jumps)
    GRP_CALL: 2,               // all call instructions
    GRP_RET: 3,                // all return instructions
    GRP_INT: 4,                // all interrupt instructions (int+syscall)
    GRP_IRET: 5,               // all interrupt return instructions

    // Common instruction operand types - to be consistent across all architectures.
    OP_INVALID: 0,
    OP_REG: 1,
    OP_IMM: 2,
    OP_MEM: 3,
    OP_FP: 4,

    // query id for cs_support()
    SUPPORT_DIET: 0xFFFF + 1,
    SUPPORT_X86_REDUCE: 0xFFFF + 2,

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
