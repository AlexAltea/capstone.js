/**
 * (c) 2014-2017 Capstone.JS
 * Wrapper made by Alexandro Sanchez Bach.
 */

// Emscripten demodularize
var MCapstone = new MCapstone();

var cs = {
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
        major_ptr = MCapstone._malloc(4);
        minor_ptr = MCapstone._malloc(4);
        var ret = MCapstone.ccall('cs_version', 'number',
            ['pointer', 'pointer'], [major_ptr, minor_ptr]);
        major = MCapstone.getValue(major_ptr, 'i32');
        minor = MCapstone.getValue(minor_ptr, 'i32');
        MCapstone._free(major_ptr);
        MCapstone._free(minor_ptr);
        return ret;
    },

    support: function(query) {
        var ret = MCapstone.ccall('cs_support', 'number', ['number'], [query]);
        return ret;
    },

    strerror: function(code) {
        var ret = MCapstone.ccall('cs_strerror', 'string', ['number'], [code]);
        return ret;
    },

    /**
     * Instruction object
     */
    Instruction: function (pointer) {
        // Instruction ID
        this.id = MCapstone.getValue(pointer, 'i32');

        // Address (EIP) of this instruction
        this.address = MCapstone.getValue(pointer + 8, 'i64');

        // Size of this instruction
        this.size = MCapstone.getValue(pointer + 16, 'i16');

        // Machine bytes of this instruction (length indicated by @size above)
        this.bytes = [];
        for (var i = 0; i < this.size; i++) {
            var byteValue = MCapstone.getValue(pointer + 18 + i, 'i8');
            if (byteValue < 0) {
                byteValue = 256 + byteValue;
            }
            this.bytes.push(byteValue);
        }

        // ASCII representation of instruction mnemonic
        this.mnemonic = MCapstone.Pointer_stringify(pointer + 34);

        // ASCII representation of instruction operands
        this.op_str = MCapstone.Pointer_stringify(pointer + 66);
    },

    /**
     * Capstone object
     */
    Capstone: function (arch, mode) {
        this.arch = arch;
        this.mode = mode;
        this.handle_ptr = MCapstone._malloc(4);

        // Options
        this.option = function(option, value) {
            var handle = MCapstone.getValue(this.handle_ptr, '*');
            if (!handle) {
                return;
            }
            var ret = MCapstone.ccall('cs_option', 'number',
                ['pointer', 'number', 'number'],
                [handle, option, value]
            );
            if (ret != cs.ERR_OK) {
                var error = 'Capstone.js: Function cs_option failed with code ' + ret + ':\n' + cs.strerror(ret);
                throw error;
            }
        }

        // Disassemble
        this.disasm = function (buffer, addr, max) {
            var handle = MCapstone.getValue(this.handle_ptr, 'i32');

            // Allocate buffer and copy data
            var buffer_len = buffer.length;
            var buffer_ptr = MCapstone._malloc(buffer_len);
            MCapstone.writeArrayToMemory(buffer, buffer_ptr);

            // Pointer to the instruction array
            var insn_ptr_ptr = MCapstone._malloc(4);

            var count = MCapstone.ccall('cs_disasm', 'number',
                ['number', 'pointer', 'number', 'number', 'number', 'pointer'],
                [handle, buffer_ptr, buffer_len, addr, 0, max || 0, insn_ptr_ptr]
            );
            if (count == 0 && buffer_len != 0) {
                MCapstone._free(insn_ptr_ptr);
                MCapstone._free(buffer_ptr);

                var code = this.errno();
                var error = 'Capstone.js: Function cs_disasm failed with code ' + code + ':\n' + cs.strerror(code);
                throw error;
            }

            // Dereference intruction array
            var insn_ptr = MCapstone.getValue(insn_ptr_ptr, 'i32');
            var insn_size = 232;
            var instructions = [];

            // Save instructions
            for (var i = 0; i < count; i++) {
                instructions.push(new cs.Instruction(insn_ptr + i * insn_size));
            }

            var count = MCapstone.ccall('cs_free', 'void',
                ['pointer', 'number'],
                [insn_ptr, count]
            );

            MCapstone._free(insn_ptr_ptr);
            MCapstone._free(buffer_ptr);
            return instructions;
        };

        this.reg_name = function(reg_id) {
            var handle = MCapstone.getValue(this.handle_ptr, '*');
            var ret = MCapstone.ccall('cs_reg_name', 'string', ['pointer', 'number'], [handle, reg_id]);
            return ret;
        }

        this.insn_name = function(insn_id) {
            var handle = MCapstone.getValue(this.handle_ptr, '*');
            var ret = MCapstone.ccall('cs_insn_name', 'string', ['pointer', 'number'], [handle, insn_id]);
            return ret;
        }

        this.group_name = function(group_id) {
            var handle = MCapstone.getValue(this.handle_ptr, '*');
            var ret = MCapstone.ccall('cs_group_name', 'string', ['pointer', 'number'], [handle, group_id]);
            return ret;
        }

        this.errno = function() {
            var handle = MCapstone.getValue(this.handle_ptr, '*');
            var ret = MCapstone.ccall('cs_errno', 'number', ['pointer'], [handle]);
            return ret;
        }

        this.close = function() {
            var handle = MCapstone.getValue(this.handle_ptr, '*');
            var ret = MCapstone.ccall('cs_close', 'number', ['pointer'], [handle]);
            if (ret != cs.ERR_OK) {
                var error = 'Capstone.js: Function cs_close failed with code ' + ret + ':\n' + cs.strerror(ret);
                throw error;
            }
            MCapstone._free(this.handle_ptr);
        }


        // Constructor
        var ret = MCapstone.ccall('cs_open', 'number',
            ['number', 'number', 'pointer'],
            [this.arch, this.mode, this.handle_ptr]
        );

        if (ret != cs.ERR_OK) {
            MCapstone.setValue(this.handle_ptr, 0, '*');
            var error = 'Capstone.js: Function cs_open failed with code ' + ret + ':\n' + cs.strerror(ret);
            throw error;
        }
    },
};
