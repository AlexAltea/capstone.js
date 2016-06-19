/**
 * (c) 2014 Capstone.JS
 * Wrapper made by Alexandro Sanchez Bach.
 */

var capstone = {
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

    /**
     * Instruction object
     */
    Instruction: function (pointer) {
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
        this.mnemonic = Pointer_stringify(pointer + 34);

        // ASCII representation of instruction operands
        this.op_str = Pointer_stringify(pointer + 66);   
    },

    /**
     * Capstone object
     */
    Cs: function (arch, mode) {
        this.arch = arch;
        this.mode = mode;
        this.handle_ptr = Module._malloc(4);

        // Destructor
        this.delete = function () {
            Module._free(this.handle_ptr);
        }

        // Disassemble
        this.disasm = function (buffer, addr, max) {
            var handle = Module.getValue(this.handle_ptr, 'i32');

            // Allocate buffer and copy data
            var buffer_ptr = Module._malloc(buffer.length);
            var buffer_heap = new Uint8Array(Module.HEAPU8.buffer, buffer_ptr, buffer.length);
            buffer_heap.set(new Uint8Array(buffer));

            // Pointer to the instruction array
            var insn_ptr_ptr = Module._malloc(4);

            var count = Module.ccall('cs_disasm', 'number',
                ['number', 'pointer', 'number', 'number', 'number', 'pointer'],
                [handle, buffer_heap.byteOffset, buffer_heap.length, addr, 0, max || 0, insn_ptr_ptr]
            );

            // Dereference intruction array
            var insn_ptr = Module.getValue(insn_ptr_ptr, 'i32');
            var insn_size = 232;
            var instructions = [];

            // Save instructions
            for (var i = 0; i < count; i++) {
                instructions.push(new capstone.Instruction(insn_ptr + i * insn_size));
            }

            var count = Module.ccall('cs_free', 'void',
                ['pointer', 'number'],
                [insn_ptr, count]
            );

            Module._free(insn_ptr_ptr);
            Module._free(buffer_ptr);
            return instructions;
        };

        // Constructor
        var ret = Module.ccall('cs_open', 'number',
            ['number', 'number', 'pointer'],
            [this.arch, this.mode, this.handle_ptr]
        );

        if (ret != capstone.ERR_OK) {
            console.error('Capstone.js: Function cs_open failed with code %d.', ret);
        }
    },
};
