#!/usr/bin/env python3

# INFORMATION:
# This scripts compiles the original Capstone framework to JavaScript.
# It is the single entry point for the build: it generates the JS constants,
# compiles Capstone with Emscripten, and bundles the final dist artifact.

import glob
import os
import re
import shutil
import sys

EXPORTED_FUNCTIONS = [
    '_malloc',
    '_free',
    '_cs_open',
    '_cs_disasm',
    '_cs_free',
    '_cs_close',
    '_cs_option',
    '_cs_group_name',
    '_cs_insn_name',
    '_cs_insn_group',
    '_cs_reg_name',
    '_cs_errno',
    '_cs_support',
    '_cs_version',
    '_cs_strerror',
    '_cs_disasm',
    '_cs_disasm_iter',
    '_cs_malloc',
    '_cs_reg_read',
    '_cs_reg_write',
    '_cs_op_count',
    '_cs_op_index',
]

AVAILABLE_TARGETS = [
    'ARM', 'ARM64', 'MIPS', 'PPC', 'SPARC', 'SYSZ', 'XCORE', 'X86',
    'M68K', 'TMS320C64X', 'M680X', 'EVM', 'MOS65XX', 'WASM', 'BPF',
    'RISCV', 'SH', 'TRICORE'
]

# Architectures built as standalone bundles by `--release` (mirrors the
# previous Grunt `release` task: the combined build plus one bundle per arch).
RELEASE_TARGETS = [
    [], ['arm'], ['arm64'], ['mips'], ['ppc'],
    ['sparc'], ['sysz'], ['x86'], ['xcore'],
]

# Capstone headers and the constant prefix(es) to export from each. Taken from
# Capstone's own bindings/const_generator.py (the `include` list + per-header
# prefixes), so this tracks whatever architectures Capstone ships.
CONST_HEADERS = [
    ('arm.h', 'arm'),
    ('arm64.h', 'arm64'),
    ('m68k.h', 'm68k'),
    ('mips.h', 'mips'),
    ('x86.h', 'x86'),
    ('ppc.h', 'ppc'),
    ('sparc.h', 'sparc'),
    ('systemz.h', 'sysz'),
    ('xcore.h', 'xcore'),
    ('tms320c64x.h', 'tms320c64x'),
    ('m680x.h', 'm680x'),
    ('evm.h', 'evm'),
    ('mos65xx.h', 'mos65xx'),
    ('wasm.h', 'wasm'),
    ('bpf.h', 'bpf'),
    ('riscv.h', 'riscv'),
    ('sh.h', 'sh'),
    ('tricore.h', ['TRICORE', 'TriCore']),
]

# Core operand types (capstone.h `cs_op_type`), referenced by some arch headers
# e.g. `TRICORE_OP_REG = CS_OP_REG`. Seeded so those aliases resolve.
CS_OP_SEED = {
    'CS_OP_INVALID': 0, 'CS_OP_REG': 1, 'CS_OP_IMM': 2, 'CS_OP_MEM': 3, 'CS_OP_FP': 4,
}

MARKUP = '//>'

# Directories
CAPSTONE_DIR = os.path.abspath("capstone")
INCLUDE_DIR = os.path.join(CAPSTONE_DIR, 'include', 'capstone')


def generateConstants():
    """Generate src/capstone-constants.js from Capstone's C headers.

    Adapted from capstone/bindings/const_generator.py: it parses each arch
    header's `typedef enum` / `#define` constants and resolves every value to an
    integer (mirroring that script's `swift` branch). Resolving means aliases
    such as `ARM_REG_FP = ARM_REG_R11` and expressions such as `(1ULL << 3)`
    collapse into plain integer literals, valid as `cs.NAME = <int>;`. This is
    immune to the textual quirks of Capstone's pre-generated Python bindings.
    """
    out = open('src/capstone-constants.js', 'w')
    for header, prefix in CONST_HEADERS:
        prefixes = []
        if isinstance(prefix, list):
            prefixes = prefix
            prefix = prefix[0].lower()

        def has_prefix(token, prefix=prefix, prefixes=prefixes):
            if prefixes:
                return any(token.startswith(p) for p in prefixes)
            return token.startswith(prefix.upper())

        out.write('// AUTO-GENERATED, DO NOT EDIT [%s]\n' % header)
        values = dict(CS_OP_SEED)  # running namespace for value resolution
        count = 0
        for line in open(os.path.join(INCLUDE_DIR, header)):
            line = line.strip()
            if line.startswith(MARKUP) or line == '' or line.startswith('//'):
                continue
            if line.startswith('#define '):
                fields = re.split(r'\s+', line[len('#define '):], 1)
                if len(fields) != 2 or '(' in fields[0] or ')' in fields[0]:
                    continue  # skip multi-token / function-like macros
                line = fields[0] + ' = ' + fields[1]
            if not has_prefix(line):
                continue

            for token in line.split(','):
                token = token.strip()
                if not token or token.startswith('//'):
                    continue
                # Normalize C casts/shifts into evaluable expressions.
                token = token.replace('(uint64_t)', '')
                token = re.sub(r'\((\d+)ULL << (\d+)\)', r'\1 << \2', token)
                fields = re.split(r'\s+', token)
                if not has_prefix(fields[0]):
                    continue
                if len(fields) > 1 and fields[1] not in ('//', '///<', '='):
                    continue
                if len(fields) > 1 and fields[1] == '=':
                    rhs = ''.join(fields[2:])
                else:
                    rhs = str(count)
                    count += 1
                try:
                    count = int(rhs) + 1
                except ValueError:
                    pass
                name = fields[0].strip()
                value = eval(rhs, None, values)       # resolve to integer
                exec('%s = %d' % (name, value), None, values)
                out.write('cs.%s = %d;\n' % (name, value))
    out.close()


def compileCapstone(targets):
    # Clean CMake cache
    try:
        os.remove('capstone/CMakeCache.txt')
    except OSError:
        pass

    # CMake
    cmd = 'emcmake cmake'
    cmd += ' -DCMAKE_BUILD_TYPE=Release'
    cmd += ' -DCMAKE_C_FLAGS="-Wno-warn-absolute-paths"'
    cmd += ' -DCAPSTONE_BUILD_TESTS=OFF'
    cmd += ' -DCAPSTONE_BUILD_STATIC_LIBS=ON'
    cmd += ' -DCAPSTONE_BUILD_SHARED=OFF'
    if targets:
        targets = [t.upper() for t in targets]
        for arch in AVAILABLE_TARGETS:
            if arch not in targets:
                cmd += ' -DCAPSTONE_%s_SUPPORT=0' % arch
    if os.name == 'nt':
        cmd += ' -G \"MinGW Makefiles\"'
    if os.name == 'posix':
        cmd += ' -G \"Unix Makefiles\"'
    cmd += ' capstone/CMakeLists.txt'
    if os.system(cmd) != 0:
        print("CMake errored")
        sys.exit(1)

    # MinGW (Windows) or Make (Linux/Unix)
    os.chdir('capstone')
    if os.name == 'nt':
        make = 'mingw32-make'
    if os.name == 'posix':
        make = 'emmake make'
    if os.system(make) != 0:
        print("Make errored")
        sys.exit(1)
    os.chdir('..')

    # Compile static library to JavaScript
    exports = EXPORTED_FUNCTIONS
    methods = [
        'ccall', 'getValue', 'setValue', 'writeArrayToMemory', 'UTF8ToString'
    ]
    cmd = 'emcc'
    cmd += ' -Os'
    cmd += ' capstone/libcapstone.a'
    cmd += ' -s EXPORTED_FUNCTIONS=\"[\''+ '\', \''.join(exports) +'\']\"'
    cmd += ' -s EXPORTED_RUNTIME_METHODS=\"[\''+ '\', \''.join(methods) +'\']\"'
    cmd += ' -s ALLOW_MEMORY_GROWTH=1'
    cmd += ' -s MODULARIZE=1'
    cmd += ' -s WASM=2'
    cmd += ' -s EXPORT_NAME="\'MCapstone\'"'
    if targets:
        cmd += ' -o src/libcapstone-%s.out.js' % '-'.join(targets).lower()
    else:
        cmd += ' -o src/libcapstone.out.js'
    if os.system(cmd) != 0:
        print("Emscripten errored", cmd)
        sys.exit(1)


def bundle(suffix):
    """Assemble the final dist artifact. Replaces the former Grunt concat+copy.

    Concatenation order matters: libcapstone.out.js defines `MCapstone` (used by
    the wrapper's `MCapstone = MCapstone()`), the wrapper defines `var cs`, and
    the constants append `cs.X = ...` onto it.
    """
    parts = [
        'src/libcapstone%s.out.js' % suffix,
        'src/capstone-wrapper.js',
        'src/capstone-constants.js',
    ]
    os.makedirs('dist', exist_ok=True)
    with open('dist/capstone%s.min.js' % suffix, 'w') as out:
        for part in parts:
            with open(part) as f:
                out.write(f.read())
            out.write('\n')
    # The emitted .out.js references its .wasm by name, so keep the basenames.
    for pattern in ("src/*.wasm", "src/*.wasm.js"):
        for file in glob.glob(pattern):
            shutil.copy(file, os.path.join('dist', os.path.basename(file)))


def suffix_for(targets):
    return ('-' + '-'.join(t.lower() for t in targets)) if targets else ''


if __name__ == "__main__":
    # Initialize Capstone submodule if necessary
    if not os.listdir(CAPSTONE_DIR):
        os.system("git submodule update --init")

    if os.name not in ('nt', 'posix'):
        print("Your operating system is not supported by this script:")
        print("Please, use Emscripten to compile Capstone manually to src/libcapstone.out.js")
        sys.exit(1)

    args = sys.argv[1:]
    generateConstants()
    if '--release' in args:
        for targets in RELEASE_TARGETS:
            compileCapstone(targets)
            bundle(suffix_for(targets))
    else:
        targets = sorted(args)
        compileCapstone(targets)
        bundle(suffix_for(targets))
