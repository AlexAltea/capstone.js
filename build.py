#!/usr/bin/env python3

# INFORMATION:
# This scripts compiles the original Capstone framework to JavaScript.
# It is the single entry point for the build: it generates the JS constants and
# compiles Capstone with Emscripten straight to the final dist/ artifact (the
# constants and the JS wrapper are baked in via `--post-js`).

import os
import re
import subprocess
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
    """Generate src/constants_<arch>.js from Capstone's C headers (one per header).

    Each file is loaded into the module via Emscripten `--post-js` (see
    compileCapstone), so it runs with `Module` in scope and merges its constants
    directly into the module. capstone-wrapper.js (also `--post-js`) then adds the
    generic constants and the high-level API onto that same module, which becomes
    the public `cs` object.

    Adapted from capstone/bindings/const_generator.py: it parses each arch
    header's `typedef enum` / `#define` constants and resolves every value to an
    integer (mirroring that script's `swift` branch). Resolving means aliases
    such as `ARM_REG_FP = ARM_REG_R11` and expressions such as `(1ULL << 3)`
    collapse into plain integer literals. This is immune to the textual quirks
    of Capstone's pre-generated Python bindings.
    """
    for header, prefix in CONST_HEADERS:
        prefixes = []
        if isinstance(prefix, list):
            prefixes = prefix
            prefix = prefix[0].lower()

        def has_prefix(token, prefix=prefix, prefixes=prefixes):
            if prefixes:
                return any(token.startswith(p) for p in prefixes)
            return token.startswith(prefix.upper())

        out = open('src/constants_%s.js' % prefix, 'w')
        out.write('// AUTO-GENERATED, DO NOT EDIT [%s]\n' % header)
        out.write('Object.assign(Module, {\n')
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
                out.write('  %s: %d,\n' % (name, value))
        out.write('});\n')
        out.close()


def constant_files():
    """Per-arch constants files from generateConstants(), loaded via --post-js."""
    files = []
    for header, prefix in CONST_HEADERS:
        if isinstance(prefix, list):
            prefix = prefix[0].lower()
        files.append('src/constants_%s.js' % prefix)
    return files


def compileCapstone(targets):
    # Clean CMake cache
    try:
        os.remove('capstone/CMakeCache.txt')
    except OSError:
        pass

    # Configure with CMake
    cmd = [
        'emcmake', 'cmake',
        '-DCMAKE_BUILD_TYPE=Release',
        '-DCMAKE_C_FLAGS=-Wno-warn-absolute-paths',
        '-DCAPSTONE_BUILD_TESTS=OFF',
        '-DCAPSTONE_BUILD_STATIC_LIBS=ON',
        '-DCAPSTONE_BUILD_SHARED=OFF',
    ]
    if targets:
        targets = [t.upper() for t in targets]
        for arch in AVAILABLE_TARGETS:
            if arch not in targets:
                cmd.append('-DCAPSTONE_%s_SUPPORT=0' % arch)
    cmd += ['-G', 'Unix Makefiles', 'capstone/CMakeLists.txt']
    subprocess.run(cmd, check=True)

    # Build the static library
    subprocess.run(['emmake', 'make'], check=True, cwd='capstone')

    # Compile the static library to JavaScript
    methods = [
        'ccall', 'getValue', 'setValue', 'writeArrayToMemory', 'UTF8ToString'
    ]
    cmd = [
        'emcc',
        '-Os',
        'capstone/libcapstone.a',
        '-s', "EXPORTED_FUNCTIONS=[%s]" % ', '.join("'%s'" % f for f in EXPORTED_FUNCTIONS),
        '-s', "EXPORTED_RUNTIME_METHODS=[%s]" % ', '.join("'%s'" % m for m in methods),
        '-s', 'ALLOW_MEMORY_GROWTH=1',
        '-s', 'MODULARIZE=1',
        '-s', 'WASM=2',
        '-s', "EXPORT_NAME='MCapstone'",
    ]
    for path in constant_files():
        cmd += ['--post-js', path]
    cmd += ['--post-js', 'src/capstone-wrapper.js']
    os.makedirs('dist', exist_ok=True)
    cmd += ['-o', 'dist/capstone%s.js' % suffix_for(targets)]
    subprocess.run(cmd, check=True)


def suffix_for(targets):
    return ('-' + '-'.join(t.lower() for t in targets)) if targets else ''


if __name__ == "__main__":
    # Initialize Capstone submodule if necessary
    if not os.listdir(CAPSTONE_DIR):
        os.system("git submodule update --init")

    args = sys.argv[1:]
    generateConstants()
    if '--release' in args:
        for targets in RELEASE_TARGETS:
            compileCapstone(targets)
    else:
        compileCapstone(sorted(args))
