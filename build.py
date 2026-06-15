#!/usr/bin/env python3

import os
import re
import shutil
import subprocess
import sys

# Directories
CAPSTONE_DIR = os.path.abspath('capstone')
CAPSTONE_BUILD_DIR = os.path.join(CAPSTONE_DIR, 'build')
CAPSTONE_INCLUDE_DIR = os.path.join(CAPSTONE_DIR, 'include', 'capstone')

EXPORTED_FUNCTIONS = [
    '_cs_close',
    '_cs_disasm_iter',
    '_cs_disasm',
    '_cs_errno',
    '_cs_free',
    '_cs_group_name',
    '_cs_insn_group',
    '_cs_insn_name',
    '_cs_malloc',
    '_cs_op_count',
    '_cs_op_index',
    '_cs_open',
    '_cs_option',
    '_cs_reg_name',
    '_cs_reg_read',
    '_cs_reg_write',
    '_cs_regs_access',
    '_cs_strerror',
    '_cs_support',
    '_cs_version',
    '_free',
    '_malloc',
]

AVAILABLE_ARCHITECTURES = [
    'ARM', 'ARM64', 'BPF', 'EVM', 'M680X', 'M68K', 'MIPS', 'MOS65XX',
    'PPC', 'RISCV', 'SH', 'SPARC', 'SYSZ', 'TMS320C64X', 'TRICORE',
    'WASM', 'X86', 'XCORE'
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

        out = open(f'src/constants_{prefix}.js', 'w')
        out.write(f'// AUTO-GENERATED, DO NOT EDIT [{header}]\n')
        out.write('Object.assign(Module, {\n')
        values = dict(CS_OP_SEED)  # running namespace for value resolution
        count = 0
        for line in open(os.path.join(CAPSTONE_INCLUDE_DIR, header)):
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
                exec(f'{name} = {value}', None, values)
                out.write(f'  {name}: {value},\n')
        out.write('});\n')
        out.close()


def constant_files(archs):
    """Per-arch constants files from generateConstants(), loaded via --post-js."""
    wanted = {a.lower() for a in archs} if archs else None
    files = []
    for header, prefix in CONST_HEADERS:
        if isinstance(prefix, list):
            prefix = prefix[0].lower()
        if wanted and prefix not in wanted:
            continue
        files.append(f'src/constants_{prefix}.js')
    return files


def suffix_for(archs):
    """Generates suffixes for the final bundle, e.g. '-x86' in capstone-x86.js."""
    return ('_' + '+'.join(a.lower() for a in archs)) if archs else ''


def compileCapstone(archs=[], diet=False):
    archs = [a.upper() for a in archs]
    shutil.rmtree(CAPSTONE_BUILD_DIR, ignore_errors=True)

    # Configure with CMake
    cmd = [
        'emcmake', 'cmake',
        '-S', CAPSTONE_DIR,
        '-B', CAPSTONE_BUILD_DIR,
        '-G', 'Unix Makefiles',
        '-DCMAKE_BUILD_TYPE=Release',
        '-DCMAKE_C_FLAGS=-Wno-warn-absolute-paths',
        '-DCAPSTONE_BUILD_STATIC_LIBS=ON',
        '-DCAPSTONE_BUILD_SHARED_LIBS=OFF',
        '-DCAPSTONE_BUILD_TESTS=OFF',
        '-DCAPSTONE_BUILD_CSTOOL=OFF',
    ]
    for a in AVAILABLE_ARCHITECTURES:
        if archs and a not in archs:
            cmd.append(f'-DCAPSTONE_{a}_SUPPORT=0')
    subprocess.run(cmd, check=True)

    # Build the static library
    jobs = os.cpu_count() or 1
    cmd = ['emmake', 'make', f'-j{jobs}']
    subprocess.run(cmd, check=True, cwd=CAPSTONE_BUILD_DIR)

    # Port the static library to JavaScript/WASM
    methods = [
        'ccall', 'getValue', 'setValue', 'writeArrayToMemory', 'UTF8ToString'
    ]
    cmd = [
        'emcc',
        '-Os',
        os.path.join(CAPSTONE_BUILD_DIR, 'libcapstone.a'),
        '-s', f"EXPORTED_FUNCTIONS={EXPORTED_FUNCTIONS}",
        '-s', f"EXPORTED_RUNTIME_METHODS={methods}",
        '-s', 'ALLOW_MEMORY_GROWTH=1',
        '-s', 'MODULARIZE=1',
        '-s', 'WASM=1',
        '-s', 'WASM_BIGINT=1',
        '-s', "EXPORT_NAME='MCapstone'",
    ]
    for path in constant_files(archs):
        cmd += ['--post-js', path]
    cmd += ['--post-js', 'src/capstone-wrapper.js']
    cmd += ['-o', f'dist/capstone{suffix_for(archs)}.js']
    os.makedirs('dist', exist_ok=True)
    subprocess.run(cmd, check=True)


if __name__ == "__main__":
    # Initialize Capstone submodule if necessary
    if not os.listdir(CAPSTONE_DIR):
        os.system("git submodule update --init")

    args = sys.argv[1:]
    diet = '--diet' in args
    generateConstants()
    if '--release' in args:
        compileCapstone([], diet) # Build all
        for arch in AVAILABLE_ARCHITECTURES:
            compileCapstone([arch], diet)
    else:
        archs = sorted([a for a in args if not a.startswith('--')])
        compileCapstone(archs, diet)
