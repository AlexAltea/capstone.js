#!/usr/bin/python

# INFORMATION:
# This scripts compiles the original Capstone framework to JavaScript

from __future__ import print_function
import os
import re
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
    '_cs_disasm_ex',
    '_cs_disasm_iter',
    '_cs_malloc',
    '_cs_reg_read',
    '_cs_reg_write',
    '_cs_op_count',
    '_cs_op_index',
]

EXPORTED_CONSTANTS = [
    'bindings/python/capstone/arm64_const.py',
    'bindings/python/capstone/arm_const.py',
    'bindings/python/capstone/mips_const.py',
    'bindings/python/capstone/ppc_const.py',
    'bindings/python/capstone/sparc_const.py',
    'bindings/python/capstone/sysz_const.py',
    'bindings/python/capstone/x86_const.py',
    'bindings/python/capstone/xcore_const.py',
]

AVAILABLE_TARGETS = [
    'ARM', 'ARM64', 'MIPS', 'PPC', 'SPARC', 'SYSZ', 'XCORE', 'X86'
]

# Directories
CAPSTONE_DIR = os.path.abspath("capstone")

def generateConstants():
    out = open('src/capstone-constants.js', 'w')
    for path in EXPORTED_CONSTANTS:
        path = os.path.join(CAPSTONE_DIR, path)
        with open(path, 'r') as f:
            code = f.read()
            code = re.sub('\n([^#\t\r\n ])', '\ncs.\g<1>', code)
            code = re.sub('(.* = [A-Za-z_])', '# \g<1>', code)
            code = code.replace('#', '//')
        out.write(code)
    out.close()

def compileCapstone(targets):
    # Clean CMake cache
    try:
        os.remove('capstone/CMakeCache.txt')
    except OSError:
        pass

    # CMake
    cmd = 'cmake'
    cmd += os.path.expandvars(' -DCMAKE_TOOLCHAIN_FILE=$EMSCRIPTEN/cmake/Modules/Platform/Emscripten.cmake')
    cmd += ' -DCMAKE_BUILD_TYPE=Release'
    cmd += ' -DCMAKE_C_FLAGS=\"-Wno-warn-absolute-paths\"'
    cmd += ' -DCAPSTONE_BUILD_TESTS=OFF'
    cmd += ' -DCAPSTONE_BUILD_SHARED=OFF'
    if targets:
        targets = map(lambda t: t.upper(), targets)
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
        make = 'make'
    if os.system(make) != 0:
        print("Make errored")
        sys.exit(1)
    os.chdir('..')

    # Compile static library to JavaScript
    exports = EXPORTED_FUNCTIONS[:]
    methods = [
        'ccall', 'getValue', 'setValue', 'writeArrayToMemory', 'UTF8ToString'
    ]
    cmd = os.path.expandvars('$EMSCRIPTEN/emcc')
    cmd += ' -Os --memory-init-file 0'
    cmd += ' capstone/libcapstone.a'
    cmd += ' -s EXPORTED_FUNCTIONS=\"[\''+ '\', \''.join(exports) +'\']\"'
    cmd += ' -s EXTRA_EXPORTED_RUNTIME_METHODS=\"[\''+ '\', \''.join(methods) +'\']\"'
    cmd += ' -s ALLOW_MEMORY_GROWTH=1'
    cmd += ' -s MODULARIZE=1'
    cmd += ' -s WASM=0'
    cmd += ' -s EXPORT_NAME="\'MCapstone\'"'
    if targets:
        cmd += ' -o src/libcapstone-%s.out.js' % '-'.join(targets).lower()
    else:
        cmd += ' -o src/libcapstone.out.js'
    if os.system(cmd) != 0:
        print("Emscripten errored")
        sys.exit(1)


if __name__ == "__main__":
    # Initialize Capstone submodule if necessary
    if not os.listdir(CAPSTONE_DIR):
        os.system("git submodule update --init")
    # Compile Capstone
    targets = sorted(sys.argv[1:])
    if os.name in ['nt', 'posix']:
        generateConstants()
        compileCapstone(targets)
    else:
        print("Your operating system is not supported by this script:")
        print("Please, use Emscripten to compile Capstone manually to src/libcapstone.out.js")
