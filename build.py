#!/usr/bin/python

# INFORMATION:
# This scripts compiles the original Capstone framework to JavaScript

import os
import sys

EXPORTED_FUNCTIONS = [
    '_cs_open',
    '_cs_disasm',
    '_cs_free',
    '_cs_close',
    '_cs_option',
    '_cs_insn_name',
    '_cs_reg_name'
]

AVAILABLE_TARGETS = [
    'ARM', 'ARM64', 'MIPS', 'PPC', 'SPARC', 'SYSZ', 'XCORE', 'X86'
]

# Directories
CAPSTONE_DIR = os.path.abspath("capstone")

def compileCapstone(targets):
	# Clean CMake cache
    if os.name == 'nt':
        os.system('del capstone\\CMakeCache.txt')
    if os.name == 'posix':
        os.system('rm capstone/CMakeCache.txt')

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
    os.system(cmd)

    # MinGW (Windows) or Make (Linux/Unix)
    os.chdir('capstone')
    if os.name == 'nt':
        os.system('mingw32-make')
    if os.name == 'posix':
        os.system('make')
    os.chdir('..')

    # Compile static library to JavaScript
    cmd = os.path.expandvars('$EMSCRIPTEN/emcc')
    cmd += ' -Os --memory-init-file 0'
    cmd += ' capstone/libcapstone.a'
    cmd += ' -s EXPORTED_FUNCTIONS=\"[\''+ '\', \''.join(EXPORTED_FUNCTIONS) +'\']\"'
    cmd += ' -s MODULARIZE=1'
    cmd += ' -s EXPORT_NAME="\'MCapstone\'"'
    cmd += ' -o src/libcapstone.out.js'
    if targets:
        cmd += ' -o src/libcapstone-%s.out.js' % ('-'.join(targets))
    else:
        cmd += ' -o src/libcapstone.out.js'
    os.system(cmd)


if __name__ == "__main__":
    # Initialize Capstone submodule if necessary
    if not os.listdir(CAPSTONE_DIR):
        os.system("git submodule update --init")
    # Compile Capstone
    targets = sorted(sys.argv[1:])
    if os.name in ['nt', 'posix']:
        compileCapstone(targets)
    else:
        print "Your operating system is not supported by this script:"
        print "Please, use Emscripten to compile Capstone manually to src/libcapstone.out.js"
