#!/usr/bin/python

# INFORMATION:
# This scripts compiles the original Capstone framework to JavaScript

import os

EXPORTED_FUNCTIONS = [
    '_cs_open',
    '_cs_disasm',
    '_cs_free',
    '_cs_close',
    '_cs_option',
    '_cs_insn_name',
    '_cs_reg_name'
]

def compileCapstone():
    # CMake
    cmd = 'cmake'
    cmd += os.path.expandvars(' -DCMAKE_TOOLCHAIN_FILE=$EMSCRIPTEN/cmake/Modules/Platform/Emscripten.cmake')
    cmd += ' -DCMAKE_BUILD_TYPE=Release'
    cmd += ' -DCMAKE_C_FLAGS=\"-Wno-warn-absolute-paths\"'
    cmd += ' -DCAPSTONE_BUILD_TESTS=OFF'
    cmd += ' -DCAPSTONE_BUILD_SHARED=OFF'
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
    cmd += ' -O1'
    cmd += ' capstone/libcapstone.a'
    cmd += ' -s EXPORTED_FUNCTIONS=\"[\''+ '\', \''.join(EXPORTED_FUNCTIONS) +'\']\"'
    cmd += ' -o src/capstone.out.js'
    os.system(cmd)


if __name__ == "__main__":
    if os.name in ['nt', 'posix']:
        compileCapstone()        
    else:
        print "Your operating system is not supported by this script:"
        print "Please, use Emscripten to compile Capstone manually to src/capstone.out.js"
