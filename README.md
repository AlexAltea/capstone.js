Capstone.js
===========
[![Last Release](https://badge.fury.io/gh/AlexAltea%2Fcapstone.js.svg)](https://github.com/AlexAltea/capstone.js/releases)

Port of the [Capstone](https://github.com/aquynh/capstone) disassembler framework for JavaScript. Powered by [Emscripten](https://github.com/kripken/emscripten).

**Notes:** _Capstone_ is a lightweight multi-architecture disassembly framework originally developed by Nguyen Anh Quynh and released under BSD license. More information about contributors and license terms can be found in the files `CREDITS.TXT` and `LICENSE.TXT` of the *capstone* submodule in this repository.

### Deploy
To build the Capstone.js framework, clone the *master* branch of this repository, and do the following:

1. Initialize Git submodules to fetch the original Capstone repository: `git submodule update --init`.

2. Install the development and client dependencies with: `npm install` and `bower install`.

3. Install the lastest [Python 2.x (64-bit)](https://www.python.org/downloads/), [CMake](http://www.cmake.org/download/) and the [Emscripten SDK](http://kripken.github.io/emscripten-site/docs/getting_started/downloads.html). Follow the respective instructions and make sure all environment variables are configured correctly. The command `emcc` should launch the Emscripten C compiler. Under Windows [MinGW](http://www.mingw.org/) (specifically *mingw32-make*) is required.

4. Finally, build the source with: `grunt build`.
