Capstone.js
===========

Port of the [Capstone](https://github.com/aquynh/capstone) disassembler framework for JavaScript/WASM. Powered by [Emscripten](https://github.com/emscripten-core/emscripten).

**Notes:** _Capstone_ is a lightweight multi-architecture disassembly framework originally developed by Nguyen Anh Quynh and released under BSD license. More information about contributors and license terms can be found in the files `CREDITS.TXT` and `LICENSE.TXT` of the *capstone* submodule in this repository.

## Installation

To add Capstone.js to your web application, include it with:

```html
<script src="capstone.min.js"></script>
```

or install it with the NPM command:

```bash
npm install @alexaltea/capstone-js
```

## Usage                                                      
```javascript
// Input: Machine code bytes and offset where they are located
var buffer = [0x55, 0x31, 0xD2, 0x89, 0xE5, 0x8B, 0x45, 0x08];
var offset = 0x10000;

// WebAssembly loads asynchronously; wait for it before using Capstone
cs.MCapstone.then(function () {
    // Initialize the decoder
    var d = new cs.Capstone(cs.ARCH_X86, cs.MODE_32);

    // Output: Array of cs.Instruction objects
    var instructions = d.disasm(buffer, offset);

    // Display results;
    instructions.forEach(function (instr) {
        console.log("0x%s:\t%s\t%s",
            instr.address.toString(16),
            instr.mnemonic,
            instr.op_str
        );
    });

    // Delete decoder
    d.close();
});
```

## Building

To build the Capstone.js library, clone the *master* branch of this repository, and do the following:

1. Initialize the original Capstone submodule: `git submodule update --init`.

2. Install the latest [Python 3.x](https://www.python.org/downloads/), [CMake](http://www.cmake.org/download/) and the [Emscripten SDK](http://kripken.github.io/emscripten-site/docs/getting_started/downloads.html). Follow the respective instructions and make sure all environment variables are configured correctly. Under Windows [MinGW](http://www.mingw.org/) (specifically *mingw32-make*) is required.

3. Build the library with: `python3 build.py`. The output is written to `dist/`. Pass architecture names to produce a smaller, single-architecture bundle (e.g. `python3 build.py x86`), or `python3 build.py --release` to build every variant.

The build uses `WASM=2`: the bundle loads the `.wasm` binary when the browser supports it and transparently falls back to pure JavaScript otherwise. Because loading WebAssembly is asynchronous, wait for it before using Capstone:

```javascript
cs.MCapstone.then(() => {
    // ... initialize and use Capstone here ....
});
```
