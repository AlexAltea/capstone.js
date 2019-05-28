Capstone.js
===========

Port of the [Capstone](https://github.com/aquynh/capstone) disassembler framework for JavaScript. Powered by [Emscripten](https://github.com/kripken/emscripten).

**Notes:** _Capstone_ is a lightweight multi-architecture disassembly framework originally developed by Nguyen Anh Quynh and released under BSD license. More information about contributors and license terms can be found in the files `CREDITS.TXT` and `LICENSE.TXT` of the *capstone* submodule in this repository.

## Installation
To add Capstone.js to your web application, include it with:
```html
<script src="capstone.min.js"></script>
```
or install it with the Bower command:
```bash
bower install capstonejs
```

## Usage                                                      
```javascript
// Input: Machine code bytes and offset where they are located
var buffer = [0x55, 0x31, 0xD2, 0x89, 0xE5, 0x8B, 0x45, 0x08];
var offset = 0x10000;

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
```

## Building
To build the Capstone.js library, clone the *master* branch of this repository, and do the following:

1. Initialize the original Capstone submodule: `git submodule update --init`.

2. Install the latest [Python 2.x (64-bit)](https://www.python.org/downloads/), [CMake](http://www.cmake.org/download/) and the [Emscripten SDK](http://kripken.github.io/emscripten-site/docs/getting_started/downloads.html). Follow the respective instructions and make sure all environment variables are configured correctly. Under Windows [MinGW](http://www.mingw.org/) (specifically *mingw32-make*) is required.

3. Install the development dependencies with: `npm install`.

4. Finally, build the source with: `grunt build`.

Note: To use WebAssembly, change `WASM=0` to `WASM=1` in `build.py`.

It will automatically load the `.wasm` binary, but you should wait for it to load:

```javascript
cs.MCapstone.then(() => {
    // ... initialize and use Capstone here ....
});
```
