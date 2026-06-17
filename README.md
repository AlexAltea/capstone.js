Capstone.js
===========

Port of the [Capstone](https://github.com/aquynh/capstone) disassembler framework for JavaScript/WASM. Powered by [Emscripten](https://github.com/emscripten-core/emscripten).

**Requirements:** JavaScript environment with [WebAssembly](https://developer.mozilla.org/en-US/docs/WebAssembly) and [BigInt](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt) support.

**Notes:** _Capstone_ is a lightweight multi-architecture disassembly framework originally developed by Nguyen Anh Quynh and released under BSD license. More information about contributors and license terms can be found in the files `CREDITS.TXT` and `LICENSE.TXT` of the *capstone* submodule in this repository.

## Installation

To use Capstone.js in your web application, download and include it with:

```html
<script src="capstone.js"></script>
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

MCapstone().then((cs) => {
    // Initialize the decoder
    var d = new cs.Capstone(cs.ARCH_X86, cs.MODE_32);

    // Output: Array of cs.Instruction objects
    var instructions = d.disasm(buffer, offset);

    // Display results
    instructions.forEach((instr) => {
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

To build the Capstone.js library:

1. Clone this repository including its submodules:
    ```bash
    git clone --recursive https://github.com/AlexAltea/capstone.js
    ```

2. Install the latest [Python 3.x](https://www.python.org/downloads/), [CMake](http://www.cmake.org/download/) and the [Emscripten SDK](https://emscripten.org/docs/getting_started/downloads.html). Follow the corresponding instructions and make sure all environment variables are configured correctly.

3. Run the build script:
   ```bash
   python3 build.py
   ```

Build artifacts will be saved to [`dist`](./dist/).

> [!TIP]
> Pass architecture names to produce a smaller, single-architecture bundle (e.g. `python3 build.py x86`), or `python3 build.py --release` to build every variant.
