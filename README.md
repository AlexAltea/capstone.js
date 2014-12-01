Capstone.js
===========
[![Last Release](https://badge.fury.io/gh/AlexAltea%2Fcapstone.js.svg)](https://github.com/AlexAltea/capstone.js/releases)

Port of the [Capstone](https://github.com/aquynh/capstone) disassembler framework for JavaScript. Powered by [Emscripten](https://github.com/kripken/emscripten).

### Deploy
To build the Capstone.js framework, clone the *master* branch of this repository, and do the following:

**1.** Install the development and client dependencies:
```
npm install
bower install
```

**2.** Install the lastest [Python 2.x (64-bit)](https://www.python.org/downloads/) and the [Emscripten SDK](http://kripken.github.io/emscripten-site/docs/getting_started/downloads.html). Follow the respective instructions and make sure all environment variables are configured correctly. The command `emcc` should launch the Emscripten C compiler.

**3.** Finally, build the source with:
```
grunt build
```
