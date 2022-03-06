# sims2_mac_decomp

A WIP logically matching decompilation of The Sims 2 (Bon Voyage update, PowerPC Mac OS X port).

Very barebones, and no function is matching yet.
See the bash and python scripts.

Extract a clean ppc executable of the game (see the sha1 file for the hash) from a universal binary of BV's Mac OS X port, dated December 17, 2007 and place it in the root folder as "baserom.ppc".

To generate an asm file, type ``python3 tools/mach-disasm.py baserom.ppc baserom.sym > asm/sims2.s``.
To generate an asm file that mips_to_c can read, type ``python3 tools/mach-disasm_m2c-support.py baserom.ppc baserom.sym > asm/sims2.new-syntax.s``.

# Prerequisites:
- A special cross-compiler version of Apple's version of GCC 4.0.1 (https://github.com/ChrisNonyminus/powerpc-darwin-cross/releases/download/initial/powerpc-darwin-cross.new.zip).
- build-essential, probably
- Python 3.6 or higher.
- Python dependencies: `python3 -m pip install --user colorama watchdog python-Levenshtein capstone macholib`
- binutils-powerpc-linux-gnu.

# Decompilation Instructions
1. Pick a function from the generated asm file (must not be the mips_to_c-compatible version.
2. Extract that function into its own file, to be placed as ``tmp/orig.s``.
3. Create a cpp file and place it as ``tmp/code.cpp``.
4. In a linux shell, type and enter ``COMPILER_FLAGS="-O4" FUNCTION=[Symbol name of function] ./auto_assemble_tmp_code.sh``.
5. In a seperate text editor, edit and save ``tmp/code.cpp`` or the generated file ``tmp/compiler_flags.txt``, while the script loops. (It loops so the code can automatically be compiled every time it's changed.)
6. View ``tmp/diff.txt``.
7. Repeat steps 5 and 6 until a function is matching.
