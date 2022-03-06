#!/bin/bash

# to run type "COMPILER_PATH=<path-to-compiler> COMPILER=<cc1 or cc1plus> COMPILER_FLAGS=<flags to pass in> ./auto_assemble_tmp_code.sh"
# you must have code in ./tmp/code.c (or ./tmp/code.cpp if compiling cpp code) first, and must have orig.s containing the original assembly code you are decompiling, in proper gas 1.x syntax
# to quit type ctrl-c

if [[ "$COMPILER_PATH" == "" ]]; then
    COMPILER_PATH=/opt/powerpc-darwin-cross/bin
fi

if [[ "$COMPILER" == "" ]]; then
    COMPILER=cc1plus
fi

if [[ "$COMPILER" == "cc1" ]]; then
    m1=$(md5sum ./tmp/code.c)
fi

if [[ "$COMPILER" == "cc1plus" ]]; then
    m1=$(md5sum ./tmp/code.cpp)
fi
echo "Note: To allow for automatic diffing, this script will loop until you press CTRL+C."
while :
do
    if [[ "$COMPILER" == "cc1" ]]; then
        m2=$(md5sum ./tmp/code.c)
    fi

    if [[ "$COMPILER" == "cc1plus" ]]; then
        m2=$(md5sum ./tmp/code.cpp)
    fi
    if [ "$m1" != "$m2" ] ; then
        if [[ "$COMPILER" == "cc1" ]]; then
            ${COMPILER_PATH}/${COMPILER} ./tmp/code.c ${COMPILER_FLAGS}
        fi

        if [[ "$COMPILER" == "cc1plus" ]]; then
            ${COMPILER_PATH}/${COMPILER} ./tmp/code.cpp -I${COMPILER_PATH}/../powerpc-apple-darwin/include -I${COMPILER_PATH}/../powerpc-apple-darwin/include/c++/4.0.0 ${COMPILER_FLAGS}
        fi

        ${COMPILER_PATH}/as ./tmp/code.s -o ./tmp/code.o -V
        ${COMPILER_PATH}/as ./tmp/orig.s -o ./tmp/orig.o -V

        python3 tools/dump_macho_text.py ./tmp/code.o ./tmp/code.bin
        python3 tools/dump_macho_text.py ./tmp/orig.o ./tmp/orig.bin

        python3 tools/asm_differ/diff.py 0 --format plain > tmp/diff.txt
        m1=$m2
    fi
done