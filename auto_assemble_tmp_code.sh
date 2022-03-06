#!/bin/bash

# to run type "FUNCTION=<function> COMPILER_PATH=<path-to-compiler> COMPILER=<cc1 or cc1plus> COMPILER_FLAGS=<flags to pass in> ./auto_assemble_tmp_code.sh"
# you must have code in ./tmp/code.c (or ./tmp/code.cpp if compiling cpp code) first, and must have orig.s containing the original assembly code you are decompiling, in proper gas 1.x syntax
# to quit type ctrl-c

if [[ "$COMPILER_PATH" == "" ]]; then
    COMPILER_PATH=/opt/powerpc-darwin-cross/bin
fi

if [[ "$COMPILER" == "" ]]; then
    COMPILER=cc1plus
fi

if [[ "$FUNCTION" == "" ]]; then
    echo "ERROR: You must define a function!"
    exit 1
fi

if [[ "$COMPILER" == "cc1" ]]; then
    m1=$(md5sum ./tmp/code.c)
fi

if [[ "$COMPILER" == "cc1plus" ]]; then
    m1=$(md5sum ./tmp/code.cpp)
fi
echo "Note: To allow for automatic diffing, this script will loop until you press CTRL+C."
m3=$(md5sum ./tmp/compiler_flags.txt)
echo $COMPILER_FLAGS > ./tmp/compiler_flags.txt
while :
do
    if [[ "$COMPILER" == "cc1" ]]; then
        m2=$(md5sum ./tmp/code.c)
    fi

    if [[ "$COMPILER" == "cc1plus" ]]; then
        m2=$(md5sum ./tmp/code.cpp)
    fi
    m4=$(md5sum ./tmp/compiler_flags.txt)
    if [ "$m1" != "$m2" ] ; then
        if [[ "$COMPILER" == "cc1" ]]; then
            ${COMPILER_PATH}/${COMPILER} ./tmp/code.c ${COMPILER_FLAGS}
        fi
        
        if [[ "$COMPILER" == "cc1plus" ]]; then
            ${COMPILER_PATH}/${COMPILER} ./tmp/code.cpp -I${COMPILER_PATH}/../powerpc-apple-darwin/include -I${COMPILER_PATH}/../powerpc-apple-darwin/include/c++/4.0.0 ${COMPILER_FLAGS}
        fi

        python3 tools/convert_gas_syntax.py ./tmp/code.s > ./tmp/code_new.s
        python3 tools/convert_gas_syntax.py ./tmp/orig.s > ./tmp/orig_new.s

        powerpc-linux-gnu-as tmp/code_new.s -o tmp/code_new.o
        powerpc-linux-gnu-as tmp/orig_new.s -o tmp/orig_new.o
        cp tmp/orig_new.o expected/tmp/code_new.o

        python3 tools/asm_differ/diff.py --format plain -o ${FUNCTION} -f tmp/code_new.o > tmp/diff.txt
        m1=$m2
    fi
    if [ "$m3" != "$m4" ] ; then
        COMPILER_FLAGS=$(cat ./tmp/compiler_flags.txt)
        if [[ "$COMPILER" == "cc1" ]]; then
            ${COMPILER_PATH}/${COMPILER} ./tmp/code.c ${COMPILER_FLAGS}
        fi
        
        if [[ "$COMPILER" == "cc1plus" ]]; then
            ${COMPILER_PATH}/${COMPILER} ./tmp/code.cpp -I${COMPILER_PATH}/../powerpc-apple-darwin/include -I${COMPILER_PATH}/../powerpc-apple-darwin/include/c++/4.0.0 ${COMPILER_FLAGS}
        fi

        python3 tools/convert_gas_syntax.py ./tmp/code.s > ./tmp/code_new.s
        python3 tools/convert_gas_syntax.py ./tmp/orig.s > ./tmp/orig_new.s

        powerpc-linux-gnu-as tmp/code_new.s -o tmp/code_new.o
        powerpc-linux-gnu-as tmp/orig_new.s -o tmp/orig_new.o
        cp tmp/orig_new.o expected/tmp/code_new.o

        python3 tools/asm_differ/diff.py --format plain -o ${FUNCTION} -f tmp/code_new.o > tmp/diff.txt
        m3=$m4
    fi
done