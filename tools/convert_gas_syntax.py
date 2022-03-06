#!/usr/bin/env python3
#
# Uses regex to convert files from the old gnu assembler syntax (powerpc architecture only) to a modern one that modern binutils can assemble.
# 
# USAGE: ./convert_gas_syntax.py INPUT_ASM_FILE > OUTPUT_ASM_FILE

import re
import sys

def convert_ha16(asm_line):
    ret = re.sub(r'([abcdefghijklmnopqrstuvwxyz]*) (r[1234567890]{1,2}),ha16\((.*)\)', r'\1 \2, \3@ha', asm_line)
    return ret

def convert_lo16_2reg(asm_line):
    ret = re.sub(r'([abcdefghijklmnopqrstuvwxyz]*) (r[1234567890]{1,2}),(r[1234567890]{1,2}),lo16\((.*)\)', r'\1 \2, \3, \4@l', asm_line)
    return ret

def convert_lo16_1reg(asm_line):
    ret = re.sub(r'([abcdefghijklmnopqrstuvwxyz]*) (r[1234567890]{1,2}),lo16\((.*)\)\((r[1234567890]{1,2})\)', r'\1 \2, \3@l(\4)', asm_line)
    return ret

def convert_lo16(asm_line):
    asm_line = convert_lo16_1reg(asm_line)
    asm_line = convert_lo16_2reg(asm_line)
    return asm_line

def convert_globl(asm_line):
    ret = re.sub(r'.globl (.*)', r'.global \1', asm_line)
    return ret

def process_asm_line(asm_line):
    # only print defines and instructions
    if asm_line.startswith('\t.') is True and asm_line.startswith('\t.globl') is False:
        return ';# REDACTED'
    if asm_line.startswith('.') is True and asm_line.startswith('.globl') is False:
        return ';# REDACTED'
    return asm_line

with open(sys.argv[1], 'r') as asm_file:
    print('# PowerPC Register Constants')
    for i in range(0, 32):
        print(".set r%i,%i" % (i, i))
    for i in range(0, 32):
        print(".set f%i,%i" % (i, i))
    for i in range(0, 8):
        print(".set qr%i,%i" % (i, i))
    print(' ')
    for asm_line in asm_file.readlines():
        asm_line = process_asm_line(asm_line)
        asm_line = convert_ha16(asm_line)
        asm_line = convert_lo16(asm_line)
        asm_line = convert_globl(asm_line)
        print(asm_line)