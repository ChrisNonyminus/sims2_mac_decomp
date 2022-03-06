#!/usr/bin/env python
#
# PowerPC Mach-O file disassembler
# Usage: machdisasm.py MACHO_FILE [SYMBOL_FILE] > assembly_file.s
# To make a symbol file, type (POWERPC_DARWIN_COMPILER_PATH)/nm -g (MACHO_FILE) > (SYMBOL_FILE)
#

import os
import re
from capstone import *
from capstone.ppc import *
from macholib.mach_o import *
from macholib.MachO import *
import sys

r13_addr = None
r2_addr = None

with open(sys.argv[1], 'rb') as rawfile:
    filecontent = bytearray(rawfile.read())

def read_u8(offset):
    return filecontent[offset]

def read_u32(offset):
    return (filecontent[offset + 0] << 24) | (filecontent[offset + 1] << 16) | (filecontent[offset + 2] << 8) | filecontent[offset + 3]

def sign_extend_16(value):
    if value > 0 and (value & 0x8000):
        value -= 0x10000
    return value

def sign_extend_12(value):
    if value > 0 and (value & 0x800):
        value -= 0x1000
    return value

cmdSizes = []

segmentNames = []
segmentOffsets = []
segmentAddresses = []
textSegmentSize = None
dataSegmentAddr = None

textOffsets = []
textAddresses = []
textSizes = []
textNames = []

dataOffsets = []
dataAddresses = []
dataSizes = []
dataNames = []

bssAddress = None
bssSize = None
bssOffset = None
entryPoint = None

macho = MachO(sys.argv[1])

textCount = 0
dataCount = 0

for h in macho.headers:
    for (load_cmd, cmd, data) in h.commands:
        if data:
            if hasattr(data[0], "sectname"):
                sectionName =  data[0].segname
                if b"TEXT" in sectionName:
                    textOffsets.append(data[0].offset)
                    textSizes.append(data[0].size)
                    textAddresses.append(data[0].addr)
                    textNames.append(data[0].sectname)
                    textCount += 1
                if b"DATA" in sectionName:
                    if b"bss" in data[0].sectname:
                        continue
                    dataOffsets.append(data[0].offset)
                    dataSizes.append(data[0].size)
                    dataAddresses.append(data[0].addr)
                    dataNames.append(data[0].sectname)
                    dataCount += 1
            if hasattr(data[0], "entryoff"):
                entryPoint = data[0].entryoff

# TODO: fix the above for loop so I don't have to manually define stuff
bssAddress = 0x02b92560 # Sims 2 BV: 0x02b92560 # Halo: 0x00432a60 # Sims 2: 0x022d6638 
bssSize = 0x003027fc # Sims 2 BV: 0x003027fc # Halo: 0x000ae818 # Sims 2: 0x00278d90
bssOffset = 0x00000000
entryPoint = 0x000023b0 # Sims 2: 0x0000218C # Halo and Sims 2 BV: 0x000023b0

print('# do not assemble; for use with mips_to_c only')
print('')

labels = set()
labelNames = {}

# Add entry point
labels.add(entryPoint)
labelNames[entryPoint] = '__start'

if os.path.exists(sys.argv[2]):
    sym_file = open(sys.argv[2], 'r')
    lines = sym_file.readlines()
    for line in lines:
        x = re.match(r'([0-9a-f]*) [A-Z] (.*)', line)
        if x:
            g = x.groups()
            addr = int(g[0], 16)
            name = g[1]
            labelNames[addr] = name
            labels.add(addr)
            pass
        pass
    
    
def addr_to_label(addr):
    if addr in labels:
        if addr in labelNames:
            return labelNames[addr]
        else:
            return "lbl_%08X" % addr
    else:
        return "0x%08X" % addr

def add_label(addr, name):
    labels.add(addr)
    if name != None and not addr in labelNames:
        labelNames[addr] = name

def is_label_candidate(addr):
    for i in range(0, textCount):
        if addr >= textAddresses[i] and addr < textAddresses[i] + textSizes[i] and (addr & 3) == 0:
            return True
    for i in range(0, dataCount):
        if addr >= dataAddresses[i] and addr < dataAddresses[i] + dataSizes[i]:
            return True
    if addr >= bssAddress and addr < bssAddress + bssSize:
        return True
    return False

# TODO: find all of them
loadStoreInsns = {
    PPC_INS_LWZ,
    PPC_INS_LMW,
    PPC_INS_LHA,
    PPC_INS_LHAU,
    PPC_INS_LHZ,
    PPC_INS_LHZU,
    PPC_INS_LBZ,
    PPC_INS_LBZU,
    PPC_INS_LFD,
    PPC_INS_LFDU,
    PPC_INS_LFS,
    PPC_INS_LFSU,
    PPC_INS_STW,
    PPC_INS_STWU,
    PPC_INS_STMW,
    PPC_INS_STH,
    PPC_INS_STHU,
    PPC_INS_STB,
    PPC_INS_STBU,
    PPC_INS_STFS,
    PPC_INS_STFSU,
    PPC_INS_STFD,
    PPC_INS_STDU,
}

# Returns true if the instruction is a load or store with the given register as a base
def is_load_store_reg_offset(insn, reg):
    return insn.id in loadStoreInsns and (reg == None or insn.operands[1].mem.base == reg)

cs = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
cs.detail = True
cs.imm_unsigned = False

blacklistedInsns = {
    # Unsupported instructions
    PPC_INS_ATTN,

    # Instructions that Capstone gets wrong
    PPC_INS_MFESR, PPC_INS_MFDEAR, PPC_INS_MTESR, PPC_INS_MTDEAR, PPC_INS_MFICCR, PPC_INS_MFASR
}

# Calls callback for every instruction in the specified code section
def disasm_iter(offset, address, size, callback):
    if size == 0:
        return
    start = address
    end = address + size
    while address < end:
        code = filecontent[offset + (address-start) : offset + size]
        for insn in cs.disasm(code, address):
            address = insn.address
            if insn.id in blacklistedInsns:
                callback(address, offset + address - start, None, insn.bytes)
            else:
                callback(address, offset + address - start, insn, insn.bytes)
            address += 4
        if address < end:
            o = offset + address - start
            callback(address, offset + address - start, None, filecontent[o : o + 4])
            address += 4

lisInsns = {}  # register : insn

splitDataLoads = {}  # address of load insn (both high and low) : data

linkedInsns = {}  # addr of lis insn : ori/addi insn

# Returns true if the instruction writes to the specified register
def reg_modified(insn, reg):
    if insn.op[0].type == PPC_OP_REG and insn.op[0].reg == reg:
        return True
    else:
        return False

# Computes the combined value from a lis, addi/ori instruction pairr
def combine_split_load_value(hiLoadInsn, loLoadInsn):
    assert hiLoadInsn.id == PPC_INS_LIS
    #assert loLoadInsn.id in {PPC_INS_ADDI, PPC_INS_ORI}
    #assert loLoadInsn.operands[1].reg == hiLoadInsn.operands[0].reg
    # hiLoadInsn must be "lis rX, hiPart"
    value = hiLoadInsn.operands[1].imm << 16
    # loLoadInsn must be "addi rY, rX, loPart"
    if loLoadInsn.id == PPC_INS_ORI:
        value |= loLoadInsn.operands[2].imm
    elif loLoadInsn.id == PPC_INS_ADDI:
        value += sign_extend_16(loLoadInsn.operands[2].imm)
    elif is_load_store_reg_offset(loLoadInsn, hiLoadInsn.operands[0].reg):
        value += sign_extend_16(loLoadInsn.operands[1].mem.disp)
    else:
        assert False
    return value

def is_store_insn(insn):
    # TODO: all store instructions
    return insn.id in {PPC_INS_STW}

# Get labels
def get_label_callback(address, offset, insn, bytes):
    global r13_addr
    global r2_addr
    if insn == None:
        return
    #print("%s %s" % (insn.mnemonic, insn.op_str))
    # if branch instruction
    if insn.id in {PPC_INS_B, PPC_INS_BL, PPC_INS_BC, PPC_INS_BDZ, PPC_INS_BDNZ}:
        lisInsns.clear()
        for op in insn.operands:
            if op.type == PPC_OP_IMM:
                #print("label 0x%08X" % op.imm)
                labels.add(op.imm)
                if insn.id == PPC_INS_BL:
                    #labelNames[op.imm] = 'func_%08X' % op.imm
                    add_label(op.imm, 'func_%08X' % op.imm)

    # Detect split load (high part)
    # this is 'lis rX, hipart'
    if insn.id == PPC_INS_LIS:
        # Record instruction that loads into register with 'lis'
        lisInsns[insn.operands[0].reg] = insn
    # Detect split load (low part)
    # this is either 'addi/ori rY, rX, lopart' or 'load/store rY, lopart(rX)'
    elif (insn.id in {PPC_INS_ADDI, PPC_INS_ORI} and insn.operands[1].reg in lisInsns) \
     or  (is_load_store_reg_offset(insn, None) and insn.operands[1].mem.base in lisInsns):
        hiLoadInsn = lisInsns[insn.operands[1].reg]
        # Compute combined value
        value = combine_split_load_value(hiLoadInsn, insn)
        if is_label_candidate(value):
            labels.add(value)
        # Record linked instruction
        linkedInsns[hiLoadInsn.address] = insn
        splitDataLoads[hiLoadInsn.address] = value
        splitDataLoads[insn.address] = value
        lisInsns.pop(insn.operands[1].reg, None)
        # detect r2/r13 initialization
        if insn.id == PPC_INS_ORI and insn.operands[0].reg == insn.operands[1].reg:
            if r2_addr == None and insn.operands[0].reg == PPC_REG_R2:
                r2_addr = value
                #print('# DEBUG: set r2 to 0x%08X' % value)
            elif r13_addr == None and insn.operands[0].reg == PPC_REG_R13:
                r13_addr = value
                #print('# DEBUG: set r13 to 0x%08X' % value)
    # Remove record if register is overwritten
    elif (not is_store_insn(insn)) and len(insn.operands) >= 1 and insn.operands[0].type == PPC_OP_REG:
        lisInsns.pop(insn.operands[0].reg, None)

    # Handle r13 offset values
    if r13_addr != None:
        if insn.id == PPC_INS_ADDI and insn.operands[1].value.reg == PPC_REG_R13:  # r13 offset
            value = r13_addr + sign_extend_16(insn.operands[2].imm)
            if is_label_candidate(value):
                labels.add(value)
                #labelNames[value] = 'r13_%08X' % value
        if is_load_store_reg_offset(insn, PPC_REG_R13):
            value = r13_addr + sign_extend_16(insn.operands[1].mem.disp)
            if is_label_candidate(value):
                labels.add(value)
                #labelNames[value] = 'r13_%08X' % value

    # Handle r2 offset values
    if r2_addr != None:
        if insn.id == PPC_INS_ADDI and insn.operands[1].value.reg == PPC_REG_R2:  # r13 offset
            value = r2_addr + sign_extend_16(insn.operands[2].imm)
            if is_label_candidate(value):
                labels.add(value)
                #labelNames[value] = 'r2_%08X' % value
        if is_load_store_reg_offset(insn, PPC_REG_R2):
            value = r2_addr + sign_extend_16(insn.operands[1].mem.disp)
            if is_label_candidate(value):
                labels.add(value)
                #labelNames[value] = 'r2_%08X' % value

for i in range(0, textCount):
    if textSizes[i] != 0:
        disasm_iter(textOffsets[i], textAddresses[i], textSizes[i], get_label_callback)

# Write macros
print('# PowerPC Register Constants')
for i in range(0, 32):
    print(".set r%i,%i" % (i, i))
for i in range(0, 32):
    print(".set f%i,%i" % (i, i))
for i in range(0, 8):
    print(".set qr%i,%i" % (i, i))
if r13_addr != None:
    print('# Small Data Area (read/write) Base')
    print(".set _SDA_BASE_, 0x%08X" % r13_addr)
if r2_addr != None:
    print('# Small Data Area (read only) Base')
    print(".set _SDA2_BASE_, 0x%08X" % r2_addr)
print('')


# Converts the instruction to a string, fixing various issues with Capstone
def insn_to_text(insn, raw):
    # Probably data, not a real instruction
    if insn.id == PPC_INS_BDNZ and (insn.bytes[0] & 1):
        return None
    if insn.id in {PPC_INS_B, PPC_INS_BL, PPC_INS_BDZ, PPC_INS_BDNZ}:
        return "%s %s" % (insn.mnemonic, addr_to_label(insn.operands[0].imm))
    elif insn.id == PPC_INS_BC:
        branchPred = '+' if (insn.bytes[1] & 0x20) else ''
        if len(insn.operands) == 0:
            return '.long 0x%08X' % raw
        if insn.operands[0].type == PPC_OP_IMM:
            return "%s%s %s" % (insn.mnemonic, branchPred, addr_to_label(insn.operands[0].imm))
        elif insn.operands[1].type == PPC_OP_IMM:
            return "%s%s %s,%s" % (insn.mnemonic, branchPred, insn.reg_name(insn.operands[0].value.reg), addr_to_label(insn.operands[1].imm))
    # Handle split loads (high part)
    if insn.address in splitDataLoads and insn.id == PPC_INS_LIS:
        loLoadInsn = linkedInsns[insn.address]
        #assert loLoadInsn.id in {PPC_INS_ADDI, PPC_INS_ORI}
        value = splitDataLoads[insn.address]
        suffix = 'h' if loLoadInsn.id == PPC_INS_ORI else 'ha'
        return '%s %s, %s@%s' % (insn.mnemonic, insn.reg_name(insn.operands[0].reg), addr_to_label(value), suffix)
    # Handle split loads (low part)
    elif insn.address in splitDataLoads and insn.id in {PPC_INS_ADDI, PPC_INS_ORI}:
        value = splitDataLoads[insn.address]
        return '%s %s, %s, %s@l' % (insn.mnemonic, insn.reg_name(insn.operands[0].reg), insn.reg_name(insn.operands[1].reg), addr_to_label(value))
    elif insn.address in splitDataLoads and is_load_store_reg_offset(insn, None):
        value = splitDataLoads[insn.address]
        return '%s %s, %s@l(%s)' % (insn.mnemonic, insn.reg_name(insn.operands[0].reg), addr_to_label(value), insn.reg_name(insn.operands[1].mem.base))

    # r13 offset loads
    if r13_addr != None:
        if insn.id == PPC_INS_ADDI and insn.operands[1].reg == PPC_REG_R13:
            value = r13_addr + sign_extend_16(insn.operands[2].imm)
            if value in labels:
                return "%s %s, %s, %s-_SDA_BASE_" % (insn.mnemonic, insn.reg_name(insn.operands[0].reg), insn.reg_name(insn.operands[1].reg), addr_to_label(value))
        if is_load_store_reg_offset(insn, PPC_REG_R13):
            value = r13_addr + sign_extend_16(insn.operands[1].mem.disp)
            if value in labels:
                return "%s %s, %s-_SDA_BASE_(%s)" % (insn.mnemonic, insn.reg_name(insn.operands[0].value.reg), addr_to_label(value), insn.reg_name(insn.operands[1].mem.base))

    # r2 offset loads
    if r2_addr != None:
        if insn.id == PPC_INS_ADDI and insn.operands[1].reg == PPC_REG_R2:
            value = r2_addr + sign_extend_16(insn.operands[2].imm)
            if value in labels:
                return "%s %s, %s, %s-_SDA2_BASE_" % (insn.mnemonic, insn.reg_name(insn.operands[0].reg), insn.reg_name(insn.operands[1].reg), addr_to_label(value))
        if is_load_store_reg_offset(insn, PPC_REG_R2):
            value = r2_addr + sign_extend_16(insn.operands[1].mem.disp)
            if value in labels:
                return "%s %s, %s-_SDA2_BASE_(%s)" % (insn.mnemonic, insn.reg_name(insn.operands[0].value.reg), addr_to_label(value), insn.reg_name(insn.operands[1].mem.base))

    # Sign-extend immediate values because Capstone is an idiot and doesn't do that automatically
    if insn.id in {PPC_INS_ADDI, PPC_INS_ADDIC, PPC_INS_SUBFIC, PPC_INS_MULLI} and (insn.operands[2].imm & 0x8000):
        return "%s %s,%s,%i" % (insn.mnemonic, insn.reg_name(insn.operands[0].reg), insn.reg_name(insn.operands[1].value.reg), insn.operands[2].imm - 0x10000)
    elif (insn.id == PPC_INS_LI or insn.id == PPC_INS_CMPWI) and (insn.operands[1].imm & 0x8000):
        return "%s %s,%i" % (insn.mnemonic, insn.reg_name(insn.operands[0].reg), insn.operands[1].imm - 0x10000)
    elif (insn.id in {PPC_INS_CMPWI} and len(insn.operands) > 2) and (insn.operands[2].imm & 0x8000):
        return "%s %s,%s,%i" % (insn.mnemonic, insn.reg_name(insn.operands[0].reg), insn.reg_name(insn.operands[1].reg), insn.operands[2].imm - 0x10000)
    # cntlz -> cntlzw
    elif insn.id == PPC_INS_CNTLZW:
        return "cntlzw %s" % insn.op_str
    elif insn.id == PPC_INS_MTICCR:
        return 'mtictc %s' % insn.op_str
    # Dunno why GNU assembler doesn't accept this
    elif insn.id == PPC_INS_LMW and insn.operands[0].reg == PPC_REG_R0:
        return '.long 0x%08X  /* illegal %s %s */' % (raw, insn.mnemonic, insn.op_str)
    return '%s %s' % (insn.mnemonic, insn.op_str)

def disasm_ps(inst):
    RA = ((inst >> 16) & 0x1f)
    RB = ((inst >> 11) & 0x1f)
    FA = ((inst >> 16) & 0x1f)
    FB = ((inst >> 11) & 0x1f)
    FC = ((inst >> 6) & 0x1f)
    FD = ((inst >> 21) & 0x1f)
    FS = ((inst >> 21) & 0x1f)
    IX = ((inst >> 7) & 0x7)
    WX = ((inst >> 10) & 0x1)

    opcode = (inst >> 1) & 0x1F
    if opcode == 6:  # doesn't seem to be used
        mnemonic = 'psq_lux' if inst & 0x40 else 'psq_lx'
        return '%s f%i, r%i,  r%i,%i, qr%i' % (mnemonic, FD, RA, RB, WX, IX)
    if opcode == 7:
        mnemonic = 'psq_stux' if inst & 0x40 else 'psq_stx'
        return '%s f%i, r%i, r%i,%i, qr%i' % (mnemonic, FS, RA, RB, WX, IX)
    if opcode == 18:
        return 'ps_div f%i, f%i, f%i' % (FD, FA, FB)
    if opcode == 20:
        return 'ps_sub f%i, f%i, f%i' % (FD, FA, FB)
    if opcode == 21:
        return 'ps_add f%i, f%i, f%i' % (FD, FA, FB)
    if opcode == 23:
        return 'ps_sel f%i, f%i, f%i' % (FD, FA, FC)
    if opcode == 24:
        return 'ps_res f%i, f%i' % (FD, FB)
    if opcode == 25:
        return 'ps_mul f%i, f%i, f%i' % (FD, FA, FC)
    if opcode == 26:
        return 'ps_rsqrte f%i, f%i' % (FD, FB)
    if opcode == 28:
        return 'ps_msub f%i, f%i, f%i, f%i' % (FD, FA, FC, FB)
    if opcode == 29:
        return 'ps_madd f%i, f%i, f%i, f%i' % (FD, FA, FC, FB)
    if opcode == 30:
        return 'ps_nmsub f%i, f%i, f%i, f%i' % (FD, FA, FC, FB)
    if opcode == 31:
        return 'ps_nmadd f%i, f%i, f%i, f%i' % (FD, FA, FC, FB)
    if opcode == 10:
        return 'ps_sum0 f%i, f%i, f%i, f%i' % (FD, FA, FC, FB)
    if opcode == 11:
        return 'ps_sum1 f%i, f%i, f%i, f%i' % (FD, FA, FC, FB)
    if opcode == 12:
        return 'ps_muls0 f%i, f%i, f%i' % (FD, FA, FC)
    if opcode == 13:
        return 'ps_muls1 f%i, f%i, f%i' % (FD, FA, FC)
    if opcode == 14:
        return 'ps_madds0 f%i, f%i, f%i, f%i' % (FD, FA, FC, FB)
    if opcode == 15:
        return 'ps_madds1 f%i, f%i, f%i, f%i' % (FD, FA, FC, FB)

    opcode = (inst >> 1) & 0x3FF
    if opcode == 40:
        return 'ps_neg f%i, f%i' % (FD, FB)
    if opcode == 72:
        return 'ps_mr f%i, f%i' % (FD, FB)
    if opcode == 136:
        return 'ps_nabs f%i, f%i' % (FD, FB)
    if opcode == 264:
        return 'ps_abs f%i, f%i' % (FD, FB)
    if opcode in {0, 32, 64, 96}:
        mnemonics = ['ps_cmpu0', 'ps_cmpo0', 'ps_cmpu1', 'ps_cmpo1']
        mnemonic = mnemonics[(inst >> 6) & 3]
        i = (inst & 0x03800000) >> 23
        return '%s cr%i, f%i, f%i' % (mnemonic, i, FA, FB)
    if opcode == 528:
        return 'ps_merge00 f%i, f%i, f%i' % (FD, FA, FB)
    if opcode == 560:
        return 'ps_merge01 f%i, f%i, f%i' % (FD, FA, FB)
    if opcode == 592:
        return 'ps_merge10 f%i, f%i, f%i' % (FD, FA, FB)
    if opcode == 624:
        return 'ps_merge11 f%i, f%i, f%i' % (FD, FA, FB)
    if opcode == 1014:
        if not (inst & 0x03e00000):
            if (inst & 1) == 0:
                return 'dcbz_l r%i, r%i' % ((inst & 0x001f0000) >> 16, (inst & 0x0000f800) >> 11)
    return None

def disasm_ps_mem(inst, idx):
    RA = ((inst >> 16) & 0x1f)
    RS = ((inst >> 21) & 0x1f)
    I = ((inst >> 12) & 0x7)
    W = ((inst >> 15) & 0x1)
    disp = sign_extend_12(inst & 0xFFF)
    if idx == 56:
        mnemonic = 'psq_l'
    if idx == 57:
        mnemonic = 'psq_lu'
    if idx == 60:
        mnemonic = 'psq_st'
    if idx == 61:
        mnemonic = 'psq_stu'
    return '%s f%i,%i(r%i),%i, qr%i' % (mnemonic, RS, disp, RA, W, I)

def disasm_fcmp(inst):
    crd = (inst & 0x03800000) >> 23
    a = (inst & 0x001f0000) >> 16
    b = (inst & 0x0000f800) >> 11
    return 'fcmpo cr%i, f%i, f%i' % (crd, a, b)

def disasm_mspr(inst, mode):
    if (inst & 1):
        return None
    d = (inst & 0x03e00000) >> 21
    a = (inst & 0x001f0000) >> 16
    b = (inst & 0x0000f800) >>11
    spr = (b << 5) + a
    if mode:
        return 'mtspr 0x%X, r%i' % (spr, d)
    else:
        return 'mfspr r%i, 0x%X' % (d, spr)

def disasm_mcrxr(inst):
    if (inst & 0x007ff801):
        return None
    crd = (inst & 0x03800000) >> 23
    return 'mcrxr cr%i' % crd

# Disassemble code
def disassemble_callback(address, offset, insn, bytes):
    # Output label (if any)
    if address in labels:
        if address in labelNames:
            print("\n.global %s" % addr_to_label(address))
        print("%s:" % addr_to_label(address))
    prefixComment = '/* %08X %08X  %02X %02X %02X %02X */' % (address, offset, bytes[0], bytes[1], bytes[2], bytes[3])
    asm = None
    raw = read_u32(offset)
    if insn != None:
        asm = insn_to_text(insn, raw)
    else:  # Capstone couldn't disassemble it
        idx = (raw & 0xfc000000) >> 26
        idx2 = (raw & 0x000007fe) >> 1
        # mtspr
        if idx == 31 and idx2 == 467:
            asm = disasm_mspr(raw, 1)
        # mfspr
        elif idx == 31 and idx2 == 339:
            asm = disasm_mspr(raw, 0)
        # mcrxr
        elif idx == 31 and idx2 == 512:
            asm = disasm_mcrxr(raw)
        # fcmpo
        elif idx == 63 and idx2 == 32:
            asm = disasm_fcmp(raw)
        # Paired singles
        elif idx == 4:
            asm = disasm_ps(raw)
        elif idx in {56, 57, 60, 61}:
            asm = disasm_ps_mem(raw, idx)
    if asm == None:
        asm = '.long 0x%08X  /* unknown instruction */' % raw
    print('%s\t%s' % (prefixComment, asm))

for i in range(0, textCount):
    if textSizes[i] != 0:
        print("\n.section __TEXT,%s" % (textNames[i]))
        print(".machine ppc")
        disasm_iter(textOffsets[i], textAddresses[i], textSizes[i], disassemble_callback)


# def is_ascii(code):
#     if code >= 0x20 and code <= 0x7E:  # normal characters
#         return True
#     if code == 0x09 or code == 0x0A:  # tab, newline
#         return True
#     return False

# # reads a string starting at pos
# def read_string(data, pos):
#     text = ''
#     while pos < len(data) and is_ascii(data[pos]):
#         text += chr(data[pos])
#         pos += 1
#     if pos < len(data) and data[pos] == 0:
#         return text
#     return ''

# # escapes special characters in the string for use in a C string literal
# def escape_string(text):
#     return text.replace('\\','\\\\').replace('"','\\"').replace('\n','\\n').replace('\t','\\t')

# # returns True if value is 4-byte aligned
# def is_aligned(num):
#     return num % 4 == 0

# # returns True if value is a possible pointer
# def is_pointer(num):
#     return num >= 0x80003100 and num <= 0x802F6C80

# # returns True if all elements are zero
# def is_all_zero(arr):
#     for val in arr:
#         if val != 0:
#             return False
#     return True

# # returns string of comma-separated hex bytes
# def hex_bytes(data):
#     return ', '.join('0x%02X' % n for n in data)

# # reads a 32-bit little endian value starting at pos
# def read_u32(data, pos):
#     return (data[pos]<<8) | (data[pos+1]<<16) | (data[pos+2]<<24) | (data[pos+3])

# def convert_data(data, offset, incsize):
#     text = ''
#     if incsize == 1:
#         text += '\t.byte 0x%02X\n' % data[0]
#         return text
#     elif incsize == 2:
#         text += '\t.byte 0x%02X, 0x%02X\n' % (data[0], data[1])
#         return text
#     elif incsize == 3:
#         text += '\t.byte 0x%02X, 0x%02X, 0x%02X\n' % (data[0], data[1], data[2])
#         return text
#     size = len(data)
#     pos = 0
#     while pos < size:
#         # pad unaligned
#         pad = []
#         while not is_aligned(offset + pos) and pos < size:
#             pad.append(data[pos])
#             pos += 1
#         if pad != [] and len(pad) > 0:
#             if is_all_zero(pad):
#                 text += '\t.balign 4\n'
#             else:
#                 text += '\t.byte %s\n' % hex_bytes(pad)

#         # string?
#         string = read_string(data, pos)
#         if string != '' and len(string) > 3:
#             text += '\t.asciz "%s"\n' % escape_string(string)
#             pos += len(string) + 1
#             continue
#         if incsize == 0x1:
#             continue
#         else:
#             assert(is_aligned(offset + pos))


#         if pos + 4 <= size:
#             val = read_u32(data, pos)
#             if is_pointer(val):
#                 text += '\t.word 0x%08X  ;# ptr\n' % val
#             elif val == 0:
#                 text += '\t.word 0\n'
#             else:
#                 text += '\t.byte %s\n' % hex_bytes(data[pos:pos+4])
#             pos += 4
#     return text

# baserom_folder = 'baserom_bins/'

# if not os.path.isdir(baserom_folder):
#     os.makedirs(baserom_folder)

# # Disassemble data
# for i in range(0, dataCount):
#     offset = dataOffsets[i]
#     address = dataAddresses[i]
#     size = dataSizes[i]
#     start = address
#     end = start + size
#     if size == 0:
#         continue
#     print("\n.section __DATA,%s" % (dataNames[i]))
#     # Get a sorted list of labels in this data section
#     sectionLabels = []
#     for l in labels:
#         if l >= start and l < end:
#             sectionLabels.append(l)
#     sectionLabels.sort()
#     # Split incbins by labels
#     j = 0
#     while address < end:
#         if j < len(sectionLabels):
#             bin_file_path = 'baserom_bins/data_%08X.bin' % address
#             bin_file = open(bin_file_path, 'wb')
#             b = filecontent[offset : offset + (sectionLabels[j] - address)]
#             bin_file.write(b)
#             bin_file.close()
#             incbinSize = sectionLabels[j] - address
#             if incbinSize != 0:
#                 print("\t.incbin \"%s\"" % (bin_file_path))
#             l = addr_to_label(sectionLabels[j])
#             print(".globl %s\n%s:" % (l, l))
#             j += 1
#         offset += incbinSize
#         address += incbinSize
#     # Remove labels to avoid duplicates in case of overlap with other sections
#     for l in sectionLabels:
#         labels.remove(l)

# # Disassemble bss
# start = bssAddress
# end = bssAddress + bssSize
# address = bssAddress
# print("\n.section __DATA,__bss")
# # Get a sorted list of labels in this bss section
# sectionLabels = []
# for l in labels:
#     if l >= start and l < end:
#         sectionLabels.append(l)
# sectionLabels.sort()
# # Split incbins by labels
# j = 0
# while address < end:
#     if j < len(sectionLabels):
#         gapSize = sectionLabels[j] - address
#         l = addr_to_label(sectionLabels[j])
#         print("\t.comm %s,%d" % (l, gapSize))
#         j += 1
#     address += gapSize

# # Output linker script
# origStdout = sys.stdout
# with open('ldscript.ld', 'w') as out:
#     sys.stdout = out
#     print("ENTRY(__start)")
#     print("SECTIONS\n{")
#     print("\t__TEXT 0x%08X" % 0x1000)
#     print("\t__DATA 0x%08X" % 0x02005000)
#     print("}")
#     sys.stdout = origStdout