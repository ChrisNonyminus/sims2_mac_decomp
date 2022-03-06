import os
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

# TODO: automatic offset grabbing

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
                sectionName =  data[0].sectname
                if b"text" in sectionName:
                    textOffsets.append(data[0].offset)
                    textSizes.append(data[0].size)
                    textAddresses.append(data[0].addr)
                    textNames.append(data[0].sectname)
                    textCount += 1

for i in range(0, 1):
    bin_file_path = sys.argv[2]
    bin_file = open(bin_file_path, 'wb')
    b = filecontent[textOffsets[i] : textOffsets[i] + textSizes[i]]
    bin_file.write(b)
    bin_file.close()
