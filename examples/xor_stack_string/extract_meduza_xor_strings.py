import logging

from memulator import Memulator

import re
import time
import pefile as pefile
from capstone import *

logging.basicConfig(level=logging.INFO)

# This function is from @herrcore @ OALabs
# Taken from: https://research.openanalysis.net/xorstr/decryption/python/2023/06/25/xorstr.html
# Iterates through the binary and finds xor instructions, then merges these chunks together
def find_all_pxor(md: Cs, pe: pefile.PE, scan_length):
    txt_section = pe.sections[0]
    txt_data = txt_section.get_data()
    image_base = pe.OPTIONAL_HEADER.ImageBase
    section_rva = txt_section.VirtualAddress

    pxor_vpxor_vxorps_egg = rb'(\x66\x0F\xEF|\xC5\xFD\xEF|\xC5\xF8\x57)'

    chunk_offsets = []
    last_end = 0
    for m in re.finditer(pxor_vpxor_vxorps_egg, txt_data, re.DOTALL):
        xor_start = m.start()
        # Determine the instruction length
        xor_instruction = \
            list(md.disasm(txt_data[xor_start:xor_start + 10], image_base + section_rva + xor_start))[0]

        if xor_instruction.mnemonic in ('pxor', 'vpxor', 'vxorps'):
            if scan_length > xor_start:
                scan_length = xor_start
            if xor_start - scan_length < last_end:
                # Update last chunk with new end
                chunk_offsets[-1] = (chunk_offsets[-1][0], xor_start + 10)
            else:
                chunk_offsets.append((xor_start - scan_length, xor_start + 10))

            last_end = xor_start + 10

    chunks = []

    for chunk_offset in chunk_offsets:
        chunk_data = txt_data[chunk_offset[0]:chunk_offset[1]]
        chunk_instruction_address = image_base + section_rva + chunk_offset[0]
        instructions = []
        for inst in md.disasm(chunk_data, chunk_instruction_address):
            if inst.mnemonic in ('pxor', 'vpxor', 'vxorps',
                                 'mov', 'movaps', 'movdqa', 'movdqu', 'movups',
                                 'movups', 'movdqu', 'vmovdqu', 'vmovdqa',
                                 'ret', 'retn', 'sub', 'add', 'push', 'pop'):
                instructions.append(inst)
        chunks.append(instructions)

    return chunks


# This function merges found strings that are close together
def string_builder(strings):
    out = []
    last_addr = 0
    last_string = ""
    for addr, string in strings[::-1]:
        diff = last_addr - addr
        if diff <= 88 and last_string is not None:
            last_string = string + last_string
        else:
            out.append((last_addr, last_string))
            last_string = string
        last_addr = addr
    out.append((last_addr, last_string))
    return out[::-1]


# Removes duplicate strings and prints them
def print_unique_strings(strings):
    string_dict = {}
    last_string = ''
    for a, s in strings:
        if last_string != s:
            string_dict[a] = s
        last_string = s
    print(f"Found strings: {len(string_dict.keys())}\n")
    for addr, string in string_dict.items():
        print(f"{hex(addr)} {string}")

def setup_capstone():
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    md.skipdata = True
    md.syntax = CS_OPT_SYNTAX_INTEL
    return md

# xor_stack_string stealer x32 - 29cf1ba279615a9f4c31d6441dd7c93f5b8a7d95f735c0daa3cc4dbb799f66d4
#SAMPLE_PATH = "./29cf1ba279615a9f4c31d6441dd7c93f5b8a7d95f735c0daa3cc4dbb799f66d4"
#SAMPLE_PATH = "E:/re/_malware/RisePro/bin/meduza.bin"
SAMPLE_PATH = "E:/re/_malware/RisePro/bin/2cd2f077ca597ad0ef234a357ea71558d5e039da9df9958d0b8bd0efa92e74c9.bin32"

t = time.time()

# Create the memulator
emu = Memulator()

strings = []
# Hook function for collecting strings
def collect_strings(cls: Memulator, inst: CsInsn):
    global strings
    try:
        tmp = cls.get_operand_value(inst.operands[0])
        string = tmp.to_bytes(inst.operands[0].size, 'little')
        string = string.replace(b'\x00', b'')
        string = string.decode('utf-8')
        strings.append((inst.address, string))
    except:
        pass

# Add hooks for collecting strings post xor instructions
emu.add_post_instruction_hook('pxor', collect_strings)
emu.add_post_instruction_hook('vpxor', collect_strings)

pe = pefile.PE(SAMPLE_PATH)
md = setup_capstone()

setup_time = time.time() - t
t = time.time()

# Iterate over the binary and find all xor string chunks
chunks = find_all_pxor(md, pe, 0x2000)
print(f"found {len(chunks)} chunks")

chunk_time = time.time() - t
t = time.time()

# Loop over the chunks and memulate them
for chunk in chunks:
    emu.emulate_instructions(chunk)

emulation_time = time.time() - t

strings = string_builder(strings)
print(f"Strings recovered: {len(strings)}")

print_unique_strings(strings)
print()
print(f"Setup time:      {round(setup_time*1000)}ms")
print(f"Chunk time:      {round(chunk_time*1000)}ms")
print(f"Memulation time: {round(emulation_time*1000)}ms")
print("\ndone")

# found 21 chunks
# Strings recovered: 614
# Found strings: 540
#
# 0x4011c3 Coinomi\Coinomi\wallets
# 0x4012dc Coinomi
# 0x4013f6 DashCore
# 0x401503 Dash
# 0x40161d LitecoinCore
# ...
# Setup time:       159ms
# Chunk time:       617ms
# Memulation time: 1044ms
