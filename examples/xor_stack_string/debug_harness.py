import logging
from memulator import Memulator
from capstone import *

logging.basicConfig(level=logging.DEBUG)


def setup_capstone():
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    md.skipdata = True
    md.syntax = CS_OPT_SYNTAX_INTEL
    return md


strings = []


# Hook function for collecting strings
def collect_strings(cls: Memulator, inst: CsInsn):
    global strings
    try:
        tmp = cls.get_operand_value(inst.operands[0])
        string = tmp.to_bytes(inst.operands[0].size, 'little')
        string = string.replace(b'\x00', b'')
        # string = string.decode('utf-8')
        strings.append((inst.address, string))
    except:
        pass

addr = 0x0045A09C
data = "be95e0ca52b854ce6937c7442440ebc2ea43894424488d8c24d001000089442418baf0054f00c74424448f2707468d4424408" \
       "974244cc7442410b7928636c7442414e84e69358974241c0f284c2410660fef4c2440500f294c2444e86b2cfbff83bc24e801" \
       "0000108d8424d4010000590f438424d00100006a0050ffd7c74424546400000085c00f84a3060000a12c064f0033d28b0d280" \
       "64f002bc18954240c99f77c2454c64424090085c00f844b06000089b424fc00000033f6c78424f0000000b7928636c78424f4" \
       "000000e84e6935c78424f800000054ce6937897424508d414c03c68d8c24a001000050e83915fbffa128064f008d8c24d8000" \
       "00083c03403c650e82215fbffa128064f008d8c245801000083c01c03c650e80b15fbffa128064f008d8c247001000083c004" \
       "03c650e8f414fbffa128064f008d9424d0010000c7442440eb928636c7442444e84e6935c744244854ce69378a4c06018a040" \
       "6c744244c95e0ca520f28442440660fef8424f0000000"

data = bytes.fromhex(data)

# Create the memulator
emu = Memulator()

emu.add_post_instruction_hook('pxor', collect_strings)

md = setup_capstone()

chunk = []

for inst in md.disasm(data, addr):
    if inst.mnemonic in ('pxor', 'vpxor', 'vxorps',
                         'mov', 'movaps', 'movdqa', 'movdqu', 'movups',
                         'movups', 'movdqu', 'vmovdqu', 'vmovdqa',
                         'ret', 'retn', 'sub', 'add', 'push', 'pop'):
        chunk.append(inst)

emu.emulate_instructions(chunk)


# This function merges found strings that are close together
def string_builder(strings):
    out = []
    last_addr = 0
    last_string = b""
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
    last_string = b''
    for a, s in strings:
        if last_string != s:
            string_dict[a] = s
        last_string = s
    print(f"Found strings: {len(string_dict.keys())}\n")
    for addr, string in string_dict.items():
        print(f"{hex(addr)} {string}")


strings = string_builder(strings)
print(f"Strings recovered: {len(strings)}")

print_unique_strings(strings)

# ======================================================================================================================
# .text:0045A09C BE 95 E0 CA 52                                mov     esi, 52CAE095h
# .text:0045A0A1
# .text:0045A0A1                               loc_45A0A1:                             ; CODE XREF: sub_459ED0+96↑j
# .text:0045A0A1 B8 54 CE 69 37                                mov     eax, 3769CE54h
# .text:0045A0A6 C7 44 24 40 EB C2 EA 43                       mov     dword ptr [esp+40h], 43EAC2EBh
# .text:0045A0AE 89 44 24 48                                   mov     [esp+48h], eax
# .text:0045A0B2 8D 8C 24 D0 01 00 00                          lea     ecx, [esp+1D0h] ; void *
# .text:0045A0B9 89 44 24 18                                   mov     [esp+18h], eax
# .text:0045A0BD BA F0 05 4F 00                                mov     edx, offset unk_4F05F0 ; Src
# .text:0045A0C2 C7 44 24 44 8F 27 07 46                       mov     dword ptr [esp+44h], 4607278Fh
# .text:0045A0CA 8D 44 24 40                                   lea     eax, [esp+40h]
# .text:0045A0CE 89 74 24 4C                                   mov     [esp+4Ch], esi
# .text:0045A0D2 C7 44 24 10 B7 92 86 36                       mov     dword ptr [esp+10h], 368692B7h
# .text:0045A0DA C7 44 24 14 E8 4E 69 35                       mov     dword ptr [esp+14h], 35694EE8h
# .text:0045A0E2 89 74 24 1C                                   mov     [esp+1Ch], esi
# .text:0045A0E6 0F 28 4C 24 10                                movaps  xmm1, xmmword ptr [esp+10h]
# .text:0045A0EB 66 0F EF 4C 24 40                             pxor    xmm1, xmmword ptr [esp+40h]
# .text:0045A0F1 50                                            push    eax             ; void *
# .text:0045A0F2 0F 29 4C 24 44                                movaps  xmmword ptr [esp+44h], xmm1
# .text:0045A0F7 E8 6B 2C FB FF                                call    sub_40CD67
# .text:0045A0FC 83 BC 24 E8 01 00 00 10                       cmp     [esp+324h+var_13C], 10h
# .text:0045A104 8D 84 24 D4 01 00 00                          lea     eax, [esp+324h+var_150]
# .text:0045A10B 59                                            pop     ecx
# .text:0045A10C 0F 43 84 24 D0 01 00 00                       cmovnb  eax, [esp+320h+var_150]
# .text:0045A114 6A 00                                         push    0               ; lpSecurityAttributes
# .text:0045A116 50                                            push    eax             ; lpPathName
# .text:0045A117 FF D7                                         call    edi ; CreateDirectoryA
# .text:0045A119 C7 44 24 54 64 00 00 00                       mov     [esp+320h+var_2CC], 64h ; 'd'
# .text:0045A121 85 C0                                         test    eax, eax
# .text:0045A123 0F 84 A3 06 00 00                             jz      loc_45A7CC
# .text:0045A129 A1 2C 06 4F 00                                mov     eax, dword_4F062C
# .text:0045A12E 33 D2                                         xor     edx, edx
# .text:0045A130 8B 0D 28 06 4F 00                             mov     ecx, dword_4F0628
# .text:0045A136 2B C1                                         sub     eax, ecx
# .text:0045A138 89 54 24 0C                                   mov     [esp+0Ch], edx
# .text:0045A13C 99                                            cdq
# .text:0045A13D F7 7C 24 54                                   idiv    dword ptr [esp+54h]
# .text:0045A141 C6 44 24 09 00                                mov     byte ptr [esp+9], 0
# .text:0045A146 85 C0                                         test    eax, eax
# .text:0045A148 0F 84 4B 06 00 00                             jz      loc_45A799
# .text:0045A14E 89 B4 24 FC 00 00 00                          mov     [esp+0FCh], esi
# .text:0045A155 33 F6                                         xor     esi, esi
# .text:0045A157 C7 84 24 F0 00 00 00 B7 92 86+                mov     dword ptr [esp+0F0h], 368692B7h
# .text:0045A157 36
# .text:0045A162 C7 84 24 F4 00 00 00 E8 4E 69+                mov     dword ptr [esp+0F4h], 35694EE8h
# .text:0045A162 35
# .text:0045A16D C7 84 24 F8 00 00 00 54 CE 69+                mov     dword ptr [esp+0F8h], 3769CE54h
# .text:0045A16D 37
# .text:0045A178 89 74 24 50                                   mov     [esp+320h+var_2D0], esi
# .text:0045A17C
# .text:0045A17C                               loc_45A17C:                             ; CODE XREF: sub_459ED0+8BE↓j
# .text:0045A17C 8D 41 4C                                      lea     eax, [ecx+4Ch]
# .text:0045A17F 03 C6                                         add     eax, esi
# .text:0045A181 8D 8C 24 A0 01 00 00                          lea     ecx, [esp+320h+var_180] ; void *
# .text:0045A188 50                                            push    eax             ; Src
# .text:0045A189 E8 39 15 FB FF                                call    sub_40B6C7
# .text:0045A18E A1 28 06 4F 00                                mov     eax, dword_4F0628
# .text:0045A193 8D 8C 24 D8 00 00 00                          lea     ecx, [esp+320h+lpFileName] ; void *
# .text:0045A19A 83 C0 34                                      add     eax, 34h ; '4'
# .text:0045A19D 03 C6                                         add     eax, esi
# .text:0045A19F 50                                            push    eax             ; Src
# .text:0045A1A0 E8 22 15 FB FF                                call    sub_40B6C7
# .text:0045A1A5 A1 28 06 4F 00                                mov     eax, dword_4F0628
# .text:0045A1AA 8D 8C 24 58 01 00 00                          lea     ecx, [esp+320h+var_1C8] ; void *
# .text:0045A1B1 83 C0 1C                                      add     eax, 1Ch
# .text:0045A1B4 03 C6                                         add     eax, esi
# .text:0045A1B6 50                                            push    eax             ; Src
# .text:0045A1B7 E8 0B 15 FB FF                                call    sub_40B6C7
# .text:0045A1BC A1 28 06 4F 00                                mov     eax, dword_4F0628
# .text:0045A1C1 8D 8C 24 70 01 00 00                          lea     ecx, [esp+320h+var_1B0] ; void *
# .text:0045A1C8 83 C0 04                                      add     eax, 4
# .text:0045A1CB 03 C6                                         add     eax, esi
# .text:0045A1CD 50                                            push    eax             ; Src
# .text:0045A1CE E8 F4 14 FB FF                                call    sub_40B6C7
# .text:0045A1D3 A1 28 06 4F 00                                mov     eax, dword_4F0628
# .text:0045A1D8 8D 94 24 D0 01 00 00                          lea     edx, [esp+1D0h] ; Src
# .text:0045A1DF C7 44 24 40 EB 92 86 36                       mov     dword ptr [esp+40h], 368692EBh
# .text:0045A1E7 C7 44 24 44 E8 4E 69 35                       mov     dword ptr [esp+44h], 35694EE8h
# .text:0045A1EF C7 44 24 48 54 CE 69 37                       mov     dword ptr [esp+48h], 3769CE54h
# .text:0045A1F7 8A 4C 06 01                                   mov     cl, [esi+eax+1]
# .text:0045A1FB 8A 04 06                                      mov     al, [esi+eax]
# .text:0045A1FE C7 44 24 4C 95 E0 CA 52                       mov     dword ptr [esp+4Ch], 52CAE095h
# .text:0045A206 0F 28 44 24 40                                movaps  xmm0, xmmword ptr [esp+40h]
# .text:0045A20B 66 0F EF 84 24 F0 00 00 00                    pxor    xmm0, xmmword ptr [esp+0F0h] ; <----- HERE
# ======================================================================================================================
