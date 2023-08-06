# A simple harness used to show the output of the XOR stack string example
# https://github.com/JustasMasiulis/xorstr was the library used to generate the xor strings within this sample

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


addr = 0x401050
data = "558bec83e4c081ecc0000000c744243885f8f41ec744243cb69031438b4424388b4c243c89842480000000898c2484000000c7442438a015848ac744243c888a9f678b4424388b4c243c89842488000000898c248c000000c7442438cd9d9872c744243cd9b0662c8b4424388b4c243c89442440c7442438d279e0ab894c2444c744243c888a9f678b4424388b4c243c894424488d842480000000894c244c0f284c2440660fef8c24800000005068003140000f298c2488000000e800ffffffc744244081d2d635c744244495ff286b8b4424408b4c244489842488000000898c248c000000c74424409e36aeecc7442444c4c5d1208b4424408b4c244489842490000000898c2494000000c74424408f2f9fe0c7442444d33130388b4424408b4c244489842498000000898c249c000000c74424408421f9aac744244492bf09568b4424408b4c2444898424a0000000898c24a4000000c7442440cd9d9872c7442444d9b0662c8b4424408b4c2444c7442440d279e0abc7442444888a9f67894424488b442440894c244c8b4c2444c74424408f2f9fe0c7442444d3313038894424508b442440894c24548b4c2444c74424408421f9aac744244492bf0956894424588b442440894c245c8b4c24440f288c2488000000660fef4c244889442460894c24640f298c24880000008d8424880000000f288c2498000000660fef4c24585068143140000f298c24a0000000e8aafdffffc74424489bd8ca2bc744244c95ff286b8b4424488b4c244c89842490000000898c2494000000c7442448843cb2f2c744244cc4c5d1208b4424488b4c244c89842498000000898c249c000000c7442448d96acdb9c744244c9f7e7e7f8b4424488b4c244c898424a0000000898c24a4000000c7442448d264abf3c744244cdef047118b4424488b4c244c898424a8000000898c24ac000000c744244871cd25bbc744244c9d32a6018b4424488b4c244c898424b0000000898c24b4000000c74424487607aeb7c744244cbcd94ba98b4424488b4c244c898424b8000000898c24bc000000c7442448cd9d9872c744244cd9b0662c8b4424488b4c244cc7442448d279e0abc744244c888a9f67894424508b442448894c24548b4c244cc74424488f2f9fe0c744244cd3313038894424588b442448894c245c8b4c244cc74424488421f9aac744244c92bf0956894424608b442448894c24648b4c244cc744244871cd25bbc744244c9d32a601894424688b442448894c246c8b4c244cc74424487607aeb7c744244cbcd94ba9894424708b442448894c24748b4c244c0f288c249000000089442478894c247c660fef4c24508d8424900000000f298c24900000000f288c24a0000000660fef4c24600f298c24a00000000f288c24b0000000660fef4c247050682c3140000f298c24b8000000e8b2fbffffc744245081d2d635c744245490e32e608b4424508b4c245489842498000000898c249c000000c74424509d37a7e2c7442454dbc2d3288b4424508b4c2454898424a0000000898c24a4000000c7442450c168d6b3c74424549b3130388b4424508b4c2454898424a8000000898c24ac000000c74424508421f9aac744245492bf09568b4424508b4c2454898424b0000000898c24b4000000c7442450cd9d9872c7442454d9b0662c8b4424508b4c2454c7442450d279e0abc7442454888a9f67894424588b442450894c245c8b4c2454c74424508f2f9fe0c7442454d3313038894424608b442450894c24648b4c245489442468c74424508421f9aa894c246cc744245492bf09568b4424508b4c24540f288c2498000000660fef4c2458894424708d8424980000000f298c24980000000f288c24a8000000894c2474660fef4c24685068543140000f298c24b0000000e85cfaffff83c42033c08be55dc3"
data = bytes.fromhex(data)

# Create the memulator
emu = Memulator()

# Hook function for collecting strings
strings = []


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


emu.add_post_instruction_hook('pxor', collect_strings)

md = setup_capstone()

chunk = []

for inst in md.disasm(data, addr):
    if inst.mnemonic in ('pxor', 'vpxor', 'vxorps', 'call',
                         'mov', 'movaps', 'movdqa', 'movdqu', 'movups',
                         'movups', 'movdqu', 'vmovdqu', 'vmovdqa',
                         'ret', 'retn', 'sub', 'add', 'push', 'pop'):
        chunk.append(inst)

emu.emulate_instructions(chunk)


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


strings = string_builder(strings)
print(f"Strings recovered: {len(strings)}")

print_unique_strings(strings)

# Assembly of the example we are extracting the strings from
# ======================================================================================================================
# .text:00401050 55                                            push    ebp
# .text:00401051 8B EC                                         mov     ebp, esp
# .text:00401053 83 E4 C0                                      and     esp, 0FFFFFFC0h
# .text:00401056 81 EC C0 00 00 00                             sub     esp, 0C0h
# .text:0040105C C7 44 24 38 85 F8 F4 1E                       mov     [esp+0C0h+var_88], 1EF4F885h
# .text:00401064 C7 44 24 3C B6 90 31 43                       mov     [esp+0C0h+var_84], 433190B6h
# .text:0040106C 8B 44 24 38                                   mov     eax, [esp+0C0h+var_88]
# .text:00401070 8B 4C 24 3C                                   mov     ecx, [esp+0C0h+var_84]
# .text:00401074 89 84 24 80 00 00 00                          mov     dword ptr [esp+0C0h+var_40], eax
# .text:0040107B 89 8C 24 84 00 00 00                          mov     dword ptr [esp+0C0h+var_40+4], ecx
# .text:00401082 C7 44 24 38 A0 15 84 8A                       mov     [esp+0C0h+var_88], 8A8415A0h
# .text:0040108A C7 44 24 3C 88 8A 9F 67                       mov     [esp+0C0h+var_84], 679F8A88h
# .text:00401092 8B 44 24 38                                   mov     eax, [esp+0C0h+var_88]
# .text:00401096 8B 4C 24 3C                                   mov     ecx, [esp+0C0h+var_84]
# .text:0040109A 89 84 24 88 00 00 00                          mov     dword ptr [esp+0C0h+var_40+8], eax
# .text:004010A1 89 8C 24 8C 00 00 00                          mov     dword ptr [esp+0C0h+var_40+0Ch], ecx
# .text:004010A8 C7 44 24 38 CD 9D 98 72                       mov     [esp+0C0h+var_88], 72989DCDh
# .text:004010B0 C7 44 24 3C D9 B0 66 2C                       mov     [esp+0C0h+var_84], 2C66B0D9h
# .text:004010B8 8B 44 24 38                                   mov     eax, [esp+0C0h+var_88]
# .text:004010BC 8B 4C 24 3C                                   mov     ecx, [esp+0C0h+var_84]
# .text:004010C0 89 44 24 40                                   mov     dword ptr [esp+0C0h+var_80], eax
# .text:004010C4 C7 44 24 38 D2 79 E0 AB                       mov     [esp+0C0h+var_88], 0ABE079D2h
# .text:004010CC 89 4C 24 44                                   mov     dword ptr [esp+0C0h+var_80+4], ecx
# .text:004010D0 C7 44 24 3C 88 8A 9F 67                       mov     [esp+0C0h+var_84], 679F8A88h
# .text:004010D8 8B 44 24 38                                   mov     eax, [esp+0C0h+var_88]
# .text:004010DC 8B 4C 24 3C                                   mov     ecx, [esp+0C0h+var_84]
# .text:004010E0 89 44 24 48                                   mov     dword ptr [esp+0C0h+var_80+8], eax
# .text:004010E4 8D 84 24 80 00 00 00                          lea     eax, [esp+0C0h+var_40]
# .text:004010EB 89 4C 24 4C                                   mov     dword ptr [esp+0C0h+var_80+0Ch], ecx
# .text:004010EF 0F 28 4C 24 40                                movaps  xmm1, [esp+0C0h+var_80]
# .text:004010F4 66 0F EF 8C 24 80 00 00 00                    pxor    xmm1, [esp+0C0h+var_40]
# .text:004010FD 50                                            push    eax
# .text:004010FE 68 00 31 40 00                                push    offset _Format  ; "Hello World! : %s\n"
# .text:00401103 0F 29 8C 24 88 00 00 00                       movaps  [esp+0C8h+var_40], xmm1
# .text:0040110B E8 00 FF FF FF                                call    _printf
# .text:00401110 C7 44 24 40 81 D2 D6 35                       mov     [esp+0C8h+var_88], 35D6D281h
# .text:00401118 C7 44 24 44 95 FF 28 6B                       mov     [esp+0C8h+var_84], 6B28FF95h
# .text:00401120 8B 44 24 40                                   mov     eax, [esp+0C8h+var_88]
# .text:00401124 8B 4C 24 44                                   mov     ecx, [esp+0C8h+var_84]
# .text:00401128 89 84 24 88 00 00 00                          mov     dword ptr [esp+0C8h+var_40], eax
# .text:0040112F 89 8C 24 8C 00 00 00                          mov     dword ptr [esp+0C8h+var_40+4], ecx
# .text:00401136 C7 44 24 40 9E 36 AE EC                       mov     [esp+0C8h+var_88], 0ECAE369Eh
# .text:0040113E C7 44 24 44 C4 C5 D1 20                       mov     [esp+0C8h+var_84], 20D1C5C4h
# .text:00401146 8B 44 24 40                                   mov     eax, [esp+0C8h+var_88]
# .text:0040114A 8B 4C 24 44                                   mov     ecx, [esp+0C8h+var_84]
# .text:0040114E 89 84 24 90 00 00 00                          mov     dword ptr [esp+0C8h+var_40+8], eax
# .text:00401155 89 8C 24 94 00 00 00                          mov     dword ptr [esp+0C8h+var_40+0Ch], ecx
# .text:0040115C C7 44 24 40 8F 2F 9F E0                       mov     [esp+0C8h+var_88], 0E09F2F8Fh
# .text:00401164 C7 44 24 44 D3 31 30 38                       mov     [esp+0C8h+var_84], 383031D3h
# .text:0040116C 8B 44 24 40                                   mov     eax, [esp+0C8h+var_88]
# .text:00401170 8B 4C 24 44                                   mov     ecx, [esp+0C8h+var_84]
# .text:00401174 89 84 24 98 00 00 00                          mov     dword ptr [esp+0C8h+var_30], eax
# .text:0040117B 89 8C 24 9C 00 00 00                          mov     dword ptr [esp+0C8h+var_30+4], ecx
# .text:00401182 C7 44 24 40 84 21 F9 AA                       mov     [esp+0C8h+var_88], 0AAF92184h
# .text:0040118A C7 44 24 44 92 BF 09 56                       mov     [esp+0C8h+var_84], 5609BF92h
# .text:00401192 8B 44 24 40                                   mov     eax, [esp+0C8h+var_88]
# .text:00401196 8B 4C 24 44                                   mov     ecx, [esp+0C8h+var_84]
# .text:0040119A 89 84 24 A0 00 00 00                          mov     dword ptr [esp+0C8h+var_30+8], eax
# .text:004011A1 89 8C 24 A4 00 00 00                          mov     dword ptr [esp+0C8h+var_30+0Ch], ecx
# .text:004011A8 C7 44 24 40 CD 9D 98 72                       mov     [esp+0C8h+var_88], 72989DCDh
# .text:004011B0 C7 44 24 44 D9 B0 66 2C                       mov     [esp+0C8h+var_84], 2C66B0D9h
# .text:004011B8 8B 44 24 40                                   mov     eax, [esp+0C8h+var_88]
# .text:004011BC 8B 4C 24 44                                   mov     ecx, [esp+0C8h+var_84]
# .text:004011C0 C7 44 24 40 D2 79 E0 AB                       mov     [esp+0C8h+var_88], 0ABE079D2h
# .text:004011C8 C7 44 24 44 88 8A 9F 67                       mov     [esp+0C8h+var_84], 679F8A88h
# .text:004011D0 89 44 24 48                                   mov     dword ptr [esp+0C8h+var_80], eax
# .text:004011D4 8B 44 24 40                                   mov     eax, [esp+0C8h+var_88]
# .text:004011D8 89 4C 24 4C                                   mov     dword ptr [esp+0C8h+var_80+4], ecx
# .text:004011DC 8B 4C 24 44                                   mov     ecx, [esp+0C8h+var_84]
# .text:004011E0 C7 44 24 40 8F 2F 9F E0                       mov     [esp+0C8h+var_88], 0E09F2F8Fh
# .text:004011E8 C7 44 24 44 D3 31 30 38                       mov     [esp+0C8h+var_84], 383031D3h
# .text:004011F0 89 44 24 50                                   mov     dword ptr [esp+0C8h+var_80+8], eax
# .text:004011F4 8B 44 24 40                                   mov     eax, [esp+0C8h+var_88]
# .text:004011F8 89 4C 24 54                                   mov     dword ptr [esp+0C8h+var_80+0Ch], ecx
# .text:004011FC 8B 4C 24 44                                   mov     ecx, [esp+0C8h+var_84]
# .text:00401200 C7 44 24 40 84 21 F9 AA                       mov     [esp+0C8h+var_88], 0AAF92184h
# .text:00401208 C7 44 24 44 92 BF 09 56                       mov     [esp+0C8h+var_84], 5609BF92h
# .text:00401210 89 44 24 58                                   mov     dword ptr [esp+0C8h+var_70], eax
# .text:00401214 8B 44 24 40                                   mov     eax, [esp+0C8h+var_88]
# .text:00401218 89 4C 24 5C                                   mov     dword ptr [esp+0C8h+var_70+4], ecx
# .text:0040121C 8B 4C 24 44                                   mov     ecx, [esp+0C8h+var_84]
# .text:00401220 0F 28 8C 24 88 00 00 00                       movaps  xmm1, [esp+0C8h+var_40]
# .text:00401228 66 0F EF 4C 24 48                             pxor    xmm1, [esp+0C8h+var_80]
# .text:0040122E 89 44 24 60                                   mov     dword ptr [esp+0C8h+var_70+8], eax
# .text:00401232 89 4C 24 64                                   mov     dword ptr [esp+0C8h+var_70+0Ch], ecx
# .text:00401236 0F 29 8C 24 88 00 00 00                       movaps  [esp+0C8h+var_40], xmm1
# .text:0040123E 8D 84 24 88 00 00 00                          lea     eax, [esp+0C8h+var_40]
# .text:00401245 0F 28 8C 24 98 00 00 00                       movaps  xmm1, [esp+0C8h+var_30]
# .text:0040124D 66 0F EF 4C 24 58                             pxor    xmm1, [esp+0C8h+var_70]
# .text:00401253 50                                            push    eax
# .text:00401254 68 14 31 40 00                                push    offset aLonglonglonglo ; "LONGLONGLONGLONG : %s\n"
# .text:00401259 0F 29 8C 24 A0 00 00 00                       movaps  [esp+0D0h+var_30], xmm1
# .text:00401261 E8 AA FD FF FF                                call    _printf
# .text:00401266 C7 44 24 48 9B D8 CA 2B                       mov     [esp+0D0h+var_88], 2BCAD89Bh
# .text:0040126E C7 44 24 4C 95 FF 28 6B                       mov     [esp+0D0h+var_84], 6B28FF95h
# .text:00401276 8B 44 24 48                                   mov     eax, [esp+0D0h+var_88]
# .text:0040127A 8B 4C 24 4C                                   mov     ecx, [esp+0D0h+var_84]
# .text:0040127E 89 84 24 90 00 00 00                          mov     dword ptr [esp+0D0h+var_40], eax
# .text:00401285 89 8C 24 94 00 00 00                          mov     dword ptr [esp+0D0h+var_40+4], ecx
# .text:0040128C C7 44 24 48 84 3C B2 F2                       mov     [esp+0D0h+var_88], 0F2B23C84h
# .text:00401294 C7 44 24 4C C4 C5 D1 20                       mov     [esp+0D0h+var_84], 20D1C5C4h
# .text:0040129C 8B 44 24 48                                   mov     eax, [esp+0D0h+var_88]
# .text:004012A0 8B 4C 24 4C                                   mov     ecx, [esp+0D0h+var_84]
# .text:004012A4 89 84 24 98 00 00 00                          mov     dword ptr [esp+0D0h+var_40+8], eax
# .text:004012AB 89 8C 24 9C 00 00 00                          mov     dword ptr [esp+0D0h+var_40+0Ch], ecx
# .text:004012B2 C7 44 24 48 D9 6A CD B9                       mov     [esp+0D0h+var_88], 0B9CD6AD9h
# .text:004012BA C7 44 24 4C 9F 7E 7E 7F                       mov     [esp+0D0h+var_84], 7F7E7E9Fh
# .text:004012C2 8B 44 24 48                                   mov     eax, [esp+0D0h+var_88]
# .text:004012C6 8B 4C 24 4C                                   mov     ecx, [esp+0D0h+var_84]
# .text:004012CA 89 84 24 A0 00 00 00                          mov     dword ptr [esp+0D0h+var_30], eax
# .text:004012D1 89 8C 24 A4 00 00 00                          mov     dword ptr [esp+0D0h+var_30+4], ecx
# .text:004012D8 C7 44 24 48 D2 64 AB F3                       mov     [esp+0D0h+var_88], 0F3AB64D2h
# .text:004012E0 C7 44 24 4C DE F0 47 11                       mov     [esp+0D0h+var_84], 1147F0DEh
# .text:004012E8 8B 44 24 48                                   mov     eax, [esp+0D0h+var_88]
# .text:004012EC 8B 4C 24 4C                                   mov     ecx, [esp+0D0h+var_84]
# .text:004012F0 89 84 24 A8 00 00 00                          mov     dword ptr [esp+0D0h+var_30+8], eax
# .text:004012F7 89 8C 24 AC 00 00 00                          mov     dword ptr [esp+0D0h+var_30+0Ch], ecx
# .text:004012FE C7 44 24 48 71 CD 25 BB                       mov     [esp+0D0h+var_88], 0BB25CD71h
# .text:00401306 C7 44 24 4C 9D 32 A6 01                       mov     [esp+0D0h+var_84], 1A6329Dh
# .text:0040130E 8B 44 24 48                                   mov     eax, [esp+0D0h+var_88]
# .text:00401312 8B 4C 24 4C                                   mov     ecx, [esp+0D0h+var_84]
# .text:00401316 89 84 24 B0 00 00 00                          mov     dword ptr [esp+0D0h+var_20], eax
# .text:0040131D 89 8C 24 B4 00 00 00                          mov     dword ptr [esp+0D0h+var_20+4], ecx
# .text:00401324 C7 44 24 48 76 07 AE B7                       mov     [esp+0D0h+var_88], 0B7AE0776h
# .text:0040132C C7 44 24 4C BC D9 4B A9                       mov     [esp+0D0h+var_84], 0A94BD9BCh
# .text:00401334 8B 44 24 48                                   mov     eax, [esp+0D0h+var_88]
# .text:00401338 8B 4C 24 4C                                   mov     ecx, [esp+0D0h+var_84]
# .text:0040133C 89 84 24 B8 00 00 00                          mov     dword ptr [esp+0D0h+var_20+8], eax
# .text:00401343 89 8C 24 BC 00 00 00                          mov     dword ptr [esp+0D0h+var_20+0Ch], ecx
# .text:0040134A C7 44 24 48 CD 9D 98 72                       mov     [esp+0D0h+var_88], 72989DCDh
# .text:00401352 C7 44 24 4C D9 B0 66 2C                       mov     [esp+0D0h+var_84], 2C66B0D9h
# .text:0040135A 8B 44 24 48                                   mov     eax, [esp+0D0h+var_88]
# .text:0040135E 8B 4C 24 4C                                   mov     ecx, [esp+0D0h+var_84]
# .text:00401362 C7 44 24 48 D2 79 E0 AB                       mov     [esp+0D0h+var_88], 0ABE079D2h
# .text:0040136A C7 44 24 4C 88 8A 9F 67                       mov     [esp+0D0h+var_84], 679F8A88h
# .text:00401372 89 44 24 50                                   mov     dword ptr [esp+0D0h+var_80], eax
# .text:00401376 8B 44 24 48                                   mov     eax, [esp+0D0h+var_88]
# .text:0040137A 89 4C 24 54                                   mov     dword ptr [esp+0D0h+var_80+4], ecx
# .text:0040137E 8B 4C 24 4C                                   mov     ecx, [esp+0D0h+var_84]
# .text:00401382 C7 44 24 48 8F 2F 9F E0                       mov     [esp+0D0h+var_88], 0E09F2F8Fh
# .text:0040138A C7 44 24 4C D3 31 30 38                       mov     [esp+0D0h+var_84], 383031D3h
# .text:00401392 89 44 24 58                                   mov     dword ptr [esp+0D0h+var_80+8], eax
# .text:00401396 8B 44 24 48                                   mov     eax, [esp+0D0h+var_88]
# .text:0040139A 89 4C 24 5C                                   mov     dword ptr [esp+0D0h+var_80+0Ch], ecx
# .text:0040139E 8B 4C 24 4C                                   mov     ecx, [esp+0D0h+var_84]
# .text:004013A2 C7 44 24 48 84 21 F9 AA                       mov     [esp+0D0h+var_88], 0AAF92184h
# .text:004013AA C7 44 24 4C 92 BF 09 56                       mov     [esp+0D0h+var_84], 5609BF92h
# .text:004013B2 89 44 24 60                                   mov     dword ptr [esp+0D0h+var_70], eax
# .text:004013B6 8B 44 24 48                                   mov     eax, [esp+0D0h+var_88]
# .text:004013BA 89 4C 24 64                                   mov     dword ptr [esp+0D0h+var_70+4], ecx
# .text:004013BE 8B 4C 24 4C                                   mov     ecx, [esp+0D0h+var_84]
# .text:004013C2 C7 44 24 48 71 CD 25 BB                       mov     [esp+0D0h+var_88], 0BB25CD71h
# .text:004013CA C7 44 24 4C 9D 32 A6 01                       mov     [esp+0D0h+var_84], 1A6329Dh
# .text:004013D2 89 44 24 68                                   mov     dword ptr [esp+0D0h+var_70+8], eax
# .text:004013D6 8B 44 24 48                                   mov     eax, [esp+0D0h+var_88]
# .text:004013DA 89 4C 24 6C                                   mov     dword ptr [esp+0D0h+var_70+0Ch], ecx
# .text:004013DE 8B 4C 24 4C                                   mov     ecx, [esp+0D0h+var_84]
# .text:004013E2 C7 44 24 48 76 07 AE B7                       mov     [esp+0D0h+var_88], 0B7AE0776h
# .text:004013EA C7 44 24 4C BC D9 4B A9                       mov     [esp+0D0h+var_84], 0A94BD9BCh
# .text:004013F2 89 44 24 70                                   mov     dword ptr [esp+0D0h+var_60], eax
# .text:004013F6 8B 44 24 48                                   mov     eax, [esp+0D0h+var_88]
# .text:004013FA 89 4C 24 74                                   mov     dword ptr [esp+0D0h+var_60+4], ecx
# .text:004013FE 8B 4C 24 4C                                   mov     ecx, [esp+0D0h+var_84]
# .text:00401402 0F 28 8C 24 90 00 00 00                       movaps  xmm1, [esp+0D0h+var_40]
# .text:0040140A 89 44 24 78                                   mov     dword ptr [esp+0D0h+var_60+8], eax
# .text:0040140E 89 4C 24 7C                                   mov     dword ptr [esp+0D0h+var_60+0Ch], ecx
# .text:00401412 66 0F EF 4C 24 50                             pxor    xmm1, [esp+0D0h+var_80]
# .text:00401418 8D 84 24 90 00 00 00                          lea     eax, [esp+0D0h+var_40]
# .text:0040141F 0F 29 8C 24 90 00 00 00                       movaps  [esp+0D0h+var_40], xmm1
# .text:00401427 0F 28 8C 24 A0 00 00 00                       movaps  xmm1, [esp+0D0h+var_30]
# .text:0040142F 66 0F EF 4C 24 60                             pxor    xmm1, [esp+0D0h+var_70]
# .text:00401435 0F 29 8C 24 A0 00 00 00                       movaps  [esp+0D0h+var_30], xmm1
# .text:0040143D 0F 28 8C 24 B0 00 00 00                       movaps  xmm1, [esp+0D0h+var_20]
# .text:00401445 66 0F EF 4C 24 70                             pxor    xmm1, [esp+0D0h+var_60]
# .text:0040144B 50                                            push    eax
# .text:0040144C 68 2C 31 40 00                                push    offset aVerylongverylo ; "VERYLONGVERYLONGVERYLONGVERYLONG : %s\n"
# .text:00401451 0F 29 8C 24 B8 00 00 00                       movaps  [esp+0D8h+var_20], xmm1
# .text:00401459 E8 B2 FB FF FF                                call    _printf
# .text:0040145E C7 44 24 50 81 D2 D6 35                       mov     [esp+0D8h+var_88], 35D6D281h
# .text:00401466 C7 44 24 54 90 E3 2E 60                       mov     [esp+0D8h+var_84], 602EE390h
# .text:0040146E 8B 44 24 50                                   mov     eax, [esp+0D8h+var_88]
# .text:00401472 8B 4C 24 54                                   mov     ecx, [esp+0D8h+var_84]
# .text:00401476 89 84 24 98 00 00 00                          mov     dword ptr [esp+0D8h+var_40], eax
# .text:0040147D 89 8C 24 9C 00 00 00                          mov     dword ptr [esp+0D8h+var_40+4], ecx
# .text:00401484 C7 44 24 50 9D 37 A7 E2                       mov     [esp+0D8h+var_88], 0E2A7379Dh
# .text:0040148C C7 44 24 54 DB C2 D3 28                       mov     [esp+0D8h+var_84], 28D3C2DBh
# .text:00401494 8B 44 24 50                                   mov     eax, [esp+0D8h+var_88]
# .text:00401498 8B 4C 24 54                                   mov     ecx, [esp+0D8h+var_84]
# .text:0040149C 89 84 24 A0 00 00 00                          mov     dword ptr [esp+0D8h+var_40+8], eax
# .text:004014A3 89 8C 24 A4 00 00 00                          mov     dword ptr [esp+0D8h+var_40+0Ch], ecx
# .text:004014AA C7 44 24 50 C1 68 D6 B3                       mov     [esp+0D8h+var_88], 0B3D668C1h
# .text:004014B2 C7 44 24 54 9B 31 30 38                       mov     [esp+0D8h+var_84], 3830319Bh
# .text:004014BA 8B 44 24 50                                   mov     eax, [esp+0D8h+var_88]
# .text:004014BE 8B 4C 24 54                                   mov     ecx, [esp+0D8h+var_84]
# .text:004014C2 89 84 24 A8 00 00 00                          mov     dword ptr [esp+0D8h+var_30], eax
# .text:004014C9 89 8C 24 AC 00 00 00                          mov     dword ptr [esp+0D8h+var_30+4], ecx
# .text:004014D0 C7 44 24 50 84 21 F9 AA                       mov     [esp+0D8h+var_88], 0AAF92184h
# .text:004014D8 C7 44 24 54 92 BF 09 56                       mov     [esp+0D8h+var_84], 5609BF92h
# .text:004014E0 8B 44 24 50                                   mov     eax, [esp+0D8h+var_88]
# .text:004014E4 8B 4C 24 54                                   mov     ecx, [esp+0D8h+var_84]
# .text:004014E8 89 84 24 B0 00 00 00                          mov     dword ptr [esp+0D8h+var_30+8], eax
# .text:004014EF 89 8C 24 B4 00 00 00                          mov     dword ptr [esp+0D8h+var_30+0Ch], ecx
# .text:004014F6 C7 44 24 50 CD 9D 98 72                       mov     [esp+0D8h+var_88], 72989DCDh
# .text:004014FE C7 44 24 54 D9 B0 66 2C                       mov     [esp+0D8h+var_84], 2C66B0D9h
# .text:00401506 8B 44 24 50                                   mov     eax, [esp+0D8h+var_88]
# .text:0040150A 8B 4C 24 54                                   mov     ecx, [esp+0D8h+var_84]
# .text:0040150E C7 44 24 50 D2 79 E0 AB                       mov     [esp+0D8h+var_88], 0ABE079D2h
# .text:00401516 C7 44 24 54 88 8A 9F 67                       mov     [esp+0D8h+var_84], 679F8A88h
# .text:0040151E 89 44 24 58                                   mov     dword ptr [esp+0D8h+var_80], eax
# .text:00401522 8B 44 24 50                                   mov     eax, [esp+0D8h+var_88]
# .text:00401526 89 4C 24 5C                                   mov     dword ptr [esp+0D8h+var_80+4], ecx
# .text:0040152A 8B 4C 24 54                                   mov     ecx, [esp+0D8h+var_84]
# .text:0040152E C7 44 24 50 8F 2F 9F E0                       mov     [esp+0D8h+var_88], 0E09F2F8Fh
# .text:00401536 C7 44 24 54 D3 31 30 38                       mov     [esp+0D8h+var_84], 383031D3h
# .text:0040153E 89 44 24 60                                   mov     dword ptr [esp+0D8h+var_80+8], eax
# .text:00401542 8B 44 24 50                                   mov     eax, [esp+0D8h+var_88]
# .text:00401546 89 4C 24 64                                   mov     dword ptr [esp+0D8h+var_80+0Ch], ecx
# .text:0040154A 8B 4C 24 54                                   mov     ecx, [esp+0D8h+var_84]
# .text:0040154E 89 44 24 68                                   mov     dword ptr [esp+0D8h+var_70], eax
# .text:00401552 C7 44 24 50 84 21 F9 AA                       mov     [esp+0D8h+var_88], 0AAF92184h
# .text:0040155A 89 4C 24 6C                                   mov     dword ptr [esp+0D8h+var_70+4], ecx
# .text:0040155E C7 44 24 54 92 BF 09 56                       mov     [esp+0D8h+var_84], 5609BF92h
# .text:00401566 8B 44 24 50                                   mov     eax, [esp+0D8h+var_88]
# .text:0040156A 8B 4C 24 54                                   mov     ecx, [esp+0D8h+var_84]
# .text:0040156E 0F 28 8C 24 98 00 00 00                       movaps  xmm1, [esp+0D8h+var_40]
# .text:00401576 66 0F EF 4C 24 58                             pxor    xmm1, [esp+0D8h+var_80]
# .text:0040157C 89 44 24 70                                   mov     dword ptr [esp+0D8h+var_70+8], eax
# .text:00401580 8D 84 24 98 00 00 00                          lea     eax, [esp+0D8h+var_40]
# .text:00401587 0F 29 8C 24 98 00 00 00                       movaps  [esp+0D8h+var_40], xmm1
# .text:0040158F 0F 28 8C 24 A8 00 00 00                       movaps  xmm1, [esp+0D8h+var_30]
# .text:00401597 89 4C 24 74                                   mov     dword ptr [esp+0D8h+var_70+0Ch], ecx
# .text:0040159B 66 0F EF 4C 24 68                             pxor    xmm1, [esp+0D8h+var_70]
# .text:004015A1 50                                            push    eax
# .text:004015A2 68 54 31 40 00                                push    offset aLongishlongish ; "LONGISHLONGISHLONGISH : %s\n"
# .text:004015A7 0F 29 8C 24 B0 00 00 00                       movaps  [esp+0E0h+var_30], xmm1
# .text:004015AF E8 5C FA FF FF                                call    _printf
# .text:004015B4 83 C4 20                                      add     esp, 20h
# .text:004015B7 33 C0                                         xor     eax, eax
# .text:004015B9 8B E5                                         mov     esp, ebp
# .text:004015BB 5D                                            pop     ebp
# .text:004015BC C3                                            retn
# .text:004015BC                               _main           endp
# ======================================================================================================================
