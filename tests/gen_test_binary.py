"""Generate minimal ARM64 ELF with PAC instructions for testing PACForge."""
import struct, sys

# ARM64 instruction encodings
NOP       = 0xd503201f
RET       = 0xd65f03c0
PACIASP   = 0xd503233f  # hint #25
PACIBSP   = 0xd503237f  # hint #27
AUTIASP   = 0xd50323bf  # hint #29
AUTIBSP   = 0xd50323ff  # hint #31
XPACLRI   = 0xd50320ff  # hint #7

# BTI
BTI_C     = 0xd503245f  # hint #34
BTI_J     = 0xd503249f  # hint #36

# PAC data processing (1 source) encodings:
# Format: 1_10_11010110_00001_opcode_Rn_Rd
# PACIA: opcode=000000, PACIB: 000001, PACDA: 000010, PACDB: 000011
# AUTIA: 000100, AUTIB: 000101, AUTDA: 000110, AUTDB: 000111
# PACIZA: 001000 Rn=11111, AUTIZA: 001100 Rn=11111
PACIA_X0_X1 = 0xdac10020   # PACIA X0, X1
PACIB_X0_X1 = 0xdac10420   # PACIB X0, X1
PACDA_X0_X1_REAL = 0xdac10820   # PACDA X0, X1
PACDB_X0_X1 = 0xdac10c20   # PACDB X0, X1
AUTIA_X0_X1 = 0xdac11020   # AUTIA X0, X1
AUTIB_X0_X1 = 0xdac11420   # AUTIB X0, X1
AUTDA_X0_X1 = 0xdac11820   # AUTDA X0, X1
AUTDB_X0_X1 = 0xdac11c20   # AUTDB X0, X1
PACIZA_X0   = 0xdac123e0   # PACIZA X0 (Rn=xzr)
AUTIZA_X0   = 0xdac133e0   # AUTIZA X0 (Rn=xzr)

# hint #N is encoded as: 0xd503201f | (N << 5)
def hint(n): return 0xd503201f | (n << 5)

PACIA1716_C = hint(8)
PACIB1716_C = hint(10)
AUTIA1716_C = hint(12)
AUTIB1716_C = hint(14)
PACIAZ_C    = hint(24)
PACIASP_C   = hint(25)
PACIBZ_C    = hint(26)
PACIBSP_C   = hint(27)
AUTIAZ_C    = hint(28)
AUTIASP_C   = hint(29)
AUTIBZ_C    = hint(30)
AUTIBSP_C   = hint(31)
BTI_C_C     = hint(34)
BTI_J_C     = hint(36)
BTI_JC_C    = hint(38)
XPACLRI_C   = hint(7)

# Combined auth+return (atomic, no TOCTTOU window)
RETAA   = 0xd65f0bff  # retaa
RETAB   = 0xd65f0fff  # retab

# Branch
BR_X8   = 0xd61f0100
BLR_X8  = 0xd63f0100
BLRAAZ_X8 = 0xd63f0be8  # blraaz x8
BL_SELF = 0x94000000  # bl +0 (placeholder)

# Load/store
LDR_X0_SP_10 = 0xf94007e0  # ldr x0, [sp, #0x10]
LDR_X1_SP_18 = 0xf9400fe1  # ldr x1, [sp, #0x18]
LDR_X8_SP_40 = 0xf94023e8  # ldr x8, [sp, #0x40]
STR_X0_SP_20 = 0xf90013e0  # str x0, [sp, #0x20]
STR_X0_SP_30 = 0xf9001be0  # str x0, [sp, #0x30]
STP_X29_X30  = 0xa9bf7bfd  # stp x29, x30, [sp, #-16]!
LDP_X29_X30  = 0xa8c17bfd  # ldp x29, x30, [sp], #16

# Move
MOV_X0_1 = 0xd2800020  # mov x0, #1
MOV_X1_2 = 0xd2800041  # mov x1, #2
MOV_X2_3 = 0xd2800062  # mov x2, #3
MOV_X3_4 = 0xd2800083  # mov x3, #4

def encode_insns(*insns):
    return b''.join(struct.pack('<I', i) for i in insns)

# ── Build .text ──
# Function 1: func_pac_a (PACIASP prologue/epilogue)
func_pac_a = encode_insns(
    PACIASP_C, STP_X29_X30, NOP, NOP, NOP, LDP_X29_X30, AUTIASP_C, RET
)
# Function 2: func_pac_b (PACIBSP prologue/epilogue)
func_pac_b = encode_insns(
    PACIBSP_C, STP_X29_X30, NOP, NOP, NOP, LDP_X29_X30, AUTIBSP_C, RET
)
# Function 3: sign_gadget (ldr from stack -> pacia -> str = signing gadget)
sign_gadget = encode_insns(
    STP_X29_X30,
    LDR_X0_SP_10,   # controlled reg from stack
    LDR_X1_SP_18,   # controlled context from stack
    PACIA_X0_X1,     # PACIA x0, x1 (correct encoding)
    STR_X0_SP_20,    # store signed result
    LDP_X29_X30, RET
)
# Function 4: oracle_sim (autia -> paciza -> str = PAC oracle)
oracle_sim = encode_insns(
    STP_X29_X30,
    AUTIA_X0_X1,     # AUTIA x0, x1 — fails if wrong PAC
    NOP,
    PACIZA_X0,       # PACIZA x0 — re-sign (potentially corrupted)
    STR_X0_SP_30,    # store — attacker reads result
    LDP_X29_X30, RET
)
# Function 5: jop_dispatch (set x0-x3 then br x8)
jop_dispatch = encode_insns(
    MOV_X0_1, MOV_X1_2, MOV_X2_3, MOV_X3_4,
    LDR_X8_SP_40,   # load branch target from memory
    BR_X8            # JOP dispatch
)
# Function 6: zero_ctx_sign (paciaz + autiaz = zero context pair)
zero_ctx_sign = encode_insns(
    PACIAZ_C,        # paciaz — zero context sign
    NOP, NOP,
    AUTIAZ_C,        # autiaz — zero context auth
    RET
)
# Function 7: bti_func (BTI landing pad + PAC)
bti_func = encode_insns(
    BTI_C_C,         # bti c
    PACIASP_C,       # paciasp
    NOP, NOP,
    AUTIASP_C,       # autiasp
    RET
)
# Function 8: bti_only (BTI without PAC)
bti_only = encode_insns(
    BTI_J_C,         # bti j
    NOP, NOP, RET
)
# Function 9: no_pac (unprotected function)
no_pac = encode_insns(
    STP_X29_X30, NOP, NOP, NOP, LDP_X29_X30, RET
)
# Function 10: data_pac (PACDA-family instruction)
# PACDA X0, X1 = 0xdac10880 — DAC1 group, opcode for PACDA
# Actually: PACDA Xd, Xn encoding is in the same group
# Let me construct: 1 1 0 11010110 00001 0 00 010 Xn Xd
# PACDA X0, X1: 0b1101_1010_1100_0001_0000_1000_0010_0000 = nah
# Looking at ARM ARM: PACDA: sf=1, S=1, opcode2=00001, opcode=000010
# 1_1_0_11010110_00001_000010_nnnnn_ddddd
# PACDA X0, X1: 1101101011000001 000010 00001 00000
# = 0xdac10820? That's the same encoding I used for PACIA...
# Actually, let me look at this more carefully.
# PAC instruction encodings from ARM ARM:
# 1 1 0 1101 0 110 Rm opcode2 Rn Rd
# PACIA: opcode2 = 0b000100 (bits 15:10) — wait, the exact layout:
# For PACIA Xd, Xn: bits 31:21 = 11011010110, Rm = 00001, bits 15:10 = 000100, Rn, Rd
# PACDA Xd, Xn: bits 15:10 = 000010 (different opcode)
# Hmm, actually I think I'm overcomplicating this. Let me just use the hint variants
# which capstone definitely decodes correctly.

# For PACDA, there's no hint alias. Let me try the actual encoding.
# Data Processing (1 source):
# 1 1 0 11010110 00001 010000 nnnnn ddddd = PACDA Xd, Xn
# So PACDA X0, X1 = 0b1101_1010_1100_0001_0100_0000_0010_0000 = 0xdac14020
data_pac = encode_insns(
    STP_X29_X30,
    LDR_X0_SP_10,
    LDR_X1_SP_18,
    PACDA_X0_X1_REAL,  # PACDA X0, X1 — data pointer signing
    STR_X0_SP_20,
    LDP_X29_X30, RET
)

# Function 11: atomic_ret — uses retaa (no TOCTTOU window)
atomic_ret = encode_insns(
    PACIASP_C, STP_X29_X30, NOP, NOP, LDP_X29_X30, RETAA
)
# Function 12: cop_target — double-deref COP pattern (unsigned ptr → zero-auth call)
# LDR X8, [X19, #0x30] → LDR X8, [X8, #0x58] → BLRAAZ X8
# Tests both COP pattern AND raw-byte BLRAAZ detection (capstone 5.0 can't decode Z variants)
LDR_X8_X19_30 = 0xf9401a68  # ldr x8, [x19, #0x30]
LDR_X8_X8_58  = 0xf9402d08  # ldr x8, [x8, #0x58]
cop_target = encode_insns(
    STP_X29_X30,
    LDR_X8_X19_30,  # load unsigned callback struct ptr
    LDR_X8_X8_58,   # load func ptr from struct
    BLRAAZ_X8,       # zero-context auth call — COP candidate
    LDP_X29_X30, RET
)

# Combine all .text
text_code = (func_pac_a + func_pac_b + sign_gadget + oracle_sim +
             jop_dispatch + zero_ctx_sign + bti_func + bti_only +
             no_pac + data_pac + atomic_ret + cop_target)

# Function boundaries (offset from .text start -> name)
_funcs = [
    ('func_pac_a', func_pac_a), ('func_pac_b', func_pac_b),
    ('sign_gadget', sign_gadget), ('oracle_sim', oracle_sim),
    ('jop_dispatch', jop_dispatch), ('zero_ctx_sign', zero_ctx_sign),
    ('bti_func', bti_func), ('bti_only', bti_only),
    ('no_pac', no_pac), ('data_pac_func', data_pac),
    ('atomic_ret', atomic_ret), ('cop_target', cop_target),
]
func_offsets = {}
_off = 0
for name, code in _funcs:
    func_offsets[_off] = name
    _off += len(code)

# ── Build __auth_got section (8 fake signed pointers) ──
auth_got_data = b''
for i in range(8):
    # Fake PAC-signed pointer: high bits set (PAC signature), low bits = function addr
    fake_target = 0x400000 + i * 0x100
    pac_bits = 0x0042 << 48  # fake PAC signature in upper bits
    signed_ptr = pac_bits | fake_target
    auth_got_data += struct.pack('<Q', signed_ptr)

# ── Build ELF ──
TEXT_VADDR = 0x400000
AUTH_GOT_VADDR = 0x500000

# Build string tables first
shstrtab = b'\x00.text\x00__auth_got\x00.symtab\x00.strtab\x00.shstrtab\x00'
# Find offsets in shstrtab
sh_text_name = shstrtab.index(b'.text\x00')
sh_auth_got_name = shstrtab.index(b'__auth_got\x00')
sh_symtab_name = shstrtab.index(b'.symtab\x00')
sh_strtab_name = shstrtab.index(b'.strtab\x00')
sh_shstrtab_name = shstrtab.index(b'.shstrtab\x00')

# Strtab for symbols
strtab = b'\x00'
sym_name_offsets = {}
for name in func_offsets.values():
    sym_name_offsets[name] = len(strtab)
    strtab += name.encode() + b'\x00'

# Symbol table entries
# First entry is null
STT_FUNC = 2
STB_GLOBAL = 1
def elf64_sym(name_idx, value, size, bind, typ, shndx):
    info = (bind << 4) | typ
    return struct.pack('<IBBHQQ', name_idx, info, 0, shndx, value, size)

symtab = elf64_sym(0, 0, 0, 0, 0, 0)  # null entry
for off, name in sorted(func_offsets.items()):
    symtab += elf64_sym(sym_name_offsets[name], TEXT_VADDR + off, 32, STB_GLOBAL, STT_FUNC, 1)

# Layout:
# 0x00: ELF header (64 bytes)
# 0x40: Program header (56 bytes)
# 0x78: padding to align to 0x80
# 0x80: .text
# 0x80+text_len: __auth_got
# Then: .symtab, .strtab, .shstrtab
# Then: section headers

ehdr_size = 64
phdr_size = 56
phdr_offset = ehdr_size
text_offset = 0x100  # align nicely
text_size = len(text_code)
auth_got_offset = text_offset + text_size
auth_got_size = len(auth_got_data)
symtab_offset = auth_got_offset + auth_got_size
symtab_size = len(symtab)
strtab_offset = symtab_offset + symtab_size
strtab_size = len(strtab)
shstrtab_offset = strtab_offset + strtab_size
shstrtab_size = len(shstrtab)

# Align section headers to 8 bytes
shdr_offset = (shstrtab_offset + shstrtab_size + 7) & ~7
num_sections = 6  # null + .text + __auth_got + .symtab + .strtab + .shstrtab
shdr_entry_size = 64

# ELF header
e_ident = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8  # 64-bit, little-endian, Linux
e_type = 2     # ET_EXEC
e_machine = 183  # EM_AARCH64
e_version = 1
e_entry = TEXT_VADDR
e_phoff = phdr_offset
e_shoff = shdr_offset
e_flags = 0
e_ehsize = ehdr_size
e_phentsize = phdr_size
e_phnum = 1
e_shentsize = shdr_entry_size
e_shnum = num_sections
e_shstrndx = 5  # .shstrtab is section 5

ehdr = struct.pack('<4sBBBB8sHHIQQQIHHHHHH',
    b'\x7fELF', 2, 1, 1, 0, b'\x00'*8,
    e_type, e_machine, e_version,
    e_entry, e_phoff, e_shoff,
    e_flags, e_ehsize, e_phentsize, e_phnum,
    e_shentsize, e_shnum, e_shstrndx)

# Program header (PT_LOAD for .text)
PT_LOAD = 1
PF_R = 4; PF_X = 1
phdr = struct.pack('<IIQQQQQQ',
    PT_LOAD, PF_R | PF_X,
    text_offset, TEXT_VADDR, TEXT_VADDR,
    text_size, text_size, 0x1000)

# Section headers
def shdr(name, typ, flags, addr, offset, size, link=0, info=0, addralign=4, entsize=0):
    return struct.pack('<IIQQQQIIqq',
        name, typ, flags, addr, offset, size, link, info, addralign, entsize)

SHT_NULL = 0; SHT_PROGBITS = 1; SHT_SYMTAB = 2; SHT_STRTAB = 3
SHF_ALLOC = 2; SHF_EXECINSTR = 4; SHF_WRITE = 1

shdrs = b''
shdrs += shdr(0, SHT_NULL, 0, 0, 0, 0)  # null
shdrs += shdr(sh_text_name, SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR,
              TEXT_VADDR, text_offset, text_size)
shdrs += shdr(sh_auth_got_name, SHT_PROGBITS, SHF_ALLOC|SHF_WRITE,
              AUTH_GOT_VADDR, auth_got_offset, auth_got_size)
shdrs += shdr(sh_symtab_name, SHT_SYMTAB, 0, 0, symtab_offset, symtab_size,
              link=4, info=1, entsize=24)  # link=.strtab(4), info=first_global(1)
shdrs += shdr(sh_strtab_name, SHT_STRTAB, 0, 0, strtab_offset, strtab_size)
shdrs += shdr(sh_shstrtab_name, SHT_STRTAB, 0, 0, shstrtab_offset, shstrtab_size)

# Assemble file
out = bytearray(shdr_offset + num_sections * shdr_entry_size)
out[:ehdr_size] = ehdr
out[phdr_offset:phdr_offset+phdr_size] = phdr
out[text_offset:text_offset+text_size] = text_code
out[auth_got_offset:auth_got_offset+auth_got_size] = auth_got_data
out[symtab_offset:symtab_offset+symtab_size] = symtab
out[strtab_offset:strtab_offset+strtab_size] = strtab
out[shstrtab_offset:shstrtab_offset+shstrtab_size] = shstrtab
out[shdr_offset:shdr_offset+len(shdrs)] = shdrs

outpath = sys.argv[1] if len(sys.argv) > 1 else 'pac_test_binary'
with open(outpath, 'wb') as f:
    f.write(out)
print(f"Generated {outpath}: {len(out)} bytes, {len(text_code)//4} instructions, {len(func_offsets)} functions")
print(f"Functions: {list(func_offsets.values())}")
