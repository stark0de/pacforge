"""Generate minimal ARM64 Mach-O with PAC instructions for testing pacforge.py."""
import struct, sys

# ── ARM64 instruction encodings (same as ELF test) ──
NOP       = 0xd503201f
RET       = 0xd65f03c0
RETAA     = 0xd65f0bff
PACIASP   = 0xd503233f
PACIBSP   = 0xd503237f
AUTIASP   = 0xd50323bf
AUTIBSP   = 0xd50323ff
XPACLRI   = 0xd50320ff
BTI_C     = 0xd503245f
BTI_J     = 0xd503249f
PACIA_X0_X1 = 0xdac10020
PACIB_X0_X1 = 0xdac10420
PACDA_X0_X1 = 0xdac10820
AUTIA_X0_X1 = 0xdac11020
AUTIB_X0_X1 = 0xdac11420
PACIZA_X0   = 0xdac123e0
AUTIZA_X0   = 0xdac133e0
PACIAZ      = 0xd503231f
AUTIAZ      = 0xd503239f
BR_X8   = 0xd61f0100
BLR_X8  = 0xd63f0100
BLRAAZ_X8 = 0xd63f0be8
STP_X29_X30  = 0xa9bf7bfd
LDP_X29_X30  = 0xa8c17bfd
LDR_X0_SP_10 = 0xf94007e0
LDR_X1_SP_18 = 0xf9400fe1
LDR_X8_SP_40 = 0xf94023e8
STR_X0_SP_20 = 0xf90013e0
STR_X0_SP_30 = 0xf9001be0
LDR_X8_X19_30 = 0xf9401a68
LDR_X8_X8_58  = 0xf9402d08
MOV_X0_1 = 0xd2800020
MOV_X1_2 = 0xd2800041
MOV_X2_3 = 0xd2800062
MOV_X3_4 = 0xd2800083

def encode(*insns):
    return b''.join(struct.pack('<I', i) for i in insns)

# ── Functions ──
func_pac_a = encode(PACIASP, STP_X29_X30, NOP, NOP, NOP, LDP_X29_X30, AUTIASP, RET)
func_pac_b = encode(PACIBSP, STP_X29_X30, NOP, NOP, NOP, LDP_X29_X30, AUTIBSP, RET)
sign_gadget = encode(STP_X29_X30, LDR_X0_SP_10, LDR_X1_SP_18, PACIA_X0_X1, STR_X0_SP_20, LDP_X29_X30, RET)
oracle_sim = encode(STP_X29_X30, AUTIA_X0_X1, NOP, PACIZA_X0, STR_X0_SP_30, LDP_X29_X30, RET)
jop_dispatch = encode(MOV_X0_1, MOV_X1_2, MOV_X2_3, MOV_X3_4, LDR_X8_SP_40, BR_X8)
zero_ctx_sign = encode(PACIAZ, NOP, NOP, AUTIAZ, RET)
bti_func = encode(BTI_C, PACIASP, NOP, NOP, AUTIASP, RET)
bti_only = encode(BTI_J, NOP, NOP, RET)
no_pac = encode(STP_X29_X30, NOP, NOP, NOP, LDP_X29_X30, RET)
data_pac = encode(STP_X29_X30, LDR_X0_SP_10, LDR_X1_SP_18, PACDA_X0_X1, STR_X0_SP_20, LDP_X29_X30, RET)
atomic_ret = encode(PACIASP, STP_X29_X30, NOP, NOP, LDP_X29_X30, RETAA)
cop_target = encode(STP_X29_X30, LDR_X8_X19_30, LDR_X8_X8_58, BLRAAZ_X8, LDP_X29_X30, RET)

_funcs = [
    ('_func_pac_a', func_pac_a), ('_func_pac_b', func_pac_b),
    ('_sign_gadget', sign_gadget), ('_oracle_sim', oracle_sim),
    ('_jop_dispatch', jop_dispatch), ('_zero_ctx_sign', zero_ctx_sign),
    ('_bti_func', bti_func), ('_bti_only', bti_only),
    ('_no_pac', no_pac), ('_data_pac_func', data_pac),
    ('_atomic_ret', atomic_ret), ('_cop_target', cop_target),
]
text_code = b''.join(code for _, code in _funcs)
func_offsets = {}
off = 0
for name, code in _funcs:
    func_offsets[off] = name
    off += len(code)

# ── __auth_got section (8 fake PAC-signed pointers) ──
auth_got_data = b''
for i in range(8):
    signed_ptr = (0x0042 << 48) | (0x100000 + i * 0x100)
    auth_got_data += struct.pack('<Q', signed_ptr)

# ── Mach-O constants ──
MH_MAGIC_64 = 0xfeedfacf
CPU_TYPE_ARM64 = 0x0100000c
CPU_SUBTYPE_ARM64_ALL = 0
CPU_SUBTYPE_ARM64E = 2
MH_EXECUTE = 2
MH_PIE = 0x200000

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02

# ── Layout ──
TEXT_VMADDR = 0x100000000
DATA_VMADDR = 0x100004000
PAGE = 0x4000

# Compute __text's address before emitting nlist values. Symbol values are
# virtual addresses in the section, not offsets from the segment base.
mach_header_size = 32
lc_segment_text_size = 72 + 80
lc_segment_data_size = 72 + 80
lc_symtab_size = 24
total_lc_size = lc_segment_text_size + lc_segment_data_size + lc_symtab_size
ncmds = 3
header_area = mach_header_size + total_lc_size
text_file_offset = (header_area + 15) & ~15
text_size = len(text_code)
text_vmaddr = TEXT_VMADDR + text_file_offset

# Build symbol table (nlist_64 entries)
# nlist_64: n_strx(4) n_type(1) n_sect(1) n_desc(2) n_value(8) = 16 bytes
strtab = b'\x00'
nlist_entries = []
for foff, name in sorted(func_offsets.items()):
    n_strx = len(strtab)
    strtab += name.encode() + b'\x00'
    n_type = 0x0f  # N_SECT | N_EXT
    n_sect = 1     # __text is section 1
    n_desc = 0
    n_value = text_vmaddr + foff
    nlist_entries.append(struct.pack('<IBBHQ', n_strx, n_type, n_sect, n_desc, n_value))

symtab_data = b''.join(nlist_entries)
nsyms = len(nlist_entries)

# ── Compute remaining file layout ──
# __TEXT segment covers header + code
text_seg_fileoff = 0
text_seg_filesize = (text_file_offset + text_size + PAGE - 1) & ~(PAGE - 1)
text_seg_vmsize = text_seg_filesize

# __DATA segment
data_file_offset = text_seg_filesize
auth_got_size = len(auth_got_data)
data_seg_filesize = (auth_got_size + PAGE - 1) & ~(PAGE - 1)
data_seg_vmsize = data_seg_filesize

# Symtab/strtab after data segment
symtab_file_offset = data_file_offset + data_seg_filesize
strtab_file_offset = symtab_file_offset + len(symtab_data)

total_file_size = strtab_file_offset + len(strtab)

# ── Build Mach-O header ──
# mach_header_64: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
macho_header = struct.pack('<IiiIIIII',
    MH_MAGIC_64, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E,
    MH_EXECUTE, ncmds, total_lc_size, MH_PIE, 0)

# ── LC_SEGMENT_64 __TEXT ──
def lc_segment_64(segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags):
    segname_bytes = segname.encode().ljust(16, b'\x00')
    cmdsize = 72 + nsects * 80
    return struct.pack('<II16sQQQQiiII',
        LC_SEGMENT_64, cmdsize, segname_bytes,
        vmaddr, vmsize, fileoff, filesize,
        maxprot, initprot, nsects, flags)

def section_64(sectname, segname, addr, size, offset, align, reloff, nreloc, flags):
    sect_bytes = sectname.encode().ljust(16, b'\x00')
    seg_bytes = segname.encode().ljust(16, b'\x00')
    return struct.pack('<16s16sQQIIIIII4x4x',
        sect_bytes, seg_bytes, addr, size, offset, align,
        reloff, nreloc, flags, 0)

# __TEXT segment
seg_text = lc_segment_64('__TEXT', TEXT_VMADDR, text_seg_vmsize,
                          text_seg_fileoff, text_seg_filesize,
                          5, 5, 1, 0)  # r-x
sect_text = section_64('__text', '__TEXT',
                        TEXT_VMADDR + text_file_offset, text_size,
                        text_file_offset, 2, 0, 0,
                        0x80000400)  # S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS

# __DATA segment
seg_data = lc_segment_64('__DATA', DATA_VMADDR, data_seg_vmsize,
                          data_file_offset, data_seg_filesize,
                          3, 3, 1, 0)  # rw-
sect_auth_got = section_64('__auth_got', '__DATA',
                            DATA_VMADDR, auth_got_size,
                            data_file_offset, 3, 0, 0,
                            0x00000000)  # S_REGULAR

# LC_SYMTAB
lc_symtab = struct.pack('<IIIIII',
    LC_SYMTAB, lc_symtab_size,
    symtab_file_offset, nsyms,
    strtab_file_offset, len(strtab))

# ── Assemble ──
out = bytearray(total_file_size)
p = 0
out[p:p+len(macho_header)] = macho_header; p += len(macho_header)
out[p:p+len(seg_text)] = seg_text; p += len(seg_text)
out[p:p+len(sect_text)] = sect_text; p += len(sect_text)
out[p:p+len(seg_data)] = seg_data; p += len(seg_data)
out[p:p+len(sect_auth_got)] = sect_auth_got; p += len(sect_auth_got)
out[p:p+len(lc_symtab)] = lc_symtab; p += len(lc_symtab)

# Write code
out[text_file_offset:text_file_offset+text_size] = text_code
# Write auth_got data
out[data_file_offset:data_file_offset+auth_got_size] = auth_got_data
# Write symtab
out[symtab_file_offset:symtab_file_offset+len(symtab_data)] = symtab_data
# Write strtab
out[strtab_file_offset:strtab_file_offset+len(strtab)] = strtab

outpath = sys.argv[1] if len(sys.argv) > 1 else 'pac_test_macho'
with open(outpath, 'wb') as f:
    f.write(out)

print(f"Generated {outpath}: {len(out)} bytes, {len(text_code)//4} instructions, {nsyms} symbols")
print(f"Format: Mach-O arm64e (CPU_SUBTYPE_ARM64E)")
print(f"Sections: __text ({text_size}B), __auth_got ({auth_got_size}B)")
print(f"Functions: {[name.lstrip('_') for name in sorted(func_offsets.values())]}")
