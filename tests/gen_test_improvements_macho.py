"""Generate ARM64 Mach-O binary to test detection improvements."""
import struct, sys

NOP       = 0xd503201f
RET       = 0xd65f03c0
PACIASP   = 0xd503233f
AUTIASP   = 0xd50323bf
STP_X29_X30  = 0xa9bf7bfd
LDP_X29_X30  = 0xa8c17bfd
BR_X8     = 0xd61f0100

PACIA_X0_X1  = 0xdac10020
AUTIA_X0_X1  = 0xdac11020
PACDA_X0_X1  = 0xdac10820
AUTDA_X0_X1  = 0xdac11820

LDR_X0_SP_8  = 0xf94007e0
LDR_X1_SP_10 = 0xf9400be1
LDR_X2_SP_18 = 0xf9400fe2
LDR_X3_SP_20 = 0xf94013e3
LDR_X8_SP_40 = 0xf94023e8
LDR_X0_X19_0 = 0xf9400260
LDR_X1_X19_8 = 0xf9400661

STR_X0_X19_0  = 0xf9000260
STR_X1_X19_8  = 0xf9000661
STR_X2_X19_10 = 0xf9000a62
STR_X3_X19_18 = 0xf9000e63
STR_X0_X20_0  = 0xf9000280
STR_X1_X20_8  = 0xf9000681
STR_X2_X20_10 = 0xf9000a82
STR_X3_X20_18 = 0xf9000e83
STR_X0_X21_0  = 0xf90002a0
STR_X1_X21_8  = 0xf90006a1

MOV_X0_1 = 0xd2800020
MOV_X1_2 = 0xd2800041
MOV_X2_3 = 0xd2800062
MOV_X3_4 = 0xd2800083

def encode(*insns):
    return b''.join(struct.pack('<I', i) for i in insns)

def bl_offset(from_off, to_off):
    delta = (to_off - from_off) >> 2
    return 0x94000000 | (delta & 0x3ffffff)

funcs = {}
code_parts = []
current_off = 0

def add_func(name, *insns):
    global current_off
    funcs[name] = current_off
    code = encode(*insns)
    code_parts.append((name, code))
    current_off += len(code)

# Mach-O symbols need leading underscore
add_func('_main', PACIASP, STP_X29_X30, 0x94000000, LDP_X29_X30, AUTIASP, RET)
add_func('_server_loop', PACIASP, STP_X29_X30, 0x94000000, 0x94000000, LDP_X29_X30, AUTIASP, RET)
add_func('_handle_request', PACIASP, STP_X29_X30, 0x94000000, 0x94000000, LDP_X29_X30, AUTIASP, RET)
add_func('_fork', PACIASP, STP_X29_X30, NOP, NOP, LDP_X29_X30, AUTIASP, RET)
add_func('_dispatch_stack', LDR_X0_SP_8, LDR_X1_SP_10, LDR_X2_SP_18, LDR_X3_SP_20, LDR_X8_SP_40, BR_X8)
add_func('_dispatch_const', MOV_X0_1, MOV_X1_2, MOV_X2_3, MOV_X3_4, LDR_X8_SP_40, BR_X8)
add_func('_dop_hotspot', STP_X29_X30, LDR_X0_X19_0, LDR_X1_X19_8,
         STR_X0_X19_0, STR_X1_X19_8, STR_X2_X19_10, STR_X3_X19_18,
         STR_X0_X20_0, STR_X1_X20_8, STR_X2_X20_10, STR_X3_X20_18,
         STR_X0_X21_0, STR_X1_X21_8, LDP_X29_X30, RET)
add_func('_ipac_only', PACIASP, STP_X29_X30, PACIA_X0_X1, AUTIA_X0_X1, NOP, NOP, LDP_X29_X30, AUTIASP, RET)
add_func('_both_pac', PACIASP, STP_X29_X30, PACIA_X0_X1, AUTIA_X0_X1, PACDA_X0_X1, AUTDA_X0_X1, LDP_X29_X30, AUTIASP, RET)
add_func('_check_credentials', PACIASP, STP_X29_X30, NOP, NOP, LDP_X29_X30, AUTIASP, RET)
add_func('_verify_auth_token', PACIASP, STP_X29_X30, NOP, NOP, LDP_X29_X30, AUTIASP, RET)

STR_X0_SP_8 = 0xf90007e0
LDR_X0_SP_30 = 0xf9401be0
add_func('_arg_sign', PACIA_X0_X1, STR_X0_SP_8, RET)
add_func('_call_arg_sign', PACIASP, STP_X29_X30, LDR_X0_SP_30, LDR_X1_X19_8,
         0x94000000, LDP_X29_X30, AUTIASP, RET)

ADD_X1_X0_4 = 0x91001001  # add x1, x0, #4
add_func('_dep_sign', LDR_X0_SP_8, ADD_X1_X0_4, PACIA_X0_X1, STR_X0_SP_8, RET)

MOV_SP_X0 = 0x9100001f   # mov sp, x0
AUTIBSP = 0xd50323ff     # autibsp
AUTIAZ = 0xd503239f      # autiaz
MOV_X30_X0 = 0xaa0003fe  # mov x30, x0

add_func('_stack_pivot', PACIASP, STP_X29_X30, NOP, NOP, MOV_SP_X0, LDP_X29_X30, AUTIASP, RET)
add_func('_key_confused', PACIASP, STP_X29_X30, PACIA_X0_X1, NOP, NOP, LDP_X29_X30, AUTIBSP, RET)
PACIA_X0_X1_M = 0xdac10020  # pacia x0, x1
add_func('_modifier_confused', PACIASP, STP_X29_X30, PACIA_X0_X1_M, NOP, AUTIAZ, LDP_X29_X30, AUTIASP, RET)
add_func('_context_manip', PACIASP, STP_X29_X30, NOP, MOV_X30_X0, AUTIASP, RET)

XPACI_X8  = 0xdac143e8   # xpaci x8
XPACI_X0  = 0xdac143e0   # xpaci x0
CMP_X8_X0 = 0xeb00011f   # cmp x8, x0
XPACLRI   = 0xd50320ff   # xpaclri

add_func('_xpac_bypass', PACIASP, STP_X29_X30, LDR_X8_SP_40, XPACI_X8, BR_X8)
add_func('_xpac_safe', PACIASP, STP_X29_X30, XPACI_X0, CMP_X8_X0, NOP, LDP_X29_X30, AUTIASP, RET)
add_func('_xpaclri_bypass', PACIASP, STP_X29_X30, NOP, NOP, LDP_X29_X30, XPACLRI, RET)

def patch_bl(func_name, insn_idx, target_name):
    src_off = funcs[func_name] + insn_idx * 4
    dst_off = funcs[target_name]
    delta = (dst_off - src_off) >> 2
    return 0x94000000 | (delta & 0x3ffffff)

text_code = bytearray()
for name, code in code_parts:
    text_code.extend(code)

# Patch BLs
for func_name, insn_idx, target in [
    ('_main', 2, '_server_loop'),
    ('_server_loop', 2, '_handle_request'),
    ('_server_loop', 3, '_fork'),
    ('_handle_request', 2, '_dispatch_stack'),
    ('_handle_request', 3, '_dispatch_const'),
    ('_call_arg_sign', 4, '_arg_sign'),
]:
    off = funcs[func_name] + insn_idx * 4
    struct.pack_into('<I', text_code, off, patch_bl(func_name, insn_idx, target))

text_code = bytes(text_code)

# ── Mach-O construction ──
MH_MAGIC_64 = 0xfeedfacf
CPU_TYPE_ARM64 = 0x0100000c
CPU_SUBTYPE_ARM64E = 2
MH_EXECUTE = 2
MH_PIE = 0x200000
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02

TEXT_VMADDR = 0x100000000
PAGE = 0x4000

mach_header_size = 32
lc_segment_size = 72 + 80
lc_symtab_size = 24
total_lc_size = lc_segment_size + lc_symtab_size
ncmds = 2

header_area = mach_header_size + total_lc_size
text_file_offset = (header_area + 15) & ~15
text_size = len(text_code)
text_vmaddr = TEXT_VMADDR + text_file_offset

strtab = b'\x00'
nlist_entries = []
for name, off in sorted(funcs.items(), key=lambda x: x[1]):
    n_strx = len(strtab)
    strtab += name.encode() + b'\x00'
    nlist_entries.append(struct.pack('<IBBHQ', n_strx, 0x0f, 1, 0, text_vmaddr + off))

symtab_data = b''.join(nlist_entries)
nsyms = len(nlist_entries)

text_seg_fileoff = 0
text_seg_filesize = (text_file_offset + text_size + PAGE - 1) & ~(PAGE - 1)
text_seg_vmsize = text_seg_filesize

symtab_file_offset = text_seg_filesize
strtab_file_offset = symtab_file_offset + len(symtab_data)
total_file_size = strtab_file_offset + len(strtab)

macho_header = struct.pack('<IiiIIIII',
    MH_MAGIC_64, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E,
    MH_EXECUTE, ncmds, total_lc_size, MH_PIE, 0)

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

seg_text = lc_segment_64('__TEXT', TEXT_VMADDR, text_seg_vmsize,
                          text_seg_fileoff, text_seg_filesize, 5, 5, 1, 0)
sect_text = section_64('__text', '__TEXT',
                        TEXT_VMADDR + text_file_offset, text_size,
                        text_file_offset, 2, 0, 0, 0x80000400)

lc_symtab = struct.pack('<IIIIII',
    LC_SYMTAB, lc_symtab_size,
    symtab_file_offset, nsyms,
    strtab_file_offset, len(strtab))

out = bytearray(total_file_size)
p = 0
out[p:p+len(macho_header)] = macho_header; p += len(macho_header)
out[p:p+len(seg_text)] = seg_text; p += len(seg_text)
out[p:p+len(sect_text)] = sect_text; p += len(sect_text)
out[p:p+len(lc_symtab)] = lc_symtab

out[text_file_offset:text_file_offset+text_size] = text_code
out[symtab_file_offset:symtab_file_offset+len(symtab_data)] = symtab_data
out[strtab_file_offset:strtab_file_offset+len(strtab)] = strtab

outpath = sys.argv[1] if len(sys.argv) > 1 else 'pac_test_improvements_macho'
with open(outpath, 'wb') as f:
    f.write(out)
print(f"Generated {outpath}: {len(out)} bytes, {len(text_code)//4} instructions, {nsyms} symbols")
print(f"Format: Mach-O arm64e")
print(f"Functions: {[n.lstrip('_') for n in sorted(funcs.keys())]}")
