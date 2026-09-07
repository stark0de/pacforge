"""Generate ARM64 ELF binary to test detection improvements.

Tests:
- Dispatcher arg provenance (stack vs const), chainable dispatchers
- Fork reachable from main via call graph
- DOP hotspot function (many stores, no PAC)
- Per-function data PAC breakdown
"""
import struct, sys

NOP       = 0xd503201f
RET       = 0xd65f03c0
PACIASP   = 0xd503233f
AUTIASP   = 0xd50323bf
STP_X29_X30  = 0xa9bf7bfd
LDP_X29_X30  = 0xa8c17bfd
BR_X8     = 0xd61f0100
BLR_X8    = 0xd63f0100

# PAC data instructions
PACIA_X0_X1  = 0xdac10020
AUTIA_X0_X1  = 0xdac11020
PACDA_X0_X1  = 0xdac10820
AUTDA_X0_X1  = 0xdac11820

# Load/store with various bases
LDR_X0_SP_8  = 0xf94007e0  # ldr x0, [sp, #8]  -- stack source
LDR_X1_SP_10 = 0xf9400be1  # ldr x1, [sp, #0x10]
LDR_X2_SP_18 = 0xf9400fe2  # ldr x2, [sp, #0x18]
LDR_X3_SP_20 = 0xf94013e3  # ldr x3, [sp, #0x20]
LDR_X8_SP_40 = 0xf94023e8  # ldr x8, [sp, #0x40]
LDR_X0_X19_0 = 0xf9400260  # ldr x0, [x19]  -- heap/mem source
LDR_X1_X19_8 = 0xf9400661  # ldr x1, [x19, #8]

# Store to non-stack (heap/global destinations for DOP)
STR_X0_X19_0  = 0xf9000260  # str x0, [x19]
STR_X1_X19_8  = 0xf9000661  # str x1, [x19, #8]
STR_X2_X19_10 = 0xf9000a62  # str x2, [x19, #0x10]
STR_X3_X19_18 = 0xf9000e63  # str x3, [x19, #0x18]
STR_X0_X20_0  = 0xf9000280  # str x0, [x20]
STR_X1_X20_8  = 0xf9000681  # str x1, [x20, #8]
STR_X2_X20_10 = 0xf9000a82  # str x2, [x20, #0x10]
STR_X3_X20_18 = 0xf9000e83  # str x3, [x20, #0x18]
STR_X0_X21_0  = 0xf90002a0  # str x0, [x21]
STR_X1_X21_8  = 0xf90006a1  # str x1, [x21, #8]

# MOV immediates
MOV_X0_1 = 0xd2800020
MOV_X1_2 = 0xd2800041
MOV_X2_3 = 0xd2800062
MOV_X3_4 = 0xd2800083

TEXT_VADDR = 0x400000

def encode_insns(*insns):
    return b''.join(struct.pack('<I', i) for i in insns)

def bl_offset(from_off, to_off):
    """Encode BL with relative offset (in bytes from function start)."""
    delta = (to_off - from_off) >> 2
    return 0x94000000 | (delta & 0x3ffffff)

# Track function positions for BL encoding
funcs = {}
code_parts = []
current_off = 0

def add_func(name, *insns):
    global current_off
    funcs[name] = current_off
    code = encode_insns(*insns)
    code_parts.append((name, code))
    current_off += len(code)
    return current_off - len(code)

# ── Function 1: main - calls server_loop (reachable chain to fork)
# Will patch BL after all functions defined
main_off = add_func('main',
    PACIASP, STP_X29_X30,
    0x94000000,  # bl server_loop (placeholder)
    LDP_X29_X30, AUTIASP, RET
)

# ── Function 2: server_loop - calls handle_request and fork_worker
server_loop_off = add_func('server_loop',
    PACIASP, STP_X29_X30,
    0x94000000,  # bl handle_request (placeholder)
    0x94000000,  # bl fork_worker (placeholder)
    LDP_X29_X30, AUTIASP, RET
)

# ── Function 3: handle_request - calls dispatch_stack and dispatch_const
handle_request_off = add_func('handle_request',
    PACIASP, STP_X29_X30,
    0x94000000,  # bl dispatch_stack (placeholder)
    0x94000000,  # bl dispatch_const (placeholder)
    LDP_X29_X30, AUTIASP, RET
)

# ── Function 4: fork_worker - symbol named 'fork' to trigger fork key detection
fork_worker_off = add_func('fork',
    PACIASP, STP_X29_X30,
    NOP, NOP,
    LDP_X29_X30, AUTIASP, RET
)

# ── Function 5: dispatch_stack - JOP dispatcher with STACK-sourced args
# Dispatcher improvement: args from stack = attacker-controllable
dispatch_stack_off = add_func('dispatch_stack',
    LDR_X0_SP_8,   # x0 from stack -- controllable
    LDR_X1_SP_10,  # x1 from stack -- controllable
    LDR_X2_SP_18,  # x2 from stack -- controllable
    LDR_X3_SP_20,  # x3 from stack -- controllable
    LDR_X8_SP_40,  # branch target from stack
    BR_X8           # JOP dispatch with all stack args
)

# ── Function 6: dispatch_const - JOP dispatcher with CONST-sourced args
# Dispatcher improvement: args from constants = NOT controllable
dispatch_const_off = add_func('dispatch_const',
    MOV_X0_1,       # x0 = 1 -- constant
    MOV_X1_2,       # x1 = 2 -- constant
    MOV_X2_3,       # x2 = 3 -- constant
    MOV_X3_4,       # x3 = 4 -- constant
    LDR_X8_SP_40,   # branch target still from memory
    BR_X8            # JOP dispatch with const args
)

# ── Function 7: dop_hotspot - many non-stack stores, no PAC (DOP target)
# DOP improvement: per-function DOP density
dop_hotspot_off = add_func('dop_hotspot',
    STP_X29_X30,
    LDR_X0_X19_0,   # load from heap
    LDR_X1_X19_8,   # load from heap
    STR_X0_X19_0,   # store to heap (non-stack)
    STR_X1_X19_8,   # store to heap
    STR_X2_X19_10,  # store to heap
    STR_X3_X19_18,  # store to heap
    STR_X0_X20_0,   # store to different obj
    STR_X1_X20_8,   # store to different obj
    STR_X2_X20_10,  # store to different obj
    STR_X3_X20_18,  # store to different obj
    STR_X0_X21_0,   # store to third obj
    STR_X1_X21_8,   # store to third obj
    LDP_X29_X30, RET
)

# ── Function 8: ipac_only - instruction PAC only (no data PAC)
# Data PAC improvement: shows up as "instruction PAC but no data PAC"
ipac_only_off = add_func('ipac_only',
    PACIASP, STP_X29_X30,
    PACIA_X0_X1,
    AUTIA_X0_X1,
    NOP, NOP,
    LDP_X29_X30, AUTIASP, RET
)

# ── Function 9: both_pac - has both instruction AND data PAC
# Data PAC improvement: contrast with ipac_only
both_pac_off = add_func('both_pac',
    PACIASP, STP_X29_X30,
    PACIA_X0_X1,
    AUTIA_X0_X1,
    PACDA_X0_X1,
    AUTDA_X0_X1,
    LDP_X29_X30, AUTIASP, RET
)

# ── Function 10: security_check - symbol name triggers DOP security_globals
security_check_off = add_func('check_credentials',
    PACIASP, STP_X29_X30,
    NOP, NOP,
    LDP_X29_X30, AUTIASP, RET
)

# ── Function 11: auth_token_verify - another security-relevant symbol
auth_token_off = add_func('verify_auth_token',
    PACIASP, STP_X29_X30,
    NOP, NOP,
    LDP_X29_X30, AUTIASP, RET
)

# ── Function 12: arg_sign - signing gadget using function args (inter-procedural test)
STR_X0_SP_8 = 0xf90007e0  # str x0, [sp, #8]
arg_sign_off = add_func('arg_sign',
    PACIA_X0_X1,    # sign using x0/x1 from caller (no local load)
    STR_X0_SP_8,    # store result
    RET
)

# ── Function 13: call_arg_sign - caller that sets x0/x1 then calls arg_sign
LDR_X0_SP_30 = 0xf9401be0  # ldr x0, [sp, #0x30]
call_arg_sign_off = add_func('call_arg_sign',
    PACIASP, STP_X29_X30,
    LDR_X0_SP_30,   # x0 from stack (attacker-controllable)
    LDR_X1_X19_8,   # x1 from heap (memory)
    0x94000000,      # bl arg_sign (placeholder)
    LDP_X29_X30, AUTIASP, RET
)

# ── Function 14: dep_sign - signing gadget where x1 = x0 + 4 (arithmetic dependency)
# Z3 can detect x0 and x1 are NOT independent, heuristic cannot
ADD_X1_X0_4 = 0x91001001  # add x1, x0, #4
dep_sign_off = add_func('dep_sign',
    LDR_X0_SP_8,    # x0 from stack
    ADD_X1_X0_4,    # x1 = x0 + 4 — dependent on x0!
    PACIA_X0_X1,    # sign: key=x1 depends on ptr=x0
    STR_X0_SP_8,    # store result
    RET
)

# ── Function 15: stack_pivot - SP modification before auth
MOV_SP_X0 = 0x9100001f  # mov sp, x0
stack_pivot_off = add_func('stack_pivot',
    PACIASP, STP_X29_X30,
    NOP, NOP,
    MOV_SP_X0,       # attacker controls SP before auth
    LDP_X29_X30, AUTIASP, RET
)

# ── Function 16: key_confused - signs with key A, auths with key B
PACIBSP = 0xd503237f    # pacibsp (key B sign)
AUTIBSP = 0xd50323ff    # autibsp (key B auth)
key_confused_off = add_func('key_confused',
    PACIASP, STP_X29_X30,   # sign with key A (paciasp)
    PACIA_X0_X1,             # more key A signing
    NOP, NOP,
    LDP_X29_X30, AUTIBSP, RET  # auth with key B (autibsp)
)

# ── Function 17: modifier_confused - pacia x0,x1 (register modifier) + autiaz (zero modifier)
PACIA_X0_X1 = 0xdac10020  # pacia x0, x1 (register modifier)
AUTIAZ = 0xd503239f       # autiaz (zero-modifier auth)
modifier_confused_off = add_func('modifier_confused',
    PACIASP, STP_X29_X30,
    PACIA_X0_X1,             # sign data ptr with register modifier
    NOP,
    AUTIAZ,                  # auth data ptr with zero modifier — mismatch!
    LDP_X29_X30, AUTIASP, RET
)

# ── Function 18: context_manip - LR/x30 modification before auth
MOV_X30_X0 = 0xaa0003fe  # mov x30, x0
context_manip_off = add_func('context_manip',
    PACIASP, STP_X29_X30,
    NOP,
    MOV_X30_X0,       # attacker controls LR before auth
    AUTIASP, RET
)

# ── Function 19: xpac_bypass - XPACI then BR (strip without auth, then branch)
XPACI_X8 = 0xdac143e8    # xpaci x8
xpac_bypass_off = add_func('xpac_bypass',
    PACIASP, STP_X29_X30,
    LDR_X8_SP_40,     # load signed pointer from stack
    XPACI_X8,          # strip PAC bits without authenticating
    BR_X8,             # branch to stripped pointer — PAC bypassed
)

# ── Function 20: xpac_safe - XPACI for comparison, auth before branch (NOT a bypass)
CMP_X8_X0 = 0xeb00011f   # cmp x8, x0
XPACI_X0  = 0xdac143e0   # xpaci x0
xpac_safe_off = add_func('xpac_safe',
    PACIASP, STP_X29_X30,
    XPACI_X0,          # strip for comparison only
    CMP_X8_X0,         # compare stripped pointer
    NOP,
    LDP_X29_X30, AUTIASP, RET  # proper auth on return
)

# ── Function 21: xpaclri_bypass - XPACLRI then RET (strip LR without auth)
XPACLRI = 0xd50320ff     # xpaclri
xpaclri_bypass_off = add_func('xpaclri_bypass',
    PACIASP, STP_X29_X30,
    NOP, NOP,
    LDP_X29_X30,
    XPACLRI,            # strip LR PAC bits without authenticating
    RET,                # return to stripped LR — PAC bypassed
)

# Now patch BL instructions with correct offsets
def patch_bl(func_name, insn_idx, target_name):
    """Patch a BL instruction in a function to point to target."""
    src_off = funcs[func_name] + insn_idx * 4
    dst_off = funcs[target_name]
    delta = (dst_off - src_off) >> 2
    return 0x94000000 | (delta & 0x3ffffff)

# Rebuild code with patched BLs
text_code = bytearray()
for name, code in code_parts:
    text_code.extend(code)

# Patch: main -> server_loop (insn index 2)
off = funcs['main'] + 2 * 4
struct.pack_into('<I', text_code, off, patch_bl('main', 2, 'server_loop'))

# Patch: server_loop -> handle_request (insn index 2)
off = funcs['server_loop'] + 2 * 4
struct.pack_into('<I', text_code, off, patch_bl('server_loop', 2, 'handle_request'))

# Patch: server_loop -> fork (insn index 3)
off = funcs['server_loop'] + 3 * 4
struct.pack_into('<I', text_code, off, patch_bl('server_loop', 3, 'fork'))

# Patch: handle_request -> dispatch_stack (insn index 2)
off = funcs['handle_request'] + 2 * 4
struct.pack_into('<I', text_code, off, patch_bl('handle_request', 2, 'dispatch_stack'))

# Patch: handle_request -> dispatch_const (insn index 3)
off = funcs['handle_request'] + 3 * 4
struct.pack_into('<I', text_code, off, patch_bl('handle_request', 3, 'dispatch_const'))

# Patch: call_arg_sign -> arg_sign (insn index 4)
off = funcs['call_arg_sign'] + 4 * 4
struct.pack_into('<I', text_code, off, patch_bl('call_arg_sign', 4, 'arg_sign'))

text_code = bytes(text_code)

# ── Build ELF ──
shstrtab = b'\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00'
sh_text_name = shstrtab.index(b'.text\x00')
sh_symtab_name = shstrtab.index(b'.symtab\x00')
sh_strtab_name = shstrtab.index(b'.strtab\x00')
sh_shstrtab_name = shstrtab.index(b'.shstrtab\x00')

strtab = b'\x00'
sym_name_offsets = {}
for name in funcs:
    sym_name_offsets[name] = len(strtab)
    strtab += name.encode() + b'\x00'

STT_FUNC = 2
STB_GLOBAL = 1
def elf64_sym(name_idx, value, size, bind, typ, shndx):
    info = (bind << 4) | typ
    return struct.pack('<IBBHQQ', name_idx, info, 0, shndx, value, size)

symtab = elf64_sym(0, 0, 0, 0, 0, 0)
for name, off in sorted(funcs.items(), key=lambda x: x[1]):
    symtab += elf64_sym(sym_name_offsets[name], TEXT_VADDR + off, 32, STB_GLOBAL, STT_FUNC, 1)

ehdr_size = 64
phdr_size = 56
text_offset = 0x100
text_size = len(text_code)
symtab_offset = text_offset + text_size
symtab_size = len(symtab)
strtab_offset = symtab_offset + symtab_size
strtab_size = len(strtab)
shstrtab_offset = strtab_offset + strtab_size
shstrtab_size = len(shstrtab)
shdr_offset = (shstrtab_offset + shstrtab_size + 7) & ~7
num_sections = 5

ehdr = struct.pack('<4sBBBB8sHHIQQQIHHHHHH',
    b'\x7fELF', 2, 1, 1, 0, b'\x00'*8,
    2, 183, 1,
    TEXT_VADDR, ehdr_size, shdr_offset,
    0, ehdr_size, phdr_size, 1,
    64, num_sections, 4)

phdr = struct.pack('<IIQQQQQQ',
    1, 5,
    text_offset, TEXT_VADDR, TEXT_VADDR,
    text_size, text_size, 0x1000)

def shdr(name, typ, flags, addr, offset, size, link=0, info=0, addralign=4, entsize=0):
    return struct.pack('<IIQQQQIIqq',
        name, typ, flags, addr, offset, size, link, info, addralign, entsize)

shdrs = b''
shdrs += shdr(0, 0, 0, 0, 0, 0)
shdrs += shdr(sh_text_name, 1, 6, TEXT_VADDR, text_offset, text_size)
shdrs += shdr(sh_symtab_name, 2, 0, 0, symtab_offset, symtab_size, link=3, info=1, entsize=24)
shdrs += shdr(sh_strtab_name, 3, 0, 0, strtab_offset, strtab_size)
shdrs += shdr(sh_shstrtab_name, 3, 0, 0, shstrtab_offset, shstrtab_size)

out = bytearray(shdr_offset + num_sections * 64)
out[:ehdr_size] = ehdr
out[ehdr_size:ehdr_size+phdr_size] = phdr
out[text_offset:text_offset+text_size] = text_code
out[symtab_offset:symtab_offset+symtab_size] = symtab
out[strtab_offset:strtab_offset+strtab_size] = strtab
out[shstrtab_offset:shstrtab_offset+shstrtab_size] = shstrtab
out[shdr_offset:shdr_offset+len(shdrs)] = shdrs

outpath = sys.argv[1] if len(sys.argv) > 1 else 'pac_test_improvements'
with open(outpath, 'wb') as f:
    f.write(out)
print(f"Generated {outpath}: {len(out)} bytes, {len(text_code)//4} instructions, {len(funcs)} functions")
print(f"Functions: {list(funcs.keys())}")
