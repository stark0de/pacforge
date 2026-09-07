#!/usr/bin/env python3
"""
PACForge - ARM64 Pointer Authentication Bypass Toolkit

35 analysis modules covering PAC attack surfaces and mitigation failures:
  1. Signing gadget discovery
  2. PAC oracle detection
  3. Cross-function chain analysis
  4. PACMAN speculative gadgets
  5. Brute-force feasibility
  6. SCTLR manipulation detection
  7. Data vs instruction PAC split
  8. EL key separation detection
  9. JOP dispatcher detection
  10. Zero-context pair correlation
  11. Composability scoring
  12. Key diversity analysis
  13. Auth pointer inventory
  14. PAC transition mapping
  15. FPAC status
  16. Return signing coverage
  17. Constraint analysis
  18. BTI+PAC combined analysis
  19. Auth-to-use TOCTTOU window
  20. Context/modifier entropy
  21. Diversifier reuse
  22. COP callback indirection
  23. Fork/thread key inheritance
  24. setjmp/longjmp PAC risks
  25. JIT/dynamic code PAC surface
  26. Dynamic linker signing surface
  27. Stack protection mode
  28. DOP surface estimator
  29. QARMA3 cryptanalysis risk
  30. Stack pivot gadgets
  31. Key confusion detection
  32. Modifier confusion detection
  33. Context manipulation detection
  34. Pre-auth pointer loads
  35. XPAC strip-and-branch detection

Usage:
  python3 pacforge.py <binary> --all
  python3 pacforge.py <binary> --signing-gadgets --oracles
  python3 pacforge.py <binary> --chain-suggest
  python3 pacforge.py <binary> --json > report.json
"""
import argparse
import bisect
import functools
import gzip
import hashlib
import io
import json
import platform
import struct
import subprocess
import sys
import re
from collections import defaultdict
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Set

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.relocation import RelocationSection
    HAS_PYELFTOOLS = True
except ImportError:
    HAS_PYELFTOOLS = False

try:
    import capstone
    from capstone import Cs, CsInsn
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False


PACFORGE_VERSION = '2.0.0'
DETECTION_MODULES = 35
CPU_TYPE_ARM64 = 0x0100000C


class PacForgeError(Exception):
    """Base class for user-facing analysis errors."""


class UnsupportedBinaryError(PacForgeError):
    """Raised when input is not a supported AArch64 ELF/Mach-O image."""


class MalformedBinaryError(PacForgeError):
    """Raised when a recognized container is truncated or internally invalid."""


class DependencyError(PacForgeError):
    """Raised when a required parser/disassembler dependency is unavailable."""


def cached_analysis(fn):
    """Memoize no-argument analysis methods for one immutable analyzer instance."""
    @functools.wraps(fn)
    def wrapped(self, *args, **kwargs):
        if args or kwargs:
            return fn(self, *args, **kwargs)
        cache = getattr(self, '_analysis_cache', None)
        if cache is None:
            return fn(self)
        if fn.__name__ not in cache:
            cache[fn.__name__] = fn(self)
        return cache[fn.__name__]
    return wrapped


def _read_uleb(data: bytes, offset: int, limit: Optional[int] = None) -> Tuple[int, int]:
    """Read one bounded unsigned LEB128 value."""
    end = len(data) if limit is None else min(limit, len(data))
    value = 0
    shift = 0
    while offset < end and shift < 70:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
    raise MalformedBinaryError('truncated or oversized ULEB128 value')


# ── Instruction classification sets ──────────────────────────────────────

PAC_SIGN_A = {'paciasp', 'paciaz', 'pacia', 'pacia1716', 'paciza'}
PAC_SIGN_B = {'pacibsp', 'pacibz', 'pacib', 'pacib1716', 'pacizb'}
PAC_SIGN_DA = {'pacda', 'pacdza'}
PAC_SIGN_DB = {'pacdb', 'pacdzb'}
PAC_SIGN_ALL = PAC_SIGN_A | PAC_SIGN_B | PAC_SIGN_DA | PAC_SIGN_DB

PAC_AUTH_A = {'autiasp', 'autiaz', 'autia', 'autia1716', 'autiza'}
PAC_AUTH_B = {'autibsp', 'autibz', 'autib', 'autib1716', 'autizb'}
PAC_AUTH_LOAD_DA = {'ldraa'}
PAC_AUTH_LOAD_DB = {'ldrab'}
PAC_AUTH_LOAD = PAC_AUTH_LOAD_DA | PAC_AUTH_LOAD_DB
PAC_AUTH_DA = {'autda', 'autdza'} | PAC_AUTH_LOAD_DA
PAC_AUTH_DB = {'autdb', 'autdzb'} | PAC_AUTH_LOAD_DB
PAC_AUTH_ALL = PAC_AUTH_A | PAC_AUTH_B | PAC_AUTH_DA | PAC_AUTH_DB

PAC_AUTH_RET = {'retaa', 'retab', 'eretaa', 'eretab'}
PAC_AUTH_BR = {'braa', 'brab', 'blraa', 'blrab'}
PAC_AUTH_BR_Z = {'braaz', 'brabz', 'blraaz', 'blrabz'}

PAC_ZERO_CTX_SIGN = {'paciaz', 'pacibz', 'pacdza', 'pacdzb', 'paciza', 'pacizb'}
PAC_ZERO_CTX_AUTH = ({'autiaz', 'autibz', 'autdza', 'autdzb', 'autiza', 'autizb'} |
                     PAC_AUTH_BR_Z | PAC_AUTH_LOAD)
PAC_SP_CTX_SIGN = {'paciasp', 'pacibsp'}
PAC_SP_CTX_AUTH = {'autiasp', 'autibsp'}

PAC_ALL = PAC_SIGN_ALL | PAC_AUTH_ALL | PAC_AUTH_RET | PAC_AUTH_BR | PAC_AUTH_BR_Z

PAC_INSTRUCTION_KEY = PAC_SIGN_A | PAC_SIGN_B | PAC_AUTH_A | PAC_AUTH_B
PAC_DATA_KEY = PAC_SIGN_DA | PAC_SIGN_DB | PAC_AUTH_DA | PAC_AUTH_DB

BTI_MNEMONICS = {'bti'}
STRIP_MNEMONICS = {'xpaclri', 'xpaci', 'xpacd'}

INDIRECT_BRANCH = {'br', 'blr'} | PAC_AUTH_BR | PAC_AUTH_BR_Z
RET_INSNS = {'ret'} | PAC_AUTH_RET

PROLOGUE_PAC = {'paciasp', 'pacibsp'}
EPILOGUE_PAC = {'autiasp', 'autibsp'} | PAC_AUTH_RET

KERNEL_SYMBOLS = frozenset({
    'do_syscall_64', 'sys_call_table', 'start_kernel', 'rest_init',
    'kernel_init', 'cpu_do_idle', 'schedule', 'do_page_fault',
    'vbar_el1', '__exception_text_start', 'cpu_switch_to',
    '__primary_switched', 'el1_irq', 'el0_sync',
})

RUNTIME_FUNC_PATTERNS = (
    'uw_update_context', 'uw_init_context', '_Unwind_',
    '__gnu_unwind', '__gcc_personality', '_dl_runtime',
    '__libc_csu', '__gmon_start', 'frame_dummy',
    'register_tm_clones', 'deregister_tm_clones',
)


# ── Data classes ─────────────────────────────────────────────────────────

@dataclass
class SigningGadget:
    address: int
    function: str
    instructions: List[str]
    pac_mnemonic: str
    controlled_regs: List[str]
    stores_result: bool
    store_target: str
    difficulty: str  # easy / medium / hard

@dataclass
class PacOracle:
    address: int
    function: str
    instructions: List[str]
    auth_mnemonic: str
    sign_mnemonic: str
    result_destination: str
    notes: str

@dataclass
class JopDispatcher:
    address: int
    instructions: List[str]
    arg_regs_set: List[str]
    branch_reg: str
    category: str  # dispatcher / trampoline / functional
    arg_sources: Dict[str, str] = field(default_factory=dict)
    branch_source: str = 'unknown'
    function: str = ''

@dataclass
class PacTransition:
    sign_func: str
    sign_addr: int
    auth_func: str
    auth_addr: int
    key_type: str
    notes: str

@dataclass
class AuthPointerEntry:
    section: str
    offset: int
    virtual_addr: int
    target_name: str
    key_hint: str

@dataclass
class FunctionPacInfo:
    name: str
    address: int
    has_pac_prologue: bool
    pac_type: str
    has_bti: bool
    has_pac_epilogue: bool
    epilogue_type: str

@dataclass
class ComposabilityScore:
    signing_gadgets: int
    oracles: int
    arg_control: int
    branch_control: int
    stack_pivot: int
    preauth_unsigned: int
    key_confusion: int
    modifier_confusion: int
    context_manip: int
    xpac_bypass: int
    zero_ctx: int
    coverage_pct: float
    score: float  # 0-100
    verdict: str
    missing: List[str]
    breakdown: Dict[str, float]


# ── Main analyzer ────────────────────────────────────────────────────────

class PacAnalyzer:
    def __init__(self, path: str, verbose: bool = False, suppress_file: str = None,
                 deep: bool = False, libs: str = None, symbolic: bool = False,
                 raw_arm64: bool = False, va_bits: Optional[int] = None,
                 fpac: str = 'auto', qarma_variant: str = 'auto'):
        self.path = Path(path)
        self.verbose = verbose
        # Library correlation and symbolic propagation depend on the CFG/deep
        # indexes. Keep that invariant true for API callers as well as the CLI.
        self.deep = deep or symbolic or bool(libs)
        self.symbolic = symbolic
        self.libs = libs
        self.raw_arm64 = raw_arm64
        if va_bits is not None and va_bits not in (32, 36, 39, 42, 48, 52, 56):
            raise ValueError('va_bits must be one of 32, 36, 39, 42, 48, 52, 56')
        if fpac not in ('auto', 'yes', 'no'):
            raise ValueError('fpac must be auto, yes, or no')
        if qarma_variant not in ('auto', 'qarma3', 'qarma5'):
            raise ValueError('qarma_variant must be auto, qarma3, or qarma5')
        self.va_bits_override = va_bits
        self.fpac_override = fpac
        self.qarma_variant = qarma_variant
        self.raw = self.path.read_bytes()
        self.binary_sha256 = hashlib.sha256(self.raw).hexdigest()
        self.is_elf = self.raw[:4] == b'\x7fELF'
        self.is_macho = self.raw[:4] in (
            b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe',
            b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
            b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
            b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca',
        )
        self.sections = []          # (name, vaddr, data_bytes)
        self.data_sections = []     # (name, vaddr, size, data_bytes)
        self.section_meta = []      # section name/address/size/segment/permissions
        self.segment_meta = []      # segment vm/file ranges and permissions
        self.auth_pointer_metadata = []
        self.chained_fixups_present = False
        self._binary_endian = 'little'
        self.symbols = {}           # name -> addr
        self.symbol_types = {}      # name -> loader-specific symbol type
        self.data_symbols = {}      # data-object name -> address
        self.imports = set()
        self.insns = []             # list of (addr, mnemonic, op_str, size)
        self.insn_meta = {}          # addr -> capstone regs/groups metadata
        self.func_boundaries = {}   # addr -> name
        self.stub_ranges = []       # [(start, end)] for __stubs/__stub_helper/PLT
        self.stub_symbols = {}      # stub address -> imported symbol name
        self.macho_filetype = None  # 'executable', 'dylib', 'bundle' for Mach-O
        self.is_arm64e = False      # Mach-O arm64e subtype (PAC-enabled ABI)
        self._analysis_cache = {}
        self.suppressions = self._load_suppressions(suppress_file)
        self.cs = None

        self._load()
        self._disassemble()
        self._build_indexes()
        self._build_call_graph()
        if self.deep:
            self._build_cfg()
            self._resolve_indirect_calls()
            self._propagate_constants()
            if self.libs:
                self._resolve_cross_binary(self.libs)
            if self.symbolic:
                self._build_symbolic_maps()

    def _load_suppressions(self, path):
        if not path:
            return {'rules': [], 'legacy_addresses': set(),
                    'legacy_functions': set(), 'legacy_patterns': []}
        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError('suppression file must contain a JSON object')
            bound_hash = data.get('binary_sha256')
            if bound_hash and bound_hash.lower() != self.binary_sha256:
                raise ValueError('suppression file belongs to a different binary (SHA-256 mismatch)')
            rules = []
            for rule in data.get('rules', []):
                if not isinstance(rule, dict):
                    raise ValueError('every suppression rule must be an object')
                normalized = dict(rule)
                if 'address' in normalized:
                    address = normalized['address']
                    normalized['address'] = int(address, 0) if isinstance(address, str) else int(address)
                rules.append(normalized)
            return {
                'rules': rules,
                'legacy_addresses': {
                    int(a, 0) if isinstance(a, str) else int(a)
                    for a in data.get('addresses', [])
                },
                'legacy_functions': set(data.get('functions', [])),
                'legacy_patterns': data.get('patterns', []),
            }
        except (FileNotFoundError, json.JSONDecodeError, TypeError, ValueError) as e:
            print(f"Warning: could not load suppressions from {path}: {e}")
            return {'rules': [], 'legacy_addresses': set(),
                    'legacy_functions': set(), 'legacy_patterns': []}

    def _is_suppressed(self, addr: int, func: str = '', finding_type: str = '') -> bool:
        for rule in self.suppressions['rules']:
            if rule.get('type') and rule['type'] != finding_type:
                continue
            if 'address' in rule and rule['address'] != addr:
                continue
            if rule.get('function') and rule['function'] != func:
                continue
            if rule.get('function_prefix') and not func.startswith(rule['function_prefix']):
                continue
            return True
        if addr in self.suppressions['legacy_addresses']:
            return True
        if func and func in self.suppressions['legacy_functions']:
            return True
        for pat in self.suppressions['legacy_patterns']:
            pattern_type = pat.get('type', '')
            if pattern_type and pattern_type != finding_type:
                continue
            if pat.get('function_prefix') and func.startswith(pat['function_prefix']):
                return True
        return False

    # ── Loading ──────────────────────────────────────────────────────

    def _load(self):
        if self.is_elf:
            if not HAS_PYELFTOOLS:
                raise DependencyError('pyelftools is required to validate and parse ELF files')
            self._load_elf()
        elif self.is_macho:
            self._load_macho_minimal()
        elif self.raw_arm64:
            self._load_raw()
        else:
            raise UnsupportedBinaryError(
                'unsupported input; expected an AArch64 ELF or 64-bit Mach-O '
                '(use --raw-arm64 only for headerless ARM64 code)')

    def _load_elf(self):
        try:
            with open(self.path, 'rb') as f:
                elf = ELFFile(f)
                if elf.elfclass != 64 or elf.header.e_machine != 'EM_AARCH64':
                    raise UnsupportedBinaryError(
                        f'unsupported ELF architecture: class={elf.elfclass}, '
                        f'machine={elf.header.e_machine}; PACForge requires AArch64')
                self._binary_endian = 'little' if elf.little_endian else 'big'

                section_rows = list(elf.iter_sections())
                executable_indices = set()
                allocated_data_indices = set()
                for index, section in enumerate(section_rows):
                    name = section.name
                    flags = int(section.header.sh_flags)
                    addr = int(section.header.sh_addr)
                    try:
                        section_data = section.data()
                    except (OSError, ValueError, TypeError) as exc:
                        if self.verbose:
                            print(f'Warning: cannot read ELF section {name}: {exc}', file=sys.stderr)
                        continue
                    is_exec = bool(flags & 0x4)
                    is_alloc = bool(flags & 0x2)
                    if is_exec:
                        executable_indices.add(index)
                        self.sections.append((name, addr, section_data))
                        if name in ('.plt', '.plt.got', '.plt.sec'):
                            self.stub_ranges.append((addr, addr + len(section_data)))
                    elif is_alloc and section.header.sh_type != 'SHT_NOBITS':
                        allocated_data_indices.add(index)
                        self.data_sections.append((name, addr, len(section_data), section_data))
                    self.section_meta.append({
                        'name': name, 'segment': '', 'address': addr,
                        'size': len(section_data), 'readable': is_alloc,
                        'writable': bool(flags & 0x1), 'executable': is_exec,
                    })

                for section in section_rows:
                    if not isinstance(section, SymbolTableSection):
                        continue
                    for sym in section.iter_symbols():
                        if not sym.name:
                            continue
                        val = int(sym.entry.st_value)
                        self.symbols[sym.name] = val
                        sym_type = str(sym.entry.st_info.type)
                        self.symbol_types[sym.name] = sym_type
                        if not val:
                            self.imports.add(sym.name)
                            continue
                        shndx = sym.entry.st_shndx
                        if (sym_type == 'STT_FUNC' and
                                isinstance(shndx, int) and shndx in executable_indices):
                            self.func_boundaries[val] = sym.name
                        elif (sym_type in ('STT_OBJECT', 'STT_COMMON') and
                              isinstance(shndx, int) and shndx in allocated_data_indices):
                            self.data_symbols[sym.name] = val

                # Associate AArch64 PLT entries with the relocations that name
                # their imported symbols. This turns BL-to-stub sites into
                # named calls for setjmp/fork/JIT/linker/canary analysis.
                plt = next((s for s in section_rows if s.name == '.plt.sec'), None)
                plt_has_resolver = False
                if plt is None:
                    plt = next((s for s in section_rows if s.name == '.plt'), None)
                    plt_has_resolver = plt is not None
                if plt is not None:
                    entry_size = int(plt.header.sh_entsize) or 16
                    plt_addr = int(plt.header.sh_addr)
                    plt_size = int(plt.header.sh_size)
                    relocations = [s for s in section_rows
                                   if isinstance(s, RelocationSection) and 'plt' in s.name]
                    reloc_index = 0
                    for relsec in relocations:
                        symtab = elf.get_section(relsec.header.sh_link)
                        if symtab is None:
                            continue
                        for rel in relsec.iter_relocations():
                            symbol = symtab.get_symbol(rel.entry.r_info_sym)
                            if not symbol.name:
                                continue
                            slot = reloc_index + (1 if plt_has_resolver else 0)
                            stub_addr = plt_addr + slot * entry_size
                            if stub_addr < plt_addr + plt_size:
                                self.stub_symbols[stub_addr] = symbol.name
                            reloc_index += 1

                for segment in elf.iter_segments():
                    if segment.header.p_type != 'PT_LOAD':
                        continue
                    flags = int(segment.header.p_flags)
                    self.segment_meta.append({
                        'name': 'PT_LOAD', 'vmaddr': int(segment.header.p_vaddr),
                        'vmsize': int(segment.header.p_memsz),
                        'fileoff': int(segment.header.p_offset),
                        'filesize': int(segment.header.p_filesz),
                        'readable': bool(flags & 4), 'writable': bool(flags & 2),
                        'executable': bool(flags & 1),
                    })
        except UnsupportedBinaryError:
            raise
        except Exception as exc:
            raise MalformedBinaryError(f'invalid ELF file: {exc}') from exc

    def _load_macho_minimal(self):
        """Bounds-checked 64-bit Mach-O loader with fat32/fat64 support."""
        data = self._select_macho_slice(self.raw)
        if len(data) < 32:
            raise MalformedBinaryError('truncated Mach-O header')
        magic = data[:4]
        if magic == b'\xcf\xfa\xed\xfe':
            endian = '<'
        elif magic == b'\xfe\xed\xfa\xcf':
            endian = '>'
        elif magic in (b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xce'):
            raise UnsupportedBinaryError('32-bit Mach-O is unsupported; PAC requires AArch64')
        else:
            raise MalformedBinaryError('fat slice is not a 64-bit Mach-O image')
        self._binary_endian = 'little' if endian == '<' else 'big'

        cputype, cpusubtype, filetype, ncmds, sizeofcmds = struct.unpack_from(
            f'{endian}iiIII', data, 4)
        if cputype != CPU_TYPE_ARM64:
            raise UnsupportedBinaryError(f'unsupported Mach-O CPU type: {cputype:#x}')
        if ncmds > 65535 or 32 + sizeofcmds > len(data):
            raise MalformedBinaryError('invalid Mach-O load-command table')
        self.is_arm64e = self.is_arm64e or ((cpusubtype & 0xff) == 2)
        self.macho_filetype = {2: 'executable', 6: 'dylib', 8: 'bundle',
                               11: 'kext_bundle', 12: 'fileset'}.get(filetype, f'type_{filetype}')

        commands = []
        offset = 32
        command_end = 32 + sizeofcmds
        for _ in range(ncmds):
            if offset + 8 > command_end:
                raise MalformedBinaryError('truncated Mach-O load command')
            cmd, cmdsize = struct.unpack_from(f'{endian}II', data, offset)
            if cmdsize < 8 or offset + cmdsize > command_end:
                raise MalformedBinaryError(f'invalid Mach-O command size {cmdsize} at {offset:#x}')
            commands.append((cmd, offset, cmdsize))
            offset += cmdsize

        section_number = 0
        text_vmaddr = None
        for cmd, cmd_off, cmdsize in commands:
            if cmd != 0x19:
                continue
            if cmdsize < 72:
                raise MalformedBinaryError('truncated LC_SEGMENT_64')
            segname = data[cmd_off + 8:cmd_off + 24].split(b'\0')[0].decode('utf-8', 'replace')
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(f'{endian}QQQQ', data, cmd_off + 24)
            maxprot, initprot, nsects = struct.unpack_from(f'{endian}iiI', data, cmd_off + 56)
            if nsects > 65535 or 72 + nsects * 80 > cmdsize:
                raise MalformedBinaryError(f'invalid section count in segment {segname}')
            if filesize and (fileoff > len(data) or filesize > len(data) - fileoff):
                raise MalformedBinaryError(f'segment {segname} exceeds file bounds')
            segment = {
                'name': segname, 'vmaddr': vmaddr, 'vmsize': vmsize,
                'fileoff': fileoff, 'filesize': filesize,
                'readable': bool(initprot & 1), 'writable': bool(initprot & 2),
                'executable': bool(initprot & 4), 'maxprot': maxprot,
            }
            self.segment_meta.append(segment)
            if segname == '__TEXT':
                text_vmaddr = vmaddr
            sect_off = cmd_off + 72
            for _ in range(nsects):
                section_number += 1
                sectname = data[sect_off:sect_off + 16].split(b'\0')[0].decode('utf-8', 'replace')
                section_seg = data[sect_off + 16:sect_off + 32].split(b'\0')[0].decode('utf-8', 'replace')
                addr, size = struct.unpack_from(f'{endian}QQ', data, sect_off + 32)
                file_offset, align, _, _, flags = struct.unpack_from(f'{endian}IIIII', data, sect_off + 48)
                reserved1, reserved2, reserved3 = struct.unpack_from(f'{endian}III', data, sect_off + 68)
                section_type = flags & 0xff
                zerofill = section_type in (1, 2, 12, 18)
                if not zerofill and size and (file_offset > len(data) or size > len(data) - file_offset):
                    raise MalformedBinaryError(f'section {section_seg},{sectname} exceeds file bounds')
                section_data = b'' if zerofill else data[file_offset:file_offset + size]
                is_exec = bool(initprot & 4) and (
                    sectname.startswith('__text') or sectname in ('__stubs', '__stub_helper', '__auth_stubs')
                    or bool(flags & (0x80000000 | 0x00000400)))
                self.section_meta.append({
                    'index': section_number, 'name': sectname, 'segment': section_seg,
                    'address': addr, 'size': size, 'file_offset': file_offset,
                    'align': align, 'flags': flags, 'readable': bool(initprot & 1),
                    'writable': bool(initprot & 2), 'executable': is_exec,
                    'reserved1': reserved1, 'reserved2': reserved2,
                    'reserved3': reserved3,
                })
                if is_exec:
                    self.sections.append((sectname, addr, section_data))
                    if sectname in ('__stubs', '__stub_helper', '__auth_stubs'):
                        self.stub_ranges.append((addr, addr + size))
                elif not zerofill:
                    self.data_sections.append((sectname, addr, size, section_data))
                sect_off += 80

        code_ranges = [(start, start + len(blob)) for _, start, blob in self.sections]
        macho_symbol_names = []
        symtab_cmd = next((entry for entry in commands if entry[0] == 0x02), None)
        if symtab_cmd:
            _, cmd_off, cmdsize = symtab_cmd
            if cmdsize < 24:
                raise MalformedBinaryError('truncated LC_SYMTAB')
            symoff, nsyms, stroff, strsize = struct.unpack_from(f'{endian}IIII', data, cmd_off + 8)
            if (nsyms > len(data) // 16 or symoff > len(data) or
                    nsyms * 16 > len(data) - symoff or stroff > len(data) or strsize > len(data) - stroff):
                raise MalformedBinaryError('invalid Mach-O symbol/string table bounds')
            strtab = data[stroff:stroff + strsize]
            for index in range(nsyms):
                nlist_off = symoff + index * 16
                str_idx, ntype, sect_num, _, value = struct.unpack_from(f'{endian}IBBHQ', data, nlist_off)
                if str_idx >= len(strtab):
                    macho_symbol_names.append('')
                    continue
                end = strtab.find(b'\0', str_idx)
                if end < 0:
                    end = len(strtab)
                name = strtab[str_idx:end].decode('utf-8', 'replace')
                if name.startswith('_'):
                    name = name[1:]
                if not name:
                    macho_symbol_names.append('')
                    continue
                macho_symbol_names.append(name)
                self.symbols[name] = value
                self.symbol_types[name] = f'nlist:{ntype:#x}'
                if (ntype & 0x0e) == 0:
                    self.imports.add(name)
                if value and (ntype & 0x0e) == 0x0e and any(lo <= value < hi for lo, hi in code_ranges):
                    self.func_boundaries[value] = name
                elif value and (ntype & 0x0e) == 0x0e:
                    section = next((meta for meta in self.section_meta
                                    if meta.get('index') == sect_num), None)
                    if section and not section.get('executable'):
                        self.data_symbols[name] = value

        # Resolve lazy/non-lazy/authenticated stubs using LC_DYSYMTAB's
        # indirect symbol table and each section's reserved1/reserved2 fields.
        dysymtab_cmd = next((entry for entry in commands if entry[0] == 0x0b), None)
        if dysymtab_cmd and macho_symbol_names:
            _, cmd_off, cmdsize = dysymtab_cmd
            if cmdsize < 80:
                raise MalformedBinaryError('truncated LC_DYSYMTAB')
            indirect_off, indirect_count = struct.unpack_from(f'{endian}II', data, cmd_off + 56)
            if (indirect_off > len(data) or indirect_count > len(data) // 4 or
                    indirect_count * 4 > len(data) - indirect_off):
                raise MalformedBinaryError('invalid Mach-O indirect symbol table bounds')
            indirect = struct.unpack_from(
                f'{endian}{indirect_count}I', data, indirect_off) if indirect_count else ()
            for section in self.section_meta:
                if (section.get('flags', 0) & 0xff) != 0x8:  # S_SYMBOL_STUBS
                    continue
                stride = section.get('reserved2', 0)
                if stride <= 0:
                    continue
                count = section['size'] // stride
                first = section.get('reserved1', 0)
                for index in range(count):
                    indirect_index = first + index
                    if indirect_index >= len(indirect):
                        break
                    symbol_index = indirect[indirect_index]
                    if symbol_index & 0xC0000000 or symbol_index >= len(macho_symbol_names):
                        continue
                    symbol = macho_symbol_names[symbol_index]
                    if symbol:
                        self.stub_symbols[section['address'] + index * stride] = symbol

        for cmd, cmd_off, cmdsize in commands:
            if cmd == 0x26 and cmdsize >= 16 and text_vmaddr is not None:  # LC_FUNCTION_STARTS
                dataoff, datasize = struct.unpack_from(f'{endian}II', data, cmd_off + 8)
                if dataoff > len(data) or datasize > len(data) - dataoff:
                    raise MalformedBinaryError('LC_FUNCTION_STARTS exceeds file bounds')
                cursor, end, running = dataoff, dataoff + datasize, 0
                while cursor < end:
                    delta, cursor = _read_uleb(data, cursor, end)
                    if delta == 0:
                        break
                    running += delta
                    address = text_vmaddr + running
                    if any(lo <= address < hi for lo, hi in code_ranges):
                        self.func_boundaries.setdefault(address, f'sub_{address:x}')
            elif cmd == 0x80000033 and cmdsize >= 16:  # LC_DYLD_EXPORTS_TRIE
                dataoff, datasize = struct.unpack_from(f'{endian}II', data, cmd_off + 8)
                self._load_export_trie(data, dataoff, datasize, text_vmaddr or 0)
            elif cmd == 0x80000022 and cmdsize >= 48:  # LC_DYLD_INFO_ONLY
                export_off, export_size = struct.unpack_from(f'{endian}II', data, cmd_off + 40)
                self._load_export_trie(data, export_off, export_size, text_vmaddr or 0)
            elif cmd == 0x80000034 and cmdsize >= 16:  # LC_DYLD_CHAINED_FIXUPS
                dataoff, datasize = struct.unpack_from(f'{endian}II', data, cmd_off + 8)
                self.chained_fixups_present = True
                self._load_chained_fixups(data, dataoff, datasize, endian)

        self._reconcile_exported_functions()
        if not self.sections:
            raise UnsupportedBinaryError('Mach-O contains no executable ARM64 sections')

    @staticmethod
    def _select_macho_slice(data: bytes) -> bytes:
        if len(data) < 4:
            raise MalformedBinaryError('truncated Mach-O magic')
        formats = {
            b'\xca\xfe\xba\xbe': ('>', 20), b'\xbe\xba\xfe\xca': ('<', 20),
            b'\xca\xfe\xba\xbf': ('>', 32), b'\xbf\xba\xfe\xca': ('<', 32),
        }
        if data[:4] not in formats:
            return data
        if len(data) < 8:
            raise MalformedBinaryError('truncated fat Mach-O header')
        endian, entry_size = formats[data[:4]]
        nfat = struct.unpack_from(f'{endian}I', data, 4)[0]
        if nfat == 0 or nfat > 4096 or 8 + nfat * entry_size > len(data):
            raise MalformedBinaryError('invalid fat Mach-O architecture table')
        candidates = []
        for index in range(nfat):
            entry = 8 + index * entry_size
            cputype, subtype = struct.unpack_from(f'{endian}ii', data, entry)
            if entry_size == 20:
                slice_off, size = struct.unpack_from(f'{endian}II', data, entry + 8)
            else:
                slice_off, size = struct.unpack_from(f'{endian}QQ', data, entry + 8)
            if slice_off > len(data) or size > len(data) - slice_off:
                raise MalformedBinaryError('fat Mach-O slice exceeds file bounds')
            if cputype == CPU_TYPE_ARM64:
                candidates.append((bool((subtype & 0xff) == 2), slice_off, size))
        if not candidates:
            raise UnsupportedBinaryError('fat Mach-O has no ARM64 slice')
        _, slice_off, size = max(candidates, key=lambda item: item[0])
        return data[slice_off:slice_off + size]

    @staticmethod
    def _parse_export_trie_symbols(data: bytes, dataoff: int,
                                   datasize: int, base: int) -> Dict[str, int]:
        if not datasize:
            return {}
        if dataoff > len(data) or datasize > len(data) - dataoff:
            raise MalformedBinaryError('export trie exceeds file bounds')
        blob = data[dataoff:dataoff + datasize]
        symbols = {}
        pending = [(0, '')]
        visited = set()
        while pending and len(visited) < 1_000_000:
            node_off, prefix = pending.pop()
            if node_off in visited or node_off >= len(blob):
                continue
            visited.add(node_off)
            terminal_size, cursor = _read_uleb(blob, node_off)
            terminal_end = cursor + terminal_size
            if terminal_end > len(blob):
                raise MalformedBinaryError('truncated export trie terminal')
            if terminal_size and prefix:
                flags, payload = _read_uleb(blob, cursor, terminal_end)
                if not flags & 0x08:
                    address, _ = _read_uleb(blob, payload, terminal_end)
                    clean = prefix[1:] if prefix.startswith('_') else prefix
                    symbols.setdefault(clean, base + address)
            cursor = terminal_end
            if cursor >= len(blob):
                continue
            child_count = blob[cursor]
            cursor += 1
            for _ in range(child_count):
                edge_end = blob.find(b'\0', cursor)
                if edge_end < 0:
                    raise MalformedBinaryError('truncated export trie edge')
                edge = blob[cursor:edge_end].decode('utf-8', 'replace')
                child_off, cursor = _read_uleb(blob, edge_end + 1)
                if child_off < len(blob):
                    pending.append((child_off, prefix + edge))
        return symbols

    def _load_export_trie(self, data: bytes, dataoff: int, datasize: int, base: int):
        for name, address in self._parse_export_trie_symbols(
                data, dataoff, datasize, base).items():
            self.symbols.setdefault(name, address)

    def _reconcile_exported_functions(self):
        """Use export-trie names for executable addresses discovered by metadata."""
        code_ranges = [(start, start + len(blob)) for _, start, blob in self.sections]
        for name, address in sorted(self.symbols.items()):
            if not address or not any(start <= address < end for start, end in code_ranges):
                continue
            current = self.func_boundaries.get(address)
            if current is None or current.startswith('sub_'):
                self.func_boundaries[address] = name

    def _load_chained_fixups(self, data: bytes, dataoff: int, datasize: int, endian: str):
        if not datasize:
            return
        if dataoff > len(data) or datasize > len(data) - dataoff or datasize < 28:
            raise MalformedBinaryError('invalid chained-fixups payload')
        _, starts_offset = struct.unpack_from(f'{endian}II', data, dataoff)
        starts = dataoff + starts_offset
        payload_end = dataoff + datasize
        if starts + 4 > payload_end:
            raise MalformedBinaryError('truncated chained-fixups starts table')
        seg_count = struct.unpack_from(f'{endian}I', data, starts)[0]
        if seg_count > 4096 or starts + 4 + seg_count * 4 > payload_end:
            raise MalformedBinaryError('invalid chained-fixups segment count')
        # Apple dyld chained pointer formats. Kernel/firmware/segmented formats
        # use a four-byte chain stride; userland and shared-cache formats use
        # eight. Entries themselves remain 64-bit.
        format_strides = {1: 8, 7: 4, 9: 8, 10: 4, 12: 8, 13: 8, 14: 4}
        for seg_index in range(min(seg_count, len(self.segment_meta))):
            relative = struct.unpack_from(f'{endian}I', data, starts + 4 + seg_index * 4)[0]
            if relative == 0:
                continue
            info = starts + relative
            if info + 22 > payload_end:
                raise MalformedBinaryError('truncated chained-fixups segment info')
            size, page_size, pointer_format = struct.unpack_from(f'{endian}IHH', data, info)
            page_count = struct.unpack_from(f'{endian}H', data, info + 20)[0]
            if size < 22 + page_count * 2 or info + size > payload_end:
                raise MalformedBinaryError('invalid chained-fixups page table')
            if pointer_format not in format_strides or not page_size:
                continue
            segment = self.segment_meta[seg_index]
            entry_count = (size - 22) // 2
            page_entries = struct.unpack_from(
                f'{endian}{entry_count}H', data, info + 22) if entry_count else ()
            for page_index in range(page_count):
                page_start = page_entries[page_index]
                if page_start == 0xffff:
                    continue
                chain_starts = []
                if page_start & 0x8000:
                    overflow_index = page_start & 0x7fff
                    while True:
                        if overflow_index >= entry_count:
                            raise MalformedBinaryError('chained-fixups multi-start index exceeds table')
                        overflow = page_entries[overflow_index]
                        chain_starts.append(overflow & 0x7fff)
                        overflow_index += 1
                        if overflow & 0x8000:
                            break
                else:
                    chain_starts.append(page_start)

                page_file = int(segment['fileoff'] + page_index * page_size)
                page_vm = int(segment['vmaddr'] + page_index * page_size)
                segment_file_end = int(segment['fileoff'] + segment['filesize'])
                page_file_end = min(len(data), segment_file_end, page_file + page_size)
                stride = format_strides[pointer_format]
                for chain_start in chain_starts:
                    if chain_start >= page_size:
                        raise MalformedBinaryError('chained-fixups start exceeds page')
                    file_cursor = page_file + chain_start
                    vm_cursor = page_vm + chain_start
                    seen = set()
                    while file_cursor not in seen and file_cursor + 8 <= page_file_end:
                        seen.add(file_cursor)
                        raw = struct.unpack_from(f'{endian}Q', data, file_cursor)[0]
                        auth = bool(raw >> 63)
                        if pointer_format == 13:
                            bind = False
                            next_delta = (raw >> 52) & 0x7ff
                            key_name = 'DA' if ((raw >> 51) & 1) else 'IA'
                            address_diversity = bool((raw >> 50) & 1)
                            diversity = (raw >> 34) & 0xffff
                            target = raw & ((1 << 34) - 1)
                        elif pointer_format == 14:
                            bind = False
                            next_delta = (raw >> 51) & 0xfff
                            key_name = ('IA', 'IB', 'DA', 'DB')[(raw >> 49) & 0x3]
                            address_diversity = bool((raw >> 48) & 1)
                            diversity = (raw >> 32) & 0xffff
                            target = raw & 0xffffffff
                        else:
                            bind = bool((raw >> 62) & 1)
                            next_delta = (raw >> 51) & 0x7ff
                            key_name = ('IA', 'IB', 'DA', 'DB')[(raw >> 49) & 0x3]
                            address_diversity = bool((raw >> 48) & 1)
                            diversity = (raw >> 32) & 0xffff
                            target = raw & (0xffffff if pointer_format == 12 and bind
                                            else 0xffffffff)
                        if auth:
                            self.auth_pointer_metadata.append({
                                'virtual_addr': vm_cursor, 'raw': raw,
                                'key': key_name,
                                'address_diversity': address_diversity,
                                'diversity': diversity, 'bind': bind,
                                'target': target, 'pointer_format': pointer_format,
                            })
                        if not next_delta:
                            break
                        step = next_delta * stride
                        if file_cursor + step + 8 > page_file_end:
                            break
                        file_cursor += step
                        vm_cursor += step

    def _load_raw(self):
        self.sections.append(('raw', 0, self.raw))

    def _disassemble(self):
        if not HAS_CAPSTONE:
            raise DependencyError('capstone required. Install: pip install capstone')
        arch_const = getattr(capstone, 'CS_ARCH_ARM64',
                     getattr(capstone, 'CS_ARCH_AARCH64', None))
        if arch_const is None:
            raise DependencyError('capstone version lacks ARM64 support')
        mode = capstone.CS_MODE_ARM
        byte_order = '<'
        if self._binary_endian == 'big':
            if not hasattr(capstone, 'CS_MODE_BIG_ENDIAN'):
                raise DependencyError('capstone version lacks big-endian ARM64 support')
            mode |= capstone.CS_MODE_BIG_ENDIAN
            byte_order = '>'

        # Capstone 4 accepts ARM64 but does not decode the PAuth instructions
        # PACForge is built around. Fail closed instead of returning an empty,
        # apparently successful report.
        probe = struct.pack(f'{byte_order}I', 0xdac10020)  # PACIA x0, x1
        probe_cs = Cs(arch_const, mode)
        probe_insns = list(probe_cs.disasm(probe, 0))
        if not probe_insns or probe_insns[0].mnemonic != 'pacia':
            version = getattr(capstone, '__version__', 'unknown')
            raise DependencyError(
                f'capstone >= 5.0 with ARM64 PAuth decoding is required '
                f'(found {version})')

        self.cs = Cs(arch_const, mode)
        self.cs.detail = True

        _BRAAZ_PATTERNS = {
            0xd61f0be0: 'braaz',   0xd61f0fe0: 'brabz',
            0xd63f0be0: 'blraaz',  0xd63f0fe0: 'blrabz',
        }
        _REG_NAMES = [f'x{i}' for i in range(31)] + ['xzr']

        for name, addr, code in self.sections:
            off = 0
            while off < len(code):
                decoded = False
                for insn in self.cs.disasm(code[off:], addr + off):
                    self.insns.append((insn.address, insn.mnemonic,
                                       insn.op_str or '', insn.size))
                    try:
                        reads, writes = insn.regs_access()
                        self.insn_meta[insn.address] = {
                            'regs_read': tuple(insn.reg_name(reg) for reg in reads),
                            'regs_write': tuple(insn.reg_name(reg) for reg in writes),
                            'groups': tuple(insn.group_name(group) for group in insn.groups),
                        }
                    except (AttributeError, capstone.CsError):
                        self.insn_meta[insn.address] = {
                            'regs_read': (), 'regs_write': (), 'groups': (),
                        }
                    off += insn.size
                    decoded = True
                if not decoded and off + 4 <= len(code):
                    word = struct.unpack_from(f'{byte_order}I', code, off)[0]
                    base = word & 0xffffffe0
                    if base in _BRAAZ_PATTERNS:
                        rn = word & 0x1f
                        self.insns.append((addr + off, _BRAAZ_PATTERNS[base],
                                           _REG_NAMES[rn], 4))
                    off += 4
                elif not decoded:
                    break

        self.insns.sort(key=lambda row: row[0])

    def _build_indexes(self):
        """Build immutable address/function indexes shared by every analysis."""
        self._insn_addrs = [row[0] for row in self.insns]
        self._addr_to_insn_idx = {address: index for index, address in enumerate(self._insn_addrs)}
        self._code_ranges = sorted(
            (address, address + len(blob))
            for _, address, blob in self.sections if blob
        )
        self._code_range_starts = [start for start, _ in self._code_ranges]
        self._func_starts = sorted(self.func_boundaries)
        self._func_names = [self.func_boundaries[address] for address in self._func_starts]
        self._func_name_to_addr = {
            name: address for address, name in self.func_boundaries.items()
        }
        self._func_slices = {}
        for index, address in enumerate(self._func_starts):
            code_range = self._code_range_for(address)
            if code_range is None:
                continue
            section_end = code_range[1]
            next_start = (self._func_starts[index + 1]
                          if index + 1 < len(self._func_starts) else section_end)
            end = min(next_start, section_end)
            self._func_slices[self.func_boundaries[address]] = (
                bisect.bisect_left(self._insn_addrs, address),
                bisect.bisect_left(self._insn_addrs, end),
            )

    def _code_range_for(self, addr: int) -> Optional[Tuple[int, int]]:
        """Return the executable section containing *addr*, never an unmapped interval."""
        starts = getattr(self, '_code_range_starts', ())
        if not starts:
            return None
        index = bisect.bisect_right(starts, addr) - 1
        if index >= 0:
            start, end = self._code_ranges[index]
            if start <= addr < end:
                return start, end
        return None

    def _func_at(self, addr: int) -> str:
        starts = getattr(self, '_func_starts', None)
        code_range = self._code_range_for(addr)
        if not starts or code_range is None:
            return 'unknown'
        index = bisect.bisect_right(starts, addr) - 1
        if index < 0 or starts[index] < code_range[0]:
            return 'unknown'
        return self._func_names[index] if addr < self._func_end(starts[index]) else 'unknown'

    def _func_end(self, func_addr: int) -> int:
        starts = getattr(self, '_func_starts', sorted(self.func_boundaries.keys()))
        code_range = self._code_range_for(func_addr)
        if code_range is None:
            return func_addr
        idx = bisect.bisect_right(starts, func_addr)
        if idx < len(starts) and starts[idx] < code_range[1]:
            return starts[idx]
        return code_range[1]

    def _iter_func_insns(self, function):
        func_name = self.func_boundaries.get(function, function) if isinstance(function, int) else function
        bounds = self._func_slices.get(func_name)
        if bounds is None:
            return iter(())
        return iter(self.insns[bounds[0]:bounds[1]])

    @staticmethod
    def _reg_in(reg: str, operand_str: str) -> bool:
        """Check if register name appears as a whole word in operand string."""
        return bool(re.search(r'(?<![a-z0-9])' + re.escape(reg) + r'(?![a-z0-9])', operand_str))

    @staticmethod
    def _operand_regs(operand_str: str) -> List[str]:
        return re.findall(r'(?<![a-z0-9])(?:x(?:[12]?\d|30)|w(?:[12]?\d|30)|sp|lr|xzr|wzr)(?![a-z0-9])',
                          operand_str.lower())

    @staticmethod
    def _canonical_reg(reg: str) -> str:
        reg = reg.lower()
        if reg == 'lr':
            return 'x30'
        if reg.startswith('w') and reg[1:].isdigit():
            return 'x' + reg[1:]
        return reg

    def _pac_dest_reg(self, mnemonic: str, operands: str) -> Optional[str]:
        if mnemonic in PAC_SP_CTX_SIGN | PAC_SP_CTX_AUTH | PAC_AUTH_RET or mnemonic == 'xpaclri':
            return 'x30'
        regs = self._operand_regs(operands)
        if mnemonic in PAC_AUTH_LOAD:
            # LDRAA/LDRAB authenticate the address held in the memory base
            # register; their first operand is the value loaded from memory.
            bases = self._memory_base_regs(operands)
            return next(iter(bases), None)
        return self._canonical_reg(regs[0]) if regs else None

    @staticmethod
    def _pac_key(mnemonic: str) -> Optional[str]:
        if mnemonic in PAC_SIGN_A | PAC_AUTH_A or mnemonic in ('braa', 'blraa', 'braaz', 'blraaz', 'retaa', 'eretaa'):
            return 'IA'
        if mnemonic in PAC_SIGN_B | PAC_AUTH_B or mnemonic in ('brab', 'blrab', 'brabz', 'blrabz', 'retab', 'eretab'):
            return 'IB'
        if mnemonic in PAC_SIGN_DA | PAC_AUTH_DA:
            return 'DA'
        if mnemonic in PAC_SIGN_DB | PAC_AUTH_DB:
            return 'DB'
        return None

    def _pac_modifier(self, address: int, mnemonic: str,
                      operands: str) -> Tuple[str, str]:
        """Classify a PAC modifier without equating unresolved register names."""
        parts = [part.strip() for part in operands.split(',')]
        if mnemonic in PAC_ZERO_CTX_SIGN | PAC_ZERO_CTX_AUTH or 'xzr' in parts[1:]:
            return 'zero', '0'
        if mnemonic in PAC_SP_CTX_SIGN | PAC_SP_CTX_AUTH | PAC_AUTH_RET or 'sp' in parts[1:]:
            return 'sp', 'sp'
        if len(parts) >= 2:
            register = self._canonical_reg(parts[1])
            constant = getattr(self, '_const_at', {}).get(address, {}).get(register)
            if constant is not None:
                return 'constant', f'{constant:#x}'
            return 'register', register
        return 'implicit', 'unknown'

    def _memory_base_regs(self, operands: str) -> Set[str]:
        if '[' not in operands:
            return set()
        bracket = operands[operands.index('['):operands.find(']', operands.index('[')) + 1]
        return {self._canonical_reg(reg) for reg in self._operand_regs(bracket)}

    def _read_u64_at_vmaddr(self, address: int) -> Optional[int]:
        for _, base, size, blob in self.data_sections:
            if base <= address and address + 8 <= base + size:
                offset = address - base
                if offset + 8 <= len(blob):
                    return int.from_bytes(blob[offset:offset + 8], self._binary_endian)
        return None

    def _resolve_code_pointer(self, value: int) -> Optional[int]:
        candidates = (value, value & 0x00ffffffffffffff,
                      value & 0x0000ffffffffffff)
        for candidate in candidates:
            if self._code_range_for(candidate) is not None and self._func_at(candidate) != 'unknown':
                return candidate
        return None

    def _call_target_name(self, operands: str) -> str:
        """Resolve a direct call operand to an internal or imported symbol."""
        target = operands.strip().split()[0].rstrip(',') if operands.strip() else ''
        clean = target.lstrip('#')
        try:
            address = int(clean, 0)
        except ValueError:
            name = clean.removeprefix('_')
            return name[:-4] if name.endswith('@plt') else name
        if address in self.stub_symbols:
            return self.stub_symbols[address].removeprefix('_')
        if address in self.func_boundaries:
            return self.func_boundaries[address]
        exact = next((name for name, value in self.symbols.items() if value == address), '')
        return exact or f'{address:#x}'

    def _call_arg_constant(self, call_index: int, register: str,
                           lookback: int = 20) -> Optional[int]:
        """Best-effort constant recovery for a register at a direct call."""
        register = self._canonical_reg(register)
        value = None
        for index in range(call_index - 1, max(-1, call_index - lookback - 1), -1):
            _, mnemonic, operands, _ = self.insns[index]
            if mnemonic in RET_INSNS or mnemonic in ('b', 'br', 'blr', 'bl'):
                break
            parts = [part.strip() for part in operands.split(',')]
            if not parts or self._canonical_reg(parts[0]) != register:
                continue
            if mnemonic in ('mov', 'movz') and len(parts) >= 2 and parts[1].startswith('#'):
                try:
                    value = int(parts[1][1:], 0)
                    if mnemonic == 'movz' and len(parts) >= 3 and 'lsl' in parts[2]:
                        value <<= int(parts[2].split('#')[-1], 0)
                    return value & 0xffffffffffffffff
                except ValueError:
                    return None
            return None
        return value

    def _in_stub_section(self, addr: int) -> bool:
        for start, end in self.stub_ranges:
            if start <= addr < end:
                return True
        return False

    def _is_runtime_func(self, func_name: str) -> bool:
        for pat in RUNTIME_FUNC_PATTERNS:
            if pat in func_name:
                return True
        return False

    def _is_kernel_binary(self) -> bool:
        if 'vmlinux' in str(self.path).lower():
            return True
        return sum(1 for s in self.symbols if s in KERNEL_SYMBOLS) >= 3

    def _detect_va_bits(self) -> int:
        """Return configured VA width when known, otherwise a documented default.

        Link addresses are not evidence of the CPU translation regime: PIEs and
        shared-cache images can be linked low while running in a 48/52-bit space.
        """
        if self.va_bits_override is not None:
            self._va_bits_source = 'user override'
            return self.va_bits_override
        if self.is_arm64e:
            self._va_bits_source = 'arm64e ABI default'
            return 48
        self._va_bits_source = 'conservative default (override with --va-bits)'
        return 48

    @property
    def app_pac_count(self) -> int:
        if not hasattr(self, '_cached_app_pac'):
            self._cached_app_pac = sum(
                1 for addr, m, _, _ in self.insns
                if m in PAC_ALL and not self._is_runtime_func(self._func_at(addr))
            )
        return self._cached_app_pac

    def _window(self, center_idx: int, before: int = 10, after: int = 10):
        start = max(0, center_idx - before)
        end = min(len(self.insns), center_idx + after + 1)
        return self.insns[start:end]

    # ── Call Graph (direct calls, tail calls, static register targets) ──

    def _build_call_graph(self):
        """Build caller->callee graph from BL targets and tail calls. O(n) single pass."""
        self._callers = defaultdict(set)
        self._callees = defaultdict(set)
        func_starts = set(self.func_boundaries.keys())
        for addr, m, o, sz in self.insns:
            if m == 'bl':
                caller = self._func_at(addr)
                callee = self._call_target_name(o)
                if caller != 'unknown' and callee and not callee.startswith('0x'):
                    self._callers[callee].add(caller)
                    self._callees[caller].add(callee)
            elif m == 'b':
                target = o.strip().lstrip('#')
                try:
                    target_addr = int(target, 0)
                    if target_addr in func_starts:
                        caller = self._func_at(addr)
                        callee = self.func_boundaries[target_addr]
                        if callee != caller:
                            self._callers[callee].add(caller)
                            self._callees[caller].add(callee)
                except ValueError:
                    pass
        insn_idx = {a: i for i, (a, _, _, _) in enumerate(self.insns)}
        for addr, m, o, sz in self.insns:
            if m not in ('br', 'blr') or o.strip().lower() == 'x30':
                continue
            branch_reg = o.strip().split(',')[0].lower()
            idx = insn_idx.get(addr)
            if idx is None:
                continue
            adrp_val = None
            for k in range(max(0, idx - 6), idx):
                _, km, ko, _ = self.insns[k]
                kparts = ko.replace(' ', '').split(',')
                if km == 'adrp' and len(kparts) >= 2 and kparts[0].lower() == branch_reg:
                    try:
                        adrp_val = int(kparts[1].strip().lstrip('#'), 0)
                    except ValueError:
                        adrp_val = None
                elif km == 'add' and len(kparts) >= 3 and kparts[0].lower() == branch_reg and kparts[1].lower() == branch_reg:
                    if adrp_val is not None:
                        try:
                            adrp_val += int(kparts[2].strip().lstrip('#'), 0)
                        except ValueError:
                            pass
            if adrp_val is not None:
                callee = self._func_at(adrp_val)
                if callee and callee != 'unknown':
                    caller = self._func_at(addr)
                    if callee != caller:
                        self._callers[callee].add(caller)
                        self._callees[caller].add(callee)

    def _reachable(self, src_func: str, dst_func: str, max_depth: int = 5) -> bool:
        """BFS: can src_func reach dst_func within max_depth calls?"""
        if src_func == dst_func:
            return True
        visited = {src_func}
        frontier = {src_func}
        for _ in range(max_depth):
            next_frontier = set()
            for f in frontier:
                for callee in self._callees.get(f, ()):
                    if callee == dst_func:
                        return True
                    if callee not in visited:
                        visited.add(callee)
                        next_frontier.add(callee)
            frontier = next_frontier
            if not frontier:
                break
        return False

    # ── Register Taint (basic-block provenance) ────────────────────

    _CALLER_SAVED = tuple(f'x{i}' for i in range(19)) + ('x30',)

    def _apply_taint_instruction(self, state: dict, address: int,
                                 mnemonic: str, operands: str) -> None:
        """Apply one AArch64 instruction to a lightweight provenance state."""
        parts = [part.strip() for part in operands.split(',')]
        if mnemonic == 'bl':
            for reg in self._CALLER_SAVED:
                state.pop(reg, None)
            state['x30'] = ('return_addr', f'{address + 4:#x}')
            return
        if not parts or not parts[0]:
            return

        def set_load(registers):
            bases = self._memory_base_regs(operands)
            source = 'stack' if bases.intersection({'sp', 'x29'}) else 'mem'
            bracket = (operands[operands.index('['):operands.find(']', operands.index('[')) + 1]
                       if '[' in operands and ']' in operands else operands)
            for register in registers:
                state[self._canonical_reg(register)] = (source, bracket)

        if mnemonic.startswith(('ldr', 'ldur')) and '[' in operands:
            set_load(parts[:1])
            return
        if mnemonic.startswith(('ldp', 'ldnp')) and '[' in operands:
            set_load(parts[:2])
            return

        dst = self._canonical_reg(parts[0])
        if mnemonic in ('mov', 'movz', 'movn') and len(parts) >= 2:
            src = self._canonical_reg(parts[1])
            if parts[1].startswith('#'):
                state[dst] = ('const', parts[1])
            else:
                state[dst] = state.get(src, ('reg', src))
            return
        if mnemonic == 'movk' and len(parts) >= 2:
            state[dst] = ('computed', f'movk:{",".join(parts[1:])}')
            return
        if mnemonic in ('add', 'sub', 'eor', 'orr', 'and', 'lsl', 'lsr') and len(parts) >= 2:
            state[dst] = ('computed', f'{mnemonic}:' + ','.join(parts[1:]))
            return
        if mnemonic in ('adrp', 'adr') and len(parts) >= 2:
            state[dst] = ('const', parts[1])
            return
        if mnemonic in PAC_AUTH_LOAD:
            bases = self._memory_base_regs(operands)
            reads.update(bases)
            if operand_regs:
                writes.add(operand_regs[0])
            if operands.rstrip().endswith('!'):
                writes.update(bases)
            return reads, writes
        if mnemonic in PAC_ALL:
            # Signing/authentication transforms the pointer but preserves where
            # its underlying value originated.
            return

        writes = {
            self._canonical_reg(register)
            for register in self.insn_meta.get(address, {}).get('regs_write', ())
        }
        for register in writes:
            state.pop(register, None)

    def _insn_read_write_regs(self, address: int, mnemonic: str,
                              operands: str) -> Tuple[Set[str], Set[str]]:
        """Return explicit register reads/writes with a syntax fallback."""
        meta = self.insn_meta.get(address, {})
        reads = {self._canonical_reg(reg) for reg in meta.get('regs_read', ())}
        writes = {self._canonical_reg(reg) for reg in meta.get('regs_write', ())}
        operand_regs = [self._canonical_reg(reg) for reg in self._operand_regs(operands)]
        parts = [part.strip() for part in operands.split(',')]

        if mnemonic in PAC_ALL:
            reads.update(operand_regs)
            destination = self._pac_dest_reg(mnemonic, operands)
            if destination:
                writes.add(destination)
            return reads, writes
        if reads or writes:
            return reads, writes
        if not operand_regs:
            return reads, writes
        if (mnemonic.startswith(('str', 'stur', 'stp', 'stnp', 'stxr', 'stlxr', 'stlr')) or
                mnemonic.startswith(('cas', 'swp', 'ldadd', 'ldclr', 'ldeor', 'ldset')) or
                mnemonic in INDIRECT_BRANCH | RET_INSNS or mnemonic.startswith(('cb', 'tb'))):
            reads.update(operand_regs)
            return reads, writes
        if mnemonic.startswith(('ldp', 'ldnp')) and len(parts) >= 2:
            writes.update(self._canonical_reg(part) for part in parts[:2])
            reads.update(self._memory_base_regs(operands))
            return reads, writes
        if mnemonic.startswith(('ldr', 'ldur')):
            writes.add(self._canonical_reg(parts[0]))
            reads.update(self._memory_base_regs(operands))
            return reads, writes
        writes.add(self._canonical_reg(parts[0]))
        reads.update(operand_regs[1:])
        return reads, writes

    def _taint_basic_block(self, center_idx: int, lookback: int = 0) -> dict:
        """Track register provenance within a basic block ending at center_idx.
        Returns reg -> (source_type, detail) where source_type is one of:
        'stack', 'mem', 'const', 'reg', 'computed'.
        Walks back to nearest branch/ret/function boundary (no fixed window)."""
        center_addr = self.insns[center_idx][0]
        func = self._func_at(center_addr)
        func_start = self._func_slices.get(func, (0, center_idx))[0]
        start = max(func_start, center_idx - lookback) if lookback > 0 else func_start
        if lookback <= 0:
            for index in range(center_idx - 1, func_start - 1, -1):
                mnemonic = self.insns[index][1]
                if (mnemonic in RET_INSNS or mnemonic in INDIRECT_BRANCH or
                        (mnemonic.startswith('b') and mnemonic not in PAC_ALL)):
                    start = index + 1
                    break
        reg_src = {}
        for index in range(start, center_idx):
            address, mnemonic, operands, _ = self.insns[index]
            self._apply_taint_instruction(reg_src, address, mnemonic, operands)
        return reg_src

    # ── Basic-block CFG (opt-in via --deep-analysis) ─────────────────

    def _build_cfg(self):
        """Build basic-block CFG from branch targets. O(n) construction."""
        leaders = set()
        if self.insns:
            leaders.add(self.insns[0][0])
        for f_addr in self.func_boundaries:
            leaders.add(f_addr)

        for i, (addr, m, o, sz) in enumerate(self.insns):
            is_branch = (m.startswith('b') and m not in PAC_ALL) or m in RET_INSNS or m in INDIRECT_BRANCH
            if is_branch:
                if i + 1 < len(self.insns):
                    leaders.add(self.insns[i + 1][0])
                target = o.strip().lstrip('#')
                if m in ('cbz', 'cbnz', 'tbz', 'tbnz'):
                    parts = o.replace(' ', '').split(',')
                    target = parts[-1].lstrip('#')
                try:
                    leaders.add(int(target, 0))
                except ValueError:
                    pass

        leader_set = set(leaders)
        self._blocks = {}
        self._addr_to_block = {}
        self._cfg_edges = defaultdict(set)

        current_start = None
        current_insns = []
        for addr, m, o, sz in self.insns:
            if addr in leader_set:
                if current_start is not None and current_insns:
                    self._blocks[current_start] = current_insns
                current_start = addr
                current_insns = []
            current_insns.append((addr, m, o, sz))
            self._addr_to_block[addr] = current_start
        if current_start is not None and current_insns:
            self._blocks[current_start] = current_insns

        for block_start, block_insns in self._blocks.items():
            last_addr, last_m, last_o, _ = block_insns[-1]
            is_unconditional = last_m in ('b',) or last_m in RET_INSNS or last_m in INDIRECT_BRANCH
            if not is_unconditional:
                next_addr = last_addr + 4
                next_block = self._addr_to_block.get(next_addr)
                if next_block is not None and next_block != block_start:
                    self._cfg_edges[block_start].add(next_block)
            if last_m.startswith('b') and last_m not in ('bl', 'br', 'blr') and last_m not in PAC_ALL:
                target = last_o.strip().lstrip('#')
                if last_m in ('cbz', 'cbnz', 'tbz', 'tbnz'):
                    parts = last_o.replace(' ', '').split(',')
                    target = parts[-1].lstrip('#')
                try:
                    target_addr = int(target, 0)
                    target_block = self._addr_to_block.get(target_addr)
                    if target_block is not None:
                        self._cfg_edges[block_start].add(target_block)
                except ValueError:
                    pass
            if last_m == 'b':
                target = last_o.strip().lstrip('#')
                try:
                    target_addr = int(target, 0)
                    target_block = self._addr_to_block.get(target_addr)
                    if target_block is not None:
                        self._cfg_edges[block_start].add(target_block)
                except ValueError:
                    pass

        self._cfg_preds = defaultdict(set)
        for block_start, successors in self._cfg_edges.items():
            for succ in successors:
                self._cfg_preds[succ].add(block_start)

        # Keep call/return edges separate so intra-function data-flow can remain
        # conservative while cross-function reachability gets a real ICFG.
        self._icfg_edges = defaultdict(set, {
            block: set(successors) for block, successors in self._cfg_edges.items()
        })
        return_blocks = defaultdict(set)
        for block_start, block_insns in self._blocks.items():
            if block_insns and block_insns[-1][1] in RET_INSNS:
                return_blocks[self._func_at(block_start)].add(block_start)
        for index, (address, mnemonic, operands, _) in enumerate(self.insns):
            if mnemonic != 'bl':
                continue
            try:
                target_address = int(operands.strip().lstrip('#'), 0)
            except ValueError:
                continue
            source_block = self._addr_to_block.get(address)
            target_block = self._addr_to_block.get(target_address)
            if source_block is None or target_block is None:
                continue
            self._icfg_edges[source_block].add(target_block)
            if index + 1 < len(self.insns):
                return_block = self._addr_to_block.get(self.insns[index + 1][0])
                if return_block is not None:
                    callee_name = self._func_at(target_address)
                    for exit_block in return_blocks.get(callee_name, ()):
                        self._icfg_edges[exit_block].add(return_block)

    def _taint_cross_block(self, center_idx: int, lookback: int = 0, max_pred_blocks: int = 3) -> dict:
        """Extended taint: basic-block taint + walk CFG predecessors (deep mode only).
        Merges provenance from predecessor blocks when the center block has
        insufficient context. Returns same format as _taint_basic_block."""
        if not hasattr(self, '_cfg_preds'):
            return self._taint_basic_block(center_idx, lookback)
        reg_src = self._taint_basic_block(center_idx, lookback)
        center_addr = self.insns[center_idx][0]
        center_block = self._addr_to_block.get(center_addr)
        if center_block is None:
            return reg_src
        center_func = self._func_at(center_addr)
        preds = self._cfg_preds.get(center_block, set())
        for depth in range(max_pred_blocks):
            if not preds:
                break
            next_preds = set()
            for pred_start in preds:
                if self._func_at(pred_start) != center_func:
                    continue
                pred_insns = self._blocks.get(pred_start, [])
                if not pred_insns:
                    continue
                pred_last_idx = self._addr_to_insn_idx.get(pred_insns[-1][0])
                if pred_last_idx is None:
                    continue
                pred_taint = self._taint_basic_block(pred_last_idx, lookback=len(pred_insns))
                for reg, src in pred_taint.items():
                    existing = reg_src.get(reg)
                    if (existing is None or
                            self._TAINT_PRIORITY.get(src[0], 0) >
                            self._TAINT_PRIORITY.get(existing[0], 0)):
                        reg_src[reg] = src
                for pp in self._cfg_preds.get(pred_start, set()):
                    if self._func_at(pp) == center_func:
                        next_preds.add(pp)
            preds = next_preds
        return reg_src

    def _taint_paths_to(self, center_idx: int, max_pred_blocks: int = 4,
                        max_paths: int = 32) -> List[dict]:
        """Return distinct provenance states for CFG paths reaching an instruction."""
        if not hasattr(self, '_cfg_preds'):
            return [self._taint_basic_block(center_idx)]
        center_addr = self.insns[center_idx][0]
        center_block = self._addr_to_block.get(center_addr)
        if center_block is None:
            return [self._taint_basic_block(center_idx)]
        func = self._func_at(center_addr)
        paths = []

        def visit(block, reverse_path, depth):
            preds = [pred for pred in self._cfg_preds.get(block, ())
                     if self._func_at(pred) == func and pred not in reverse_path]
            if depth >= max_pred_blocks or not preds:
                paths.append(list(reversed(reverse_path + [block])))
                return
            for pred in sorted(preds):
                if len(paths) >= max_paths:
                    break
                visit(pred, reverse_path + [block], depth + 1)

        visit(center_block, [], 0)
        states = []
        for blocks in paths[:max_paths]:
            rows = []
            for block in blocks:
                for row in self._blocks.get(block, ()):
                    if row[0] >= center_addr:
                        break
                    rows.append(row)
            state = {}
            for address, mnemonic, operands, _ in rows:
                self._apply_taint_instruction(state, address, mnemonic, operands)
            if state not in states:
                states.append(state)
        return states or [self._taint_basic_block(center_idx)]

    # ── Symbolic analysis (opt-in via --symbolic) ────────────────────

    def _build_symbolic_maps(self):
        """Build address-to-index map and per-function input register summaries."""
        self._addr_to_insn_idx = {}
        for i, (a, _, _, _) in enumerate(self.insns):
            self._addr_to_insn_idx[a] = i
        self._func_input_regs = {}
        arg_set = {'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'}
        blocks_by_func = defaultdict(list)
        for block in self._blocks:
            func_name = self._func_at(block)
            if func_name != 'unknown':
                blocks_by_func[func_name].append(block)

        for func_addr in self._func_starts:
            func_name = self.func_boundaries[func_addr]
            blocks = blocks_by_func.get(func_name, [])
            local_reads = {}
            local_writes = {}
            for block in blocks:
                written_here = set()
                read_before_write = set()
                for address, mnemonic, operands, _ in self._blocks[block]:
                    reads, writes = self._insn_read_write_regs(address, mnemonic, operands)
                    read_before_write.update((reads & arg_set) - written_here)
                    written_here.update(writes & arg_set)
                local_reads[block] = read_before_write
                local_writes[block] = written_here

            all_args = set(arg_set)
            entry = self._addr_to_block.get(func_addr)
            in_defs = {block: (set() if block == entry else set(all_args))
                       for block in blocks}
            out_defs = {block: set(in_defs[block]) | local_writes[block]
                        for block in blocks}
            for _ in range(max(1, len(blocks) * 2)):
                changed = False
                for block in blocks:
                    predecessors = [pred for pred in self._cfg_preds.get(block, ())
                                    if pred in in_defs]
                    incoming = (set.intersection(*(out_defs[pred] for pred in predecessors))
                                if predecessors else set())
                    outgoing = incoming | local_writes[block]
                    if incoming != in_defs[block] or outgoing != out_defs[block]:
                        in_defs[block] = incoming
                        out_defs[block] = outgoing
                        changed = True
                if not changed:
                    break
            inputs = set()
            for block in blocks:
                inputs.update(local_reads[block] - in_defs[block])
            self._func_input_regs[func_name] = inputs

    _TAINT_PRIORITY = {'stack': 5, 'mem': 4, 'computed': 3, 'reg': 2, 'const': 1}

    def _interprocedural_taint(self, center_idx: int, max_depth: int = 4) -> dict:
        """Taint with inter-procedural propagation through callers.
        Merges taint from all callers and call sites, keeping the
        least-constrained source (stack > memory > reg > const)."""
        taint = self._taint_cross_block(center_idx) if self.deep else self._taint_basic_block(center_idx)
        if max_depth <= 0:
            return taint
        center_addr = self.insns[center_idx][0]
        func = self._func_at(center_addr)
        input_regs = self._func_input_regs.get(func, set())
        if not input_regs:
            return taint
        unresolved = {}
        for reg in input_regs:
            if reg not in taint:
                unresolved[reg] = reg
            elif taint[reg][0] == 'reg':
                src_reg = taint[reg][1]
                x = src_reg.replace('w', 'x') if src_reg.startswith('w') else src_reg
                if x in input_regs:
                    unresolved[reg] = x
        if not unresolved:
            return taint
        callers = self._callers.get(func, set())
        for caller_name in callers:
            if caller_name not in self._func_name_to_addr:
                continue
            for addr, m, o, sz in self._iter_func_insns(caller_name):
                if m not in ('bl', 'b'):
                    continue
                callee = self._call_target_name(o)
                if callee != func:
                    continue
                bl_idx = self._addr_to_insn_idx.get(addr)
                if bl_idx is None:
                    continue
                if max_depth > 1:
                    caller_taint = self._interprocedural_taint(bl_idx, max_depth - 1)
                else:
                    caller_taint = self._taint_cross_block(bl_idx) if self.deep else self._taint_basic_block(bl_idx)
                for callee_reg, caller_reg in unresolved.items():
                    if caller_reg in caller_taint:
                        src_type, detail = caller_taint[caller_reg]
                        existing = taint.get(callee_reg)
                        if existing is None or self._TAINT_PRIORITY.get(src_type, 0) > self._TAINT_PRIORITY.get(existing[0], 0):
                            taint[callee_reg] = (src_type, f'{detail} via {caller_name}')
        return taint

    def _build_z3_expr(self, taint: dict, reg: str, sym_vars: dict, depth: int = 0):
        """Build Z3 BitVec expression from taint entry, recursing through copies/computations."""
        if depth > 5 or reg not in taint:
            key = f'free_{reg}'
            if key not in sym_vars:
                sym_vars[key] = z3.BitVec(key, 64)
            return sym_vars[key]
        src_type, detail = taint[reg]
        if isinstance(detail, str) and ' via ' in detail:
            detail = detail.split(' via ', 1)[0]
        if src_type == 'const':
            try:
                val = int(detail.strip().lstrip('#'), 0)
                return z3.BitVecVal(val, 64)
            except (ValueError, AttributeError):
                key = f'const_{detail}'
                if key not in sym_vars:
                    sym_vars[key] = z3.BitVec(key, 64)
                return sym_vars[key]
        elif src_type == 'stack':
            key = f'stack_{detail}'
            if key not in sym_vars:
                sym_vars[key] = z3.BitVec(key, 64)
            return sym_vars[key]
        elif src_type == 'mem':
            key = f'mem_{detail}'
            if key not in sym_vars:
                sym_vars[key] = z3.BitVec(key, 64)
            return sym_vars[key]
        elif src_type == 'reg':
            return self._build_z3_expr(taint, detail, sym_vars, depth + 1)
        elif src_type == 'computed':
            operator = 'add'
            expression = detail
            if ':' in detail:
                operator, expression = detail.split(':', 1)
            parts = expression.split(',')
            if len(parts) >= 2:
                base_reg = parts[0].strip()
                operand = parts[1].strip()
                base_expr = self._build_z3_expr(taint, base_reg, sym_vars, depth + 1)
                if operand.startswith('#'):
                    try:
                        imm = int(operand[1:], 0)
                        return base_expr - imm if operator == 'sub' else base_expr + imm
                    except ValueError:
                        pass
                else:
                    op_expr = self._build_z3_expr(taint, operand, sym_vars, depth + 1)
                    return base_expr - op_expr if operator == 'sub' else base_expr + op_expr
        key = f'unknown_{reg}_{depth}'
        if key not in sym_vars:
            sym_vars[key] = z3.BitVec(key, 64)
        return sym_vars[key]

    def _solve_constraints(self, reg_provenance: dict, taint: dict = None) -> dict:
        """Constraint solver: Z3-based when available, heuristic fallback otherwise."""
        if not reg_provenance:
            return {'satisfiable': None, 'classification': 'unknown',
                    'conflicts': [], 'details': 'No register provenance available'}
        if HAS_Z3 and taint is not None:
            return self._solve_constraints_z3(reg_provenance, taint)
        return self._solve_constraints_heuristic(reg_provenance)

    def _solve_constraints_z3(self, reg_provenance: dict, taint: dict) -> dict:
        """Use self-composition to test whether required values vary independently.

        There is no concrete target assignment at static-analysis time, so checking
        one arbitrary pair of constants is unsound.  Instead, duplicate every free
        input and ask whether each expression can change while the other is held
        fixed.  If it cannot, the two required registers are functionally dependent.
        """
        if isinstance(taint, list):
            outcomes = []
            for path in taint:
                path_provenance = {}
                for register in reg_provenance:
                    canonical = self._canonical_reg(register)
                    source, detail = path.get(canonical, ('unknown', canonical))
                    path_provenance[register] = {'source': source, 'detail': detail}
                outcomes.append(self._solve_constraints_z3(path_provenance, path))
            exploitable = next((result for result in outcomes
                                if result['classification'] in ('satisfiable', 'partial')), None)
            if exploitable:
                result = dict(exploitable)
                result['details'] += f' (one of {len(outcomes)} CFG paths)'
                result['path_count'] = len(outcomes)
                return result
            dependent = [result for result in outcomes if result['classification'] == 'dependent']
            if dependent and len(dependent) == len(outcomes):
                result = dict(dependent[0])
                result['details'] += f' (all {len(outcomes)} CFG paths)'
                result['path_count'] = len(outcomes)
                return result
            return {'satisfiable': None, 'classification': 'unknown', 'conflicts': [],
                    'details': f'Z3: mixed/unknown result across {len(outcomes)} CFG paths',
                    'path_count': len(outcomes)}

        sym_vars = {}
        reg_exprs = {}
        for reg in reg_provenance:
            reg_lower = reg.lower()
            expr = self._build_z3_expr(taint, reg_lower, sym_vars)
            reg_exprs[reg] = expr
        reg_classes = {}
        for register, expression in reg_exprs.items():
            variables = z3.z3util.get_vars(expression)
            names = {variable.decl().name() for variable in variables}
            if not names:
                reg_classes[register] = 'fixed'
            elif all(name.startswith(('stack_', 'mem_')) for name in names):
                reg_classes[register] = 'controllable'
            else:
                reg_classes[register] = 'unknown'
        controllable_srcs = {
            variable.decl().name()
            for expression in reg_exprs.values()
            for variable in z3.z3util.get_vars(expression)
            if variable.decl().name().startswith(('stack_', 'mem_'))
        }
        controllable_regs = [r for r, kind in reg_classes.items()
                             if kind == 'controllable']
        fixed_regs = [r for r, kind in reg_classes.items() if kind == 'fixed']
        unknown_regs = [r for r, kind in reg_classes.items() if kind == 'unknown']
        regs = list(reg_exprs.keys())
        conflicts = []
        for i, r1 in enumerate(regs):
            for r2 in regs[i + 1:]:
                # A constant is intentionally fixed, not functionally dependent
                # on a variable register.  Pairwise self-composition only applies
                # when both expressions can vary.
                if reg_classes[r1] == 'fixed' or reg_classes[r2] == 'fixed':
                    continue
                variables = list({str(var): var for var in (
                    z3.z3util.get_vars(reg_exprs[r1]) + z3.z3util.get_vars(reg_exprs[r2])
                )}.values())
                if not variables:
                    continue
                primed = [z3.BitVec(f'{var.decl().name()}__prime', var.size()) for var in variables]
                substitutions = list(zip(variables, primed))
                r1_prime = z3.substitute(reg_exprs[r1], *substitutions)
                r2_prime = z3.substitute(reg_exprs[r2], *substitutions)

                def can_change(target, target_prime, held, held_prime):
                    solver = z3.Solver()
                    solver.set('timeout', 1000)
                    solver.add(held == held_prime, target != target_prime)
                    return solver.check()

                r1_changes = can_change(reg_exprs[r1], r1_prime, reg_exprs[r2], r2_prime)
                r2_changes = can_change(reg_exprs[r2], r2_prime, reg_exprs[r1], r1_prime)
                if r1_changes == z3.unknown or r2_changes == z3.unknown:
                    conflicts.append(f'{r1}/{r2} dependency check timed out')
                elif r1_changes == z3.unsat or r2_changes == z3.unsat:
                    conflicts.append(f'{r1} and {r2} are functionally dependent')
        all_issues = conflicts
        total = len(reg_provenance)
        if all_issues:
            timed_out = any('timed out' in issue for issue in all_issues)
            return {'satisfiable': None if timed_out else False,
                    'classification': 'unknown' if timed_out else 'dependent',
                    'conflicts': all_issues,
                    'details': f'Z3: {"; ".join(all_issues)}'}
        if len(controllable_regs) == total:
            return {'satisfiable': True, 'classification': 'satisfiable',
                    'conflicts': [],
                    'details': f'Z3: all {total} regs independently controllable ({len(controllable_srcs)} free variables)'}
        if len(fixed_regs) == total:
            return {'satisfiable': True, 'classification': 'fixed',
                    'conflicts': [],
                    'details': f'Z3: all {total} regs are constants'}
        if controllable_regs and fixed_regs and not unknown_regs:
            return {'satisfiable': True, 'classification': 'partial',
                    'conflicts': [],
                    'details': f'Z3: {len(controllable_regs)} controllable, {len(fixed_regs)} fixed'}
        if unknown_regs:
            return {'satisfiable': None, 'classification': 'unknown',
                    'conflicts': [],
                    'details': (f'Z3: {len(unknown_regs)} of {total} regs depend on '
                                'unmodeled or unresolved inputs')}
        return {'satisfiable': None, 'classification': 'unknown',
                'conflicts': [], 'details': 'Z3: insufficient provenance'}

    def _solve_constraints_heuristic(self, reg_provenance: dict) -> dict:
        """Heuristic fallback when Z3 is not available."""
        source_groups = defaultdict(list)
        controllable = []
        fixed = []
        for reg, info in reg_provenance.items():
            src = info['source']
            detail = info['detail']
            key = (src, detail)
            source_groups[key].append(reg)
            if src in ('stack', 'mem'):
                controllable.append(reg)
            elif src == 'const':
                fixed.append(reg)
        conflicts = []
        for key, regs in source_groups.items():
            if len(regs) > 1 and key[0] in ('stack', 'mem'):
                conflicts.append(f'{", ".join(regs)} alias {key[0]}:{key[1]}')
        if conflicts:
            return {'satisfiable': False, 'classification': 'unsatisfiable',
                    'conflicts': conflicts,
                    'details': f'Aliased sources: {"; ".join(conflicts)}'}
        total = len(reg_provenance)
        if len(controllable) == total:
            return {'satisfiable': True, 'classification': 'satisfiable',
                    'conflicts': [],
                    'details': f'All {total} regs from independent controllable sources'}
        if fixed and not controllable:
            return {'satisfiable': True, 'classification': 'fixed',
                    'conflicts': [],
                    'details': f'All {total} regs are constants'}
        if controllable and fixed:
            return {'satisfiable': True, 'classification': 'partial',
                    'conflicts': [],
                    'details': f'{len(controllable)} controllable, {len(fixed)} fixed constants'}
        return {'satisfiable': None, 'classification': 'unknown',
                'conflicts': [], 'details': 'Insufficient provenance data'}

    def _blocks_reachable(self, src_addr: int, dst_addr: int, max_blocks: int = 30) -> bool:
        """BFS: can src_addr reach dst_addr through the CFG?"""
        if not hasattr(self, '_cfg_edges'):
            return False
        src_block = self._addr_to_block.get(src_addr)
        dst_block = self._addr_to_block.get(dst_addr)
        if src_block is None or dst_block is None:
            return False
        if src_block == dst_block:
            return True
        visited = {src_block}
        frontier = {src_block}
        for _ in range(max_blocks):
            next_frontier = set()
            for b in frontier:
                graph = getattr(self, '_icfg_edges', self._cfg_edges)
                for succ in graph.get(b, ()):
                    if succ == dst_block:
                        return True
                    if succ not in visited:
                        visited.add(succ)
                        next_frontier.add(succ)
            frontier = next_frontier
            if not frontier:
                break
        return False

    # ── Intra-function def-use chains (opt-in) ───────────────────────

    def _def_use_in_func(self, func_name: str, reg: str, start_addr: int) -> list:
        """Track where reg is defined and used within a function from start_addr.
        Returns list of (addr, 'def'|'use', mnemonic, op_str) entries."""
        if not hasattr(self, '_cfg_edges'):
            return []
        reg_lower = reg.lower()
        entries = []
        func_start = None
        for f_addr, f_name in self.func_boundaries.items():
            if f_name == func_name:
                func_start = f_addr
                break
        if func_start is None:
            return entries
        start_block = self._addr_to_block.get(start_addr)
        if start_block is None:
            return entries
        queue = [start_block]
        visited = set()
        while queue and len(entries) < 50:
            block = queue.pop(0)
            if block in visited or self._func_at(block) != func_name:
                continue
            visited.add(block)
            for addr, m, o, _ in self._blocks.get(block, ()):
                if block == start_block and addr < start_addr:
                    continue
                reads, writes = self._insn_read_write_regs(addr, m, o)
                if reg_lower in reads:
                    entries.append((addr, 'use', m, o))
                if reg_lower in writes:
                    entries.append((addr, 'def', m, o))
            queue.extend(sorted(self._cfg_edges.get(block, ())))
        return entries[:50]

    # ── Indirect call resolution (opt-in) ────────────────────────────

    def _resolve_indirect_calls(self):
        """Resolve static register targets through address/load/copy chains."""
        resolved = 0
        indirect_targets = {}
        for i, (addr, m, o, sz) in enumerate(self.insns):
            if m not in ('br', 'blr') and m not in PAC_AUTH_BR | PAC_AUTH_BR_Z:
                continue
            branch_reg = self._canonical_reg(o.split(',')[0].strip())
            if branch_reg in ('x30', 'lr'):
                continue
            func = self._func_at(addr)
            func_slice = self._func_slices.get(func, (max(0, i - 24), i))
            start = max(func_slice[0], i - 32)
            values = {}
            for waddr, wm, wo, _ in self.insns[start:i]:
                parts = wo.replace(' ', '').split(',')
                if not parts:
                    continue
                dst = self._canonical_reg(parts[0])
                if wm in ('adrp', 'adr') and len(parts) >= 2:
                    try:
                        values[dst] = int(parts[1].lstrip('#'), 0)
                    except ValueError:
                        values.pop(dst, None)
                elif wm == 'mov' and len(parts) >= 2:
                    src = self._canonical_reg(parts[1])
                    if parts[1].startswith('#'):
                        try:
                            values[dst] = int(parts[1][1:], 0)
                        except ValueError:
                            values.pop(dst, None)
                    elif src in values:
                        values[dst] = values[src]
                    else:
                        values.pop(dst, None)
                elif wm == 'add' and len(parts) >= 3:
                    src = self._canonical_reg(parts[1])
                    try:
                        immediate = int(parts[2].lstrip('#'), 0)
                        if src in values:
                            values[dst] = values[src] + immediate
                        else:
                            values.pop(dst, None)
                    except ValueError:
                        values.pop(dst, None)
                elif wm.startswith(('ldr', 'ldur')) and '[' in wo:
                    inner = wo[wo.index('[') + 1:wo.find(']', wo.index('['))]
                    address_parts = inner.replace(' ', '').split(',')
                    base = self._canonical_reg(address_parts[0]) if address_parts else ''
                    immediate = 0
                    if len(address_parts) > 1 and address_parts[1].startswith('#'):
                        try:
                            immediate = int(address_parts[1][1:], 0)
                        except ValueError:
                            immediate = 0
                    if base in values:
                        pointer = self._read_u64_at_vmaddr(values[base] + immediate)
                        if pointer is not None:
                            values[dst] = pointer
                        else:
                            values.pop(dst, None)
                    else:
                        values.pop(dst, None)
                elif wm == 'bl':
                    for reg in ('x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7',
                                'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14',
                                'x15', 'x16', 'x17', 'x18', 'x30'):
                        values.pop(reg, None)
                else:
                    meta = self.insn_meta.get(waddr, {})
                    if dst in {self._canonical_reg(reg) for reg in meta.get('regs_write', ())}:
                        values.pop(dst, None)
            target_addr = self._resolve_code_pointer(values[branch_reg]) if branch_reg in values else None
            if target_addr is not None:
                caller = self._func_at(addr)
                target_func = self._func_at(target_addr)
                if target_func and target_func != 'unknown' and caller != target_func:
                    self._callers[target_func].add(caller)
                    self._callees[caller].add(target_func)
                    indirect_targets[addr] = target_func
                    resolved += 1
        self._indirect_resolved = resolved
        self._indirect_targets = indirect_targets

    # ── Constant propagation (opt-in) ────────────────────────────────

    def _propagate_constants(self):
        """Propagate immediate values through MOV/MOVK/ADD chains.
        Builds self._const_at: addr -> {reg: resolved_value}.
        Used by entropy and diversifier collision for concrete modifier values."""
        self._const_at = {}
        regs = {}
        last_func = None
        for addr, m, o, sz in self.insns:
            func = self._func_at(addr)
            if func != last_func:
                regs = {}
                last_func = func
            parts = o.replace(' ', '').split(',')
            if not parts or not parts[0]:
                continue
            dst = parts[0]
            if m == 'mov' and len(parts) >= 2 and parts[1].startswith('#'):
                try:
                    regs[dst] = int(parts[1].lstrip('#'), 0)
                except ValueError:
                    regs.pop(dst, None)
            elif m == 'movk' and len(parts) >= 2 and dst in regs:
                try:
                    imm = int(parts[1].lstrip('#'), 0)
                    shift = 0
                    for p in parts[2:]:
                        if p.startswith('lsl#'):
                            shift = int(p[4:])
                    mask = ~(0xFFFF << shift)
                    regs[dst] = (regs[dst] & mask) | (imm << shift)
                except (ValueError, IndexError):
                    regs.pop(dst, None)
            elif m == 'movz' and len(parts) >= 2:
                try:
                    imm = int(parts[1].lstrip('#'), 0)
                    shift = 0
                    for p in parts[2:]:
                        if p.startswith('lsl#'):
                            shift = int(p[4:])
                    regs[dst] = imm << shift
                except ValueError:
                    regs.pop(dst, None)
            elif m in RET_INSNS or (m.startswith('b') and m not in ('bl',) and m not in PAC_ALL):
                regs = {}
                continue
            elif m == 'bl':
                for r in ('x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7',
                          'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14',
                          'x15', 'x16', 'x17', 'x18'):
                    regs.pop(r, None)
            else:
                if dst.startswith('x') or dst.startswith('w'):
                    regs.pop(dst, None)
            if m in PAC_SIGN_ALL or m in PAC_AUTH_ALL:
                if regs:
                    self._const_at[addr] = dict(regs)

    # ── Cross-binary call resolution (opt-in) ──────────────────────

    @staticmethod
    def _load_lib_exports(path: Path) -> dict:
        """Extract exported symbols from a companion binary (ELF or Mach-O).
        Returns {symbol_name: address}. Lightweight — no disassembly."""
        data = path.read_bytes()
        symbols = {}
        if data[:4] == b'\x7fELF':
            if HAS_PYELFTOOLS:
                elf = ELFFile(io.BytesIO(data))
                if elf.elfclass != 64 or elf.header.e_machine != 'EM_AARCH64':
                    return symbols
                for section in elf.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        for sym in section.iter_symbols():
                            if sym.name and sym.entry['st_value'] and \
                               sym.entry['st_info']['bind'] in ('STB_GLOBAL', 'STB_WEAK') and \
                               sym.entry['st_info']['type'] in ('STT_FUNC', 'STT_OBJECT'):
                                symbols[sym.name] = sym.entry['st_value']
        elif data[:4] in (b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe',
                          b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
                          b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'):
            data = PacAnalyzer._select_macho_slice(data)
            if len(data) < 32 or data[:4] not in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf'):
                return symbols
            fmt = '<' if data[:4] == b'\xcf\xfa\xed\xfe' else '>'
            if struct.unpack_from(f'{fmt}i', data, 4)[0] != CPU_TYPE_ARM64:
                return symbols
            ncmds = struct.unpack_from(f'{fmt}I', data, 16)[0]
            sizeofcmds = struct.unpack_from(f'{fmt}I', data, 20)[0]
            if ncmds > 65535 or 32 + sizeofcmds > len(data):
                raise MalformedBinaryError(f'invalid load commands in {path}')
            offset = 32
            commands = []
            for _ in range(ncmds):
                if offset + 8 > 32 + sizeofcmds:
                    raise MalformedBinaryError(f'truncated load commands in {path}')
                cmd, cmdsize = struct.unpack_from(f'{fmt}II', data, offset)
                if cmdsize < 8 or offset + cmdsize > 32 + sizeofcmds:
                    raise MalformedBinaryError(f'invalid command size in {path}')
                commands.append((cmd, offset, cmdsize))
                offset += cmdsize

            image_base = 0
            for cmd, offset, cmdsize in commands:
                if cmd == 0x19 and cmdsize >= 72:
                    segname = data[offset + 8:offset + 24].split(b'\0')[0]
                    if segname == b'__TEXT':
                        image_base = struct.unpack_from(f'{fmt}Q', data, offset + 24)[0]
                        break

            for cmd, offset, cmdsize in commands:
                if cmd == 0x02:  # LC_SYMTAB
                    symoff = struct.unpack_from(f'{fmt}I', data, offset + 8)[0]
                    nsyms = struct.unpack_from(f'{fmt}I', data, offset + 12)[0]
                    stroff = struct.unpack_from(f'{fmt}I', data, offset + 16)[0]
                    strsize = struct.unpack_from(f'{fmt}I', data, offset + 20)[0]
                    if symoff + nsyms * 16 > len(data) or stroff + strsize > len(data):
                        raise MalformedBinaryError(f'invalid symbol table in {path}')
                    strtab = data[stroff:stroff + strsize]
                    for si in range(nsyms):
                        nlist_off = symoff + si * 16
                        if nlist_off + 16 > len(data):
                            break
                        str_idx = struct.unpack_from(f'{fmt}I', data, nlist_off)[0]
                        ntype = data[nlist_off + 4]
                        value = struct.unpack_from(f'{fmt}Q', data, nlist_off + 8)[0]
                        if (ntype & 0x01) and value and str_idx < len(strtab):
                            end = strtab.find(b'\x00', str_idx)
                            if end < 0:
                                end = len(strtab)
                            name = strtab[str_idx:end].decode('ascii', errors='replace')
                            if name.startswith('_'):
                                name = name[1:]
                            if name:
                                symbols[name] = value
                elif cmd == 0x80000033 and cmdsize >= 16:
                    trie_off, trie_size = struct.unpack_from(f'{fmt}II', data, offset + 8)
                    symbols.update(PacAnalyzer._parse_export_trie_symbols(
                        data, trie_off, trie_size, image_base))
                elif cmd == 0x80000022 and cmdsize >= 48:
                    trie_off, trie_size = struct.unpack_from(f'{fmt}II', data, offset + 40)
                    symbols.update(PacAnalyzer._parse_export_trie_symbols(
                        data, trie_off, trie_size, image_base))
        return symbols

    def _resolve_cross_binary(self, lib_dir: str):
        """Match imported symbols against companion library exports.
        Reports which imported functions exist in which companion libraries."""
        lib_path = Path(lib_dir)
        if not lib_path.is_dir():
            self._xbin_resolved = 0
            self._xbin_libs = {}
            return
        imported = set(self.imports)
        lib_exports = {}
        lib_names = {}
        provider_paths = {}
        for f in sorted(lib_path.iterdir()):
            if f.is_file() and f.name != self.path.name and not f.name.startswith('.'):
                try:
                    exports = self._load_lib_exports(f)
                    matched = imported.intersection(exports)
                    for sym in matched:
                        if sym not in lib_exports:
                            lib_exports[sym] = exports[sym]
                            lib_names[sym] = f.name
                            provider_paths[f.name] = f
                except (OSError, PacForgeError, ValueError, struct.error) as exc:
                    if self.verbose:
                        print(f'Warning: skipped companion library {f}: {exc}', file=sys.stderr)
                    continue
        xbin_edges = {}
        for sym in imported:
            if sym in lib_exports:
                xbin_edges[sym] = lib_names[sym]
                namespaced_root = f'{lib_names[sym]}!{sym}'
                self._callees[sym].add(namespaced_root)
                self._callers[namespaced_root].add(sym)
        library_graphs = {}
        for library, provider in provider_paths.items():
            try:
                companion = PacAnalyzer(str(provider), verbose=False)
                library_graphs[library] = companion._callees
            except (OSError, PacForgeError, ValueError, struct.error) as exc:
                if self.verbose:
                    print(f'Warning: could not analyze provider {provider}: {exc}',
                          file=sys.stderr)
        for library, graph in library_graphs.items():
            for caller, callees in graph.items():
                namespaced_caller = f'{library}!{caller}'
                for callee in callees:
                    namespaced_callee = f'{library}!{callee}'
                    self._callees[namespaced_caller].add(namespaced_callee)
                    self._callers[namespaced_callee].add(namespaced_caller)
        self._xbin_resolved = len(xbin_edges)
        self._xbin_libs = xbin_edges
        self._xbin_internal_edges = sum(
            len(callees) for graph in library_graphs.values() for callees in graph.values())

    # ── Runtime Context Detection ───────────────────────────────────

    def detect_runtime_context(self) -> dict:
        """Detect host architecture, OS, and CPU PAC features.
        Runtime-applicability notes never disable static binary analysis."""
        if hasattr(self, '_cached_runtime_ctx'):
            return self._cached_runtime_ctx
        ctx = {
            'host_arch': platform.machine().lower(),
            'host_os': platform.system(),
            'is_arm64_host': False,
            'is_arm32_host': False,
            'cpu_features': {},
            'kernel_pac_config': {},
            'module_applicability': {},
        }

        arch = ctx['host_arch']
        ctx['is_arm64_host'] = arch in ('aarch64', 'arm64')
        ctx['is_arm32_host'] = arch in ('armv7l', 'armv8l', 'arm', 'armhf')

        if ctx['host_os'] == 'Linux':
            ctx['cpu_features'] = self._detect_linux_cpu_features()
            ctx['kernel_pac_config'] = self._detect_linux_kernel_pac()
        elif ctx['host_os'] == 'Darwin':
            ctx['cpu_features'] = self._detect_macos_cpu_features()

        feat = ctx['cpu_features']
        on_arm64 = ctx['is_arm64_host']
        has_pauth = feat.get('pauth', False)
        has_fpac = feat.get('fpac', False)

        def _applicability(module, needs_arm64, needs_pauth, hw_dependent, note=''):
            if not needs_arm64:
                return {'applicable': True, 'note': note or 'Static analysis - no hardware dependency'}
            if not on_arm64:
                return {'applicable': False, 'note': f'Requires ARM64 host (current: {arch})'}
            if needs_pauth and not has_pauth:
                return {'applicable': False, 'note': 'Host CPU lacks FEAT_PAuth'}
            if hw_dependent:
                return {'applicable': True, 'note': note}
            return {'applicable': True, 'note': note or 'Running on ARM64'}

        ctx['module_applicability'] = {
            'signing_gadgets':  _applicability('signing_gadgets', False, False, False),
            'pac_oracles':      _applicability('pac_oracles', False, False, False),
            'cross_chains':     _applicability('cross_chains', False, False, False),
            'jop_dispatchers':  _applicability('jop_dispatchers', False, False, False),
            'coverage':         _applicability('coverage', False, False, False),
            'key_diversity':    _applicability('key_diversity', False, False, False),
            'auth_inventory':   _applicability('auth_inventory', False, False, False),
            'transitions':      _applicability('transitions', False, False, False),
            'constraints':      _applicability('constraints', False, False, False),
            'bti_pac_combined': _applicability('bti_pac_combined', False, False, False),
            'composability':    _applicability('composability', False, False, False),
            'data_vs_inst':     _applicability('data_vs_inst', False, False, False),
            'zero_context':     _applicability('zero_context', False, False, False),
            'pacman':           _applicability('pacman', True, True, True,
                                'Requires speculative execution of PAC auth + TLB timing side-channel; '
                                'CPU-specific susceptibility requires measurement on the target'),
            'brute_force':      _applicability('brute_force', True, True, True,
                                'Requires process restart/fork without re-keying; '
                                + ('FPAC detected - each failure faults' if has_fpac
                                   else 'No FPAC - failed auth only corrupts pointer')),
            'fpac':             _applicability('fpac', True, True, False,
                                f"Host FPAC: {'yes' if has_fpac else 'no'}"),
            'sctlr':            _applicability('sctlr', True, False, True,
                                'Requires EL1+ write access to SCTLR - kernel exploit prerequisite'),
            'el_key_sep':       _applicability('el_key_sep', True, False, True,
                                'Apple-specific EL key derivation - check target SoC'),
        }

        self._cached_runtime_ctx = ctx
        return ctx

    def _detect_linux_cpu_features(self) -> dict:
        """Parse /proc/cpuinfo for PAC-related CPU features."""
        features = {}
        try:
            cpuinfo = Path('/proc/cpuinfo').read_text()
            for line in cpuinfo.splitlines():
                if line.startswith('Features'):
                    feats = line.split(':', 1)[1].strip().split()
                    features['pauth'] = 'paca' in feats or 'pacg' in feats
                    features['fpac'] = 'fpac' in feats or 'fpaccombine' in feats
                    features['pauth2'] = 'pauth2' in feats or 'epac' in feats
                    features['bti'] = 'bti' in feats
                    features['mte'] = 'mte' in feats or 'mte2' in feats or 'mte3' in feats
                    features['sve'] = 'sve' in feats
                    features['raw'] = [f for f in feats if f in (
                        'paca', 'pacg', 'fpac', 'fpaccombine', 'pauth2', 'epac',
                        'bti', 'mte', 'mte2', 'mte3')]
                    break
        except (OSError, PermissionError):
            pass
        return features

    def _detect_macos_cpu_features(self) -> dict:
        """Query sysctl for PAC-related CPU features on macOS."""
        features = {}
        sysctl_keys = {
            'pauth': ['hw.optional.arm.FEAT_PAuth',
                       'hw.optional.armv8_3_compnum'],
            'pauth2': ['hw.optional.arm.FEAT_PAuth2'],
            'fpac': ['hw.optional.arm.FEAT_FPAC'],
            'bti': ['hw.optional.arm.FEAT_BTI'],
        }
        for feat_name, keys in sysctl_keys.items():
            for key in keys:
                try:
                    result = subprocess.run(
                        ['sysctl', '-n', key],
                        capture_output=True, text=True, timeout=3)
                    if result.returncode == 0 and result.stdout.strip() == '1':
                        features[feat_name] = True
                        break
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if feat_name not in features:
                features[feat_name] = False
        return features

    def _detect_linux_kernel_pac(self) -> dict:
        """Check kernel config for PAC-related options."""
        config = {}
        config_text = None

        try:
            config_text = gzip.open('/proc/config.gz', 'rt').read()
        except (OSError, gzip.BadGzipFile):
            pass

        if config_text is None:
            import glob
            for path in sorted(glob.glob('/boot/config-*'), reverse=True):
                try:
                    config_text = Path(path).read_text()
                    break
                except OSError:
                    continue

        if config_text is None:
            return config

        pac_keys = [
            'CONFIG_ARM64_PTR_AUTH',
            'CONFIG_ARM64_PTR_AUTH_KERNEL',
            'CONFIG_ARM64_BTI',
            'CONFIG_ARM64_BTI_KERNEL',
            'CONFIG_ARM64_MTE',
            'CONFIG_ARM64_EPAN',
        ]
        for key in pac_keys:
            for line in config_text.splitlines():
                stripped = line.strip()
                if stripped.startswith(key + '='):
                    config[key] = stripped.split('=', 1)[1]
                elif stripped == f'# {key} is not set':
                    config[key] = 'n'
        return config

    # ── Signing Gadget Discovery ──────────────────────────────

    @cached_analysis
    def find_signing_gadgets(self) -> List[SigningGadget]:
        """Find non-prologue signing sites and nearby input/storage evidence."""
        results = []
        for i, (addr, m, o, sz) in enumerate(self.insns):
            if m not in PAC_SIGN_ALL:
                continue
            is_sp_sign = m in PROLOGUE_PAC or \
                         (m in ('pacia', 'pacib') and o.replace(' ', '') == 'x30,sp')
            if is_sp_sign:
                func_addr = None
                for fa in self.func_boundaries:
                    if fa <= addr < fa + 16:
                        func_addr = fa
                        break
                if func_addr is not None:
                    continue
                # Heuristic for stripped binaries: pac + frame setup = prologue
                next_insns = self._window(i, before=0, after=3)
                is_prologue = any(
                    (nm.startswith('stp') and 'x29' in no and 'x30' in no) or
                    (nm == 'sub' and no.startswith('sp, sp,')) or
                    (nm.startswith('stp') and 'sp' in no and 'x30' in no)
                    for _, nm, no, _ in next_insns[1:3]
                )
                if is_prologue:
                    continue

            # Filter intentional vtable signing: pacda/pacia with compile-time
            # discriminator (movk #imm, lsl #48) in context register -- these are
            # the kernel/system's own PAC-protected vtable initialization, not gadgets
            if m in ('pacda', 'pacia', 'pacdb', 'pacib'):
                parts = o.replace(' ', '').split(',')
                if len(parts) == 2:
                    ctx_reg = parts[1]
                    pre = self._window(i, before=6, after=0)
                    has_disc = any(
                        wm == 'movk' and ctx_reg in wo and 'lsl#48' in wo.replace(' ', '')
                        for _, wm, wo, _ in pre
                    )
                    if has_disc:
                        continue

            window_before = self._window(i, before=8, after=0)
            window_after = self._window(i, before=0, after=6)

            stores_result = False
            store_target = ''
            signed_reg = self._pac_dest_reg(m, o)
            aliases = {signed_reg} if signed_reg else set()
            for after_index, (after_addr, wm, wo, _) in enumerate(window_after):
                if after_index == 0:
                    continue
                if self._func_at(after_addr) != self._func_at(addr) or wm in RET_INSNS or wm in INDIRECT_BRANCH or wm == 'b':
                    break
                parts = wo.replace(' ', '').split(',')
                if wm == 'mov' and len(parts) >= 2:
                    dst = self._canonical_reg(parts[0])
                    src = self._canonical_reg(parts[1])
                    if src in aliases:
                        aliases.add(dst)
                if wm.startswith(('str', 'stp')):
                    value_operands = wo.split('[', 1)[0]
                    if any(self._reg_in(reg, value_operands) for reg in aliases if reg):
                        stores_result = True
                        store_target = wo
                        break
                meta = self.insn_meta.get(after_addr, {})
                overwritten = {self._canonical_reg(reg) for reg in meta.get('regs_write', ())}
                if signed_reg in overwritten and not (wm == 'mov' and signed_reg in aliases):
                    break

            controlled = self._estimate_controlled_regs(window_before, m, o)
            if not controlled and not stores_result:
                continue

            difficulty = 'hard'
            if stores_result and len(controlled) >= 2:
                difficulty = 'easy'
            elif stores_result or len(controlled) >= 1:
                difficulty = 'medium'

            instrs = [f"{a:#x}: {mm} {oo}" for a, mm, oo, _ in
                      self._window(i, before=3, after=3)]

            func = self._func_at(addr)
            if self._is_suppressed(addr, func, 'signing-gadget'):
                continue
            results.append(SigningGadget(
                address=addr,
                function=func,
                instructions=instrs,
                pac_mnemonic=m,
                controlled_regs=controlled,
                stores_result=stores_result,
                store_target=store_target,
                difficulty=difficulty,
            ))
        return results

    def _estimate_controlled_regs(self, window, pac_mnem, pac_ops) -> List[str]:
        """Heuristic: check if registers used by PAC instruction are loaded
        from stack/memory shortly before.
        Stops backward scan at ret/branch to avoid cross-function matches."""
        target_regs = set()
        is_sp_variant = pac_mnem in ('paciasp', 'pacibsp') or \
                        (pac_mnem in ('pacia', 'pacib') and pac_ops.replace(' ', '') == 'x30,sp')
        if is_sp_variant:
            target_regs = {'x30', 'lr'}
        elif pac_mnem in ('paciaz', 'pacibz', 'paciza', 'pacizb', 'pacdza', 'pacdzb'):
            parts = pac_ops.split(',')
            if parts:
                target_regs.add(parts[0].strip())
        elif pac_ops:
            for p in pac_ops.split(','):
                p = p.strip()
                if p.startswith('x') or p.startswith('w'):
                    target_regs.add(p)

        controlled = []
        for _, wm, wo, _ in reversed(window):
            if wm in RET_INSNS or wm == 'b' or wm.startswith('b.') or wm == 'bl':
                break
            if wm.startswith('ldr') or wm.startswith('ldp'):
                parts = wo.split(',')
                for p in parts:
                    p = p.strip().rstrip(']').lstrip('[')
                    if p in target_regs:
                        if 'sp' in wo or 'x29' in wo:
                            controlled.append(p)
            elif wm == 'mov':
                parts = wo.split(',')
                if len(parts) >= 2:
                    dst = parts[0].strip()
                    src = parts[1].strip()
                    if dst in target_regs and not src.startswith('#'):
                        controlled.append(dst)
        return controlled

    # ── PAC Oracle Detection ──────────────────────────────────

    @cached_analysis
    def find_pac_oracles(self) -> List[PacOracle]:
        """Detect AUTIA->PACIA/PACIZA chains that leak signing results.
        Pattern: auth fails -> pointer corrupted -> re-sign -> store.
        Attacker flips bit 62 of stored result to recover valid PAC.
        Stops at control flow boundaries (ret/branch) to avoid
        cross-function false positives."""
        results = []
        for i, (addr, m, o, sz) in enumerate(self.insns):
            if m not in PAC_AUTH_ALL or m in PAC_AUTH_LOAD:
                continue
            auth_reg = self._pac_dest_reg(m, o)
            auth_key = self._pac_key(m)
            lookahead = self._window(i, before=0, after=8)
            for j, (a2, m2, o2, _) in enumerate(lookahead):
                if j == 0:
                    continue
                if m2 in RET_INSNS or m2 in INDIRECT_BRANCH or \
                   m2 == 'b' or m2.startswith('b.') or m2 == 'bl':
                    break
                if m2 not in PAC_SIGN_ALL:
                    continue
                sign_reg = self._pac_dest_reg(m2, o2)
                if not auth_reg or sign_reg != auth_reg or self._pac_key(m2) != auth_key:
                    continue
                # Found auth->sign chain. Check if result stored.
                dest = ''
                for _, m3, o3, _ in lookahead[j+1:]:
                    if m3.startswith(('str', 'stp')) and self._reg_in(sign_reg, o3.split('[', 1)[0]):
                        dest = o3
                        break

                instrs = [f"{a:#x}: {mm} {oo}" for a, mm, oo, _ in
                          self._window(i, before=1, after=j+3)]
                notes = 'AUTIA fail corrupts pointer; re-signing gives PAC with bit 62 flipped'
                if not dest:
                    notes += ' (result not stored - may still leak via register)'

                func = self._func_at(addr)
                if self._is_suppressed(addr, func, 'oracle'):
                    break
                results.append(PacOracle(
                    address=addr,
                    function=func,
                    instructions=instrs,
                    auth_mnemonic=m,
                    sign_mnemonic=m2,
                    result_destination=dest or 'register only',
                    notes=notes,
                ))
                break
        return results

    # ── PACMAN Speculative Oracle Gadgets ─────────────────────

    @cached_analysis
    def find_pacman_gadgets(self) -> List[dict]:
        """Identify gadgets suitable for PACMAN-style speculative probing.
        Pattern: auth instruction followed by memory access (TLB probe)
        within a small window, without intervening branches."""
        results = []
        for i, (addr, m, o, sz) in enumerate(self.insns):
            if m not in PAC_AUTH_ALL or m in PAC_AUTH_LOAD:
                continue
            auth_reg = self._pac_dest_reg(m, o)
            if not auth_reg:
                continue
            window = self._window(i, before=0, after=6)
            for j, (a2, m2, o2, _) in enumerate(window):
                if j == 0:
                    continue
                if m2 in ('b', 'b.eq', 'b.ne', 'b.lt', 'b.gt', 'b.le', 'b.ge',
                          'cbz', 'cbnz', 'tbz', 'tbnz', 'bl'):
                    break
                if m2 in ('sb', 'csdb', 'isb', 'dsb', 'dmb', 'ssbb', 'pssbb'):
                    break
                if (m2.startswith(('ldr', 'str', 'ldp', 'stp')) and
                        auth_reg in self._memory_base_regs(o2)):
                    func = self._func_at(addr)
                    is_rt = self._is_runtime_func(func)
                    notes = ('Authenticated pointer is dereferenced without an intervening speculation '
                             'barrier; PACMAN feasibility still depends on CPU speculation and a '
                             'measurable microarchitectural channel')
                    if is_rt:
                        notes = f'[RUNTIME/UNWINDER - {func}] ' + notes
                    instrs = [f"{a:#x}: {mm} {oo}" for a, mm, oo, _ in window[:j+1]]
                    if self._is_suppressed(addr, func, 'pacman-gadget'):
                        break
                    results.append({
                        'address': addr,
                        'function': func,
                        'instructions': instrs,
                        'auth_mnemonic': m,
                        'mem_access': f"{m2} {o2}",
                        'distance': j,
                        'is_runtime': is_rt,
                        'notes': notes,
                    })
                    break
        return results

    # ── Brute Force Feasibility ───────────────────────────────

    @cached_analysis
    def analyze_brute_force(self) -> dict:
        """Estimate PAC bit width and brute-force timing."""
        is_kernel = self._is_kernel_binary()

        va_bits = self._detect_va_bits()
        pac_min = max(1, 55 - va_bits)
        pac_max = max(pac_min, min(64 - va_bits, 24 if is_kernel else 16))
        addr_type = 'kernel (TTBR1)' if is_kernel else 'userspace (TTBR0)'

        attempts = 2 ** pac_min
        attempts_max = 2 ** pac_max
        us_per_attempt = 50  # ~50µs per signing/verification cycle
        time_s = (attempts * us_per_attempt) / 1_000_000
        time_s_max = (attempts_max * us_per_attempt) / 1_000_000
        time_min = time_s / 60

        has_fpac = self._detect_fpac_support()
        if has_fpac is True:
            fpac_impact = 'Each failed authentication faults immediately; isolated retry/restart is required.'
        elif has_fpac is False:
            fpac_impact = 'Failed authentication corrupts the pointer until use; non-faulting oracle paths may exist.'
        else:
            fpac_impact = 'Unknown from the binary; use --fpac-mode or --runtime-ctx for target evidence.'

        return {
            'address_type': addr_type,
            'va_bits': va_bits,
            'va_bits_source': getattr(self, '_va_bits_source', 'unknown'),
            'estimated_pac_bits': pac_min,
            'estimated_pac_bits_range': [pac_min, pac_max],
            'brute_force_attempts': attempts,
            'brute_force_attempts_range': [attempts, attempts_max],
            'estimated_time_seconds': round(time_s, 1),
            'estimated_time_seconds_range': [round(time_s, 1), round(time_s_max, 1)],
            'estimated_time_minutes': round(time_min, 2),
            'us_per_attempt': us_per_attempt,
            'fpac_enabled': has_fpac,
            'fpac_impact': fpac_impact,
            'zero_context_count': sum(1 for _, m, _, _ in self.insns if m in PAC_ZERO_CTX_SIGN),
            'zero_context_note': 'Zero-context signatures are portable across call sites - reduces search space',
            'qarma3_interaction': 'If FEAT_PACQARMA3 is used and signing oracles exist, '
                                  'differential cryptanalysis may be faster than brute-force',
        }

    # ── SCTLR Manipulation Detection ──────────────────────────

    @cached_analysis
    def find_sctlr_manipulation(self) -> List[dict]:
        """Detect MSR instructions targeting SCTLR_EL1 or PAC-related
        system registers. These can disable PAC entirely."""
        results = []
        sctlr_patterns = ['sctlr_el1', 'sctlr_el2', 'sctlr_el3',
                          's3_0_c1_c0_0',   # SCTLR_EL1 encoding
                          's3_4_c1_c0_0',   # SCTLR_EL2
                          's3_4_c15_c0_4',  # Apple EL key selection
                          'apiakeylo_el1', 'apiakeyhi_el1',
                          'apibkeylo_el1', 'apibkeyhi_el1',
                          'apdakeylo_el1', 'apdakeyhi_el1',
                          'apdbkeylo_el1', 'apdbkeyhi_el1',
                          'apgakeylo_el1', 'apgakeyhi_el1']

        for i, (addr, m, o, sz) in enumerate(self.insns):
            if m != 'msr':
                continue
            op_lower = o.lower()
            for pat in sctlr_patterns:
                if pat in op_lower:
                    instrs = [f"{a:#x}: {mm} {oo}" for a, mm, oo, _ in
                              self._window(i, before=3, after=1)]
                    impact = 'PAC key register write' if 'key' in pat else 'SCTLR write - may disable PAC'
                    if 's3_4_c15' in pat:
                        impact = 'Apple EL key selection register - controls which EL keys are active'

                    results.append({
                        'address': addr,
                        'function': self._func_at(addr),
                        'instructions': instrs,
                        'register': pat,
                        'impact': impact,
                    })
                    break
        return results

    # ── Data vs Instruction PAC Analysis ──────────────────────

    @cached_analysis
    def analyze_data_vs_instruction_pac(self) -> dict:
        """Separate analysis of instruction-pointer PAC (PACIA/B) vs
        data-pointer PAC (PACDA/B). Excludes runtime/unwinder PAC from
        assessment to avoid false positives on non-PAC binaries."""
        i_sign = i_auth = d_sign = d_auth = 0
        i_rt = d_rt = 0
        func_ipac = defaultdict(int)
        func_dpac = defaultdict(int)
        for addr, m, _, _ in self.insns:
            func = self._func_at(addr)
            is_rt = self._is_runtime_func(func)
            if m in PAC_SIGN_A | PAC_SIGN_B:
                if is_rt: i_rt += 1
                else:
                    i_sign += 1
                    func_ipac[func] += 1
            elif m in PAC_AUTH_A | PAC_AUTH_B:
                if is_rt: i_rt += 1
                else:
                    i_auth += 1
                    func_ipac[func] += 1
            elif m in PAC_SIGN_DA | PAC_SIGN_DB:
                if is_rt: d_rt += 1
                else:
                    d_sign += 1
                    func_dpac[func] += 1
            elif m in PAC_AUTH_DA | PAC_AUTH_DB:
                if is_rt: d_rt += 1
                else:
                    d_auth += 1
                    func_dpac[func] += 1

        rt_note = (f' ({i_rt + d_rt} in runtime/unwinder - excluded from assessment)'
                   if i_rt + d_rt > 0 else '')

        unprotected_data_funcs = []
        if d_sign + d_auth == 0 and i_sign + i_auth > 0:
            assessment = (f'No DA/DB data-pointer PAC instructions observed while instruction-PAC '
                          f'operations are present; this is a usage inventory, not proof that every '
                          f'data pointer is unprotected{rt_note}')
            for func in func_ipac:
                if func not in func_dpac:
                    unprotected_data_funcs.append(func)
        elif i_sign + i_auth == 0 and d_sign + d_auth == 0:
            assessment = f'No application-level PAC usage detected{rt_note}'
        else:
            assessment = f'Both instruction- and data-key PAC operations are present{rt_note}'
            for func in func_ipac:
                if func not in func_dpac:
                    unprotected_data_funcs.append(func)

        return {
            'instruction_pac': {
                'sign_count': i_sign,
                'auth_count': i_auth,
                'total': i_sign + i_auth,
                'functions': len(func_ipac),
            },
            'data_pac': {
                'sign_count': d_sign,
                'auth_count': d_auth,
                'total': d_sign + d_auth,
                'functions': len(func_dpac),
            },
            'runtime_pac_excluded': i_rt + d_rt,
            'unprotected_data_funcs': len(unprotected_data_funcs),
            'assessment': assessment,
        }

    # ── EL Key Separation Detection ───────────────────────────

    @cached_analysis
    def find_el_key_patterns(self) -> List[dict]:
        """Detect exception-level key management patterns.
        Apple: AND Xn, Xn, #0xFFFFFFFFFFFFFFFB clears bit 2 of
        S3_4_C15_C0_4 before signing userspace pointers."""
        results = []
        for i, (addr, m, o, sz) in enumerate(self.insns):
            if m == 'and' and '0xfffffffffffffffb' in o.lower():
                window = self._window(i, before=2, after=5)
                has_msr = any(wm == 'msr' for _, wm, _, _ in window)
                has_pac = any(wm in PAC_SIGN_ALL for _, wm, _, _ in window)
                if has_msr or has_pac:
                    instrs = [f"{a:#x}: {mm} {oo}" for a, mm, oo, _ in window]
                    results.append({
                        'address': addr,
                        'function': self._func_at(addr),
                        'instructions': instrs,
                        'pattern': 'Apple EL key separation - clears bit 2 before userspace signing',
                    })
            elif m == 'msr' and 's3_4_c15' in o.lower():
                instrs = [f"{a:#x}: {mm} {oo}" for a, mm, oo, _ in
                          self._window(i, before=3, after=1)]
                results.append({
                    'address': addr,
                    'function': self._func_at(addr),
                    'instructions': instrs,
                    'pattern': 'EL key selection register access',
                })
        return results

    # ── JOP Dispatcher Detection ─────────────────────────────

    @cached_analysis
    def find_jop_dispatchers(self) -> List[JopDispatcher]:
        """Find JOP dispatcher gadgets: sequences that set argument
        registers then branch via a register. Essential for PAC-protected
        binaries where ROP is dead.

        Filters:
        - For blr: branch register must be loaded from memory (not just a
          preceding mov/bl target), otherwise it's a normal indirect call
        - Requires arg registers set from controllable sources
        - Excludes dispatchers where branch_reg == x30 (that's a ret pattern)"""
        results = []
        for i, (addr, m, o, sz) in enumerate(self.insns):
            if m not in ('br', 'blr') and m not in PAC_AUTH_BR and m not in PAC_AUTH_BR_Z:
                continue
            if self._in_stub_section(addr):
                continue

            branch_reg = self._canonical_reg(o.split(',')[0].strip())
            if branch_reg in ('x30', 'lr'):
                continue

            window = self._window(i, before=8, after=0)
            if self.symbolic:
                taint = self._interprocedural_taint(i)
            elif self.deep:
                taint = self._taint_cross_block(i)
            else:
                taint = self._taint_basic_block(i)

            branch_source = taint.get(branch_reg, ('unknown', ''))[0]
            branch_reg_from_mem = branch_source in ('mem', 'stack')
            arg_regs = set()
            for _, wm, wo, _ in window:
                if wm == 'mov':
                    parts = wo.split(',')
                    if len(parts) >= 2:
                        dst = parts[0].strip()
                        if dst in ('x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7',
                                   'w0', 'w1', 'w2', 'w3', 'w4', 'w5', 'w6', 'w7'):
                            arg_regs.add(dst)
                elif wm.startswith('ldr') and not wm.startswith('ldrs'):
                    parts = wo.split(',')
                    if parts:
                        dst = parts[0].strip()
                        if dst in ('x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'):
                            arg_regs.add(dst)
                elif wm.startswith('ldp'):
                    for p in wo.split(','):
                        p = p.strip().rstrip(']').lstrip('[')

            if not arg_regs:
                continue

            if m == 'blr' and not branch_reg_from_mem:
                continue

            is_pac_branch = m in PAC_AUTH_BR or m in PAC_AUTH_BR_Z
            if len(arg_regs) >= 3:
                cat = 'dispatcher'
            elif len(arg_regs) >= 1 and m in ({'br'} | PAC_AUTH_BR):
                cat = 'trampoline'
            else:
                cat = 'functional'

            if is_pac_branch:
                cat += '/pac-protected'
            if m in PAC_AUTH_BR_Z:
                cat += '/zero-ctx'

            if self.deep and hasattr(self, '_indirect_targets') and addr in self._indirect_targets:
                cat += f'/target:{self._indirect_targets[addr]}'

            func = self._func_at(addr)
            if self._is_suppressed(addr, func, 'jop'):
                continue
            instrs = [f"{a:#x}: {mm} {oo}" for a, mm, oo, _ in window]
            arg_sources = {}
            for reg in sorted(arg_regs):
                xreg = reg.replace('w', 'x') if reg.startswith('w') else reg
                if xreg in taint:
                    arg_sources[reg] = taint[xreg][0]
                elif reg in taint:
                    arg_sources[reg] = taint[reg][0]
            results.append(JopDispatcher(
                address=addr,
                instructions=instrs,
                arg_regs_set=sorted(arg_regs),
                branch_reg=branch_reg,
                category=cat,
                arg_sources=arg_sources,
                branch_source=branch_source,
                function=func,
            ))
        return results

    # ── Zero-Context Pair Correlation ────────────────────────

    @cached_analysis
    def find_zero_context_pairs(self) -> dict:
        """Correlate zero-context signing sites with zero-context auth sites.
        Zero-context means context=0, making signatures portable across
        all call sites using the same key."""
        sign_by_key = defaultdict(list)
        auth_by_key = defaultdict(list)
        for i, (addr, m, o, sz) in enumerate(self.insns):
            func = self._func_at(addr)
            entry = {'address': addr, 'mnemonic': m, 'function': func}
            if m in PAC_ZERO_CTX_SIGN:
                if m in PAC_SIGN_A:
                    sign_by_key['A'].append(entry)
                elif m in PAC_SIGN_B:
                    sign_by_key['B'].append(entry)
                elif m in PAC_SIGN_DA:
                    sign_by_key['DA'].append(entry)
                elif m in PAC_SIGN_DB:
                    sign_by_key['DB'].append(entry)
            elif m in PAC_ZERO_CTX_AUTH:
                if m in PAC_AUTH_A:
                    auth_by_key['A'].append(entry)
                elif m in PAC_AUTH_B:
                    auth_by_key['B'].append(entry)
                elif m in PAC_AUTH_DA:
                    auth_by_key['DA'].append(entry)
                elif m in PAC_AUTH_DB:
                    auth_by_key['DB'].append(entry)
                elif m in PAC_AUTH_BR_Z:
                    if m in ('braaz', 'blraaz'):
                        auth_by_key['A'].append(entry)
                    elif m in ('brabz', 'blrabz'):
                        auth_by_key['B'].append(entry)

            if m in ('pacia', 'pacib', 'pacda', 'pacdb') and m not in PAC_ZERO_CTX_SIGN:
                ops = o.replace(' ', '').split(',')
                if len(ops) >= 2 and ops[1] == 'xzr':
                    if m in PAC_SIGN_A:
                        sign_by_key['A'].append(entry)
                    elif m in PAC_SIGN_B:
                        sign_by_key['B'].append(entry)
                    elif m in PAC_SIGN_DA:
                        sign_by_key['DA'].append(entry)
                    elif m in PAC_SIGN_DB:
                        sign_by_key['DB'].append(entry)
            if m in ('autia', 'autib', 'autda', 'autdb') and m not in PAC_ZERO_CTX_AUTH:
                ops = o.replace(' ', '').split(',')
                if len(ops) >= 2 and ops[1] == 'xzr':
                    if m in PAC_AUTH_A:
                        auth_by_key['A'].append(entry)
                    elif m in PAC_AUTH_B:
                        auth_by_key['B'].append(entry)
                    elif m in PAC_AUTH_DA:
                        auth_by_key['DA'].append(entry)
                    elif m in PAC_AUTH_DB:
                        auth_by_key['DB'].append(entry)

        portable_keys = []
        for key in set(list(sign_by_key.keys()) + list(auth_by_key.keys())):
            if sign_by_key.get(key) and auth_by_key.get(key):
                portable_keys.append(key)

        total_sign = sum(len(v) for v in sign_by_key.values())
        total_auth = sum(len(v) for v in auth_by_key.values())

        if portable_keys:
            assessment = (
                f'{total_sign} zero-ctx sign + {total_auth} zero-ctx auth. '
                f'Portable within key(s): {", ".join(sorted(portable_keys))} - '
                f'signatures from any sign site valid at any auth site with matching key')
        else:
            assessment = 'No zero-context pairs with matching keys - replay not trivially portable'

        return {
            'sign_by_key': {k: v for k, v in sign_by_key.items()},
            'auth_by_key': {k: v for k, v in auth_by_key.items()},
            'sign_count': total_sign,
            'auth_count': total_auth,
            'portable_keys': portable_keys,
            'portable': len(portable_keys) > 0,
            'assessment': assessment,
        }

    # ── Composability Scoring ────────────────────────────────

    @cached_analysis
    def analyze_composability(self) -> ComposabilityScore:
        """Rate how close the binary's gadget set is to a full PAC bypass chain.

        Four categories:
          Signature acquisition (30) — how to forge/obtain valid PAC signatures
          Execution control    (25) — how to redirect control flow
          Argument setup       (15) — controlling gadget inputs
          Protection weakness  (30) — factors that weaken PAC enforcement

        Returns N/A for binaries without meaningful PAC protection."""
        if self.app_pac_count == 0:
            return ComposabilityScore(
                signing_gadgets=0, oracles=0, arg_control=0,
                branch_control=0, stack_pivot=0, preauth_unsigned=0,
                key_confusion=0, modifier_confusion=0, context_manip=0,
                xpac_bypass=0, zero_ctx=0, coverage_pct=0, score=-1,
                verdict='N/A - no application-level PAC instructions were observed; '
                        'PAC bypass scoring is not meaningful. Review other mitigations separately.',
                missing=[], breakdown={},
            )

        signing = len(self.find_signing_gadgets())
        oracles = len(self.find_pac_oracles())
        preauth = self.find_preauth_loads()
        preauth_unsigned = sum(1 for p in preauth if not p.get('authenticated_branch'))
        pivots = len(self.find_stack_pivot_gadgets())
        kc = len(self.find_key_confusion())
        mc = len(self.find_modifier_confusion())
        cm = len(self.find_context_manipulation())
        xb = len(self.find_xpac_bypass())

        branch_control = sum(1 for _, m, _, _ in self.insns if m in ('br', 'blr'))
        arg_control = sum(1 for _, m, o, _ in self.insns
                          if m.startswith('ldp') and 'x29' in o and 'x30' in o and 'sp' in o)

        jop = self.find_jop_dispatchers()
        jop_stack = sum(1 for d in jop if any(v == 'stack' for v in d.arg_sources.values()))

        zc = self.find_zero_context_pairs()
        zero_ctx_count = zc.get('sign_count', 0) + zc.get('auth_count', 0)

        cov = self.analyze_pac_coverage()
        coverage_pct = cov.get('coverage_percent', 100.0)

        breakdown = {}
        missing = []

        # 1. Signature acquisition (max 30)
        sig = 0
        if signing > 0: sig += 20
        if oracles > 0: sig += 15
        if preauth_unsigned > 0: sig += 10
        sig = min(sig, 30)
        breakdown['signature'] = sig
        if sig == 0:
            missing.append('signature forgery (no signing gadgets, oracles, or pre-auth loads)')

        # 2. Execution control (max 25)
        exc = 0
        if pivots > 0: exc += 12
        if branch_control > 0: exc += 8
        if cm > 0: exc += 8
        exc = min(exc, 25)
        breakdown['execution'] = exc
        if exc == 0:
            missing.append('execution redirection (no pivots, branches, or LR control)')

        # 3. Argument setup (max 15)
        arg = 0
        if jop_stack > 0: arg += 10
        if arg_control > 0: arg += 8
        arg = min(arg, 15)
        breakdown['arguments'] = arg
        if arg == 0:
            missing.append('argument control')

        # 4. Protection weaknesses (max 30)
        weak = 0
        if kc > 0: weak += 8
        if mc > 0: weak += 6
        if zero_ctx_count > 0: weak += 6
        if xb > 0: weak += 4
        if coverage_pct < 50: weak += 5
        if coverage_pct < 80 and coverage_pct >= 50: weak += 3
        weak = min(weak, 30)
        breakdown['weakness'] = weak

        score = sig + exc + arg + weak

        if score >= 80:
            verdict = 'HIGH - most components for full PAC bypass chain present'
        elif score >= 50:
            verdict = 'MEDIUM - partial chain possible, some primitives missing'
        elif score >= 20:
            verdict = 'LOW - significant primitives missing'
        else:
            verdict = 'MINIMAL - PAC bypass unlikely from this binary alone'

        return ComposabilityScore(
            signing_gadgets=signing, oracles=oracles,
            arg_control=arg_control, branch_control=branch_control,
            stack_pivot=pivots, preauth_unsigned=preauth_unsigned,
            key_confusion=kc, modifier_confusion=mc,
            context_manip=cm, xpac_bypass=xb, zero_ctx=zero_ctx_count,
            coverage_pct=coverage_pct, score=score,
            verdict=verdict, missing=missing, breakdown=breakdown,
        )

    # ── Key Diversity Analysis ───────────────────────────────

    @cached_analysis
    def analyze_key_diversity(self) -> dict:
        """Check whether binary uses A-key only, B-key only, or both.
        Single-key = simpler attack surface. Separates runtime/unwinder PAC
        from application-level PAC."""
        a_app = a_rt = b_app = b_rt = da_app = da_rt = db_app = db_rt = 0
        for addr, m, _, _ in self.insns:
            is_rt = self._is_runtime_func(self._func_at(addr))
            if m in PAC_SIGN_A | PAC_AUTH_A:
                if is_rt: a_rt += 1
                else: a_app += 1
            elif m in PAC_SIGN_B | PAC_AUTH_B:
                if is_rt: b_rt += 1
                else: b_app += 1
            elif m in PAC_SIGN_DA | PAC_AUTH_DA:
                if is_rt: da_rt += 1
                else: da_app += 1
            elif m in PAC_SIGN_DB | PAC_AUTH_DB:
                if is_rt: db_rt += 1
                else: db_app += 1

        keys_used = []
        if a_app > 0: keys_used.append('IA')
        if b_app > 0: keys_used.append('IB')
        if da_app > 0: keys_used.append('DA')
        if db_app > 0: keys_used.append('DB')

        runtime_total = a_rt + b_rt + da_rt + db_rt
        runtime_note = (f' ({runtime_total} additional PAC instructions in runtime/unwinder code - '
                        'not application-level)' if runtime_total > 0 else '')

        if not keys_used and runtime_total > 0:
            assessment = (f'No application-level PAC keys.{runtime_note}')
        elif not keys_used:
            assessment = 'No PAC keys detected.'
        elif len(keys_used) == 1:
            assessment = (f'Uses {len(keys_used)} key: {", ".join(keys_used)}. '
                         f'Single key - all signatures use same key, simplifying attack.{runtime_note}')
        else:
            assessment = (f'Uses {len(keys_used)} keys: {", ".join(keys_used)}. '
                         f'Multiple keys - attacker needs different forgery primitives per key.{runtime_note}')

        return {
            'instruction_a_key': a_app,
            'instruction_b_key': b_app,
            'data_a_key': da_app,
            'data_b_key': db_app,
            'runtime_pac_count': runtime_total,
            'keys_used': keys_used,
            'diversity': len(keys_used),
            'assessment': assessment,
        }

    # ── Authenticated Pointer Inventory ──────────────────────

    @cached_analysis
    def inventory_auth_pointers(self) -> List[AuthPointerEntry]:
        """Catalog signed pointers stored in __auth_got / __auth_ptr sections.
        Reuse requires compatible key/modifier/pointer semantics and access.
        Regular .got/.got.plt entries are not treated as authenticated."""
        results = []
        if self.auth_pointer_metadata:
            section_by_addr = []
            for meta in self.section_meta:
                section_by_addr.append((meta.get('address', 0),
                                        meta.get('address', 0) + meta.get('size', 0),
                                        meta.get('name', 'unknown')))
            for pointer in self.auth_pointer_metadata:
                address = pointer['virtual_addr']
                section = next((name for lo, hi, name in section_by_addr if lo <= address < hi),
                               'chained-fixups')
                target = (f"bind ordinal {pointer['target']}" if pointer['bind'] else
                          f"rebase target {pointer['target']:#x}")
                key_hint = (f"{pointer['key']}, diversity={pointer['diversity']:#x}, "
                            f"address-diversity={pointer['address_diversity']}")
                if not self._is_suppressed(address, target, 'auth-pointer'):
                    results.append(AuthPointerEntry(
                        section=section, offset=0, virtual_addr=address,
                        target_name=target, key_hint=key_hint,
                    ))
            return results
        for name, vaddr, size, data in self.data_sections:
            if name not in ('__auth_got', '__auth_ptr'):
                continue
            ptr_size = 8
            for off in range(0, len(data) - ptr_size + 1, ptr_size):
                raw = struct.unpack_from('<Q', data, off)[0]
                if raw == 0:
                    continue
                stripped = raw & 0x0000FFFFFFFFFFFF
                target = self.symbols.get(stripped, '')
                if not target:
                    for sym_name, sym_addr in self.symbols.items():
                        if sym_addr == stripped:
                            target = sym_name
                            break

                key_hint = ('encoded auth-pointer section entry; key/diversity require '
                            'LC_DYLD_CHAINED_FIXUPS metadata')

                if self._is_suppressed(vaddr + off, target or f'0x{stripped:x}', 'auth-pointer'):
                    continue
                results.append(AuthPointerEntry(
                    section=name,
                    offset=off,
                    virtual_addr=vaddr + off,
                    target_name=target or f'0x{stripped:x}',
                    key_hint=key_hint,
                ))
        return results

    # ── PAC Transition Mapping ───────────────────────────────

    @cached_analysis
    def find_pac_transitions(self) -> List[PacTransition]:
        """Map schema-compatible sign/auth sites across function boundaries."""
        sign_sites = []
        auth_sites = []
        for addr, mnemonic, operands, _ in self.insns:
            if mnemonic not in PAC_SIGN_ALL | PAC_AUTH_ALL | PAC_AUTH_RET:
                continue
            key = self._pac_key(mnemonic)
            if not key:
                continue
            kind, modifier = self._pac_modifier(addr, mnemonic, operands)
            site = (self._func_at(addr), addr, key, kind, modifier)
            (sign_sites if mnemonic in PAC_SIGN_ALL else auth_sites).append(site)

        ranked = []
        for sign_func, sign_addr, key, sign_kind, sign_modifier in sign_sites:
            for auth_func, auth_addr, auth_key, auth_kind, auth_modifier in auth_sites:
                if sign_func == auth_func or key != auth_key:
                    continue
                if sign_kind in ('zero', 'constant') and (sign_kind, sign_modifier) == (auth_kind, auth_modifier):
                    confidence, rank = 'exact-schema', 3
                elif sign_kind == auth_kind == 'sp':
                    confidence, rank = 'conditional-sp', 2
                elif sign_kind == auth_kind == 'register':
                    confidence, rank = 'unresolved-registers', 1
                else:
                    continue
                reachable = (self._blocks_reachable(sign_addr, auth_addr)
                             if self.deep and hasattr(self, '_cfg_edges') else None)
                distance = abs(auth_addr - sign_addr)
                notes = (f'{confidence}; modifier {sign_modifier} -> {auth_modifier}; '
                         f'link-address distance {distance:#x} (not an exploitability metric)')
                if reachable is not None:
                    notes += f'; CFG-reachable={reachable}'
                ranked.append((rank, reachable is True, PacTransition(
                    sign_func=sign_func, sign_addr=sign_addr,
                    auth_func=auth_func, auth_addr=auth_addr,
                    key_type=key, notes=notes)))
        ranked.sort(key=lambda item: (item[0], item[1]), reverse=True)
        return [item[2] for item in ranked[:100]]

    # ── FPAC Detection ───────────────────────────────────────

    def _detect_fpac_support(self) -> Optional[bool]:
        """Return FPAC state only from an explicit override or matching host CPU.

        FPAC is a CPU feature, not an ELF/Mach-O code-generation property. XPAC
        instructions and GNU branch-protection notes do not prove its presence or
        absence in the machine that will execute this image.
        """
        if self.fpac_override == 'yes':
            return True
        if self.fpac_override == 'no':
            return False
        runtime = self.detect_runtime_context()
        if runtime.get('is_arm64_host'):
            features = runtime.get('cpu_features', {})
            if 'fpac' in features:
                return bool(features['fpac'])
        return None

    @cached_analysis
    def detect_fpac(self) -> dict:
        """Full FPAC analysis."""
        has_fpac = self._detect_fpac_support()
        strip_insns = [(addr, m, o) for addr, m, o, _ in self.insns if m in STRIP_MNEMONICS]
        return {
            'fpac_likely': has_fpac,
            'fpac_status': 'enabled' if has_fpac is True else (
                'disabled' if has_fpac is False else 'unknown'),
            'strip_instructions': len(strip_insns),
            'strip_locations': [{'address': a, 'mnemonic': m, 'operands': o}
                                for a, m, o in strip_insns[:10]],
            'assessment': (
                'FEAT_FPAC enabled by explicit/runtime evidence; failed authentication faults immediately.'
                if has_fpac is True else
                'FEAT_FPAC disabled by explicit/runtime evidence; failed authentication corrupts the pointer until use.'
                if has_fpac is False else
                'FEAT_FPAC state is unknown from this binary. Use --fpac-mode yes/no or analyze on the target host.'
            ),
        }

    # ── Return Address Signing Coverage ──────────────────────

    @cached_analysis
    def analyze_pac_coverage(self) -> dict:
        """Measure symbol-resolved functions with detected return-address PAC."""
        protected = []
        unprotected = []

        func_addrs = sorted(self.func_boundaries.keys())
        for faddr in func_addrs:
            fname = self.func_boundaries[faddr]
            has_prologue_pac = False
            pac_type = ''
            has_bti = False
            has_epilogue_pac = False
            epilogue_type = ''

            for offset, (addr, m, o, sz) in enumerate(self._iter_func_insns(fname)):
                if offset < 4:
                    if m in PROLOGUE_PAC or (m in ('pacia', 'pacib') and o.replace(' ', '') == 'x30,sp'):
                        has_prologue_pac = True
                        pac_type = m
                    if m == 'bti':
                        has_bti = True
                if m in EPILOGUE_PAC or (m in ('autia', 'autib') and o.replace(' ', '') == 'x30,sp'):
                    has_epilogue_pac = True
                    epilogue_type = m

            info = FunctionPacInfo(
                name=fname, address=faddr,
                has_pac_prologue=has_prologue_pac, pac_type=pac_type,
                has_bti=has_bti,
                has_pac_epilogue=has_epilogue_pac, epilogue_type=epilogue_type,
            )
            if has_prologue_pac:
                protected.append(info)
            else:
                unprotected.append(info)

        total = len(protected) + len(unprotected)
        pct = (len(protected) / total * 100) if total > 0 else 0

        if total == 0:
            assessment = 'No symbols available - coverage cannot be measured. Use unstripped binary for accurate analysis.'
        else:
            assessment = (
                f'{pct:.1f}% PAC coverage ({len(protected)}/{total} functions). '
                + (f'{len(unprotected)} functions lack detected return signing; leaf functions '
                     'and intentionally unsigned routines require separate review.'
                   if unprotected else 'Full coverage.')
            )

        return {
            'total_functions': total,
            'protected': len(protected),
            'unprotected': len(unprotected),
            'coverage_percent': round(pct, 1),
            'protected_functions': [
                {'name': f.name, 'address': f.address, 'has_bti': f.has_bti,
                 'pac_type': f.pac_type}
                for f in protected
            ],
            'unprotected_functions': [
                {'name': f.name, 'address': f.address, 'has_bti': f.has_bti}
                for f in unprotected[:50]
            ],
            'assessment': assessment,
        }

    # ── Signing Gadget Constraint Analysis ───────────────────

    @cached_analysis
    def constraint_analysis(self) -> List[dict]:
        """For each signing gadget, determine what the attacker MUST control
        to use it (registers, memory addresses). Rate difficulty.
        Uses call graph for reachability and register taint for provenance."""
        gadgets = self.find_signing_gadgets()
        addr_to_idx = {}
        for i, (a, _, _, _) in enumerate(self.insns):
            addr_to_idx[a] = i

        results = []
        for g in gadgets:
            constraints = []
            if g.pac_mnemonic in ('pacia', 'pacda'):
                constraints.append('Must control Xd (pointer to sign) and Xn (context)')
            elif g.pac_mnemonic in ('paciza', 'pacdza', 'pacizb', 'pacdzb'):
                constraints.append('Must control Xd (pointer to sign); context is zero')
            elif g.pac_mnemonic in ('paciasp', 'pacibsp'):
                constraints.append('Must control X30/LR (return address to sign); SP is context')
                constraints.append('Must be able to call/jump to this location')

            if g.stores_result:
                constraints.append(f'Result stored: {g.store_target} - readable after execution')
            else:
                constraints.append('Result stays in register - need additional leak primitive')

            reachability = 'easy' if g.function in self.symbols else 'unknown'
            callers_of_gadget = list(self._callers.get(g.function, set()))[:5]
            if callers_of_gadget:
                reachability = 'easy'

            reg_provenance = {}
            idx = addr_to_idx.get(g.address)
            if idx is not None:
                if self.symbolic:
                    taint = self._interprocedural_taint(idx)
                elif self.deep:
                    taint = self._taint_cross_block(idx)
                else:
                    taint = self._taint_basic_block(idx)
                check_regs = list(g.controlled_regs)
                if self.symbolic:
                    pac_parts = self.insns[idx][2].replace(' ', '').split(',')
                    pac_regs = [p for p in pac_parts if p.startswith('x') or p.startswith('w')]
                    for pr in pac_regs:
                        if pr not in check_regs:
                            check_regs.append(pr)
                for reg in check_regs:
                    reg_lower = reg.lower()
                    if reg_lower in taint:
                        src_type, detail = taint[reg_lower]
                        reg_provenance[reg] = {'source': src_type, 'detail': detail}
                        if src_type == 'stack':
                            constraints.append(f'{reg} loaded from stack ({detail}) - potentially controllable if stack corruption exists')
                        elif src_type == 'mem':
                            constraints.append(f'{reg} loaded from memory ({detail}) - controllable if address is writable')
                        elif src_type == 'const':
                            constraints.append(f'{reg} is constant ({detail}) - fixed by this static path')
                        elif src_type == 'computed':
                            constraints.append(f'{reg} computed from ({detail}) - derived, not independent')
                        elif src_type == 'reg':
                            constraints.append(f'{reg} copied from {detail}')

            if self.symbolic and reg_provenance:
                solver_taint = self._taint_paths_to(idx) if self.deep else taint
                # Add inter-procedural provenance as another feasible state when
                # caller information contributes facts unavailable in local CFGs.
                if isinstance(solver_taint, list) and taint not in solver_taint:
                    solver_taint.append(taint)
                sat_result = self._solve_constraints(reg_provenance, solver_taint)
                satisfiable = sat_result['classification']
                sat_details = sat_result['details']
                sat_conflicts = sat_result['conflicts']
            else:
                sat_details = ''
                sat_conflicts = []
                satisfiable = 'unknown'
                if reg_provenance:
                    sources = [v['source'] for v in reg_provenance.values()]
                    controllable = [s for s in sources if s in ('stack', 'mem')]
                    fixed = [s for s in sources if s == 'const']
                    if len(controllable) == len(sources):
                        satisfiable = 'likely'
                    elif fixed and not controllable:
                        satisfiable = 'fixed'
                    elif controllable and fixed:
                        satisfiable = 'partial'
                    offsets = set()
                    for v in reg_provenance.values():
                        if v['source'] == 'stack':
                            offsets.add(v['detail'])
                    if len(offsets) > 1:
                        satisfiable = 'likely'
                    elif len(offsets) == 1 and len([v for v in reg_provenance.values() if v['source'] == 'stack']) > 1:
                        satisfiable = 'conflicting'

            entry = {
                'address': g.address,
                'function': g.function,
                'pac_mnemonic': g.pac_mnemonic,
                'constraints': constraints,
                'controlled_regs': g.controlled_regs,
                'reg_provenance': reg_provenance,
                'satisfiable': satisfiable,
                'stores_result': g.stores_result,
                'difficulty': g.difficulty,
                'reachability': reachability,
                'callers': callers_of_gadget,
            }
            if sat_details:
                entry['sat_details'] = sat_details
            if sat_conflicts:
                entry['sat_conflicts'] = sat_conflicts
            results.append(entry)
        return results

    # ── BTI + PAC Combined Analysis ──────────────────────────

    @cached_analysis
    def combined_bti_pac(self) -> dict:
        """BTI restricts WHERE you can branch; PAC restricts WHAT you branch
        WITH. Combined analysis inventories both static protection patterns."""
        bti_c = 0  # call targets
        bti_j = 0  # jump targets
        bti_jc = 0  # both
        total_bti = 0
        bti_with_pac = 0
        bti_without_pac = 0
        bti_no_pac_funcs = []
        coverage = self.analyze_pac_coverage()
        pac_functions = {entry['name'] for entry in coverage.get('protected_functions', [])}

        for i, (addr, m, o, sz) in enumerate(self.insns):
            if m != 'bti':
                continue
            total_bti += 1
            if 'jc' in o:
                bti_jc += 1
            elif 'j' in o:
                bti_j += 1
            elif 'c' in o:
                bti_c += 1

            func_name = self._func_at(addr)
            if func_name in pac_functions:
                bti_with_pac += 1
            else:
                bti_without_pac += 1
                bti_no_pac_funcs.append({'address': addr, 'function': func_name})

        unsigned_br = sum(1 for _, m, _, _ in self.insns if m in ('br', 'blr'))
        auth_br = sum(1 for _, m, _, _ in self.insns if m in PAC_AUTH_BR | PAC_AUTH_BR_Z)

        return {
            'bti_landing_pads': {
                'total': total_bti,
                'call_only': bti_c,
                'jump_only': bti_j,
                'call_and_jump': bti_jc,
            },
            'bti_pac_overlap': {
                'bti_with_pac': bti_with_pac,
                'bti_without_pac': bti_without_pac,
            },
            'branch_types': {
                'unsigned_br_blr': unsigned_br,
                'authenticated_br': auth_br,
            },
            'bti_without_pac_functions': bti_no_pac_funcs[:20],
            'assessment': (
                f'{total_bti} BTI pads, {unsigned_br} unsigned branches, {auth_br} authenticated branches. '
                + (f'{bti_without_pac} BTI pad(s) are in functions without detected return signing.'
                   if bti_without_pac > 0
                   else 'Every symbol-resolved BTI pad is in a return-signed function; '
                        'this does not prove indirect-call targets are authenticated.')
                if total_bti > 0
                else 'No BTI instructions observed; enforcement also depends on target CPU/runtime configuration.'
            ),
        }

    # ── Cross-Function Chain Analysis (lightweight) ───────────

    @cached_analysis
    def find_cross_function_chains(self) -> List[dict]:
        """Turn schema-compatible transitions into structural chain candidates."""
        transitions = self.find_pac_transitions()
        instruction_by_addr = {addr: (mnemonic, operands)
                               for addr, mnemonic, operands, _ in self.insns}
        chains = []
        for transition in transitions[:50]:
            reachable = self._reachable(transition.sign_func, transition.auth_func)
            sign_mnemonic, sign_operands = instruction_by_addr.get(transition.sign_addr, ('', ''))
            auth_mnemonic, auth_operands = instruction_by_addr.get(transition.auth_addr, ('', ''))
            signer = {'function': transition.sign_func, 'address': transition.sign_addr,
                      'instruction': f'{sign_mnemonic} {sign_operands}'.strip(),
                      'key': transition.key_type}
            authenticator = {'function': transition.auth_func, 'address': transition.auth_addr,
                             'instruction': f'{auth_mnemonic} {auth_operands}'.strip(),
                             'key': transition.key_type}
            chains.append({
                'signer': signer, 'authenticator': authenticator,
                'key': transition.key_type, 'reachable': reachable,
                'pointer_flow_confirmed': False,
                'callers_of_signer': sorted(self._callers.get(transition.sign_func, set()))[:5],
                'pattern': (f'{transition.sign_func} -> {transition.auth_func} '
                            f'[{transition.key_type}; {"reachable" if reachable else "no call path"}]'),
                'feasibility': ('Call reachability and PAC schema are compatible, but static analysis '
                                'has not proven that the signed value reaches this authenticator.'),
                'evidence': transition.notes,
            })
        if len(transitions) > len(chains):
            chains.append({
                'note': f'Showing {len(chains)} of {len(transitions)} schema-compatible transitions',
                'signer': {}, 'authenticator': {}, 'key': '',
                'pattern': f'... {len(transitions) - len(chains)} more omitted',
                'feasibility': '',
            })
        return chains

    # ── Auth-to-Use Window (TOCTTOU) ─────────────────────────

    @cached_analysis
    def analyze_auth_use_window(self) -> dict:
        """Inventory non-atomic authentication-to-use instruction windows."""
        separate = []
        atomic = []
        for i, (a, m, o, s) in enumerate(self.insns):
            if m in ('autiasp', 'autibsp'):
                func_name = self._func_at(a)
                for j in range(i + 1, min(i + 17, len(self.insns))):
                    a2, m2, o2, _ = self.insns[j]
                    if self._func_at(a2) != func_name:
                        break
                    if m2 in RET_INSNS:
                        if m2 == 'ret':
                            intervening = j - i - 1
                            entry = {
                                'function': func_name,
                                'address': a,
                                'auth_mnemonic': m,
                                'intervening_instructions': intervening,
                                'note': (f'{intervening} intervening instruction(s); separate auth+ret '
                                         'requires target-specific interrupt/state-control review'),
                            }
                            if self.deep and hasattr(self, '_cfg_edges'):
                                entry['cfg_verified'] = self._blocks_reachable(a, a2)
                            separate.append(entry)
                        break
                    if m2.startswith('b') and m2 not in ('bl',):
                        break
            elif m in PAC_AUTH_RET:
                func_name = self._func_at(a)
                atomic.append({
                    'function': func_name,
                    'address': a,
                    'mnemonic': m,
                })

        data_windows = []
        for i, (a, m, o, s) in enumerate(self.insns):
            if m not in ('autia', 'autib', 'autda', 'autdb'):
                continue
            func_name = self._func_at(a)
            auth_dst = self._pac_dest_reg(m, o)
            if not auth_dst:
                continue
            for j in range(i + 1, min(i + 17, len(self.insns))):
                a2, m2, o2, _ = self.insns[j]
                if self._func_at(a2) != func_name:
                    break
                intervening = j - i - 1
                is_memory_use = (m2.startswith(('ldr', 'ldp', 'str', 'stp', 'ldur', 'stur'))
                                 and auth_dst in self._memory_base_regs(o2))
                is_branch_use = m2 in INDIRECT_BRANCH and self._reg_in(auth_dst, o2)
                if is_memory_use or is_branch_use:
                        entry = {
                            'function': func_name,
                            'address': a,
                            'auth_mnemonic': m,
                            'intervening_instructions': intervening,
                            'use_instruction': f'{m2} {o2}',
                            'note': (f'{intervening} intervening instruction(s) between authentication and '
                                     'pointer use; exploitability needs asynchronous state control'),
                        }
                        if self.deep and hasattr(self, '_cfg_edges'):
                            entry['cfg_verified'] = self._blocks_reachable(a, a2)
                            trace = self._def_use_in_func(func_name, auth_dst, a)
                            entry['def_use_reaches_use'] = any(
                                event_addr == a2 and event_kind == 'use'
                                for event_addr, event_kind, _, _ in trace)
                            entry['def_use_events'] = [
                                {'address': event_addr, 'kind': event_kind,
                                 'mnemonic': event_mnemonic, 'operands': event_operands}
                                for event_addr, event_kind, event_mnemonic, event_operands
                                in trace[:12]
                            ]
                        data_windows.append(entry)
                        break
                _, written = self._insn_read_write_regs(a2, m2, o2)
                if auth_dst in written:
                    break
                if m2 in RET_INSNS or (m2.startswith('b') and m2 not in ('bl',)):
                    break

        total = len(separate) + len(atomic)
        if total == 0:
            assessment = 'No PAC-protected returns found.'
        elif not separate:
            assessment = f'All {len(atomic)} PAC returns use atomic retaa/retab - no TOCTTOU window.'
        elif not atomic:
            assessment = (f'All {len(separate)} PAC returns use separate auth+ret; '
                          'these are non-atomic review candidates, not proven vulnerabilities.')
        else:
            pct = len(separate) / total * 100
            assessment = (f'{len(separate)}/{total} ({pct:.0f}%) PAC returns use separate auth+ret. '
                          f'Atomic retaa/retab would remove the architectural window in '
                          f'{len(separate)} functions where supported.')
        if data_windows:
            assessment += f' {len(data_windows)} data pointer auth-to-use windows found.'
        has_fpac = self._detect_fpac_support()
        if has_fpac and (separate or data_windows):
            assessment += ' FPAC enabled -- auth failure faults immediately, narrowing exploit window.'
        if self.deep and hasattr(self, '_cfg_edges'):
            verified = sum(1 for e in separate if e.get('cfg_verified'))
            assessment += f' CFG-verified: {verified}/{len(separate)} auth-ret windows reachable.'
        return {
            'separate_auth_ret': separate,
            'atomic_ret': atomic,
            'data_auth_windows': data_windows,
            'fpac_enabled': has_fpac,
            'assessment': assessment,
        }

    # ── Context / Modifier Entropy Analysis ──────────────────

    @cached_analysis
    def analyze_context_entropy(self) -> dict:
        """Analyze entropy of PAC context/modifier values.
        Low entropy = easier substitution attacks (MottaSec, PACTight)."""
        contexts = defaultdict(list)
        for i, (addr, m, o, sz) in enumerate(self.insns):
            if m not in PAC_SIGN_ALL and m not in PAC_AUTH_ALL:
                continue
            func = self._func_at(addr)
            is_sp_ctx = m in PAC_SP_CTX_SIGN | PAC_SP_CTX_AUTH or \
                        (m in ('pacia', 'pacib', 'autia', 'autib') and 'sp' in o.replace(' ', '').split(',')[1:])
            if is_sp_ctx:
                contexts['sp'].append({'addr': addr, 'func': func, 'mnemonic': m})
            elif m in PAC_ZERO_CTX_SIGN | PAC_ZERO_CTX_AUTH:
                contexts['zero'].append({'addr': addr, 'func': func, 'mnemonic': m})
            else:
                ops = o.replace(' ', '').split(',')
                if len(ops) >= 2:
                    modifier = ops[1]
                    if self.deep and hasattr(self, '_const_at') and addr in self._const_at:
                        cval = self._const_at[addr].get(modifier)
                        if cval is not None:
                            modifier = f'{modifier}={cval:#x}'
                    contexts[modifier].append({'addr': addr, 'func': func, 'mnemonic': m})
                else:
                    contexts['implicit'].append({'addr': addr, 'func': func, 'mnemonic': m})

        resolved_count = sum(1 for k in contexts if '=' in k) if self.deep else 0

        total = sum(len(v) for v in contexts.values())
        if total == 0:
            return {'contexts': {}, 'assessment': 'No PAC instructions found.',
                    'total_pac_ops': 0, 'unique_modifiers': 0,
                    'sp_context_count': 0, 'zero_context_count': 0,
                    'entropy_bits': 0, 'modifier_diversity_bits': 0,
                    'per_key_entropy': {}, 'per_key_modifiers': {},
                    'resolved_modifiers': 0}

        sp_count = len(contexts.get('sp', []))
        zero_count = len(contexts.get('zero', []))
        unique_modifiers = len(contexts)
        import math
        probabilities = [len(entries) / total for entries in contexts.values()]
        entropy = -sum(probability * math.log2(probability)
                       for probability in probabilities if probability)

        issues = []
        if sp_count > 0:
            issues.append(f'{sp_count} use SP as modifier (runtime values are not recoverable statically)')
        if zero_count > 0:
            issues.append(f'{zero_count} use zero context (fully portable)')
        if unique_modifiers < 5 and total > 10:
            issues.append(f'Only {unique_modifiers} unique modifier values across {total} PAC ops - high collision risk')
        if resolved_count:
            issues.append(f'{resolved_count} modifiers resolved to concrete values via constant propagation')

        per_key = {}
        for ctx_name, entries in contexts.items():
            for e in entries:
                mn = e['mnemonic']
                if mn in PAC_SIGN_A | PAC_AUTH_A:
                    key = 'A'
                elif mn in PAC_SIGN_B | PAC_AUTH_B:
                    key = 'B'
                elif mn in PAC_SIGN_DA | PAC_AUTH_DA:
                    key = 'DA'
                elif mn in PAC_SIGN_DB | PAC_AUTH_DB:
                    key = 'DB'
                else:
                    key = 'unknown'
                if key not in per_key:
                    per_key[key] = defaultdict(int)
                per_key[key][ctx_name] += 1

        key_entropy = {}
        for key, modifiers in per_key.items():
            n_mods = len(modifiers)
            key_total = sum(modifiers.values())
            key_entropy[key] = round(-sum(
                (count / key_total) * math.log2(count / key_total)
                for count in modifiers.values() if count), 1)
            if n_mods == 1 and sum(modifiers.values()) > 5:
                mod_name = list(modifiers.keys())[0]
                issues.append(f'Key {key}: all {sum(modifiers.values())} ops use modifier "{mod_name}"')

        assessment = '; '.join(issues) if issues else f'{unique_modifiers} unique modifiers - reasonable entropy.'

        return {
            'total_pac_ops': total,
            'unique_modifiers': unique_modifiers,
            'sp_context_count': sp_count,
            'zero_context_count': zero_count,
            'entropy_bits': round(entropy, 1),
            'modifier_diversity_bits': round(entropy, 1),
            'per_key_entropy': key_entropy,
            'per_key_modifiers': {k: dict(v) for k, v in per_key.items()},
            'contexts': {k: len(v) for k, v in contexts.items()},
            'resolved_modifiers': resolved_count,
            'assessment': assessment + ' Entropy is syntactic modifier diversity, not runtime entropy.',
        }

    # ── Pointer Substitution / Diversifier Collision ─────────

    @cached_analysis
    def find_diversifier_collisions(self) -> dict:
        """Find proven or conditional (key, modifier) reuse across sign sites."""
        groups = defaultdict(list)
        auth_groups = defaultdict(list)
        unresolved = []
        all_sign_sites = 0
        for addr, mnemonic, operands, _ in self.insns:
            if mnemonic not in PAC_SIGN_ALL | PAC_AUTH_ALL | PAC_AUTH_RET:
                continue
            key = self._pac_key(mnemonic)
            if not key:
                continue
            kind, modifier = self._pac_modifier(addr, mnemonic, operands)
            site = {'address': addr, 'function': self._func_at(addr),
                    'mnemonic': mnemonic, 'key': key, 'modifier_kind': kind,
                    'diversifier': modifier}
            if mnemonic in PAC_SIGN_ALL:
                all_sign_sites += 1
                if kind == 'register':
                    unresolved.append(site)
                else:
                    groups[f'{key}:{kind}:{modifier}'].append(site)
            elif kind != 'register':
                auth_groups[f'{key}:{kind}:{modifier}'].append(site)

        reused = {key: sites for key, sites in groups.items() if len(sites) > 1}
        sp_collisions = {key: sites for key, sites in reused.items() if ':sp:' in key}
        proven_collisions = {key: sites for key, sites in reused.items() if ':sp:' not in key}
        correlated = {
            key: {'sign_sites': len(sites), 'auth_sites': len(auth_groups[key]),
                  'writable_storage_proven': False}
            for key, sites in proven_collisions.items() if auth_groups.get(key)
        }

        if not all_sign_sites:
            assessment = 'No PAC signing instructions found.'
        elif not proven_collisions and not sp_collisions:
            assessment = 'No statically proven repeated key/modifier schemas.'
        else:
            parts = []
            if proven_collisions:
                parts.append(f'{len(proven_collisions)} repeated exact key/modifier schema(s)')
            if sp_collisions:
                parts.append(f'{len(sp_collisions)} SP schema(s), conditional on equal runtime SP')
            assessment = '; '.join(parts) + '. Pointer interchangeability additionally requires '
            assessment += 'compatible pointer semantics and attacker-accessible storage.'
        if unresolved:
            assessment += f' {len(unresolved)} register-modifier site(s) remain unresolved and are not counted.'
        return {
            'total_sign_sites': all_sign_sites,
            'collision_groups': {k: [{'addr': s['address'], 'func': s['function'],
                                      'mnemonic': s['mnemonic']} for s in v]
                                 for k, v in proven_collisions.items()},
            'sp_collision_groups': {k: [{'addr': s['address'], 'func': s['function'],
                                         'mnemonic': s['mnemonic']} for s in v]
                                    for k, v in sp_collisions.items()},
            'auth_correlated_groups': correlated,
            'exploitable_groups': {},
            'unresolved_modifier_sites': unresolved,
            'assessment': assessment,
        }

    # ── Unsigned Callback Indirection (COP/BLASTPASS) ────────

    @cached_analysis
    def find_unsigned_callback_indirection(self) -> List[dict]:
        """Detect double-dereference patterns: load unsigned ptr -> load
        PAC-signed func ptr from struct -> BLRAAZ/BRAA call.
        BLASTPASS used this to swap entire callback tables."""
        results = []
        for i, (addr, m, o, sz) in enumerate(self.insns):
            if not m.startswith('ldr') or '[' not in o:
                continue
            if self._in_stub_section(addr):
                continue
            ops = o.replace(' ', '').split(',')
            if len(ops) < 2:
                continue
            dest_reg = ops[0]
            func = self._func_at(addr)
            base_regs = self._memory_base_regs(o)
            provenance = (self._interprocedural_taint(i) if self.symbolic else
                          self._taint_cross_block(i) if self.deep else
                          self._taint_basic_block(i))
            first_pointer_source = next(
                (provenance[reg][0] for reg in base_regs if reg in provenance), 'unknown')
            window = self._window(i, before=0, after=6)
            for j, (a2, m2, o2, _) in enumerate(window):
                if j == 0:
                    continue
                if self._func_at(a2) != func:
                    break
                if m2 in RET_INSNS or m2 == 'b' or m2.startswith('b.') or m2 == 'bl':
                    break
                if m2 in PAC_AUTH_ALL and self._pac_dest_reg(m2, o2) == dest_reg:
                    break
                if m2.startswith('ldr') and '[' in o2:
                    bracket = o2[o2.index('['):o2.index(']')+1] if ']' in o2 else ''
                    if not self._reg_in(dest_reg, bracket):
                        continue
                    o2_parts = o2.replace(' ', '').split(',')
                    inner_dest = o2_parts[0]
                    for k in range(j + 1, len(window)):
                        a3, m3, o3, _ = window[k]
                        if self._func_at(a3) != func:
                            break
                        if m3 in RET_INSNS or m3 == 'b' or m3.startswith('b.'):
                            break
                        if (m3 in PAC_AUTH_BR_Z or m3 in PAC_AUTH_BR) and self._reg_in(inner_dest, o3):
                            if self._is_suppressed(addr, func, 'cop'):
                                break
                            results.append({
                                'address': addr,
                                'function': func,
                                'chain': [
                                    f'{addr:#x}: {m} {o}',
                                    f'{a2:#x}: {m2} {o2}',
                                    f'{a3:#x}: {m3} {o3}',
                                ],
                                'first_pointer_auth_observed': False,
                                'first_pointer_source': first_pointer_source,
                                'final_call': m3,
                                'note': ('Double dereference reaches an authenticated call without '
                                         'an observed authentication of the intermediate table pointer. '
                                         'Exploitability requires control of that pointer/storage.'),
                            })
                            break
                        if m3 in INDIRECT_BRANCH and m3 not in PAC_AUTH_BR and self._reg_in(inner_dest, o3):
                            if self._is_suppressed(addr, func, 'cop'):
                                break
                            results.append({
                                'address': addr,
                                'function': func,
                                'chain': [
                                    f'{addr:#x}: {m} {o}',
                                    f'{a2:#x}: {m2} {o2}',
                                    f'{a3:#x}: {m3} {o3}',
                                ],
                                'first_pointer_auth_observed': False,
                                'first_pointer_source': first_pointer_source,
                                'final_call': m3,
                                'note': ('Double dereference reaches an unauthenticated indirect branch; '
                                         'no authentication of the intermediate table pointer was observed.'),
                            })
                            break
                        _, written = self._insn_read_write_regs(a3, m3, o3)
                        if inner_dest in written:
                            break
                    break
        return results

    # ── Fork/Thread Key Inheritance ──────────────────────────

    @cached_analysis
    def detect_fork_key_reuse(self) -> dict:
        """Classify process/thread creation by PAC-key inheritance semantics."""
        fork_syms = {'fork', 'vfork', '__fork', 'daemon'}
        clone_syms = {'clone', 'clone3'}
        spawn_syms = {'posix_spawn', 'posix_spawnp', 'system'}
        thread_syms = {'pthread_create', 'thrd_create', '_beginthread', '_beginthreadex'}
        prefork_syms = {'prefork', 'pre_fork', 'fork_handler'}

        calls = {'fork': [], 'clone': [], 'spawn': [], 'thread': []}
        call_targets = {}
        for index, (addr, mnemonic, operands, _) in enumerate(self.insns):
            if mnemonic != 'bl':
                continue
            target = self._call_target_name(operands).lower()
            call_targets[addr] = target
            entry = {'address': addr, 'function': self._func_at(addr), 'target': target}
            if target in fork_syms:
                calls['fork'].append(entry)
            elif target in clone_syms:
                entry['semantics'] = 'flags determine process-vs-thread key sharing'
                calls['clone'].append(entry)
            elif target in spawn_syms:
                entry['semantics'] = 'exec/spawn path; key inheritance is platform/runtime dependent'
                calls['spawn'].append(entry)
            elif target in thread_syms:
                calls['thread'].append(entry)

        referenced = {
            'fork': sorted(name for name in self.imports if name.lower().removeprefix('_') in fork_syms),
            'clone': sorted(name for name in self.imports if name.lower().removeprefix('_') in clone_syms),
            'spawn': sorted(name for name in self.imports if name.lower().removeprefix('_') in spawn_syms),
            'thread': sorted(name for name in self.imports if name.lower().removeprefix('_') in thread_syms),
        }
        found_prefork = any(any(pattern in name.lower() for pattern in prefork_syms)
                            for name in self.symbols)
        sig_handler = any(name.lower().removeprefix('_') in ('sigaction', 'signal')
                          for name in self.imports | set(self.symbols))

        # Linux PR_PAC_RESET_KEYS is prctl option 54. Merely importing prctl is
        # not evidence that re-keying occurs; require a call with x0/w0 == 54.
        rekey_sites = []
        for index, (addr, mnemonic, operands, _) in enumerate(self.insns):
            if mnemonic != 'bl' or self._call_target_name(operands).lower() != 'prctl':
                continue
            option = self._call_arg_constant(index, 'x0')
            if option == 54:
                rekey_sites.append({'address': addr, 'function': self._func_at(addr),
                                    'option': option})
        has_rekey = bool(rekey_sites)

        is_forking = bool(calls['fork'])
        is_threaded = bool(calls['thread'])

        issues = []
        if is_forking:
            targets = ', '.join(site['target'] for site in calls['fork'][:5])
            issues.append(f'Fork calls: {targets} - child initially inherits the process PAC keys')
            issues.append('A crashing child can isolate failed guesses from a long-lived parent')
            bf = self.analyze_brute_force()
            lo, hi = bf['estimated_pac_bits_range']
            tlo, thi = bf['estimated_time_seconds_range']
            issues.append(f'Conditional estimate: {lo}-{hi} PAC bits, {tlo}-{thi}s at '
                          f'{bf["us_per_attempt"]}us/attempt; actual restart cost is target-specific')
            if not sig_handler:
                issues.append('No imported signal-handler API detected; crash recovery behavior is unknown')
        if is_threaded:
            targets = ', '.join(site['target'] for site in calls['thread'][:5])
            issues.append(f'Thread creation: {targets} - threads share process PAC keys, '
                          'but do not provide process-crash isolation')
        if calls['clone']:
            issues.append(f'{len(calls["clone"])} clone/clone3 call(s); flags must be inspected '
                          'at runtime to determine key and crash isolation semantics')
        if calls['spawn']:
            issues.append(f'{len(calls["spawn"])} spawn/system call(s); not counted as inherited-key '
                          'forks because exec/runtime behavior may install fresh keys')
        if has_rekey:
            issues.append(f'{len(rekey_sites)} verified PR_PAC_RESET_KEYS call(s) re-key after fork')

        reachable_from = []
        if is_forking:
            entry_funcs = [n for n, a in self.func_boundaries.items()
                           if n in ('main', '_main', 'start', '_start')]
            exported = [n for n in self.symbols
                        if n in set(self.func_boundaries.values())
                        and n not in ('main', '_main', 'start', '_start')]
            for site in calls['fork']:
                clean = site['target']
                for entry in entry_funcs:
                    if self._reachable(entry, clean, max_depth=8):
                        reachable_from.append(f'{clean} reachable from {entry}')
                        break
                else:
                    for exp in exported[:20]:
                        if self._reachable(exp, clean, max_depth=5):
                            reachable_from.append(f'{clean} reachable from export {exp}')
                            break
            if reachable_from:
                issues.append(f'Call-graph reachability: {"; ".join(reachable_from[:3])}')

        if not issues:
            assessment = 'No executed fork/thread creation call was resolved statically.'
        else:
            assessment = ('Process/thread creation surface found; only fork-like calls are treated '
                          'as inherited-key crash-isolation candidates.')

        return {
            'is_forking_server': is_forking,
            'is_threaded': is_threaded,
            'fork_calls': calls['fork'],
            'clone_calls': calls['clone'],
            'spawn_calls': calls['spawn'],
            'thread_calls': calls['thread'],
            'referenced_symbols': referenced,
            'prefork_indicators': found_prefork,
            'has_signal_handler': sig_handler,
            'has_rekey_capability': has_rekey,
            'rekey_sites': rekey_sites,
            'reachable_from_entry': reachable_from,
            'issues': issues,
            'assessment': assessment,
        }

    # ── setjmp/longjmp PAC Analysis ──────────────────────────

    @cached_analysis
    def find_setjmp_pac_risks(self) -> dict:
        """Detect setjmp/longjmp and equivalent non-local jump patterns.
        jmp_buf stores signed LR in corruptible stack/heap memory."""
        setjmp_syms = {'setjmp', '_setjmp', 'sigsetjmp', '__sigsetjmp',
                       '__builtin_setjmp', 'savectx'}
        longjmp_syms = {'longjmp', '_longjmp', 'siglongjmp', '__siglongjmp',
                        '__builtin_longjmp', 'restorectx'}
        # C++ exception unwinding (functionally equivalent to longjmp for PAC)
        cxx_throw_syms = {'__cxa_throw', '__cxa_rethrow', '_Unwind_RaiseException',
                          '_Unwind_Resume', '__cxa_begin_catch', '__cxa_end_catch',
                          '__cxa_allocate_exception'}
        # ObjC exception handling (older runtimes compile @try to setjmp)
        objc_exc_syms = {'objc_exception_throw', 'objc_exception_try_enter',
                         'objc_exception_try_exit', 'objc_exception_extract',
                         '_objc_begin_catch', '_objc_end_catch',
                         'objc_setExceptionMatcher'}

        setjmp_sites = []
        longjmp_sites = []
        cxx_exc_sites = []
        objc_exc_sites = []

        for i, (addr, m, o, sz) in enumerate(self.insns):
            if m != 'bl':
                continue
            target = self._call_target_name(o)
            func = self._func_at(addr)
            if target in setjmp_syms:
                taint = (self._taint_cross_block(i) if self.deep
                         else self._taint_basic_block(i))
                source = taint.get('x0')
                storage = {'stack': 'stack', 'mem': 'heap/global'}.get(
                    source[0] if source else '', 'unknown')
                setjmp_sites.append({
                    'address': addr,
                    'function': func,
                    'target': target,
                    'jmp_buf_storage': storage,
                })
            elif target in longjmp_syms:
                longjmp_sites.append({
                    'address': addr,
                    'function': func,
                    'target': target,
                })
            elif target in cxx_throw_syms:
                cxx_exc_sites.append({
                    'address': addr,
                    'function': func,
                    'target': target,
                })
            elif target in objc_exc_syms:
                objc_exc_sites.append({
                    'address': addr,
                    'function': func,
                    'target': target,
                })

        referenced_symbols = sorted(
            name for name in self.imports
            if name in setjmp_syms | longjmp_syms | cxx_throw_syms | objc_exc_syms)

        has_pac_setjmp = False
        for s in setjmp_sites:
            if s['target'] in ('_setjmp', 'setjmp', 'sigsetjmp'):
                sym_addr = next((address for address, name in self.func_boundaries.items()
                                 if name == s['target']), 0)
                if sym_addr:
                    for addr, m_i, _, _ in self._iter_func_insns(sym_addr):
                        if m_i in PAC_SIGN_ALL:
                            has_pac_setjmp = True
                            break

        zc = self.find_zero_context_pairs()
        zero_ctx_risk = ''
        if zc.get('portable') and (setjmp_sites or longjmp_sites):
            zero_ctx_risk = ('Zero-context PAC pairs present -- if jmp_buf stores '
                             'zero-context signed LR, any other zero-context signed '
                             'pointer can substitute.')

        heap_jmpbufs = [s for s in setjmp_sites if s.get('jmp_buf_storage') == 'heap/global']

        parts = []
        if not setjmp_sites and not longjmp_sites and not cxx_exc_sites and not objc_exc_sites:
            assessment = 'No setjmp/longjmp or exception handling -- jmp_buf PAC attack not applicable.'
        else:
            if setjmp_sites:
                parts.append(f'{len(setjmp_sites)} setjmp + {len(longjmp_sites)} longjmp call sites')
                if heap_jmpbufs:
                    parts.append(f'{len(heap_jmpbufs)} jmp_buf on heap/global (higher corruption risk)')
                if has_pac_setjmp:
                    parts.append('PAC-protected setjmp detected (jmp_buf entries signed)')
                else:
                    parts.append('setjmp implementation is external or lacks a visible PAC sign; '
                                 'jmp_buf protection cannot be established statically')
            if cxx_exc_sites:
                parts.append(f'{len(cxx_exc_sites)} C++ exception sites '
                             '(__cxa_throw/_Unwind -- non-local control transfer like longjmp)')
            if objc_exc_sites:
                parts.append(f'{len(objc_exc_sites)} ObjC exception sites '
                             '(objc_exception_throw -- may use setjmp internally)')
            if zero_ctx_risk:
                parts.append(zero_ctx_risk)
            assessment = '. '.join(parts) + '.'

        return {
            'setjmp_sites': setjmp_sites,
            'longjmp_sites': longjmp_sites,
            'cxx_exception_sites': cxx_exc_sites,
            'objc_exception_sites': objc_exc_sites,
            'referenced_symbols': referenced_symbols,
            'has_pac_protected_setjmp': has_pac_setjmp,
            'heap_jmpbufs': len(heap_jmpbufs),
            'zero_context_risk': zero_ctx_risk,
            'assessment': assessment,
        }

    # ── JIT / Dynamic Code PAC Surface ──────────────────────

    @cached_analysis
    def detect_jit_pac_surface(self) -> dict:
        """Detect static indicators of JIT code generation and nearby PAC use.
        Findings identify review surfaces; they do not prove runtime writability
        or an attacker-controlled signing path (CVE-2024-27834, Predator)."""
        jit_symbols = {
            'JavaScriptCore': ['_JSC', 'WTF::', 'JSC::', 'jsc_', 'LLInt', 'DFG', 'FTL',
                               'yarr', 'Wasm'],
            'V8': ['v8::', '_ZN2v8', 'Builtins_', 'CodeStub'],
            'ART': ['art::', '_ZN3art', 'nterp_', 'jni_'],
            'Mono': ['mono_', '_mono_', 'MonoJit'],
            'LuaJIT': ['luaJIT_', 'lj_'],
        }
        rwx_sections = []
        jit_framework = None
        jit_indicators = []

        for section in self.section_meta:
            if section.get('writable') and section.get('executable'):
                rwx_sections.append({
                    'section': section['name'], 'vaddr': section['address'],
                    'size': section['size'], 'note': 'statically writable and executable',
                })
        mutable_exec_segments = []
        for segment in self.segment_meta:
            maxprot = segment.get('maxprot')
            if segment.get('writable') and segment.get('executable'):
                mutable_exec_segments.append({
                    'segment': segment['name'], 'vaddr': segment['vmaddr'],
                    'size': segment['vmsize'], 'state': 'initial-rwx',
                })
            elif maxprot is not None and (maxprot & 2) and (maxprot & 4):
                mutable_exec_segments.append({
                    'segment': segment['name'], 'vaddr': segment['vmaddr'],
                    'size': segment['vmsize'], 'state': 'maxprot-allows-write-and-execute',
                })

        for name in self.symbols:
            for framework, patterns in jit_symbols.items():
                if any(p in name for p in patterns):
                    if jit_framework is None:
                        jit_framework = framework
                    jit_indicators.append(name)
                    break

        mprotect_calls = []
        mmap_calls = []
        rwx_request_sites = []
        for index, (addr, m, o, sz) in enumerate(self.insns):
            if m == 'bl':
                target = self._call_target_name(o)
                if 'mprotect' in target:
                    mprotect_calls.append(addr)
                    protection = self._call_arg_constant(index, 'x2')
                    if protection is not None and protection & 0x6 == 0x6:
                        rwx_request_sites.append({'address': addr, 'target': target,
                                                  'protection': protection})
                elif 'mmap' in target:
                    mmap_calls.append(addr)
                    protection = self._call_arg_constant(index, 'x2')
                    if protection is not None and protection & 0x6 == 0x6:
                        rwx_request_sites.append({'address': addr, 'target': target,
                                                  'protection': protection})

        pac_near_exports = []
        pac_addrs = [(addr, m) for addr, m, _, _ in self.insns if m in PAC_SIGN_ALL]
        for name, sym_addr in self.symbols.items():
            if not any(c in name for c in ['pac', 'sign', 'Sign', 'PAC']):
                continue
            if sym_addr not in self.func_boundaries:
                continue
            func_end = self._func_end(sym_addr)
            for addr, m in pac_addrs:
                if sym_addr <= addr < func_end:
                    pac_near_exports.append({
                        'symbol': name,
                        'pac_addr': addr,
                        'pac_mnemonic': m,
                        'distance': abs(addr - sym_addr),
                    })
                    break

        if rwx_sections or any(seg['state'] == 'initial-rwx' for seg in mutable_exec_segments) or rwx_request_sites:
            assessment = (f'Static W+X mapping evidence: {len(rwx_sections)} section(s), '
                          f'{len(mutable_exec_segments)} mutable executable segment(s).')
        elif jit_framework:
            assessment = (f'{jit_framework} linkage/implementation indicators detected '
                          f'({len(jit_indicators)} symbols). Runtime-generated PAC gadgets are '
                          'possible, but their memory protections require dynamic observation.')
        elif mprotect_calls or mmap_calls:
            assessment = (f'Dynamic code generation indicators: {len(mmap_calls)} mmap, '
                          f'{len(mprotect_calls)} mprotect calls. Check for RWX regions at runtime.')
        else:
            assessment = 'No JIT framework or dynamic code generation detected.'

        return {
            'jit_framework': jit_framework,
            'jit_symbol_count': len(jit_indicators),
            'jit_symbols_sample': jit_indicators[:10],
            'mmap_calls': len(mmap_calls),
            'mprotect_calls': len(mprotect_calls),
            'rwx_sections': rwx_sections,
            'mutable_executable_segments': mutable_exec_segments,
            'rwx_request_sites': rwx_request_sites,
            'pac_near_exports': pac_near_exports[:10],
            'assessment': assessment,
        }

    # ── Dynamic Linker Signing Oracle ────────────────────────

    @cached_analysis
    def detect_linker_signing_oracle(self) -> dict:
        """Detect linker surfaces associated with public pointer-signing attacks.
        Static presence does not prove attacker control over linker state."""
        linker_sign_patterns = [
            'signPointer', '_signPointer', 'ptrauth_sign',
            'sign_pointer', '__ptrauth', 'pac_sign',
        ]
        interpose_sections = []
        linker_gadgets = []
        dlopen_sites = []

        for name, vaddr, data in self.sections:
            if name in ('__interpose', '.interpose', '__DATA.__interpose'):
                interpose_sections.append({
                    'section': name, 'vaddr': vaddr, 'size': len(data)
                })

        for name, vaddr, size, data in self.data_sections:
            if 'interpose' in name.lower():
                interpose_sections.append({
                    'section': name, 'vaddr': vaddr, 'size': size
                })

        for name, symbol_addr in self.symbols.items():
            if not any(p.lower() in name.lower() for p in linker_sign_patterns):
                continue
            internal_addr = next((addr for addr, func in self.func_boundaries.items()
                                  if func == name), None)
            pac_sites = []
            if internal_addr is not None:
                pac_sites = [addr for addr, mnemonic, _, _ in self._iter_func_insns(internal_addr)
                             if mnemonic in PAC_SIGN_ALL]
            if pac_sites or name in self.imports:
                linker_gadgets.append({
                    'symbol': name, 'address': symbol_addr,
                    'internal_pac_sites': pac_sites[:10],
                    'evidence': 'internal PAC signing implementation' if pac_sites else 'import only',
                })

        for addr, m, o, sz in self.insns:
            if m == 'bl':
                target = self._call_target_name(o)
                if target in ('dlopen', 'dlsym',
                              '_dl_runtime_resolve', '__dl_runtime_resolve'):
                    dlopen_sites.append({
                        'address': addr, 'target': target,
                        'function': self._func_at(addr),
                    })

        issues = []
        internal_signers = [entry for entry in linker_gadgets if entry['internal_pac_sites']]
        if internal_signers:
            issues.append(f'{len(internal_signers)} internal linker-signing implementation(s) '
                          'contain PAC instructions; controllability still requires data-flow review')
        elif linker_gadgets:
            issues.append(f'{len(linker_gadgets)} signing API import(s); implementation is external')
        if interpose_sections:
            issues.append(f'{len(interpose_sections)} interpose sections - '
                          f'zero-diversifier function pointer substitution target')
        if dlopen_sites:
            issues.append(f'{len(dlopen_sites)} resolved dlopen/dlsym call(s); dynamic loading is '
                          'an attack surface indicator, not proof of a signing oracle')

        assessment = '; '.join(issues) if issues else 'No linker signing oracle indicators.'
        return {
            'linker_gadgets': linker_gadgets,
            'interpose_sections': interpose_sections,
            'dlopen_sites': dlopen_sites,
            'assessment': assessment,
        }

    # ── Stack Protection Mode Detection ──────────────────────

    @cached_analysis
    def detect_stack_protection_mode(self) -> dict:
        """Detect whether binary uses PAC-as-canary, traditional canaries,
        or both. Also detects Guarded Control Stack (FEAT_GCS) and SafeStack.
        One-shot init functions are alternative targets when
        __stack_chk_fail is absent (Pixel 10 exploit)."""
        stack_chk_names = {'__stack_chk_fail', '__stack_chk_fail_local', '__stack_chk_guard'}
        has_pac_prologue = any(
            m in PROLOGUE_PAC or (m in ('pacia', 'pacib') and o.replace(' ', '') == 'x30,sp')
            for _, m, o, _ in self.insns
        )

        # FEAT_GCS (Guarded Control Stack) --AArch64 hardware shadow stack
        gcs_syms = {'__gcs_enable', 'gcs_enable', 'PR_SET_SHADOW_STACK_STATUS',
                    'ARCH_SHSTK_ENABLE'}
        has_gcs = False
        gcs_indicators = []
        for name in self.symbols:
            if name in gcs_syms or 'shadow_stack' in name.lower() or 'gcs_' in name.lower():
                has_gcs = True
                gcs_indicators.append(name)
        for addr, m, o, sz in self.insns:
            if m in ('gcspushm', 'gcspopm', 'gcspushx', 'gcsstr', 'gcssttr'):
                has_gcs = True
                gcs_indicators.append(f'{m} @ {addr:#x}')
                break

        # SafeStack (LLVM) --separate stack for return addresses
        safestack_syms = {'__safestack_init', '__safestack_unsafe_stack_ptr',
                          '__safestack_unsafe_stack_alloc'}
        has_safestack = False
        for name in self.symbols:
            if name in safestack_syms:
                has_safestack = True
                break

        init_funcs = []
        init_patterns = ('_init', '_start', '.init', 'init_module', '_do_init',
                         'module_init', '__libc_csu_init', '_dl_init',
                         'frame_dummy', '__do_global_ctors')
        for name, addr in self.symbols.items():
            if any(name.endswith(p) or name.startswith(p.lstrip('.'))
                   for p in init_patterns):
                init_funcs.append({'name': name, 'address': addr})

        cov = self.analyze_pac_coverage()
        pac_coverage_pct = cov.get('coverage_percent', 0)

        # Per-function protection breakdown
        func_modes = {'pac_only': 0, 'canary_only': 0, 'both': 0, 'none': 0}
        canary_funcs = set()
        for addr, m, o, sz in self.insns:
            if m == 'bl' and self._call_target_name(o) in stack_chk_names:
                canary_funcs.add(self._func_at(addr))
        has_stack_chk = bool(canary_funcs)

        pac_funcs = set()
        for f_addr, f_name in self.func_boundaries.items():
            for addr, m, o, sz in self._iter_func_insns(f_addr):
                if addr > f_addr + 16:
                    break
                if m in PROLOGUE_PAC or (m in ('pacia', 'pacib') and o.replace(' ', '') == 'x30,sp'):
                    pac_funcs.add(f_name)
                    break

        for f_name in self.func_boundaries.values():
            has_p = f_name in pac_funcs
            has_c = f_name in canary_funcs
            if has_p and has_c:
                func_modes['both'] += 1
            elif has_p:
                func_modes['pac_only'] += 1
            elif has_c:
                func_modes['canary_only'] += 1
            else:
                func_modes['none'] += 1

        if has_pac_prologue and not has_stack_chk:
            mode = 'pac-only'
            assessment = (f'PAC return signing is present and no executed stack-canary failure '
                          f'call was resolved; this does not prove PAC intentionally replaced canaries. '
                          f'{pac_coverage_pct:.0f}% function coverage. '
                          f'{len(init_funcs)} init functions may serve as alternative '
                          'overwrite targets (Pixel 10 pattern).')
        elif has_pac_prologue and has_stack_chk:
            mode = 'pac-and-canary'
            assessment = (f'Both PAC prologues and stack canaries present -- defense in depth. '
                          f'Per-function: {func_modes["both"]} both, '
                          f'{func_modes["pac_only"]} PAC-only, '
                          f'{func_modes["canary_only"]} canary-only, '
                          f'{func_modes["none"]} unprotected.')
        elif has_stack_chk and not has_pac_prologue:
            mode = 'canary-only'
            assessment = 'Resolved stack-canary checks, but no PAC return-signing prologue was found.'
        else:
            mode = 'none'
            assessment = ('No PAC return-signing prologue or resolved stack-canary failure call was '
                          'found; stripped symbols and external stubs can make this inconclusive.')

        if has_gcs:
            mode += '+gcs'
            assessment += f' FEAT_GCS (Guarded Control Stack) indicators: {", ".join(gcs_indicators[:3])}.'
        if has_safestack:
            mode += '+safestack'
            assessment += ' LLVM SafeStack detected -- return addresses on separate stack.'

        return {
            'mode': mode,
            'has_pac_prologues': has_pac_prologue,
            'has_stack_canaries': has_stack_chk,
            'stack_canary_functions': sorted(canary_funcs),
            'stack_canary_symbols_referenced': sorted(
                name for name in self.imports if name in stack_chk_names),
            'has_gcs': has_gcs,
            'has_safestack': has_safestack,
            'gcs_indicators': gcs_indicators,
            'init_functions': init_funcs[:20],
            'pac_coverage_percent': pac_coverage_pct,
            'per_function_modes': func_modes,
            'assessment': assessment,
        }

    # ── DOP Surface Estimator ────────────────────────────────

    @cached_analysis
    def estimate_dop_surface(self) -> dict:
        """Estimate Data-Oriented Programming attack surface - data-only
        attacks that bypass PAC entirely by never hijacking control flow."""
        nonstack_stores = 0
        controlled_stores = 0
        protected_branches = 0
        data_ptr_loads = 0
        security_globals = []

        sec_patterns = ('passwd', 'cred', 'auth', 'priv', 'perm', 'token',
                        'secret', 'key', 'admin', 'root', 'uid', 'gid',
                        'capability', 'selinux', 'sandbox')

        for name, addr in self.data_symbols.items():
            name_lower = name.lower()
            if any(p in name_lower for p in sec_patterns):
                security_globals.append({'name': name, 'address': addr})

        func_stores = defaultdict(int)
        func_controlled_stores = defaultdict(int)
        func_pac = defaultdict(int)
        store_sites = []
        for index, (addr, m, o, sz) in enumerate(self.insns):
            is_store = (m.startswith(('str', 'stp', 'stur', 'stnp', 'stxr', 'stlxr', 'stlr', 'stlur'))
                        or m.startswith(('cas', 'swp', 'ldadd', 'ldclr', 'ldeor', 'ldset')))
            bases = self._memory_base_regs(o)
            if is_store and bases and not bases.intersection({'sp', 'x29'}):
                nonstack_stores += 1
                func_stores[self._func_at(addr)] += 1
                source_text = o.split('[', 1)[0]
                source_regs = sorted(set(self._operand_regs(source_text)) - bases)
                provenance = (self._interprocedural_taint(index) if self.symbolic else
                              self._taint_cross_block(index) if self.deep else
                              self._taint_basic_block(index))
                controlled = any(provenance.get(reg, ('', ''))[0] in ('stack', 'mem')
                                 for reg in source_regs)
                if controlled:
                    controlled_stores += 1
                    func_controlled_stores[self._func_at(addr)] += 1
                store_sites.append({
                    'address': addr, 'function': self._func_at(addr),
                    'instruction': f'{m} {o}', 'source_registers': source_regs,
                    'controlled_source': controlled,
                })
            if m in PAC_AUTH_ALL | PAC_AUTH_BR | PAC_AUTH_BR_Z | PAC_AUTH_RET | PAC_SIGN_ALL:
                protected_branches += 1
                func_pac[self._func_at(addr)] += 1
            if m.startswith('ldr') and 'sp' not in o and '[' in o:
                data_ptr_loads += 1

        ratio = (nonstack_stores / max(protected_branches, 1))

        hotspots = []
        for func, stores in func_stores.items():
            pac_count = func_pac.get(func, 0)
            if stores >= 5 and (pac_count == 0 or stores / max(pac_count, 1) > 10):
                hotspots.append({'function': func, 'stores': stores,
                                 'controlled_stores': func_controlled_stores.get(func, 0),
                                 'pac_ops': pac_count})
        hotspots.sort(key=lambda h: (h['controlled_stores'], h['stores']), reverse=True)

        if protected_branches == 0:
            assessment = 'No PAC operations found; DOP-specific prioritization is not meaningful.'
        elif ratio > 20:
            assessment = (f'High static DOP surface indicator: {nonstack_stores} non-stack writes vs '
                          f'{protected_branches} PAC operations (ratio {ratio:.0f}:1).')
        elif ratio > 5:
            assessment = (f'Moderate static DOP surface indicator: {nonstack_stores} non-stack writes vs '
                          f'{protected_branches} PAC operations (ratio {ratio:.0f}:1).')
        else:
            assessment = (f'Low static DOP surface indicator: {nonstack_stores} non-stack writes, '
                          f'{protected_branches} PAC operations (ratio {ratio:.0f}:1).')

        if self.deep:
            assessment += f' {controlled_stores} write(s) have stack/memory-derived source provenance.'

        if security_globals:
            assessment += f' {len(security_globals)} security-relevant globals found.'

        return {
            'unprotected_stores': nonstack_stores,
            'nonstack_stores': nonstack_stores,
            'controlled_source_stores': controlled_stores,
            'protected_branches': protected_branches,
            'data_ptr_loads': data_ptr_loads,
            'store_to_branch_ratio': round(ratio, 1),
            'security_globals': security_globals[:15],
            'hotspot_functions': hotspots[:10],
            'store_sites': store_sites[:100],
            'assessment': assessment,
        }

    # ── QARMA3 Differential Cryptanalysis Risk ─────────────

    QARMA3_ATTACK_TABLE = [
        # (va_bits, profile, data_cp_log2, time_log2, section_ref)
        (56, 'A', 25,    60,   '5.1'),
        (52, 'A', 25.3,  55,   '5.2'),
        (48, 'A', 28,    60,   '5.3'),
        (44, 'A', 31.19, 68,   '5.4'),
        (40, 'A', 37.5,  76,   '5.5'),
        (36, 'A', 33.7,  76,   '5.6'),
        (32, 'A', 42,    76,   '5.7'),
        (32, 'M', 45,    76,   '5.7'),
    ]

    @cached_analysis
    def assess_qarma3_risk(self) -> dict:
        """Assess differential cryptanalysis risk if FEAT_PACQARMA3 (8-round
        QARMA-64) is used instead of FEAT_PACQARMA5 (12-round).
        Based on Avanzi, Dunkelman & Ghosh (ToSC 2025)."""
        va_bits = self._detect_va_bits()
        profile = 'A'

        pac_field_bits = 64 - va_bits - 1
        if va_bits <= 48:
            pac_field_bits = min(pac_field_bits, 55 - va_bits)

        best_attack = None
        for va, prof, data_log, time_log, sec in self.QARMA3_ATTACK_TABLE:
            if va == va_bits and prof == profile:
                best_attack = {
                    'va_bits': va,
                    'profile': prof,
                    'data_complexity_log2': data_log,
                    'time_complexity_log2': time_log,
                    'paper_section': sec,
                }
                break

        if best_attack is None:
            for va, prof, data_log, time_log, sec in self.QARMA3_ATTACK_TABLE:
                if va <= va_bits and prof == profile:
                    best_attack = {
                        'va_bits': va,
                        'profile': prof,
                        'data_complexity_log2': data_log,
                        'time_complexity_log2': time_log,
                        'paper_section': sec,
                    }
                    break

        has_fpac = self._detect_fpac_support()
        signing_gadgets = len(self.find_signing_gadgets())
        pac_total = sum(1 for _, m, _, _ in self.insns if m in PAC_ALL)

        zero_ctx = sum(1 for _, m, _, _ in self.insns
                       if m in PAC_ZERO_CTX_SIGN | PAC_ZERO_CTX_AUTH)

        variant_known = self.qarma_variant != 'auto'
        if pac_total == 0:
            risk_level = 'not_applicable'
            assessment = ('No PAC instructions in binary -- QARMA3 cryptanalysis '
                          'is irrelevant (no PAC to attack).')
        elif self.qarma_variant == 'qarma5':
            risk_level = 'not_applicable'
            assessment = ('Target configured as FEAT_PACQARMA5. The reduced-round '
                          'QARMA3 attack assessed here does not apply.')
        elif not variant_known:
            risk_level = 'conditional'
            assessment = (
                f'Conditional on the target implementing FEAT_PACQARMA3: the '
                f'{va_bits}-bit VA model maps to the published complexity below. '
                'The cipher variant cannot be inferred from instructions; select '
                '--qarma-variant qarma3/qarma5 using target CPU evidence.')
        elif best_attack and best_attack['time_complexity_log2'] <= 64:
            risk_level = 'high'
            assessment = (
                f'FEAT_PACQARMA3 breaks security target for {va_bits}-bit VA '
                f'(A-profile). Key recovery with 2^{best_attack["data_complexity_log2"]} '
                f'chosen plaintexts and 2^{best_attack["time_complexity_log2"]} time. '
                f'Attacker with signing oracle access can forge arbitrary PAC values. '
                f'Recommend FEAT_PACQARMA5 (12-round) instead.')
        elif best_attack and best_attack['time_complexity_log2'] <= 80:
            risk_level = 'medium'
            assessment = (
                f'FEAT_PACQARMA3 in warning zone for {va_bits}-bit VA. '
                f'Key recovery needs 2^{best_attack["data_complexity_log2"]} chosen plaintexts '
                f'and 2^{best_attack["time_complexity_log2"]} time -- within historical '
                f'feasibility threshold (2^80). Future cryptanalytic improvements may reduce this bound.')
        else:
            risk_level = 'low'
            assessment = (
                f'No known practical differential attack on FEAT_PACQARMA3 for '
                f'{va_bits}-bit VA at current complexity bounds. '
                f'FEAT_PACQARMA5 still recommended for defense in depth.')

        oracle_note = ''
        if signing_gadgets > 0:
            oracle_note = (
                f'{signing_gadgets} signing gadget(s) in binary could serve as '
                f'chosen-plaintext oracle for differential attack (attacker controls '
                f'pointer value signed by PAC).')
        elif zero_ctx > 0:
            oracle_note = (
                f'{zero_ctx} zero-context PAC instructions -- zero-context signing '
                f'simplifies oracle construction for differential attack.')

        fpac_note = ''
        if has_fpac:
            fpac_note = ('FPAC faults on bad auth but does not prevent differential '
                         'key recovery -- FPAC protects against brute-force, not '
                         'cryptanalysis with oracle access.')

        return {
            'risk_level': risk_level,
            'va_bits': va_bits,
            'pac_field_bits': pac_field_bits,
            'profile': profile,
            'va_bits_source': getattr(self, '_va_bits_source', 'unknown'),
            'qarma_variant': self.qarma_variant,
            'qarma_variant_note': (
                'The PAC computation can use FEAT_PACQARMA5 (12-round) or '
                'FEAT_PACQARMA3 (8-round). This is a CPU implementation choice, '
                'not a property recoverable from the binary.'),
            'best_known_attack': best_attack,
            'signing_oracle_available': signing_gadgets > 0,
            'oracle_note': oracle_note,
            'fpac_note': fpac_note,
            'is_arm64e': self.is_arm64e,
            'paper_reference': 'Avanzi, Dunkelman & Ghosh --"Differential Cryptanalysis '
                               'of FEAT_PACQARMA3" (ToSC 2025, Vol. 2025 No. 1, pp. 380-419)',
            'assessment': assessment,
        }

    # ── PAC Gadget Classification (pacrops-style) ─────────────────────

    @cached_analysis
    def find_stack_pivot_gadgets(self) -> list:
        """Detect non-frame SP derivation before SP-modified authentication."""
        results = []
        for i, (addr, m, o, sz) in enumerate(self.insns):
            if m not in (PAC_SP_CTX_AUTH | PAC_AUTH_RET):
                continue
            func_name = self._func_at(addr) or f'sub_{addr:x}'
            start = self._func_slices.get(func_name, (max(0, i - 64), i))[0]
            for j in range(i - 1, start - 1, -1):
                jm = self.insns[j][1]
                if (jm in RET_INSNS or jm in INDIRECT_BRANCH or
                        (jm.startswith('b') and jm not in PAC_ALL)):
                    start = j + 1
                    break
            sp_mod = None
            for j in range(start, i):
                ja, pm, po, _ = self.insns[j]
                parts = po.replace(' ', '').split(',')
                if not parts:
                    continue
                dst = parts[0].lower()
                if pm in ('mov', 'add', 'sub') and dst == 'sp' and len(parts) >= 2:
                    src = parts[1].lower()
                    if src in ('x29', 'fp'):
                        sp_mod = None
                        continue
                    if src != 'sp' or (pm != 'mov' and len(parts) >= 3 and
                                       not parts[2].startswith('#')):
                        sp_mod = (ja, pm, po)
                elif pm.startswith(('ldr', 'ldur')) and dst == 'sp':
                    sp_mod = (ja, pm, po)
            if sp_mod:
                results.append({
                    'address': addr,
                    'function': func_name,
                    'auth_insn': f'{m} {o}'.strip(),
                    'pivot_address': sp_mod[0],
                    'pivot_insn': f'{sp_mod[1]} {sp_mod[2]}'.strip(),
                    'severity': 'CRITICAL',
                })
        return results

    @cached_analysis
    def find_key_confusion(self) -> list:
        """Detect same-register sign/auth flows that switch PAC key families."""
        results = []
        for func_addr, func_name in sorted(self.func_boundaries.items()):
            signed = {}
            for addr, mnemonic, operands, _ in self._iter_func_insns(func_addr):
                is_pac = mnemonic in PAC_SIGN_ALL | PAC_AUTH_ALL | PAC_AUTH_RET
                dest = self._pac_dest_reg(mnemonic, operands) if is_pac else None
                if mnemonic in PAC_SIGN_ALL and dest:
                    domain = 'return' if mnemonic in PROLOGUE_PAC else 'data'
                    signed[dest] = {'key': self._pac_key(mnemonic), 'domain': domain,
                                    'address': addr, 'mnemonic': mnemonic, 'operands': operands}
                    continue
                preserved = set()
                if mnemonic == 'mov':
                    parts = [self._canonical_reg(part.strip()) for part in operands.split(',')]
                    if len(parts) >= 2 and parts[1] in signed:
                        signed[parts[0]] = signed[parts[1]]
                        preserved.add(parts[0])
                    elif parts:
                        signed.pop(parts[0], None)
                if mnemonic in PAC_AUTH_ALL | PAC_AUTH_RET and dest and dest in signed:
                    sign = signed[dest]
                    auth_domain = 'return' if mnemonic in EPILOGUE_PAC else 'data'
                    auth_key = self._pac_key(mnemonic)
                    if sign['domain'] == auth_domain and sign['key'] != auth_key:
                        if not self._is_suppressed(sign['address'], func_name, 'key-confusion'):
                            results.append({
                                'function': func_name, 'address': sign['address'],
                                'register': dest, 'domain': auth_domain,
                                'sign_keys': [sign['key']], 'auth_keys': [auth_key],
                                'sign_insns': [(sign['address'], f'{sign["mnemonic"]} {sign["operands"]}'.strip())],
                                'auth_insns': [(addr, f'{mnemonic} {operands}'.strip())],
                                'severity': 'HIGH',
                            })
                _, written = self._insn_read_write_regs(addr, mnemonic, operands)
                for register in written:
                    if register not in preserved:
                        signed.pop(register, None)
        return results

    @cached_analysis
    def find_modifier_confusion(self) -> list:
        """Detect same-register data-pointer flows with incompatible modifiers."""
        results = []
        for func_addr, func_name in sorted(self.func_boundaries.items()):
            signed = {}
            for addr, mnemonic, operands, _ in self._iter_func_insns(func_addr):
                is_pac = mnemonic in PAC_SIGN_ALL | PAC_AUTH_ALL | PAC_AUTH_RET
                dest = self._pac_dest_reg(mnemonic, operands) if is_pac else None
                if mnemonic in PAC_SIGN_ALL - PROLOGUE_PAC and dest:
                    kind, modifier = self._pac_modifier(addr, mnemonic, operands)
                    signed[dest] = {'kind': kind, 'modifier': modifier, 'address': addr,
                                    'mnemonic': mnemonic}
                    continue
                preserved = set()
                if mnemonic == 'mov':
                    parts = [self._canonical_reg(part.strip()) for part in operands.split(',')]
                    if len(parts) >= 2 and parts[1] in signed:
                        signed[parts[0]] = signed[parts[1]]
                        preserved.add(parts[0])
                    elif parts:
                        signed.pop(parts[0], None)
                if mnemonic in (PAC_AUTH_ALL | PAC_AUTH_RET) - EPILOGUE_PAC and dest in signed:
                    sign = signed[dest]
                    auth_kind, auth_modifier = self._pac_modifier(addr, mnemonic, operands)
                    mismatch = ({sign['kind'], auth_kind} == {'zero', 'register'} or
                                ({sign['kind'], auth_kind} == {'zero', 'constant'} and
                                 sign['modifier'] != auth_modifier))
                    if mismatch and not self._is_suppressed(sign['address'], func_name, 'modifier-confusion'):
                        results.append({
                            'function': func_name, 'address': sign['address'], 'register': dest,
                            'mismatch': f'{sign["kind"]}-sign + {auth_kind}-auth',
                            'sign_insns': [(sign['address'], sign['mnemonic'])],
                            'auth_insns': [(addr, mnemonic)], 'severity': 'MEDIUM',
                            'note': 'Same pointer register is signed and authenticated with incompatible modifiers.',
                        })
                _, written = self._insn_read_write_regs(addr, mnemonic, operands)
                for register in written:
                    if register not in preserved:
                        signed.pop(register, None)
        return results

    @cached_analysis
    def find_context_manipulation(self) -> list:
        """Detect non-restore LR/x30 definitions before return authentication."""
        results = []
        link_calls = {'bl', 'blr', 'blraa', 'blrab', 'blraaz', 'blrabz'}
        for i, (addr, m, o, sz) in enumerate(self.insns):
            if m not in PAC_SP_CTX_AUTH and m not in PAC_AUTH_RET:
                continue
            func_name = self._func_at(addr) or f'sub_{addr:x}'
            start = self._func_slices.get(func_name, (max(0, i - 64), i))[0]
            for j in range(i - 1, start - 1, -1):
                jm = self.insns[j][1]
                if (jm in RET_INSNS or jm in INDIRECT_BRANCH or
                        (jm.startswith('b') and jm not in PAC_ALL)):
                    start = j + 1
                    break
            lr_mod = None
            for j in range(start, i):
                ja, pm, po, _ = self.insns[j]
                if pm in link_calls:
                    lr_mod = None
                    continue
                parts = po.replace(' ', '').split(',')
                if not parts:
                    continue
                reads, writes = self._insn_read_write_regs(ja, pm, po)
                if 'x30' not in writes:
                    continue
                if pm in PAC_ALL:
                    lr_mod = None
                    continue
                if pm.startswith(('ldr', 'ldur', 'ldp', 'ldnp')):
                    bases = self._memory_base_regs(po)
                    if bases.intersection({'sp', 'x29'}):
                        lr_mod = None
                    else:
                        lr_mod = (ja, pm, po)
                    continue
                lr_mod = (ja, pm, po)
            if lr_mod:
                results.append({
                    'address': addr,
                    'function': func_name,
                    'auth_insn': f'{m} {o}'.strip(),
                    'manip_address': lr_mod[0],
                    'manip_insn': f'{lr_mod[1]} {lr_mod[2]}'.strip(),
                    'severity': 'HIGH',
                    'note': ('LR has a non-restore definition before authentication; '
                             'confirm that the source is attacker-influenced.'),
                })
        return results

    @cached_analysis
    def find_preauth_loads(self) -> list:
        """Detect indirect branches whose target was loaded from an auth-pointer section."""
        auth_ranges = {
            name: (address, address + size)
            for name, address, size, _ in self.data_sections
            if name in ('__auth_got', '__auth_ptr', '__got', '__la_symbol_ptr')
        }
        if not auth_ranges:
            return []
        results = []
        for index, (address, mnemonic, operands, _) in enumerate(self.insns):
            if mnemonic not in INDIRECT_BRANCH:
                continue
            branch_regs = self._operand_regs(operands)
            if not branch_regs:
                continue
            branch_reg = self._canonical_reg(branch_regs[0])
            func = self._func_at(address)
            start = self._func_slices.get(func, (max(0, index - 32), index))[0]
            values = {}
            origins = {}
            for insn_addr, op, args, _ in self.insns[max(start, index - 64):index]:
                parts = args.replace(' ', '').split(',')
                if not parts or not parts[0]:
                    continue
                dst = self._canonical_reg(parts[0])
                if op in ('adr', 'adrp') and len(parts) >= 2:
                    try:
                        values[dst] = int(parts[1].lstrip('#'), 0)
                        origins.pop(dst, None)
                    except ValueError:
                        values.pop(dst, None)
                elif op == 'add' and len(parts) >= 3:
                    src = self._canonical_reg(parts[1])
                    try:
                        if src in values:
                            values[dst] = values[src] + int(parts[2].lstrip('#'), 0)
                            if src in origins:
                                origins[dst] = origins[src]
                    except ValueError:
                        values.pop(dst, None)
                elif op == 'mov' and len(parts) >= 2:
                    src = self._canonical_reg(parts[1])
                    if src in values:
                        values[dst] = values[src]
                    else:
                        values.pop(dst, None)
                    if src in origins:
                        origins[dst] = origins[src]
                    else:
                        origins.pop(dst, None)
                elif op.startswith(('ldr', 'ldur')) and '[' in args:
                    inner = args[args.index('[') + 1:args.find(']', args.index('['))]
                    address_parts = inner.replace(' ', '').split(',')
                    base = self._canonical_reg(address_parts[0]) if address_parts else ''
                    displacement = 0
                    if len(address_parts) > 1 and address_parts[1].startswith('#'):
                        try:
                            displacement = int(address_parts[1][1:], 0)
                        except ValueError:
                            pass
                    if base in values:
                        source_address = values[base] + displacement
                        section = next((name for name, (lo, hi) in auth_ranges.items()
                                        if lo <= source_address < hi), None)
                        pointer = self._read_u64_at_vmaddr(source_address)
                        if pointer is not None:
                            values[dst] = pointer
                        else:
                            values.pop(dst, None)
                        if section:
                            origins[dst] = (section, source_address, insn_addr)
                        elif base in origins:
                            origins[dst] = origins[base]
                        else:
                            origins.pop(dst, None)
                    else:
                        values.pop(dst, None)
                        origins.pop(dst, None)
                elif op == 'bl':
                    for reg in ('x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7',
                                'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14',
                                'x15', 'x16', 'x17', 'x18', 'x30'):
                        values.pop(reg, None)
                        origins.pop(reg, None)
            if branch_reg not in origins:
                continue
            section, pointer_address, load_address = origins[branch_reg]
            authenticated = mnemonic in PAC_AUTH_BR | PAC_AUTH_BR_Z
            if self._is_suppressed(address, func, 'preauth-load'):
                continue
            results.append({
                'address': address, 'function': func,
                'branch_insn': f'{mnemonic} {operands}'.strip(),
                'load_address': load_address, 'target_offset': pointer_address,
                'section': section, 'authenticated_branch': authenticated,
                'severity': 'LOW' if authenticated else 'CRITICAL',
                'note': (f'Pointer loaded from {section}; ' +
                         ('the branch authenticates it' if authenticated else
                          'the branch uses it without authentication')),
            })
        return results

    @cached_analysis
    def find_xpac_bypass(self) -> list:
        """Detect XPAC strip-and-branch: pointer stripped without authentication
        then used for an indirect branch or return.
        Ref: HackTricks iOS exploiting - XPACI/XPACD/XPACLRI before BR/BLR/RET."""
        results = []
        branch_ends = {'b', 'bl', 'br', 'blr', 'ret', 'cbz', 'cbnz', 'tbz', 'tbnz',
                       'b.eq', 'b.ne', 'b.lt', 'b.gt', 'b.le', 'b.ge', 'b.hi', 'b.lo',
                       'b.hs', 'b.ls', 'b.cs', 'b.cc', 'b.mi', 'b.pl', 'b.vs', 'b.vc',
                       'b.al'} | PAC_AUTH_BR | PAC_AUTH_BR_Z | PAC_AUTH_RET
        for i, (addr, m, o, sz) in enumerate(self.insns):
            if m not in STRIP_MNEMONICS:
                continue
            func_name = self._func_at(addr)
            if self._is_runtime_func(func_name):
                continue
            if m == 'xpaclri':
                strip_reg = 'x30'
            else:
                strip_reg = o.replace(' ', '').split(',')[0].lower()
                if not strip_reg.startswith('x'):
                    continue
            aliases = {strip_reg}
            for j in range(i + 1, min(i + 24, len(self.insns))):
                ja, jm, jo, _ = self.insns[j]
                if self._func_at(ja) != func_name:
                    break
                if jm in PAC_AUTH_ALL:
                    auth_reg = self._pac_dest_reg(jm, jo)
                    if auth_reg in aliases:
                        break
                if jm in PAC_AUTH_RET and 'x30' in aliases:
                    break
                if jm in branch_ends:
                    matched = False
                    if jm in ('br', 'blr'):
                        regs = self._operand_regs(jo)
                        br_reg = self._canonical_reg(regs[0]) if regs else ''
                        if br_reg in aliases:
                            matched = True
                    elif jm == 'ret':
                        regs = self._operand_regs(jo)
                        ret_reg = self._canonical_reg(regs[0]) if regs else 'x30'
                        matched = ret_reg in aliases
                    if matched:
                        if self._is_suppressed(addr, func_name, 'xpac-bypass'):
                            break
                        results.append({
                            'address': addr,
                            'function': func_name or f'sub_{addr:x}',
                            'strip_insn': f'{m} {o}'.strip(),
                            'strip_reg': strip_reg,
                            'branch_address': ja,
                            'branch_insn': f'{jm} {jo}'.strip() if jo else jm,
                            'distance': j - i,
                            'severity': 'CRITICAL',
                            'note': (f'PAC stripped via {m} without authentication - '
                                     f'{strip_reg} used unsigned for {"return" if jm == "ret" else "indirect branch"}'),
                        })
                    break
                parts = jo.replace(' ', '').split(',') if jo else []
                if jm == 'mov' and len(parts) >= 2:
                    dst = self._canonical_reg(parts[0])
                    src = self._canonical_reg(parts[1])
                    if src in aliases:
                        aliases.add(dst)
                        continue
                _, writes = self._insn_read_write_regs(ja, jm, jo)
                aliases.difference_update(writes)
                if not aliases:
                    break
        return results

    # ── Report Generation ────────────────────────────────────────────

    def report(self, sections: Optional[Set[str]] = None):
        """Print full text report."""
        show_all = sections is None or 'all' in sections
        show = lambda s: show_all or s in (sections or set())

        print(f"\n{'='*70}")
        print(f"  PACForge - {self.path.name}")
        print(f"{'='*70}")
        fmt = 'Mach-O' if self.is_macho else ('ELF' if self.is_elf else 'raw')
        if self.macho_filetype:
            fmt += f' ({self.macho_filetype})'
        print(f"  Format: {fmt}")
        print(f"  Total instructions disassembled: {len(self.insns)}")
        print(f"  Functions with symbols: {len(self.func_boundaries)}")
        print(f"  Data sections: {len(self.data_sections)}")
        if self.stub_ranges:
            stub_insns = sum(1 for a, _, _, _ in self.insns if self._in_stub_section(a))
            print(f"  Stub/PLT instructions: {stub_insns} (filtered from gadget detection)")
        pac_total = sum(1 for _, m, _, _ in self.insns if m in PAC_ALL)
        print(f"  PAC instructions total: {pac_total}")
        if self.deep:
            parts = ['[deep-analysis]']
            if hasattr(self, '_blocks'):
                parts.append(f'CFG: {len(self._blocks)} blocks, '
                             f'{sum(len(s) for s in self._cfg_edges.values())} edges')
            if hasattr(self, '_indirect_resolved'):
                parts.append(f'indirect-calls resolved: {self._indirect_resolved}')
            if hasattr(self, '_const_at'):
                parts.append(f'constants propagated: {len(self._const_at)} sites')
            if hasattr(self, '_xbin_resolved') and self._xbin_resolved:
                parts.append(f'cross-binary: {self._xbin_resolved} symbols in '
                             f'{len(set(self._xbin_libs.values()))} libs')
            print(f"  {' | '.join(parts)}")
            if hasattr(self, '_xbin_libs') and self._xbin_libs:
                by_lib = defaultdict(list)
                for sym, lib in self._xbin_libs.items():
                    by_lib[lib].append(sym)
                print(f"\n  Cross-binary call edges ({self._xbin_resolved} resolved):")
                for lib in sorted(by_lib):
                    syms = sorted(by_lib[lib])
                    print(f"    {lib}: {len(syms)} symbols")
                    for s in syms[:5]:
                        print(f"      {s}")
                    if len(syms) > 5:
                        print(f"      ... +{len(syms)-5} more")

        if show('runtime-ctx') or show('runtime_ctx') or show_all:
            ctx = self.detect_runtime_context()
            print(f"\n{'-'*70}")
            print(f"  Runtime Context")
            print(f"{'-'*70}")
            print(f"  Host: {ctx['host_os']} {ctx['host_arch']}")
            if ctx['is_arm64_host']:
                print(f"  ARM64 host detected - hardware-dependent checks applicable")
                feat = ctx['cpu_features']
                if feat:
                    print(f"  CPU PAC features: ", end='')
                    tags = []
                    if feat.get('pauth'): tags.append('PAuth')
                    if feat.get('pauth2'): tags.append('PAuth2/EPAC')
                    if feat.get('fpac'): tags.append('FPAC')
                    if feat.get('bti'): tags.append('BTI')
                    if feat.get('mte'): tags.append('MTE')
                    print(', '.join(tags) if tags else 'none detected')
                kconf = ctx['kernel_pac_config']
                if kconf:
                    pac_kern = kconf.get('CONFIG_ARM64_PTR_AUTH_KERNEL', '?')
                    pac_user = kconf.get('CONFIG_ARM64_PTR_AUTH', '?')
                    print(f"  Kernel PAC config: user={pac_user} kernel={pac_kern}")
            elif ctx['is_arm32_host']:
                print(f"  ARM32 host - PAC is AArch64-only, hardware checks N/A")
            else:
                print(f"  Non-ARM host - hardware-dependent checks marked N/A")

            hw_modules = {k: v for k, v in ctx['module_applicability'].items()
                          if not v['applicable']}
            if hw_modules:
                print(f"\n  Modules with limited applicability on this host:")
                for mod, info in hw_modules.items():
                    print(f"    {mod}: {info['note']}")

        if show('coverage'):
            cov = self.analyze_pac_coverage()
            print(f"\n{'-'*70}")
            print("  Return Address Signing Coverage")
            print(f"{'-'*70}")
            print(f"  {cov['assessment']}")
            if cov['unprotected_functions']:
                print(f"\n  Unprotected functions (ROP targets):")
                for f in cov['unprotected_functions'][:15]:
                    bti = ' [BTI]' if f['has_bti'] else ''
                    print(f"    {f['address']:#x}: {f['name']}{bti}")
                if len(cov['unprotected_functions']) > 15:
                    print(f"    ... and {len(cov['unprotected_functions'])-15} more")

        if show('signing-gadgets') or show('signing_gadgets'):
            gadgets = self.find_signing_gadgets()
            print(f"\n{'-'*70}")
            print(f"  Signing Gadgets: {len(gadgets)} found")
            print(f"{'-'*70}")
            for g in gadgets[:20]:
                print(f"\n  {g.address:#x} in {g.function} [{g.difficulty.upper()}]")
                print(f"  PAC: {g.pac_mnemonic} | Controlled: {', '.join(g.controlled_regs) or 'none'}")
                print(f"  Stores result: {g.stores_result} -> {g.store_target}")
                for line in g.instructions:
                    print(f"    {line}")

        if show('oracles'):
            oracles = self.find_pac_oracles()
            print(f"\n{'-'*70}")
            print(f"  PAC Oracles: {len(oracles)} found")
            print(f"{'-'*70}")
            for o in oracles[:10]:
                print(f"\n  {o.address:#x} in {o.function}")
                print(f"  Chain: {o.auth_mnemonic} -> {o.sign_mnemonic}")
                print(f"  Result: {o.result_destination}")
                print(f"  Notes: {o.notes}")
                for line in o.instructions:
                    print(f"    {line}")

        if show('jop'):
            dispatchers = self.find_jop_dispatchers()
            print(f"\n{'-'*70}")
            print(f"  JOP Dispatchers: {len(dispatchers)} found")
            if self.deep and hasattr(self, '_indirect_resolved'):
                print(f"  Indirect calls resolved: {self._indirect_resolved}")
            stack_controlled = sum(1 for d in dispatchers
                                   if any(v == 'stack' for v in d.arg_sources.values()))
            if stack_controlled:
                print(f"  Stack-controlled args: {stack_controlled} dispatchers "
                      f"(attacker-controllable via overflow)")
            if self.deep and len(dispatchers) >= 2:
                chainable = 0
                for a in dispatchers[:30]:
                    for b in dispatchers[:30]:
                        if a.address != b.address and a.function and b.function and \
                           self._reachable(a.function, b.function):
                            chainable += 1
                            break
                if chainable:
                    print(f"  Chainable dispatchers: {chainable} reachable from another dispatcher")
            print(f"{'-'*70}")
            for d in dispatchers[:15]:
                print(f"\n  {d.address:#x} in {d.function} [{d.category.upper()}]")
                src_parts = []
                for reg in d.arg_regs_set:
                    src = d.arg_sources.get(reg, '?')
                    src_parts.append(f"{reg}({src})")
                print(f"  Args: {', '.join(src_parts)} -> {d.branch_reg}({d.branch_source})")
                for line in d.instructions:
                    print(f"    {line}")

        if show('brute-force') or show('brute_force'):
            bf = self.analyze_brute_force()
            print(f"\n{'-'*70}")
            print(f"  Brute Force Feasibility")
            print(f"{'-'*70}")
            ctx = self.detect_runtime_context()
            bf_app = ctx['module_applicability'].get('brute_force', {})
            if not bf_app.get('applicable', True):
                print(f"  [HOST] {bf_app['note']}")
            elif ctx['is_arm64_host']:
                print(f"  [HOST] {bf_app.get('note', 'ARM64 host')}")
            print(f"  Address type: {bf['address_type']}")
            bit_lo, bit_hi = bf['estimated_pac_bits_range']
            attempt_lo, attempt_hi = bf['brute_force_attempts_range']
            time_lo, time_hi = bf['estimated_time_seconds_range']
            print(f"  VA width: {bf['va_bits']} bits ({bf['va_bits_source']})")
            print(f"  Estimated PAC bits: {bit_lo}-{bit_hi}")
            print(f"  Brute-force attempts: {attempt_lo:,}-{attempt_hi:,}")
            print(f"  Idealized compute time: {time_lo}-{time_hi}s at {bf['us_per_attempt']}us/attempt")
            print(f"  FPAC: {bf['fpac_impact']}")
            print(f"  Zero-context sites: {bf['zero_context_count']} ({bf['zero_context_note']})")

        if show('inventory'):
            inv = self.inventory_auth_pointers()
            print(f"\n{'-'*70}")
            print(f"  Authenticated Pointer Inventory: {len(inv)} entries")
            print(f"{'-'*70}")
            for entry in inv[:30]:
                print(f"  {entry.virtual_addr:#x} [{entry.section}+{entry.offset:#x}] "
                      f"-> {entry.target_name} ({entry.key_hint})")

        if show('keys'):
            kd = self.analyze_key_diversity()
            print(f"\n{'-'*70}")
            print(f"  Key Diversity")
            print(f"{'-'*70}")
            print(f"  {kd['assessment']}")
            print(f"  IA: {kd['instruction_a_key']} | IB: {kd['instruction_b_key']} | "
                  f"DA: {kd['data_a_key']} | DB: {kd['data_b_key']}")

        if show('data-pac') or show('data_pac'):
            dp = self.analyze_data_vs_instruction_pac()
            print(f"\n{'-'*70}")
            print(f"  Data vs Instruction PAC")
            print(f"{'-'*70}")
            print(f"  Instruction PAC: {dp['instruction_pac']['total']} "
                  f"(sign={dp['instruction_pac']['sign_count']}, "
                  f"auth={dp['instruction_pac']['auth_count']}) "
                  f"in {dp['instruction_pac']['functions']} functions")
            print(f"  Data PAC: {dp['data_pac']['total']} "
                  f"(sign={dp['data_pac']['sign_count']}, "
                  f"auth={dp['data_pac']['auth_count']}) "
                  f"in {dp['data_pac']['functions']} functions")
            if dp.get('unprotected_data_funcs', 0) > 0:
                print(f"  {dp['unprotected_data_funcs']} functions use instruction PAC "
                      f"but no data PAC - data pointers unprotected in those scopes")
            print(f"  {dp['assessment']}")

        if show('sctlr'):
            sctlr = self.find_sctlr_manipulation()
            print(f"\n{'-'*70}")
            print(f"  SCTLR / Key Register Manipulation: {len(sctlr)} found")
            print(f"{'-'*70}")
            ctx = self.detect_runtime_context()
            sc_app = ctx['module_applicability'].get('sctlr', {})
            if not sc_app.get('applicable', True):
                print(f"  [HOST] {sc_app['note']}")
            elif sctlr:
                print(f"  [HOST] {sc_app.get('note', 'Requires EL1+ access')}")
            for s in sctlr[:10]:
                print(f"  {s['address']:#x} in {s['function']}: {s['register']}")
                print(f"  Impact: {s['impact']}")

        if show('zero-ctx') or show('zero_ctx'):
            zc = self.find_zero_context_pairs()
            print(f"\n{'-'*70}")
            print(f"  Zero-Context Pairs")
            print(f"{'-'*70}")
            print(f"  {zc['assessment']}")

        if show('fpac'):
            fp = self.detect_fpac()
            print(f"\n{'-'*70}")
            print(f"  FPAC Detection")
            print(f"{'-'*70}")
            print(f"  {fp['assessment']}")
            print(f"  XPAC strip instructions: {fp['strip_instructions']}")

        if show('bti'):
            bp = self.combined_bti_pac()
            print(f"\n{'-'*70}")
            print(f"  BTI + PAC Combined")
            print(f"{'-'*70}")
            print(f"  {bp['assessment']}")

        if show('chain-suggest') or show('chain_suggest'):
            self._print_chain_suggestions()

        if show('composability'):
            comp = self.analyze_composability()
            print(f"\n{'-'*70}")
            if comp.score < 0:
                print(f"  Composability Score: N/A")
            else:
                print(f"  Composability Score: {comp.score}/100")
            print(f"{'-'*70}")
            print(f"  {comp.verdict}")
            if comp.score >= 0:
                bd = comp.breakdown
                print(f"\n  Signature acquisition:  {bd.get('signature', 0)}/30"
                      f"  (gadgets={comp.signing_gadgets}, oracles={comp.oracles}"
                      f", pre-auth unsigned={comp.preauth_unsigned})")
                print(f"  Execution control:     {bd.get('execution', 0)}/25"
                      f"  (pivots={comp.stack_pivot}, branches={comp.branch_control}"
                      f", LR manip={comp.context_manip})")
                print(f"  Argument setup:        {bd.get('arguments', 0)}/15"
                      f"  (frame control={comp.arg_control})")
                print(f"  Protection weakness:   {bd.get('weakness', 0)}/30"
                      f"  (key confusion={comp.key_confusion}"
                      f", modifier confusion={comp.modifier_confusion}"
                      f", xpac bypass={comp.xpac_bypass}"
                      f", zero-ctx={comp.zero_ctx}"
                      f", coverage={comp.coverage_pct:.0f}%)")
                if comp.missing:
                    print(f"\n  Missing: {', '.join(comp.missing)}")

        if show('pacman'):
            pm = self.find_pacman_gadgets()
            app_pm = [g for g in pm if not g.get('is_runtime')]
            rt_pm = [g for g in pm if g.get('is_runtime')]
            print(f"\n{'-'*70}")
            print(f"  PACMAN Speculative Gadgets: {len(app_pm)} app-level"
                  + (f", {len(rt_pm)} runtime/unwinder" if rt_pm else ""))
            print(f"{'-'*70}")
            ctx = self.detect_runtime_context()
            pm_app = ctx['module_applicability'].get('pacman', {})
            if not pm_app.get('applicable', True):
                print(f"  [HOST] {pm_app['note']}")
            elif ctx['is_arm64_host']:
                print(f"  [HOST] {pm_app.get('note', 'ARM64 host - check CPU model')}")
            for g in app_pm[:10]:
                print(f"  {g['address']:#x} in {g['function']}")
                print(f"    {g['auth_mnemonic']} -> {g['mem_access']} (distance={g['distance']})")
            if rt_pm:
                print(f"\n  Runtime/unwinder (lower exploitability):")
                for g in rt_pm[:5]:
                    print(f"  {g['address']:#x} in {g['function']}")
                    print(f"    {g['auth_mnemonic']} -> {g['mem_access']} (distance={g['distance']})")

        if show('el-keys') or show('el_keys'):
            elk = self.find_el_key_patterns()
            print(f"\n{'-'*70}")
            print(f"  EL Key Separation Patterns: {len(elk)} found")
            print(f"{'-'*70}")
            for e in elk[:10]:
                print(f"  {e['address']:#x} in {e['function']}: {e['pattern']}")

        if show('transitions'):
            trans = self.find_pac_transitions()
            print(f"\n{'-'*70}")
            print(f"  Cross-Function PAC Transitions: {len(trans)} found")
            print(f"{'-'*70}")
            for t in trans[:10]:
                print(f"  {t.key_type}: {t.sign_func} ({t.sign_addr:#x}) -> "
                      f"{t.auth_func} ({t.auth_addr:#x})")

        if show('cross-chains') or show('cross_chains'):
            chains = self.find_cross_function_chains()
            reachable_ct = sum(1 for c in chains if c.get('reachable'))
            print(f"\n{'-'*70}")
            print(f"  Cross-Function Chains: {len(chains)} potential ({reachable_ct} reachable via call graph)")
            print(f"{'-'*70}")
            for c in chains[:10]:
                print(f"  {c['pattern']}")
                if c.get('callers_of_signer'):
                    print(f"    Called by: {', '.join(c['callers_of_signer'][:3])}")

        if show('constraints'):
            cons = self.constraint_analysis()
            print(f"\n{'-'*70}")
            print(f"  Signing Gadget Constraints: {len(cons)} analyzed")
            print(f"{'-'*70}")
            for c in cons[:10]:
                print(f"\n  {c['address']:#x} in {c['function']} [{c['difficulty'].upper()}]")
                for constraint in c['constraints']:
                    print(f"    - {constraint}")
                if c.get('callers'):
                    print(f"    Callers: {', '.join(c['callers'][:3])}")
                sat = c.get('satisfiable', 'unknown')
                if sat != 'unknown':
                    labels = {'likely': 'LIKELY satisfiable (independent controllable sources)',
                              'partial': 'PARTIALLY constrained (mix of controllable + fixed)',
                              'fixed': 'FIXED values on the analyzed static path',
                              'conflicting': 'CONFLICTING (same stack slot for multiple regs)',
                              'satisfiable': 'SATISFIABLE (all regs from independent controllable sources)',
                              'unsatisfiable': 'UNSATISFIABLE (aliased sources - regs share memory location)'}
                    print(f"    Satisfiability: {labels.get(sat, sat)}")
                if c.get('sat_details'):
                    print(f"    Solver: {c['sat_details']}")
                if c.get('sat_conflicts'):
                    for conflict in c['sat_conflicts']:
                        print(f"    Conflict: {conflict}")

        if show('auth-window') or show('auth_window'):
            aw = self.analyze_auth_use_window()
            print(f"\n{'-'*70}")
            print(f"  Auth-to-Use Window (TOCTTOU)")
            print(f"{'-'*70}")
            print(f"  {aw['assessment']}")
            for s in aw['separate_auth_ret'][:10]:
                cfg_tag = ''
                if 'cfg_verified' in s:
                    cfg_tag = ' [CFG-verified]' if s['cfg_verified'] else ' [CFG-unverified]'
                print(f"    {s['function']}: {s['auth_mnemonic']} - {s['intervening_instructions']} intervening insn(s){cfg_tag}")
            if aw.get('data_auth_windows'):
                print(f"  Data pointer auth-to-use windows: {len(aw['data_auth_windows'])}")
                for d in aw['data_auth_windows'][:10]:
                    cfg_tag = ''
                    if 'cfg_verified' in d:
                        cfg_tag = ' [CFG-verified]' if d['cfg_verified'] else ' [CFG-unverified]'
                    print(f"    {d['function']}: {d['auth_mnemonic']} -> {d['use_instruction']} "
                          f"({d['intervening_instructions']} intervening insn(s)){cfg_tag}")

        if show('ctx-entropy') or show('ctx_entropy'):
            ce = self.analyze_context_entropy()
            print(f"\n{'-'*70}")
            print(f"  Context / Modifier Entropy")
            print(f"{'-'*70}")
            print(f"  {ce['assessment']}")
            print(f"  Entropy: {ce['entropy_bits']} bits across {ce['unique_modifiers']} unique modifiers")
            if ce.get('resolved_modifiers'):
                print(f"  Resolved to concrete values: {ce['resolved_modifiers']} modifiers")

        if show('div-collisions') or show('div_collisions'):
            dc = self.find_diversifier_collisions()
            print(f"\n{'-'*70}")
            print(f"  Diversifier Collisions (Pointer Substitution)")
            print(f"{'-'*70}")
            print(f"  {dc['assessment']}")
            for group, sites in dc.get('collision_groups', {}).items():
                print(f"  Group {group}: {len(sites)} interchangeable signing sites")
                for s in sites[:5]:
                    print(f"    {s['func']} @ {s['addr']:#x}: {s['mnemonic']}")
            for group, sites in dc.get('sp_collision_groups', {}).items():
                print(f"  Group {group} (conditional - requires matching SP): {len(sites)} sites")

        if show('cop') or show('callback-indirection'):
            cop = self.find_unsigned_callback_indirection()
            print(f"\n{'-'*70}")
            print(f"  Unsigned Callback Indirection (COP/BLASTPASS): {len(cop)} found")
            print(f"{'-'*70}")
            for c in cop[:10]:
                print(f"  {c['function']} @ {c['address']:#x}")
                for line in c['chain']:
                    print(f"    {line}")
                print(f"    {c['note']}")

        if show('fork-keys') or show('fork_keys'):
            fk = self.detect_fork_key_reuse()
            print(f"\n{'-'*70}")
            print(f"  Fork/Thread Key Inheritance")
            print(f"{'-'*70}")
            print(f"  {fk['assessment']}")
            for issue in fk.get('issues', []):
                print(f"    {issue}")

        if show('setjmp'):
            sj = self.find_setjmp_pac_risks()
            print(f"\n{'-'*70}")
            print(f"  setjmp/longjmp PAC Analysis")
            print(f"{'-'*70}")
            print(f"  {sj['assessment']}")
            if sj['setjmp_sites']:
                for s in sj['setjmp_sites'][:10]:
                    print(f"    setjmp @ {s['address']:#x} in {s['function']} "
                          f"[{s['target']}] storage={s['jmp_buf_storage']}")
            if sj.get('has_pac_protected_setjmp'):
                print(f"  PAC-protected setjmp detected (jmp_buf entries signed)")
            if sj.get('cxx_exception_sites'):
                print(f"  C++ exception sites: {len(sj['cxx_exception_sites'])}")
            if sj.get('objc_exception_sites'):
                print(f"  ObjC exception sites: {len(sj['objc_exception_sites'])}")
            if sj.get('zero_context_risk'):
                print(f"  WARNING: {sj['zero_context_risk']}")

        if show('jit'):
            jit = self.detect_jit_pac_surface()
            print(f"\n{'-'*70}")
            print(f"  JIT / Dynamic Code PAC Surface")
            print(f"{'-'*70}")
            print(f"  {jit['assessment']}")
            if jit.get('pac_near_exports'):
                print(f"  PAC instructions near exported symbols:")
                for p in jit['pac_near_exports'][:5]:
                    print(f"    {p['symbol']} +{p['distance']:#x}: {p['pac_mnemonic']}")

        if show('linker-oracle') or show('linker_oracle'):
            lo = self.detect_linker_signing_oracle()
            print(f"\n{'-'*70}")
            print(f"  Dynamic Linker Signing Oracle")
            print(f"{'-'*70}")
            print(f"  {lo['assessment']}")

        if show('stack-mode') or show('stack_mode'):
            sm = self.detect_stack_protection_mode()
            print(f"\n{'-'*70}")
            print(f"  Stack Protection Mode")
            print(f"{'-'*70}")
            print(f"  Mode: {sm['mode']}")
            print(f"  {sm['assessment']}")
            fm = sm.get('per_function_modes', {})
            if any(fm.values()):
                print(f"  Per-function: PAC-only={fm.get('pac_only',0)}, "
                      f"canary-only={fm.get('canary_only',0)}, "
                      f"both={fm.get('both',0)}, none={fm.get('none',0)}")
            if sm.get('has_gcs'):
                print(f"  GCS indicators: {', '.join(sm['gcs_indicators'][:5])}")
            if sm.get('has_safestack'):
                print(f"  SafeStack: LLVM separate-stack for return addresses")

        if show('dop'):
            dop = self.estimate_dop_surface()
            print(f"\n{'-'*70}")
            print(f"  DOP (Data-Only) Attack Surface")
            print(f"{'-'*70}")
            print(f"  {dop['assessment']}")
            if dop.get('hotspot_functions'):
                print(f"  DOP hotspot functions (high store count, low/no PAC):")
                for h in dop['hotspot_functions'][:5]:
                    pac_note = f", {h['pac_ops']} PAC" if h['pac_ops'] else ", no PAC"
                    print(f"    {h['function']}: {h['stores']} non-stack stores{pac_note}")
            if dop.get('security_globals'):
                print(f"  Security-relevant globals:")
                for g in dop['security_globals'][:10]:
                    print(f"    {g['name']} @ {g['address']:#x}")

        if show('qarma3'):
            q3 = self.assess_qarma3_risk()
            print(f"\n{'-'*70}")
            print(f"  QARMA3 Differential Cryptanalysis Risk")
            print(f"{'-'*70}")
            print(f"  Risk level: {q3['risk_level'].upper()}")
            print(f"  {q3['assessment']}")
            print(f"  VA bits: {q3['va_bits']} | PAC field: {q3['pac_field_bits']} bits | "
                  f"arm64e: {q3['is_arm64e']}")
            if q3['best_known_attack']:
                a = q3['best_known_attack']
                print(f"  Best attack: 2^{a['data_complexity_log2']} CP, "
                      f"2^{a['time_complexity_log2']} time "
                      f"(paper Section {a['paper_section']})")
            if q3['oracle_note']:
                print(f"  Oracle: {q3['oracle_note']}")
            if q3['fpac_note']:
                print(f"  FPAC: {q3['fpac_note']}")
            print(f"  Ref: {q3['paper_reference']}")

        if show('stack-pivot') or show('stack_pivot'):
            pivots = self.find_stack_pivot_gadgets()
            print(f"\n{'-'*70}")
            print(f"  Stack Pivot Gadgets: {len(pivots)} found")
            print(f"{'-'*70}")
            if pivots:
                for p in pivots[:10]:
                    print(f"\n  {p['address']:#x} in {p['function']} [{p['severity']}]")
                    print(f"    SP modified: {p['pivot_insn']} @ {p['pivot_address']:#x}")
                    print(f"    Auth: {p['auth_insn']}")
                if len(pivots) > 10:
                    print(f"\n  ... and {len(pivots)-10} more")
            else:
                print("  No SP modification before auth detected.")

        if show('key-confusion') or show('key_confusion'):
            kc = self.find_key_confusion()
            print(f"\n{'-'*70}")
            print(f"  Key Confusion: {len(kc)} found")
            print(f"{'-'*70}")
            if kc:
                for k in kc[:10]:
                    print(f"\n  {k['address']:#x} {k['function']} [{k['severity']}]")
                    print(f"    Signs with key {','.join(k['sign_keys'])}, "
                          f"authenticates with key {','.join(k['auth_keys'])}")
                    for a, insn in k['sign_insns']:
                        print(f"      sign: {insn} @ {a:#x}")
                    for a, insn in k['auth_insns']:
                        print(f"      auth: {insn} @ {a:#x}")
                if len(kc) > 10:
                    print(f"\n  ... and {len(kc)-10} more")
            else:
                print("  No key A/B confusion detected.")

        if show('modifier-confusion') or show('modifier_confusion'):
            mc = self.find_modifier_confusion()
            print(f"\n{'-'*70}")
            print(f"  Modifier Confusion: {len(mc)} found")
            print(f"{'-'*70}")
            if mc:
                for m_entry in mc[:10]:
                    print(f"\n  {m_entry['address']:#x} {m_entry['function']} [{m_entry['severity']}]")
                    print(f"    Mismatch: {m_entry['mismatch']}")
                    print(f"    {m_entry['note']}")
                if len(mc) > 10:
                    print(f"\n  ... and {len(mc)-10} more")
            else:
                print("  No modifier mismatch detected.")

        if show('context-manip') or show('context_manip'):
            cm = self.find_context_manipulation()
            print(f"\n{'-'*70}")
            print(f"  Context Manipulation: {len(cm)} found")
            print(f"{'-'*70}")
            if cm:
                for c in cm[:10]:
                    print(f"\n  {c['address']:#x} in {c['function']} [{c['severity']}]")
                    print(f"    LR modified: {c['manip_insn']} @ {c['manip_address']:#x}")
                    print(f"    Auth: {c['auth_insn']}")
                    print(f"    {c['note']}")
                if len(cm) > 10:
                    print(f"\n  ... and {len(cm)-10} more")
            else:
                print("  No LR/x30 manipulation before auth detected.")

        if show('preauth-load') or show('preauth_load'):
            pl = self.find_preauth_loads()
            print(f"\n{'-'*70}")
            print(f"  Pre-Auth Pointer Loads: {len(pl)} found")
            print(f"{'-'*70}")
            if pl:
                unsigned = [p for p in pl if not p['authenticated_branch']]
                signed = [p for p in pl if p['authenticated_branch']]
                if unsigned:
                    print(f"\n  Unsigned branches from auth sections ({len(unsigned)}):")
                    for p in unsigned[:10]:
                        print(f"    {p['address']:#x} in {p['function']}: "
                              f"{p['branch_insn']} [loaded from {p['section']}]")
                if signed:
                    print(f"\n  Authenticated branches from auth sections ({len(signed)}):")
                    for p in signed[:5]:
                        print(f"    {p['address']:#x} in {p['function']}: "
                              f"{p['branch_insn']} [loaded from {p['section']}]")
                if len(pl) > 15:
                    print(f"\n  ... and {len(pl)-15} more")
            else:
                print("  No branch targets loaded from auth/GOT sections detected.")

        if show('xpac-bypass') or show('xpac_bypass'):
            xb = self.find_xpac_bypass()
            print(f"\n{'-'*70}")
            print(f"  XPAC Strip-and-Branch: {len(xb)} found")
            print(f"{'-'*70}")
            if xb:
                for x in xb[:15]:
                    print(f"\n  {x['address']:#x} in {x['function']} [{x['severity']}]")
                    print(f"    Strip: {x['strip_insn']}")
                    print(f"    Branch: {x['branch_insn']} @ {x['branch_address']:#x}")
                    print(f"    {x['note']}")
                if len(xb) > 15:
                    print(f"\n  ... and {len(xb)-15} more")
            else:
                print("  No XPAC strip-and-branch patterns detected.")

        print(f"\n{'='*70}\n")

    def _print_chain_suggestions(self):
        """Suggest exploit chain strategies based on what's available."""
        print(f"\n{'-'*70}")
        print(f"  Chain Suggestions")
        print(f"{'-'*70}")

        if self.app_pac_count == 0:
            print("\n  Binary has no application-level PAC protection.")
            print("  Traditional exploitation applies - ROP, JOP, ret2libc, etc.")
            print("  PAC-specific bypass strategies are not relevant.")
            return

        signing = self.find_signing_gadgets()
        oracles = self.find_pac_oracles()
        jop = self.find_jop_dispatchers()
        bf = self.analyze_brute_force()
        kd = self.analyze_key_diversity()
        zc = self.find_zero_context_pairs()
        inv = self.inventory_auth_pointers()
        dp = self.analyze_data_vs_instruction_pac()
        cov = self.analyze_pac_coverage()

        strategies = []

        if oracles:
            strategies.append(
                "STRATEGY 1 - PAC Oracle (Project Zero style)\n"
                f"  Use oracle at {oracles[0].address:#x}: "
                f"{oracles[0].auth_mnemonic} -> {oracles[0].sign_mnemonic}\n"
                "  1. Trigger auth with controlled pointer\n"
                "  2. Auth fails -> corrupts pointer\n"
                "  3. Re-sign corrupted pointer\n"
                "  4. Flip bit 62 of result -> valid PAC"
            )

        if signing:
            easy = [g for g in signing if g.difficulty == 'easy']
            if easy:
                strategies.append(
                    f"STRATEGY 2 - Direct Signing Gadget\n"
                    f"  Use gadget at {easy[0].address:#x} ({easy[0].pac_mnemonic})\n"
                    f"  Control {', '.join(easy[0].controlled_regs)} -> get signed result\n"
                    f"  Result stored to: {easy[0].store_target}"
                )

        if inv:
            strategies.append(
                f"STRATEGY 3 - Review Authenticated Pointer Reuse\n"
                f"  {len(inv)} pre-signed pointers in data sections\n"
                f"  First candidate is in {inv[0].section}; verify destination schema and access\n"
                f"  Best target: {inv[0].target_name} at {inv[0].virtual_addr:#x}"
            )

        if zc['portable']:
            strategies.append(
                f"STRATEGY 4 - Zero-Context Replay\n"
                f"  {zc['sign_count']} zero-ctx signers, {zc['auth_count']} zero-ctx authenticators\n"
                "  Sign at any zero-ctx site -> valid at ANY zero-ctx auth site"
            )

        bit_lo, bit_hi = bf['estimated_pac_bits_range']
        if bit_hi <= 16 and bf['fpac_enabled'] is False:
            strategies.append(
                f"STRATEGY 5 - Conditional Brute Force ({bit_lo}-{bit_hi} bits)\n"
                f"  {bf['brute_force_attempts_range'][0]:,}-{bf['brute_force_attempts_range'][1]:,} "
                "idealized attempts; explicit target evidence says FPAC is disabled"
            )

        if dp['data_pac']['total'] == 0 and dp['instruction_pac']['total'] > 0:
            strategies.append(
                "STRATEGY 6 - Review Data-Pointer Protection\n"
                "  Instruction-key PAC is present but no DA/DB operations were observed\n"
                "  This is a prioritization hint, not proof that all data pointers are unsigned"
            )

        unprotected = cov.get('unprotected_functions', [])
        if unprotected:
            strategies.append(
                f"STRATEGY 7 - Review Functions Without Return Signing\n"
                f"  {len(unprotected)} functions lack PACIASP\n"
                f"  First candidate: {unprotected[0]['name']} ({unprotected[0]['address']:#x}); "
                "check canaries, BTI/GCS/CFI, reachability, and overwrite control"
            )

        if jop:
            dispatchers = [d for d in jop if d.category == 'dispatcher']
            if dispatchers:
                strategies.append(
                    f"STRATEGY 8 - JOP via Dispatcher\n"
                    f"  {len(dispatchers)} dispatcher gadgets found\n"
                    f"  Best: {dispatchers[0].address:#x} - "
                    f"sets {', '.join(dispatchers[0].arg_regs_set)} -> {dispatchers[0].branch_reg}"
                )

        if not strategies:
            strategies.append("No viable PAC bypass strategies identified from static analysis alone.")

        for s in strategies:
            print(f"\n  {s}")

    # ── JSON Output ──────────────────────────────────────────────────

    def json_output(self) -> dict:
        """Full analysis as JSON-serializable dict."""

        def dc_list(items):
            return [asdict(i) if hasattr(i, '__dataclass_fields__') else i for i in items]

        comp = self.analyze_composability()
        return {
            'binary': str(self.path),
            'total_instructions': len(self.insns),
            'total_pac_instructions': sum(1 for _, m, _, _ in self.insns if m in PAC_ALL),
            'functions': len(self.func_boundaries),
            'runtime_context': self.detect_runtime_context(),
            'signing_gadgets': dc_list(self.find_signing_gadgets()),
            'pac_oracles': dc_list(self.find_pac_oracles()),
            'jop_dispatchers': dc_list(self.find_jop_dispatchers()),
            'pacman_gadgets': self.find_pacman_gadgets(),
            'brute_force': self.analyze_brute_force(),
            'sctlr_manipulation': self.find_sctlr_manipulation(),
            'data_vs_instruction': self.analyze_data_vs_instruction_pac(),
            'el_key_patterns': self.find_el_key_patterns(),
            'zero_context_pairs': self.find_zero_context_pairs(),
            'key_diversity': self.analyze_key_diversity(),
            'auth_pointer_inventory': dc_list(self.inventory_auth_pointers()),
            'pac_transitions': dc_list(self.find_pac_transitions()),
            'fpac': self.detect_fpac(),
            'pac_coverage': self.analyze_pac_coverage(),
            'composability': asdict(comp),
            'bti_pac_combined': self.combined_bti_pac(),
            'cross_function_chains': self.find_cross_function_chains(),
            'constraint_analysis': self.constraint_analysis(),
            'auth_use_window': self.analyze_auth_use_window(),
            'context_entropy': self.analyze_context_entropy(),
            'diversifier_collisions': self.find_diversifier_collisions(),
            'unsigned_callback_indirection': self.find_unsigned_callback_indirection(),
            'fork_key_reuse': self.detect_fork_key_reuse(),
            'setjmp_risks': self.find_setjmp_pac_risks(),
            'jit_pac_surface': self.detect_jit_pac_surface(),
            'linker_signing_oracle': self.detect_linker_signing_oracle(),
            'stack_protection_mode': self.detect_stack_protection_mode(),
            'dop_surface': self.estimate_dop_surface(),
            'qarma3_risk': self.assess_qarma3_risk(),
            'stack_pivot_gadgets': self.find_stack_pivot_gadgets(),
            'key_confusion': self.find_key_confusion(),
            'modifier_confusion': self.find_modifier_confusion(),
            'context_manipulation': self.find_context_manipulation(),
            'preauth_loads': self.find_preauth_loads(),
            'xpac_bypass': self.find_xpac_bypass(),
        }

    # ── Chain Review / Annotation System ─────────────────────────────

    def export_review(self, path: str):
        """Export all findings in annotation-ready format with stable IDs."""
        findings = []
        fid = 0

        for g in self.find_signing_gadgets():
            func = g.function
            offset = g.address - next((a for a in self.func_boundaries if self.func_boundaries[a] == func), g.address)
            findings.append({
                'id': f'sg-{fid}', 'type': 'signing-gadget',
                'address': f'{g.address:#x}', 'function': func,
                'func_offset': f'+{offset:#x}',
                'pac_mnemonic': g.pac_mnemonic,
                'controlled_regs': g.controlled_regs,
                'stores_result': g.stores_result, 'store_target': g.store_target,
                'difficulty': g.difficulty,
                'provides': 'signed_pointer',
                'requires': g.controlled_regs or ['pointer_to_sign'],
                'instructions': g.instructions,
                'status': 'unreviewed', 'notes': '', 'chain': '', 'chain_step': 0,
            })
            fid += 1

        for o in self.find_pac_oracles():
            func = o.function
            offset = o.address - next((a for a in self.func_boundaries if self.func_boundaries[a] == func), o.address)
            findings.append({
                'id': f'or-{fid}', 'type': 'oracle',
                'address': f'{o.address:#x}', 'function': func,
                'func_offset': f'+{offset:#x}',
                'auth_mnemonic': o.auth_mnemonic, 'sign_mnemonic': o.sign_mnemonic,
                'result_destination': o.result_destination,
                'provides': 'pac_oracle_leak',
                'requires': ['controlled_pointer'],
                'instructions': o.instructions,
                'status': 'unreviewed', 'notes': '', 'chain': '', 'chain_step': 0,
            })
            fid += 1

        for d in self.find_jop_dispatchers():
            func = self._func_at(d.address)
            if self._is_suppressed(d.address, func, 'jop-dispatcher'):
                continue
            findings.append({
                'id': f'jop-{fid}', 'type': 'jop-dispatcher',
                'address': f'{d.address:#x}', 'function': func,
                'category': d.category,
                'branch_reg': d.branch_reg, 'arg_regs': d.arg_regs_set,
                'provides': f'indirect_call_via_{d.branch_reg}',
                'requires': [d.branch_reg] + d.arg_regs_set,
                'instructions': d.instructions,
                'status': 'unreviewed', 'notes': '', 'chain': '', 'chain_step': 0,
            })
            fid += 1

        for c in self.find_unsigned_callback_indirection():
            func = c.get('function', 'unknown')
            findings.append({
                'id': f'cop-{fid}', 'type': 'cop',
                'address': f'{c["address"]:#x}', 'function': func,
                'provides': 'unsigned_indirect_call',
                'requires': ['corrupted_object_pointer'],
                'instructions': c.get('instructions', []),
                'status': 'unreviewed', 'notes': '', 'chain': '', 'chain_step': 0,
            })
            fid += 1

        cov = self.analyze_pac_coverage()
        for u in cov.get('unprotected_functions', []):
            if self._is_suppressed(u['address'], u['name'], 'unprotected-function'):
                continue
            findings.append({
                'id': f'unp-{fid}', 'type': 'unprotected-function',
                'address': f'{u["address"]:#x}', 'function': u['name'],
                'has_bti': u.get('has_bti', False),
                'provides': 'rop_target',
                'requires': ['stack_control'],
                'instructions': [],
                'status': 'unreviewed', 'notes': '', 'chain': '', 'chain_step': 0,
            })
            fid += 1

        for e in self.inventory_auth_pointers():
            findings.append({
                'id': f'ap-{fid}', 'type': 'auth-pointer',
                'address': f'{e.virtual_addr:#x}', 'function': e.target_name,
                'section': e.section, 'key_hint': e.key_hint,
                'provides': 'pre_signed_pointer',
                'requires': ['read_access_to_data_section'],
                'instructions': [],
                'status': 'unreviewed', 'notes': '', 'chain': '', 'chain_step': 0,
            })
            fid += 1

        for g in self.find_pacman_gadgets():
            if g.get('is_runtime'):
                continue
            findings.append({
                'id': f'pm-{fid}', 'type': 'pacman-gadget',
                'address': f'{g["address"]:#x}', 'function': g['function'],
                'auth_mnemonic': g['auth_mnemonic'],
                'mem_access': g['mem_access'],
                'provides': 'speculative_pac_oracle',
                'requires': ['tlb_timing_channel'],
                'instructions': [],
                'status': 'unreviewed', 'notes': '', 'chain': '', 'chain_step': 0,
            })
            fid += 1

        aw = self.analyze_auth_use_window()
        for s in aw.get('separate_auth_ret', []):
            if self._is_suppressed(s['address'], s['function'], 'tocttou-window'):
                continue
            findings.append({
                'id': f'tw-{fid}', 'type': 'tocttou-window',
                'address': f'{s["address"]:#x}', 'function': s['function'],
                'auth_mnemonic': s['auth_mnemonic'],
                'intervening_instructions': s['intervening_instructions'],
                'provides': 'interrupt_window',
                'requires': ['interrupt_control'],
                'instructions': [],
                'status': 'unreviewed', 'notes': '', 'chain': '', 'chain_step': 0,
            })
            fid += 1

        dc = self.find_diversifier_collisions()
        for group, sites in dc.get('collision_groups', {}).items():
            if len(sites) >= 2:
                if self._is_suppressed(sites[0]['addr'], sites[0]['func'],
                                       'diversifier-collision'):
                    continue
                findings.append({
                    'id': f'dc-{fid}', 'type': 'diversifier-collision',
                    'address': f'{sites[0]["addr"]:#x}', 'function': sites[0]['func'],
                    'collision_group': group,
                    'group_size': len(sites),
                    'provides': 'substitutable_signed_pointer',
                    'requires': ['signed_pointer_from_same_group'],
                    'instructions': [],
                    'status': 'unreviewed', 'notes': '', 'chain': '', 'chain_step': 0,
                })
                fid += 1

        dop = self.estimate_dop_surface()
        for g in dop.get('security_globals', []):
            if self._is_suppressed(g['address'], g['name'], 'dop-target'):
                continue
            findings.append({
                'id': f'dop-{fid}', 'type': 'dop-target',
                'address': f'{g["address"]:#x}', 'function': g['name'],
                'provides': 'security_state_corruption',
                'requires': ['arbitrary_write'],
                'instructions': [],
                'status': 'unreviewed', 'notes': '', 'chain': '', 'chain_step': 0,
            })
            fid += 1

        # IDs are derived from finding content rather than list position, so they
        # remain stable when another detector adds/removes unrelated findings.
        prefixes = {
            'signing-gadget': 'sg', 'oracle': 'or', 'jop-dispatcher': 'jop',
            'cop': 'cop', 'unprotected-function': 'unp', 'auth-pointer': 'ap',
            'pacman-gadget': 'pm', 'tocttou-window': 'tw',
            'diversifier-collision': 'dc', 'dop-target': 'dop',
        }
        for finding in findings:
            identity = {
                key: value for key, value in finding.items()
                if key not in ('id', 'status', 'notes', 'chain', 'chain_step', 'instructions')
            }
            digest = hashlib.sha256(
                json.dumps(identity, sort_keys=True, default=str).encode('utf-8')
            ).hexdigest()[:12]
            finding['id'] = f"{prefixes.get(finding['type'], 'finding')}-{digest}"

        review = {
            'schema_version': 2,
            'binary': str(self.path),
            'binary_sha256': self.binary_sha256,
            'format': ('Mach-O' if self.is_macho else 'ELF') + (f' ({self.macho_filetype})' if self.macho_filetype else ''),
            'total_findings': len(findings),
            'pac_instructions': sum(1 for _, m, _, _ in self.insns if m in PAC_ALL),
            'findings': findings,
            'chains': {},
            'initial_capabilities': [],
            'metadata': {
                'exported_at': __import__('datetime').datetime.now().isoformat(),
                'pacforge_version': PACFORGE_VERSION,
            },
        }

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(review, f, indent=2, default=str)
        return len(findings)

    @staticmethod
    def import_review(path: str, expected_binary: Optional[str] = None) -> dict:
        """Import annotated review file and generate chain report."""
        with open(path, encoding='utf-8') as f:
            review = json.load(f)

        if not isinstance(review, dict) or review.get('schema_version') != 2:
            raise ValueError('unsupported review schema; expected schema_version 2')
        if expected_binary:
            actual_hash = hashlib.sha256(Path(expected_binary).read_bytes()).hexdigest()
            if review.get('binary_sha256') != actual_hash:
                raise ValueError('review file does not match the supplied binary (SHA-256 mismatch)')

        findings = review.get('findings', [])
        if not isinstance(findings, list):
            raise ValueError('review findings must be a list')
        chains = defaultdict(list)
        stats = {'total': len(findings), 'confirmed': 0, 'false-positive': 0,
                 'wontfix': 0, 'unreviewed': 0}

        suppress_addrs = set()
        valid_statuses = set(stats)
        seen_ids = set()

        for f in findings:
            if not isinstance(f, dict) or not f.get('id') or not f.get('type'):
                raise ValueError('every finding must contain id and type')
            if f['id'] in seen_ids:
                raise ValueError(f'duplicate finding id: {f["id"]}')
            seen_ids.add(f['id'])
            status = f.get('status', 'unreviewed')
            if status not in valid_statuses:
                raise ValueError(f'invalid status {status!r} for {f["id"]}')
            stats[status] += 1

            if status == 'false-positive':
                addr_str = f.get('address', '')
                if addr_str:
                    suppress_addrs.add(addr_str)

            chain_name = f.get('chain', '')
            if chain_name and status not in ('false-positive', 'wontfix'):
                chains[chain_name].append(f)

        chain_reports = {}
        initial = review.get('initial_capabilities', [])
        if not isinstance(initial, list) or not all(isinstance(cap, str) for cap in initial):
            raise ValueError('initial_capabilities must be a list of strings')
        for name, members in chains.items():
            members.sort(key=lambda x: x.get('chain_step', 0))
            missing_requirements = []
            capabilities = set(initial)
            steps = [member.get('chain_step', 0) for member in members]
            if any(not isinstance(step, int) or step <= 0 for step in steps) or len(set(steps)) != len(steps):
                missing_requirements.append({'between': 'chain ordering', 'step': 'n/a',
                             'missing': ['unique positive chain_step values'],
                             'hint': 'Assign each chain member a unique positive chain_step.'})

            for i, member in enumerate(members):
                requires = member.get('requires', [])
                provides = member.get('provides', [])
                requires_set = set(requires if isinstance(requires, list) else [requires]) - {''}
                provides_set = set(provides if isinstance(provides, list) else provides.split(',')) - {''}
                unmet = requires_set - capabilities
                if unmet:
                    missing_requirements.append({
                        'between': f"capabilities -> {member['id']}",
                        'step': str(i + 1),
                        'missing': sorted(unmet),
                        'hint': f"Need primitive that provides: {', '.join(unmet)}",
                    })
                capabilities.update(provides_set)

            chain_reports[name] = {
                'steps': len(members),
                'members': [{'id': m['id'], 'type': m['type'],
                              'address': m.get('address', ''),
                              'function': m.get('function', ''),
                              'step': m.get('chain_step', 0),
                              'provides': m.get('provides', ''),
                              'requires': m.get('requires', []),
                              'status': m.get('status', 'unreviewed')}
                             for m in members],
                'missing_requirements': missing_requirements,
                'feasible': len(missing_requirements) == 0 and all(
                    member.get('status') == 'confirmed' for member in members),
                'unreviewed_steps': sum(1 for m in members if m.get('status') == 'unreviewed'),
                'final_capabilities': sorted(capabilities),
            }

        suppressions = {
            'schema_version': 2,
            'binary_sha256': review.get('binary_sha256', ''),
            'rules': [
                {
                    'type': finding['type'], 'address': finding.get('address', ''),
                    'function': finding.get('function', ''),
                    'reason': finding.get('notes', '') or 'marked false-positive during review',
                }
                for finding in findings if finding.get('status') == 'false-positive'
                and finding.get('address')
            ],
        }

        return {
            'stats': stats,
            'chains': chain_reports,
            'suppressions': suppressions,
            'binary': review.get('binary', ''),
        }


# ── CLI ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='PACForge - ARM64 Pointer Authentication Bypass Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 pacforge.py ./binary --all
  python3 pacforge.py ./binary --signing-gadgets --oracles
  python3 pacforge.py ./binary --chain-suggest
  python3 pacforge.py ./binary --all --deep-analysis
  python3 pacforge.py ./binary --all --deep-analysis --libs ./libs/
  python3 pacforge.py ./binary --json > report.json
        """)

    parser.add_argument('binary', nargs='?', help='ARM64 ELF or Mach-O binary to analyze')
    parser.add_argument('--all', action='store_true', help='Run all analyses')
    parser.add_argument('--signing-gadgets', action='store_true',
                        help='PAC signing gadgets')
    parser.add_argument('--oracles', action='store_true',
                        help='PAC oracle patterns (auth->sign->store)')
    parser.add_argument('--cross-chains', action='store_true',
                        help='Cross-function chain analysis')
    parser.add_argument('--pacman', action='store_true',
                        help='PACMAN speculative gadgets')
    parser.add_argument('--brute-force', action='store_true',
                        help='Brute-force feasibility analysis')
    parser.add_argument('--sctlr', action='store_true',
                        help='SCTLR manipulation detection')
    parser.add_argument('--data-pac', action='store_true',
                        help='Data vs instruction PAC')
    parser.add_argument('--el-keys', action='store_true',
                        help='EL key separation patterns')
    parser.add_argument('--jop', action='store_true',
                        help='JOP dispatcher detection')
    parser.add_argument('--zero-ctx', action='store_true',
                        help='Zero-context pair correlation')
    parser.add_argument('--composability', action='store_true',
                        help='Composability scoring')
    parser.add_argument('--keys', action='store_true',
                        help='Key diversity analysis')
    parser.add_argument('--inventory', action='store_true',
                        help='Authenticated pointer inventory')
    parser.add_argument('--transitions', action='store_true',
                        help='PAC transition mapping')
    parser.add_argument('--fpac', action='store_true',
                        help='FPAC detection')
    parser.add_argument('--coverage', action='store_true',
                        help='Return address signing coverage')
    parser.add_argument('--constraints', action='store_true',
                        help='Signing gadget constraint analysis')
    parser.add_argument('--bti', action='store_true',
                        help='BTI + PAC combined analysis')
    parser.add_argument('--auth-window', action='store_true',
                        help='Auth-to-use TOCTTOU window detection')
    parser.add_argument('--ctx-entropy', action='store_true',
                        help='Context/modifier entropy analysis')
    parser.add_argument('--div-collisions', action='store_true',
                        help='Diversifier collision / pointer substitution')
    parser.add_argument('--cop', action='store_true',
                        help='Unsigned callback indirection (COP/BLASTPASS)')
    parser.add_argument('--fork-keys', action='store_true',
                        help='Fork/thread PAC key inheritance')
    parser.add_argument('--setjmp', action='store_true',
                        help='setjmp/longjmp PAC analysis')
    parser.add_argument('--jit', action='store_true',
                        help='JIT / dynamic code PAC surface')
    parser.add_argument('--linker-oracle', action='store_true',
                        help='Dynamic linker signing oracle')
    parser.add_argument('--stack-mode', action='store_true',
                        help='Stack protection mode detection')
    parser.add_argument('--dop', action='store_true',
                        help='DOP (data-only) attack surface')
    parser.add_argument('--qarma3', action='store_true',
                        help='QARMA3 differential cryptanalysis risk')
    parser.add_argument('--stack-pivot', action='store_true',
                        help='Stack pivot gadget detection (SP modification before auth)')
    parser.add_argument('--key-confusion', action='store_true',
                        help='Key A/B sign-auth mismatch detection')
    parser.add_argument('--modifier-confusion', action='store_true',
                        help='Register vs zero modifier mismatch detection (data domain)')
    parser.add_argument('--context-manip', action='store_true',
                        help='LR/x30 modification before auth detection')
    parser.add_argument('--preauth-load', action='store_true',
                        help='Pre-authenticated pointer load detection')
    parser.add_argument('--xpac-bypass', action='store_true',
                        help='XPAC strip-and-branch detection (strip without auth before BR/BLR/RET)')
    parser.add_argument('--chain-suggest', action='store_true',
                        help='Suggest exploit chain strategies')
    parser.add_argument('--runtime-ctx', action='store_true',
                        help='Detect host arch/OS/CPU PAC features and module applicability')
    parser.add_argument('--json', action='store_true',
                        help='Output full analysis as JSON')
    parser.add_argument('--suppress', metavar='FILE',
                        help='JSON file with suppressed finding addresses/patterns')
    parser.add_argument('--export-findings', metavar='FILE',
                        help='Export all findings to annotation-ready JSON for chain review')
    parser.add_argument('--import-review', metavar='FILE',
                        help='Import annotated review, validate chains, generate suppressions')
    parser.add_argument('--deep-analysis', action='store_true',
                        help='Enable optional deep passes: CFG, constant propagation, '
                             'indirect call resolution, def-use chains')
    parser.add_argument('--libs', metavar='DIR',
                        help='Directory of companion libraries for cross-binary '
                             'call resolution (requires --deep-analysis)')
    parser.add_argument('--symbolic', action='store_true',
                        help='Enable inter-procedural data flow and symbolic '
                             'constraint solving (requires --deep-analysis)')
    parser.add_argument('--raw-arm64', action='store_true',
                        help='Treat a headerless input as raw ARM64 code (disabled by default)')
    parser.add_argument('--va-bits', type=int, choices=(32, 36, 39, 42, 48, 52, 56),
                        help='Override configured virtual-address width for PAC estimates')
    parser.add_argument('--fpac-mode', choices=('auto', 'yes', 'no'), default='auto',
                        help='Override FPAC availability; auto reports unknown without runtime evidence')
    parser.add_argument('--qarma-variant', choices=('auto', 'qarma3', 'qarma5'), default='auto',
                        help='Select PAC cipher variant; auto reports conditional risk')
    parser.add_argument('--verbose', '-v', action='store_true')

    args = parser.parse_args()

    if args.import_review:
        try:
            report = PacAnalyzer.import_review(args.import_review, args.binary)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        s = report['stats']
        print(f"{'='*70}")
        print(f"  Chain Review Report - {report['binary']}")
        print(f"{'='*70}")
        print(f"  Total findings: {s['total']}")
        print(f"  Confirmed: {s.get('confirmed', 0)} | False positive: {s.get('false-positive', 0)} | "
              f"Won't fix: {s.get('wontfix', 0)} | Unreviewed: {s.get('unreviewed', 0)}")

        if report['chains']:
            print(f"\n{'-'*70}")
            print(f"  Chains: {len(report['chains'])}")
            print(f"{'-'*70}")
            for name, chain in report['chains'].items():
                feasible = 'FEASIBLE' if chain['feasible'] else 'NEEDS PRIMITIVES'
                unrev = f" ({chain['unreviewed_steps']} unreviewed)" if chain['unreviewed_steps'] else ''
                print(f"\n  [{feasible}] {name} ({chain['steps']} steps){unrev}")
                for m in chain['members']:
                    status_icon = {'confirmed': '+', 'false-positive': 'x',
                                   'unreviewed': '?', 'wontfix': '-'}.get(m['status'], '?')
                    print(f"    [{status_icon}] Step {m['step']}: {m['type']} @ {m['address']} "
                          f"({m['function']})")
                    print(f"        requires: {', '.join(m['requires']) if m['requires'] else 'nothing'}")
                    print(f"        provides: {m['provides']}")
                if chain['missing_requirements']:
                    print(f"    MISSING REQUIREMENTS:")
                    for missing in chain['missing_requirements']:
                        print(f"      {missing['between']}: missing {', '.join(missing['missing'])}")
                        print(f"        {missing['hint']}")

        supp = report['suppressions']
        if supp['rules']:
            review_path = Path(args.import_review)
            supp_file = review_path.with_name(review_path.stem + '_suppress.json')
            with open(supp_file, 'w', encoding='utf-8') as f:
                json.dump(supp, f, indent=2)
            print(f"\n  Generated suppression file: {supp_file}")
            print(f"  Use: python pacforge.py <binary> --suppress {supp_file}")
        return

    if not args.binary:
        parser.error('binary is required unless --import-review is used')
    if not HAS_CAPSTONE:
        parser.error('capstone required. pip install capstone')

    libs_dir = getattr(args, 'libs', None)
    symbolic = getattr(args, 'symbolic', False)
    if libs_dir and not getattr(args, 'deep_analysis', False):
        print("Warning: --libs requires --deep-analysis, enabling it automatically",
              file=sys.stderr)
        args.deep_analysis = True
    if symbolic and not getattr(args, 'deep_analysis', False):
        print("Warning: --symbolic requires --deep-analysis, enabling it automatically",
              file=sys.stderr)
        args.deep_analysis = True
    try:
        analyzer = PacAnalyzer(
            args.binary, verbose=args.verbose, suppress_file=args.suppress,
            deep=getattr(args, 'deep_analysis', False), libs=libs_dir,
            symbolic=symbolic, raw_arm64=args.raw_arm64, va_bits=args.va_bits,
            fpac=args.fpac_mode, qarma_variant=args.qarma_variant,
        )
    except (OSError, PacForgeError, ValueError) as exc:
        parser.error(str(exc))

    if args.export_findings:
        count = analyzer.export_review(args.export_findings)
        print(f"Exported {count} findings to {args.export_findings}")
        print(f"\nWorkflow:")
        print(f"  1. Edit findings: set 'status' to confirmed/false-positive/wontfix")
        print(f"  2. Add notes explaining your reasoning")
        print(f"  3. Assign chain: set 'chain' name and 'chain_step' order (1,2,3...)")
        print(f"  4. Import: python pacforge.py <binary> --import-review {args.export_findings}")
        print(f"     Validates chains, identifies missing primitives, generates suppression file")
        return

    if args.json:
        data = analyzer.json_output()
        print(json.dumps(data, indent=2, default=str))
        return

    sections = set()
    if args.all:
        sections.add('all')
    flag_map = {
        'signing_gadgets': 'signing-gadgets',
        'oracles': 'oracles',
        'coverage': 'coverage',
        'brute_force': 'brute-force',
        'inventory': 'inventory',
        'chain_suggest': 'chain-suggest',
        'jop': 'jop',
        'keys': 'keys',
        'data_pac': 'data-pac',
        'sctlr': 'sctlr',
        'zero_ctx': 'zero-ctx',
        'fpac': 'fpac',
        'bti': 'bti',
        'pacman': 'pacman',
        'el_keys': 'el-keys',
        'transitions': 'transitions',
        'cross_chains': 'cross-chains',
        'constraints': 'constraints',
        'composability': 'composability',
        'runtime_ctx': 'runtime-ctx',
        'auth_window': 'auth-window',
        'ctx_entropy': 'ctx-entropy',
        'div_collisions': 'div-collisions',
        'cop': 'cop',
        'fork_keys': 'fork-keys',
        'setjmp': 'setjmp',
        'jit': 'jit',
        'linker_oracle': 'linker-oracle',
        'stack_mode': 'stack-mode',
        'dop': 'dop',
        'qarma3': 'qarma3',
        'stack_pivot': 'stack-pivot',
        'key_confusion': 'key-confusion',
        'modifier_confusion': 'modifier-confusion',
        'context_manip': 'context-manip',
        'preauth_load': 'preauth-load',
        'xpac_bypass': 'xpac-bypass',
    }
    for attr, sect in flag_map.items():
        if getattr(args, attr, False):
            sections.add(sect)

    if not sections:
        sections.add('all')

    analyzer.report(sections)


if __name__ == '__main__':
    main()
