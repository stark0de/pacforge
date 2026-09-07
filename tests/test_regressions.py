import hashlib
import json
import random
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pacforge as pacforge_module  # noqa: E402
from pacforge import (  # noqa: E402
    DependencyError,
    DETECTION_MODULES,
    HAS_Z3,
    MalformedBinaryError,
    PacAnalyzer,
    UnsupportedBinaryError,
)


class PacForgeRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf = ROOT / "tests" / "pac_test_improvements"
        cls.macho = ROOT / "tests" / "pac_test_improvements_macho"
        subprocess.run(
            [sys.executable, str(ROOT / "tests" / "gen_test_improvements.py"), str(cls.elf)],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [sys.executable, str(ROOT / "tests" / "gen_test_improvements_macho.py"), str(cls.macho)],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_composability_uses_real_coverage_and_zero_context(self):
        analyzer = PacAnalyzer(str(self.macho))
        coverage = analyzer.analyze_pac_coverage()["coverage_percent"]
        zero = analyzer.find_zero_context_pairs()
        score = analyzer.analyze_composability()
        self.assertEqual(score.coverage_pct, coverage)
        self.assertEqual(score.zero_ctx, zero["sign_count"] + zero["auth_count"])

    def test_documented_detector_count_is_consistent_and_sequential(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        module_numbers = [
            int(value)
            for value in re.findall(r"^\| (\d+) \| \*\*", readme, re.MULTILINE)
        ]
        self.assertEqual(module_numbers, list(range(1, DETECTION_MODULES + 1)))
        banner = (ROOT / "banner.svg").read_text(encoding="utf-8")
        self.assertRegex(
            banner,
            rf"<text[^>]*>{DETECTION_MODULES}</text>"
            rf"<text[^>]*> detection modules</text>",
        )

    @unittest.skipUnless(HAS_Z3, "z3-solver not installed")
    def test_z3_detects_arithmetic_dependency_independent_of_offset(self):
        analyzer = object.__new__(PacAnalyzer)
        for offset in (1, 4, 0x1000):
            taint = {
                "x0": ("stack", "[sp,#8]"),
                "x1": ("computed", f"add:x0,#{offset}"),
            }
            provenance = {
                "x0": {"source": "stack", "detail": "[sp,#8]"},
                "x1": {"source": "computed", "detail": f"add:x0,#{offset}"},
            }
            result = analyzer._solve_constraints_z3(provenance, taint)
            self.assertEqual(result["classification"], "dependent", result)

    @unittest.skipUnless(HAS_Z3, "z3-solver not installed")
    def test_z3_distinguishes_fixed_computed_and_controllable_values(self):
        analyzer = object.__new__(PacAnalyzer)
        partial_taint = {
            "x0": ("stack", "[sp,#8]"),
            "x1": ("const", "#7"),
        }
        partial_provenance = {
            "x0": {"source": "stack", "detail": "[sp,#8]"},
            "x1": {"source": "const", "detail": "#7"},
        }
        partial = analyzer._solve_constraints_z3(
            partial_provenance, partial_taint
        )
        self.assertEqual(partial["classification"], "partial", partial)

        fixed_taint = {
            "x0": ("const", "#4"),
            "x1": ("computed", "add:x0,#8"),
        }
        fixed_provenance = {
            "x1": {"source": "computed", "detail": "add:x0,#8"},
        }
        fixed = analyzer._solve_constraints_z3(fixed_provenance, fixed_taint)
        self.assertEqual(fixed["classification"], "fixed", fixed)

    def test_standard_fat64_selects_arm64e_slice(self):
        thin = self.macho.read_bytes()
        offset = 0x1000
        header = struct.pack(
            ">IIiiQQII",
            0xCAFEBABF,
            1,
            0x0100000C,
            2,
            offset,
            len(thin),
            12,
            0,
        )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "fat64"
            path.write_bytes(header.ljust(offset, b"\0") + thin)
            analyzer = PacAnalyzer(str(path))
            self.assertTrue(analyzer.is_macho)
            self.assertTrue(analyzer.is_arm64e)
            self.assertGreater(len(analyzer.func_boundaries), 10)

    def test_foreign_and_malformed_inputs_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            pe = td / "foreign.exe"
            pe.write_bytes(b"MZ" + b"\0" * 126)
            with self.assertRaises(UnsupportedBinaryError):
                PacAnalyzer(str(pe))

            malformed = td / "bad.macho"
            malformed.write_bytes(b"\xcf\xfa\xed\xfe")
            with self.assertRaises(MalformedBinaryError):
                PacAnalyzer(str(malformed))

    def test_capstone_without_pauth_support_fails_closed(self):
        class NoPAuthCapstone:
            def __init__(self, *args, **kwargs):
                pass

            def disasm(self, *args, **kwargs):
                return iter(())

        with mock.patch.object(pacforge_module, "Cs", NoPAuthCapstone):
            with self.assertRaisesRegex(DependencyError, "capstone >= 5.0"):
                PacAnalyzer(str(self.elf))

    def test_big_endian_aarch64_elf_disassembly(self):
        text = struct.pack(">II", 0xD503233F, 0xD65F03C0)
        shstr = b"\0.text\0.shstrtab\0"
        text_offset = 0x100
        shstr_offset = text_offset + len(text)
        shoff = (shstr_offset + len(shstr) + 7) & ~7
        ident = b"\x7fELF\x02\x02\x01\x00" + b"\0" * 8
        header = struct.pack(
            ">16sHHIQQQIHHHHHH", ident, 2, 183, 1, 0x400000,
            64, shoff, 0, 64, 56, 1, 64, 3, 2,
        )
        program = struct.pack(
            ">IIQQQQQQ", 1, 5, text_offset, 0x400000, 0x400000,
            len(text), len(text), 0x1000,
        )

        def section(name, kind, flags, address, offset, size, align=1):
            return struct.pack(
                ">IIQQQQIIQQ", name, kind, flags, address, offset, size,
                0, 0, align, 0,
            )

        sections = (
            section(0, 0, 0, 0, 0, 0)
            + section(1, 1, 6, 0x400000, text_offset, len(text), 4)
            + section(7, 3, 0, 0, shstr_offset, len(shstr))
        )
        blob = bytearray(shoff + len(sections))
        blob[:64] = header
        blob[64:120] = program
        blob[text_offset:text_offset + len(text)] = text
        blob[shstr_offset:shstr_offset + len(shstr)] = shstr
        blob[shoff:shoff + len(sections)] = sections

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "big-endian.elf"
            path.write_bytes(blob)
            analyzer = PacAnalyzer(str(path))
        self.assertEqual(analyzer._binary_endian, "big")
        self.assertEqual([m for _, m, _, _ in analyzer.insns], ["paciasp", "ret"])
        self.assertEqual(analyzer.json_output()["total_pac_instructions"], 1)

    def test_authenticated_loads_are_zero_context_data_pac(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "auth-loads.bin"
            path.write_bytes(struct.pack("<III", 0xF83FF420, 0xF8BFF420, 0xD65F03C0))
            analyzer = PacAnalyzer(str(path), raw_arm64=True)
        self.assertEqual([m for _, m, _, _ in analyzer.insns[:2]], ["ldraa", "ldrab"])
        self.assertEqual(analyzer.json_output()["total_pac_instructions"], 2)
        diversity = analyzer.analyze_key_diversity()
        self.assertEqual(diversity["data_a_key"], 1)
        self.assertEqual(diversity["data_b_key"], 1)
        self.assertEqual(analyzer.analyze_context_entropy()["zero_context_count"], 2)
        self.assertEqual(analyzer.find_pac_oracles(), [])
        self.assertEqual(analyzer.find_pacman_gadgets(), [])

    def test_json_remains_valid_when_symbolic_auto_enables_deep(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "pacforge.py"), str(self.elf),
             "--json", "--symbolic"],
            check=True, capture_output=True, text=True,
        )
        report = json.loads(result.stdout)
        self.assertEqual(report["binary"], str(self.elf))
        self.assertIn("enabling it automatically", result.stderr)

    def test_json_remains_valid_when_libs_auto_enables_deep(self):
        with tempfile.TemporaryDirectory() as td:
            result = subprocess.run(
                [sys.executable, str(ROOT / "pacforge.py"), str(self.elf),
                 "--json", "--libs", td],
                check=True, capture_output=True, text=True,
            )
        report = json.loads(result.stdout)
        self.assertEqual(report["binary"], str(self.elf))
        self.assertIn("enabling it automatically", result.stderr)

    def test_basic_macho_generator_emits_code_symbol_addresses(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "pac-test.macho"
            subprocess.run(
                [sys.executable, str(ROOT / "tests" / "gen_test_macho.py"), str(path)],
                check=True, capture_output=True, text=True,
            )
            analyzer = PacAnalyzer(str(path))
        self.assertEqual(len(analyzer.func_boundaries), 12)
        self.assertIn("sign_gadget", analyzer.func_boundaries.values())

    def test_symbolic_map_groups_each_cfg_block_once(self):
        analyzer = PacAnalyzer(str(self.elf), deep=True)
        original = analyzer._func_at
        calls = 0

        def counted(address):
            nonlocal calls
            calls += 1
            return original(address)

        analyzer._func_at = counted
        analyzer._build_symbolic_maps()
        self.assertLessEqual(calls, len(analyzer._blocks) + 1)

    def test_compiled_pac_source_uses_exact_instruction_encodings(self):
        source = (ROOT / "tests" / "sources" / "pac_test.c").read_text(encoding="utf-8")
        self.assertIn(".inst 0xdac10020", source)
        self.assertIn(".inst 0xdac11020", source)
        self.assertIn(".inst 0xdac123e0", source)
        self.assertNotIn("hint #12", source)
        words = [int(value, 16) for value in
                 re.findall(r"\.inst 0x([0-9a-fA-F]+)", source)]
        arch = getattr(pacforge_module.capstone, "CS_ARCH_ARM64", None)
        if arch is None:
            arch = getattr(pacforge_module.capstone, "CS_ARCH_AARCH64")
        decoder = pacforge_module.Cs(arch, pacforge_module.capstone.CS_MODE_ARM)
        mnemonics = [insn.mnemonic for word in words
                     for insn in decoder.disasm(struct.pack("<I", word), 0)]
        self.assertEqual(mnemonics, ["pacia", "autia", "paciza", "paciza"])

    def test_raw_arm64_requires_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as td:
            raw = Path(td) / "raw.bin"
            raw.write_bytes(struct.pack("<II", 0xD503233F, 0xD65F03C0))
            with self.assertRaises(UnsupportedBinaryError):
                PacAnalyzer(str(raw))
            analyzer = PacAnalyzer(str(raw), raw_arm64=True)
            self.assertEqual(analyzer.sections[0][0], "raw")

    def test_suppression_is_type_scoped_and_affects_signing_findings(self):
        base = PacAnalyzer(str(self.elf))
        gadget = base.find_signing_gadgets()[0]
        with tempfile.TemporaryDirectory() as td:
            suppression = Path(td) / "suppress.json"
            suppression.write_text(
                json.dumps({
                    "schema_version": 2,
                    "binary_sha256": hashlib.sha256(self.elf.read_bytes()).hexdigest(),
                    "rules": [{
                        "type": "signing-gadget",
                        "address": hex(gadget.address),
                        "reason": "regression fixture",
                    }],
                }),
                encoding="utf-8",
            )
            filtered = PacAnalyzer(str(self.elf), suppress_file=str(suppression))
            addresses = {g.address for g in filtered.find_signing_gadgets()}
            self.assertNotIn(gadget.address, addresses)

    def test_review_export_has_content_stable_ids_and_binary_binding(self):
        analyzer = PacAnalyzer(str(self.elf))
        with tempfile.TemporaryDirectory() as td:
            first = Path(td) / "one.json"
            second = Path(td) / "two.json"
            analyzer.export_review(str(first))
            analyzer.export_review(str(second))
            a = json.loads(first.read_text(encoding="utf-8"))
            b = json.loads(second.read_text(encoding="utf-8"))
            self.assertEqual(a["schema_version"], 2)
            self.assertEqual(a["binary_sha256"], hashlib.sha256(self.elf.read_bytes()).hexdigest())
            self.assertEqual(
                [f["id"] for f in a["findings"]],
                [f["id"] for f in b["findings"]],
            )
            self.assertFalse(any("numeric_category" in f for f in a["findings"]))

    def _linear_analyzer(self, instructions):
        analyzer = PacAnalyzer(str(self.elf))
        analyzer.insns = [(0x1000 + index * 4, mnemonic, operands, 4)
                          for index, (mnemonic, operands) in enumerate(instructions)]
        analyzer.sections = [('fixture', 0x1000, b'\0' * (len(instructions) * 4))]
        analyzer.func_boundaries = {0x1000: "fixture"}
        analyzer.insn_meta = {}
        analyzer._build_indexes()
        analyzer._build_call_graph()
        analyzer.suppressions = {"rules": [], "legacy_addresses": set(),
                                 "legacy_functions": set(), "legacy_patterns": []}
        return analyzer

    def test_confusion_requires_the_same_pointer_register(self):
        key_positive = self._linear_analyzer([
            ("pacia", "x0, x1"), ("autib", "x0, x1"), ("ret", "")])
        key_negative = self._linear_analyzer([
            ("pacia", "x0, x1"), ("autib", "x2, x1"), ("ret", "")])
        self.assertEqual(len(key_positive.find_key_confusion()), 1)
        self.assertEqual(key_negative.find_key_confusion(), [])

        modifier_positive = self._linear_analyzer([
            ("pacia", "x0, x1"), ("autiaz", "x0"), ("ret", "")])
        modifier_negative = self._linear_analyzer([
            ("pacia", "x0, x1"), ("autiaz", "x2"), ("ret", "")])
        self.assertEqual(len(modifier_positive.find_modifier_confusion()), 1)
        self.assertEqual(modifier_negative.find_modifier_confusion(), [])

    def test_xpac_alias_to_branch_is_detected(self):
        analyzer = self._linear_analyzer([
            ("xpaci", "x0"), ("mov", "x1, x0"), ("br", "x1")])
        findings = analyzer.find_xpac_bypass()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["branch_insn"], "br x1")

    def test_xpac_alias_killed_by_overwrite_is_not_reported(self):
        analyzer = self._linear_analyzer([
            ("xpaci", "x0"), ("mov", "x1, x0"), ("mov", "x1, x2"), ("br", "x1")])
        self.assertEqual(analyzer.find_xpac_bypass(), [])

    def test_stack_and_lr_state_are_cleared_by_legitimate_overwrites(self):
        restored_sp = self._linear_analyzer([
            ("mov", "sp, x0"), ("mov", "sp, x29"), ("autiasp", ""), ("ret", "")])
        self.assertEqual(restored_sp.find_stack_pivot_gadgets(), [])

        call_clobber = self._linear_analyzer([
            ("mov", "x30, x0"), ("bl", "#0x2000"), ("autiasp", ""), ("ret", "")])
        self.assertEqual(call_clobber.find_context_manipulation(), [])

        stack_restore = self._linear_analyzer([
            ("ldr", "x30, [sp, #8]"), ("autiasp", ""), ("ret", "")])
        self.assertEqual(stack_restore.find_context_manipulation(), [])

        memory_definition = self._linear_analyzer([
            ("ldr", "x30, [x19]"), ("autiasp", ""), ("ret", "")])
        self.assertEqual(len(memory_definition.find_context_manipulation()), 1)

    def test_symbolic_api_enables_required_deep_passes(self):
        analyzer = PacAnalyzer(str(self.elf), symbolic=True)
        self.assertTrue(analyzer.deep)
        self.assertTrue(hasattr(analyzer, "_cfg_edges"))
        self.assertTrue(hasattr(analyzer, "_func_input_regs"))

    def test_export_names_replace_generated_function_names(self):
        analyzer = object.__new__(PacAnalyzer)
        analyzer.sections = [("__text", 0x1000, b"\0" * 0x20)]
        analyzer.symbols = {"exported_name": 0x1008, "data_name": 0x2000}
        analyzer.func_boundaries = {0x1008: "sub_1008"}
        analyzer._reconcile_exported_functions()
        self.assertEqual(analyzer.func_boundaries[0x1008], "exported_name")
        self.assertNotIn(0x2000, analyzer.func_boundaries)

    def test_export_trie_parser_recovers_stripped_export(self):
        trie = bytes([0, 1]) + b"_foo\0" + bytes([8, 2, 0, 0x10, 0])
        self.assertEqual(
            PacAnalyzer._parse_export_trie_symbols(trie, 0, len(trie), 0x1000),
            {"foo": 0x1010},
        )

    def test_chained_fixup_multi_start_and_shared_cache_layout(self):
        analyzer = object.__new__(PacAnalyzer)
        analyzer.segment_meta = [{
            "fileoff": 0x100, "filesize": 0x100,
            "vmaddr": 0x100000, "vmsize": 0x100,
        }]
        analyzer.auth_pointer_metadata = []
        data = bytearray(0x500)
        dataoff = 0x300
        struct.pack_into("<IIIIIII", data, dataoff, 0, 28, 0, 0, 0, 0, 0)
        starts = dataoff + 28
        struct.pack_into("<II", data, starts, 1, 8)
        info = starts + 8
        struct.pack_into("<IHHQIH", data, info, 28, 0x100, 1, 0, 0, 1)
        struct.pack_into("<HHH", data, info + 22, 0x8001, 0, 0x8008)
        first = (1 << 63) | (1 << 48) | (0x1234 << 32) | 0x1111
        second = (1 << 63) | (2 << 49) | (0x5678 << 32) | 0x2222
        struct.pack_into("<Q", data, 0x100, first)
        struct.pack_into("<Q", data, 0x108, second)
        analyzer._load_chained_fixups(bytes(data), dataoff, 0x100, "<")
        self.assertEqual(
            [entry["virtual_addr"] for entry in analyzer.auth_pointer_metadata],
            [0x100000, 0x100008],
        )
        self.assertEqual(
            [entry["key"] for entry in analyzer.auth_pointer_metadata],
            ["IA", "DA"],
        )

        analyzer.auth_pointer_metadata = []
        data = bytearray(0x500)
        struct.pack_into("<IIIIIII", data, dataoff, 0, 28, 0, 0, 0, 0, 0)
        struct.pack_into("<II", data, starts, 1, 8)
        struct.pack_into("<IHHQIH", data, info, 24, 0x100, 13, 0, 0, 1)
        struct.pack_into("<H", data, info + 22, 0)
        shared = ((1 << 63) | (1 << 51) | (1 << 50) |
                  (0x1357 << 34) | 0x123456)
        struct.pack_into("<Q", data, 0x100, shared)
        analyzer._load_chained_fixups(bytes(data), dataoff, 0x100, "<")
        entry = analyzer.auth_pointer_metadata[0]
        self.assertEqual(entry["key"], "DA")
        self.assertEqual(entry["diversity"], 0x1357)
        self.assertEqual(entry["target"], 0x123456)

    def test_fpac_and_qarma_are_unknown_without_target_evidence(self):
        analyzer = PacAnalyzer(str(self.elf), fpac="auto", qarma_variant="auto")
        analyzer._cached_runtime_ctx = {"is_arm64_host": False, "cpu_features": {}}
        self.assertIsNone(analyzer._detect_fpac_support())
        self.assertEqual(analyzer.detect_fpac()["fpac_status"], "unknown")
        self.assertEqual(analyzer.assess_qarma3_risk()["risk_level"], "conditional")

    def test_random_foreign_inputs_fail_closed(self):
        rng = random.Random(0x504143)
        with tempfile.TemporaryDirectory() as td:
            for index in range(64):
                path = Path(td) / f"input-{index}.bin"
                path.write_bytes(rng.randbytes(rng.randrange(0, 512)))
                with self.assertRaises((UnsupportedBinaryError, MalformedBinaryError)):
                    PacAnalyzer(str(path))

    def test_function_lookup_never_crosses_executable_section_holes(self):
        analyzer = self._linear_analyzer([("ret", ""), ("ret", "")])
        analyzer.sections = [
            ("text.one", 0x1000, b"\0" * 8),
            ("text.two", 0x2000, b"\0" * 8),
        ]
        analyzer.insns = [
            (0x1000, "ret", "", 4), (0x1004, "ret", "", 4),
            (0x2000, "ret", "", 4), (0x2004, "ret", "", 4),
        ]
        analyzer.func_boundaries = {0x1000: "first", 0x2000: "second"}
        analyzer._build_indexes()
        self.assertEqual(analyzer._func_at(0x1004), "first")
        self.assertEqual(analyzer._func_at(0x1800), "unknown")
        self.assertIsNone(analyzer._resolve_code_pointer(0x1800))
        self.assertEqual(analyzer._func_at(0x2004), "second")

    def test_symbolic_input_summary_uses_register_tokens_not_substrings(self):
        analyzer = self._linear_analyzer([
            ("mov", "x10, x2"),
            ("pacia", "x0, x3"),
            ("ret", ""),
        ])
        analyzer.deep = True
        analyzer.symbolic = True
        analyzer._build_cfg()
        analyzer._build_symbolic_maps()
        inputs = analyzer._func_input_regs["fixture"]
        self.assertIn("x2", inputs)
        self.assertIn("x0", inputs)
        self.assertIn("x3", inputs)
        self.assertNotIn("x1", inputs)

    @unittest.skipUnless(HAS_Z3, "z3-solver not installed")
    def test_symbolic_solver_considers_alternative_cfg_paths(self):
        analyzer = self._linear_analyzer([
            ("cbz", "x2, #0x1010"),
            ("ldr", "x0, [sp, #8]"),
            ("b", "#0x1014"),
            ("nop", ""),
            ("mov", "x0, #1"),
            ("pacia", "x0, x1"),
            ("ret", ""),
        ])
        analyzer.deep = True
        analyzer.symbolic = True
        analyzer._build_cfg()
        analyzer._build_symbolic_maps()
        paths = analyzer._taint_paths_to(5)
        sources = {path.get("x0", ("unknown", ""))[0] for path in paths}
        self.assertIn("stack", sources)
        self.assertIn("const", sources)
        result = analyzer._solve_constraints_z3(
            {"x0": {"source": "stack", "detail": "[sp, #8]"}}, paths)
        self.assertEqual(result["classification"], "satisfiable")
        self.assertGreaterEqual(result["path_count"], 2)

    def test_auth_use_requires_same_unclobbered_pointer(self):
        positive = self._linear_analyzer([
            ("autia", "x0, x1"), ("nop", ""), ("ldr", "x2, [x0]"), ("ret", "")])
        negative = self._linear_analyzer([
            ("autia", "x0, x1"), ("mov", "x0, x2"), ("ldr", "x3, [x0]"), ("ret", "")])
        found = positive.analyze_auth_use_window()["data_auth_windows"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["intervening_instructions"], 1)
        self.assertEqual(negative.analyze_auth_use_window()["data_auth_windows"], [])

    def test_unresolved_diversifiers_are_not_reported_as_collisions(self):
        analyzer = self._linear_analyzer([
            ("pacia", "x0, x1"), ("pacia", "x2, x1"), ("ret", "")])
        result = analyzer.find_diversifier_collisions()
        self.assertEqual(result["collision_groups"], {})
        self.assertEqual(len(result["unresolved_modifier_sites"]), 2)

    def test_fork_thread_spawn_and_verified_rekey_are_distinct(self):
        spawn = self._linear_analyzer([("bl", "posix_spawn"), ("ret", "")])
        spawn_result = spawn.detect_fork_key_reuse()
        self.assertFalse(spawn_result["is_forking_server"])
        self.assertEqual(len(spawn_result["spawn_calls"]), 1)

        thread = self._linear_analyzer([("bl", "pthread_create"), ("ret", "")])
        thread_result = thread.detect_fork_key_reuse()
        self.assertFalse(thread_result["is_forking_server"])
        self.assertTrue(thread_result["is_threaded"])
        self.assertIn("do not provide process-crash isolation", " ".join(thread_result["issues"]))

        rekey = self._linear_analyzer([
            ("mov", "x0, #54"), ("bl", "prctl"), ("ret", "")])
        self.assertTrue(rekey.detect_fork_key_reuse()["has_rekey_capability"])
        wrong_option = self._linear_analyzer([
            ("mov", "x0, #53"), ("bl", "prctl"), ("ret", "")])
        self.assertFalse(wrong_option.detect_fork_key_reuse()["has_rekey_capability"])

    def test_dop_counts_only_nonstack_writes_and_tracks_source(self):
        analyzer = self._linear_analyzer([
            ("ldr", "x0, [sp, #8]"),
            ("str", "x0, [x19]"),
            ("str", "x0, [sp, #16]"),
            ("pacia", "x1, x2"),
            ("ret", ""),
        ])
        analyzer.data_symbols = {"auth_token": 0x5000, "ordinary_counter": 0x5008}
        result = analyzer.estimate_dop_surface()
        self.assertEqual(result["nonstack_stores"], 1)
        self.assertEqual(result["controlled_source_stores"], 1)
        self.assertEqual([item["name"] for item in result["security_globals"]], ["auth_token"])

    def test_review_chains_accumulate_capabilities(self):
        findings = [
            {"id": "a", "type": "primitive", "address": "0x1", "function": "a",
             "status": "confirmed", "chain": "demo", "chain_step": 1,
             "requires": ["arbitrary_write"], "provides": "signed_pointer"},
            {"id": "b", "type": "primitive", "address": "0x2", "function": "b",
             "status": "confirmed", "chain": "demo", "chain_step": 2,
             "requires": ["signed_pointer"], "provides": "branch_control"},
            {"id": "c", "type": "primitive", "address": "0x3", "function": "c",
             "status": "confirmed", "chain": "demo", "chain_step": 3,
             "requires": ["arbitrary_write", "branch_control"],
             "provides": "code_execution"},
        ]
        review = {
            "schema_version": 2,
            "binary": str(self.elf),
            "binary_sha256": hashlib.sha256(self.elf.read_bytes()).hexdigest(),
            "initial_capabilities": ["arbitrary_write"],
            "findings": findings,
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "review.json"
            path.write_text(json.dumps(review), encoding="utf-8")
            result = PacAnalyzer.import_review(str(path), str(self.elf))
        chain = result["chains"]["demo"]
        self.assertTrue(chain["feasible"])
        self.assertEqual(chain["missing_requirements"], [])
        self.assertIn("code_execution", chain["final_capabilities"])


if __name__ == "__main__":
    unittest.main()
