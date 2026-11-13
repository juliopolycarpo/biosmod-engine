"""Tests for the bme_replay package. They run against synthetic PE images only.

Without `unicorn` and `pefile` the emulation tests skip; run them inside the managed
environment: `$(bme tools paths)/replay/venv/bin/python -m unittest discover -s tools/tests`.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "replay"))
sys.path.insert(0, os.path.dirname(__file__))

import pe_builder  # noqa: E402

try:
    import bme_replay as replay
    from bme_replay import __main__ as replay_main
    from bme_replay import services, smbus

    HAVE_RUNTIME = True
except ImportError:  # no unicorn or pefile in this interpreter
    HAVE_RUNTIME = False

RETURN_7 = bytes([0xB8, 7, 0, 0, 0, 0xC3])  # mov eax, 7; ret
BASE = 0x2000_0000


def sha(data):
    return hashlib.sha256(data).hexdigest()


class SyntheticBuilderTest(unittest.TestCase):
    """The builder is the twin of `synthetic::pe`; these digests are pinned in Rust too."""

    def test_digests_match_the_rust_builder(self):
        self.assertEqual(
            sha(pe_builder.pe(True, RETURN_7)),
            "ddbe3c834fcf497f566b37609f390b23cc07120f6913a01fc5d750e682e6951e",
        )
        self.assertEqual(
            sha(pe_builder.pe(False, RETURN_7)),
            "c9b2daea4a7d7b928da079663b81c08c11af2055433d315f9e28d67cd9109ae6",
        )
        self.assertEqual(
            sha(pe_builder.pe(True, bytes(16), [0x1008])),
            "e40be8c13480b89ac2e1a7af6f67270ca5193fdf8345e889e5da82a6556fb5a1",
        )


@unittest.skipUnless(HAVE_RUNTIME, "unicorn and pefile are not installed in this interpreter")
class ReplayTest(unittest.TestCase):
    def load(self, code, wide=True, base=None, relocations=()):
        machine = replay.Machine(64 if wide else 32)
        image = replay.load_pe(machine, pe_builder.pe(wide, code, relocations), base=base, name="synthetic")
        return machine, image

    # -- images ---------------------------------------------------------------------------

    def test_a_64_bit_function_returns_its_value(self):
        machine, image = self.load(RETURN_7)
        result = machine.call(image.entry)
        self.assertEqual((result.value, image.bitness, image.sha256), (7, 64, sha(pe_builder.pe(True, RETURN_7))))

    def test_a_32_bit_function_returns_its_value(self):
        machine, image = self.load(RETURN_7, wide=False)
        self.assertEqual(machine.call(image.entry).value, 7)

    def test_relocations_follow_the_load_base_for_pe32_plus(self):
        code = bytes([0x48, 0xB8]) + (pe_builder.IMAGE_BASE + 0x1000).to_bytes(8, "little") + b"\xc3"
        machine, image = self.load(code, base=BASE, relocations=[0x1002])
        self.assertEqual(machine.call(image.entry).value, BASE + 0x1000)

    def test_relocations_follow_the_load_base_for_pe32(self):
        code = bytes([0xB8]) + (pe_builder.IMAGE_BASE + 0x1000).to_bytes(4, "little") + b"\xc3"
        machine, image = self.load(code, wide=False, base=BASE, relocations=[0x1001])
        self.assertEqual(machine.call(image.entry).value, BASE + 0x1000)

    def test_the_preferred_base_is_kept_when_no_base_is_given(self):
        _, image = self.load(RETURN_7)
        self.assertEqual((image.base, image.entry), (pe_builder.IMAGE_BASE, pe_builder.IMAGE_BASE + 0x1000))

    def test_an_image_for_the_wrong_machine_names_both_bitnesses(self):
        machine = replay.Machine(32)
        with self.assertRaises(replay.ImageError) as caught:
            replay.load_pe(machine, pe_builder.pe(True, RETURN_7), name="driver")
        self.assertIn("driver bitness: expected a 32-bit machine | received a 64-bit image", str(caught.exception))

    def test_a_declared_bitness_is_checked_against_the_header(self):
        with self.assertRaises(replay.ImageError) as caught:
            replay.load_pe(replay.Machine(64), pe_builder.pe(True, RETURN_7), bitness=32, name="driver")
        self.assertIn("driver bitness: expected 32 | received 64", str(caught.exception))

    def test_garbage_is_not_an_image(self):
        with self.assertRaises(replay.ImageError) as caught:
            replay.load_pe(replay.Machine(64), b"not a pe image", name="junk")
        self.assertIn("junk: expected a PE32, PE32+ or TE image", str(caught.exception))

    def test_a_te_image_is_mapped_at_its_section_addresses(self):
        # 40-byte TE header plus one section header (80 bytes); the original headers were
        # 0x200 bytes, so the stripped size is 0x200 - 80 + 40 and the body follows at offset 80.
        header = b"VZ" + (0x8664).to_bytes(2, "little") + bytes([1, 11]) + (0x1D8).to_bytes(2, "little")
        header += (0x1000).to_bytes(4, "little") + (0x1000).to_bytes(4, "little")
        header += (pe_builder.IMAGE_BASE).to_bytes(8, "little") + bytes(16)
        section = b".text\0\0\0" + len(RETURN_7).to_bytes(4, "little") + (0x1000).to_bytes(4, "little")
        section += (0x200).to_bytes(4, "little") + (0x200).to_bytes(4, "little") + bytes(16)
        te = header + section + RETURN_7
        machine = replay.Machine(64)
        image = replay.load_pe(machine, te, name="te")
        self.assertEqual((image.kind, machine.call(image.entry).value), ("te", 7))

    # -- calls ----------------------------------------------------------------------------

    def test_arguments_follow_the_microsoft_x64_convention(self):
        code = bytes([0x48, 0x8D, 0x04, 0x0A, 0xC3])  # lea rax, [rdx+rcx]
        machine, image = self.load(code)
        self.assertEqual(machine.call(image.entry, 30, 12).value, 42)

    def test_arguments_follow_cdecl_for_ia32(self):
        code = bytes([0x8B, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x08, 0xC3])  # mov eax,[esp+4]; add eax,[esp+8]
        machine, image = self.load(code, wide=False)
        self.assertEqual(machine.call(image.entry, 30, 12).value, 42)

    def test_a_clobbered_callee_saved_register_is_an_abi_violation(self):
        machine, image = self.load(bytes([0x31, 0xDB, 0xC3]))  # xor ebx, ebx
        with self.assertRaises(replay.AbiViolation) as caught:
            machine.call(image.entry)
        self.assertIn("rbx: expected", str(caught.exception))

    def test_a_loop_exceeds_the_instruction_budget(self):
        machine, image = self.load(bytes([0xEB, 0xFE]))  # jmp $
        with self.assertRaises(replay.BudgetExceeded) as caught:
            machine.call(image.entry, budget=1000)
        self.assertIn("expected a return within 1000 instructions", str(caught.exception))

    def test_an_unmapped_read_is_a_fault_that_can_be_captured(self):
        code = bytes([0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0x7E, 0xC3])  # mov rax, [0x7e000000]
        machine, image = self.load(code)
        result = machine.call(image.entry, capture_fault=True)
        self.assertEqual((result.value, result.fault["kind"], result.fault["address"]), (None, "read-unmapped", 0x7E000000))
        with self.assertRaises(replay.EmulationFault):
            machine.call(image.entry)

    # -- ports, MMIO, MSRs ----------------------------------------------------------------

    def test_port_reads_and_writes_reach_the_named_device(self):
        # mov dx,0x404; in ax,dx; mov ax,0x1234; out dx,ax; movzx eax, ax... returns the value read.
        code = bytes([0x66, 0xBA, 0x04, 0x04, 0x66, 0xED, 0x50, 0x66, 0xB8, 0x34, 0x12, 0x66, 0xEF, 0x58, 0xC3])
        machine, image = self.load(code)
        device = replay.PortRegisters({0x404: 0x1400})
        machine.ports.attach(device, device.ports(), "pm1")
        result = machine.call(image.entry)
        self.assertEqual((result.value & 0xFFFF, machine.ports.writes(0x404), device.values[0x404]), (0x1400, [(0x404, 2, 0x1234)], 0x1234))

    def test_a_port_without_a_model_is_unmodeled(self):
        machine, image = self.load(bytes([0x66, 0xBA, 0x80, 0x00, 0xEC, 0xC3]))  # mov dx,0x80; in al,dx
        with self.assertRaises(replay.UnmodeledAccess) as caught:
            machine.call(image.entry)
        self.assertIn("port 0x80 read size 1: expected a device model | received none", str(caught.exception))

    def test_a_claimed_port_cannot_be_claimed_twice(self):
        machine = replay.Machine(64)
        machine.ports.attach(replay.PortRegisters({0x404: 0}), [0x404], "first")
        with self.assertRaises(replay.ReplayError) as caught:
            machine.ports.attach(replay.PortRegisters({0x404: 0}), [0x404], "second")
        self.assertIn("port 0x404: expected a free port | received it claimed by first", str(caught.exception))

    def test_mmio_reads_come_from_the_register_file(self):
        code = bytes([0x8B, 0x01, 0xC3])  # mov eax, [rcx]
        machine, image = self.load(code)
        machine.mmio(0xFED1_3000, 0x1000, replay.RegisterFile({0x418: 0xCAFE}), "rcba")
        self.assertEqual(machine.call(image.entry, 0xFED1_3418).value, 0xCAFE)

    def test_an_unlisted_mmio_register_is_unmodeled(self):
        machine, image = self.load(bytes([0x8B, 0x01, 0xC3]))  # mov eax, [rcx]
        machine.mmio(0xFED1_3000, 0x1000, replay.RegisterFile({}), "rcba")
        with self.assertRaises(replay.UnmodeledAccess) as caught:
            machine.call(image.entry, 0xFED1_3000)
        self.assertIn("mmio offset 0x0 read size 4: expected a modeled register", str(caught.exception))

    def test_rdmsr_and_wrmsr_go_to_the_msr_bus(self):
        # mov ecx,0x1b; rdmsr; ret (EAX holds the low half)
        code = bytes([0xB9, 0x1B, 0, 0, 0, 0x0F, 0x32, 0xC3])
        machine, image = self.load(code)
        machine.attach_msrs(replay.MsrBus({0x1B: 0xFEE0_0900}, trace=machine.trace))
        self.assertEqual(machine.call(image.entry).value, 0xFEE0_0900)

    def test_wrmsr_updates_the_bus(self):
        # mov ecx,0x1b; xor edx,edx; mov eax,0x55; wrmsr; ret
        code = bytes([0xB9, 0x1B, 0, 0, 0, 0x31, 0xD2, 0xB8, 0x55, 0, 0, 0, 0x0F, 0x30, 0xC3])
        machine, image = self.load(code)
        bus = replay.MsrBus({0x1B: 0})
        machine.attach_msrs(bus)
        machine.call(image.entry)
        self.assertEqual(bus.values[0x1B], 0x55)

    def test_an_unlisted_msr_is_unmodeled(self):
        machine, image = self.load(bytes([0xB9, 0x99, 0, 0, 0, 0x0F, 0x32, 0xC3]))
        machine.attach_msrs(replay.MsrBus({}))
        with self.assertRaises(replay.UnmodeledAccess) as caught:
            machine.call(image.entry)
        self.assertIn("msr 0x99 read: expected a modeled register", str(caught.exception))

    # -- stubs and services ---------------------------------------------------------------

    def test_a_stub_replaces_a_function_and_sees_its_arguments(self):
        # call [rip+..] is awkward to assemble; call a stub address directly instead.
        machine = replay.Machine(64)
        seen = []
        address = machine.new_stub(lambda call: seen.append(call.args(2)) or 99, "Probe")
        self.assertEqual(machine.call(address, 5, 6).value, 99)
        self.assertEqual(seen, [[5, 6]])

    def test_dxe_variables_round_trip_through_the_runtime_services(self):
        machine = replay.Machine(64)
        store = replay.VariableStore()
        guid = "4E82091E-32A1-4689-8A00-CDE41ED63CDD"
        store.set("Setup", guid, b"\x01\x02\x03\x04")
        dxe = replay.DxeServices(machine, store)
        name = machine.allocate(32)
        machine.write(name, "Setup".encode("utf-16le") + b"\0\0")
        guid_at = machine.allocate(16)
        machine.write(guid_at, replay.parse_guid(guid))
        size, data = machine.allocate(8), machine.allocate(16)
        machine.write_uint(size, 8, 16)
        get_variable = machine.read_pointer(dxe.runtime.address + services.RUNTIME_LAYOUT["GetVariable"])
        result = machine.call(get_variable, name, guid_at, 0, size, data)
        self.assertEqual((result.value, machine.read_uint(size, 8), machine.read(data, 4)), (0, 4, b"\x01\x02\x03\x04"))
        set_variable = machine.read_pointer(dxe.runtime.address + services.RUNTIME_LAYOUT["SetVariable"])
        machine.write(data, b"\xaa\xbb")
        machine.call(set_variable, name, guid_at, 7, 2, data)
        self.assertEqual(store.get("Setup", guid), (7, b"\xaa\xbb"))

    def test_a_missing_variable_is_not_found(self):
        machine = replay.Machine(64)
        dxe = replay.DxeServices(machine)
        name = machine.allocate(32)
        machine.write(name, "Nope".encode("utf-16le") + b"\0\0")
        guid_at, size = machine.allocate(16), machine.allocate(8)
        get_variable = machine.read_pointer(dxe.runtime.address + services.RUNTIME_LAYOUT["GetVariable"])
        self.assertEqual(machine.call(get_variable, name, guid_at, 0, size, 0).value, (1 << 63) | services.EFI_NOT_FOUND)

    def test_a_short_buffer_reports_the_size_needed(self):
        machine = replay.Machine(64)
        store = replay.VariableStore()
        guid = "4E82091E-32A1-4689-8A00-CDE41ED63CDD"
        store.set("Setup", guid, bytes(10))
        dxe = replay.DxeServices(machine, store)
        name = machine.allocate(32)
        machine.write(name, "Setup".encode("utf-16le") + b"\0\0")
        guid_at, size = machine.allocate(16), machine.allocate(8)
        machine.write(guid_at, replay.parse_guid(guid))
        machine.write_uint(size, 8, 4)
        get_variable = machine.read_pointer(dxe.runtime.address + services.RUNTIME_LAYOUT["GetVariable"])
        result = machine.call(get_variable, name, guid_at, 0, size, 0)
        self.assertEqual((result.value, machine.read_uint(size, 8)), ((1 << 63) | services.EFI_BUFFER_TOO_SMALL, 10))

    def test_an_unhandled_service_names_itself(self):
        machine = replay.Machine(64)
        dxe = replay.DxeServices(machine)
        slot = machine.read_pointer(dxe.boot.address + services.BOOT_LAYOUT["Stall"])
        dxe.boot.handlers.pop("Stall")
        with self.assertRaises(replay.UnmodeledService) as caught:
            machine.call(slot, 5)
        self.assertIn("boot.Stall('0x5', '0x0', '0x0', '0x0'): expected a handler | received a call", str(caught.exception))

    def test_smm_locate_protocol_finds_a_registered_interface(self):
        machine = replay.Machine(64)
        smm = replay.SmmServices(machine)
        guid = "11111111-2222-3333-4444-555555555555"
        smm.add_protocol(guid, 0xABCD0000)
        guid_at, out = machine.allocate(16), machine.allocate(8)
        machine.write(guid_at, replay.parse_guid(guid))
        locate = machine.read_pointer(smm.table + services.SMM_LAYOUT["SmmLocateProtocol"])
        self.assertEqual(machine.call(locate, guid_at, 0, out).value, 0)
        self.assertEqual(machine.read_pointer(out), 0xABCD0000)

    def test_pei_services_report_the_boot_mode(self):
        machine = replay.Machine(32)
        pei = replay.PeiServices(machine, boot_mode=0x11)
        table = machine.read_pointer(pei.services)
        get_boot_mode = machine.read_pointer(table + services.PEI_LAYOUT["GetBootMode"])
        out = machine.allocate(4)
        self.assertEqual(machine.call(get_boot_mode, pei.services, out).value, 0)
        self.assertEqual(machine.read_uint(out, 4), 0x11)

    def test_a_64_bit_service_table_needs_a_64_bit_machine(self):
        with self.assertRaises(replay.ReplayError) as caught:
            replay.DxeServices(replay.Machine(32))
        self.assertIn("DxeServices machine: expected 64-bit | received 32-bit", str(caught.exception))

    # -- device models --------------------------------------------------------------------

    def test_an_indexed_chip_banks_its_registers(self):
        chip = replay.IndexedRegisters(0xA25, 0xA26, banks=2, bank_register=0x4E, registers={(1, 0x10): 0x77})
        chip.port_write(0xA25, 1, 0x4E)
        chip.port_write(0xA26, 1, 0x81)
        chip.port_write(0xA25, 1, 0x10)
        self.assertEqual(chip.port_read(0xA26, 1), 0x77)
        chip.port_write(0xA25, 1, 0x4E)
        self.assertEqual(chip.port_read(0xA26, 1), 0x81)

    def test_a_word_access_to_an_indexed_data_port_is_unmodeled(self):
        chip = replay.IndexedRegisters(0x2E, 0x2F)
        with self.assertRaises(replay.UnmodeledAccess) as caught:
            chip.port_read(0x2F, 2)
        self.assertIn("port 0x2f read size 2: expected 1 for an indexed data port", str(caught.exception))

    def test_a_seeded_chip_starts_from_scrambled_state(self):
        chip = replay.IndexedRegisters(0xA25, 0xA26, banks=16, bank_register=0x4E, seed=7)
        self.assertEqual((chip.selected, chip.register(0, 1)), (49, (7 + 13) & 255))

    def test_the_library_builds_a_device_by_kind_name(self):
        device = replay.devices.build("port-registers", {"values": {"0x404": 5}})
        self.assertEqual(device.ports(), [0x404])
        with self.assertRaises(replay.ReplayError) as caught:
            replay.devices.build("flux-capacitor", {})
        self.assertIn("device kind 'flux-capacitor': expected one of", str(caught.exception))

    def spd_bus(self, data):
        eeprom = smbus.SpdEeprom(data)
        device = smbus.SmbusDevice(
            0xF000, {0x50: eeprom, 0x36: smbus.SpdPageSelect(eeprom, 0), 0x37: smbus.SpdPageSelect(eeprom, 1)}
        )
        return eeprom, device

    def read_byte(self, device, address, command):
        device.port_write(0xF000 + smbus.XMIT_SLVA, 1, (address << 1) | 1)
        device.port_write(0xF000 + smbus.HST_CMD, 1, command)
        device.port_write(0xF000 + smbus.HST_CNT, 1, smbus.CNT_START | (2 << 2))
        return device.port_read(0xF000 + smbus.HST_D0, 1), device.port_read(0xF000 + smbus.HST_STS, 1)

    def test_an_spd_byte_is_read_through_the_controller(self):
        _, device = self.spd_bus(bytes(range(256)) * 2)
        self.assertEqual(self.read_byte(device, 0x50, 0x02), (2, smbus.STS_INTR))

    def test_a_page_select_quick_write_switches_the_spd_page(self):
        data = bytes(256) + bytes([0xEE]) * 256
        _, device = self.spd_bus(data)
        device.port_write(0xF000 + smbus.XMIT_SLVA, 1, 0x37 << 1)
        device.port_write(0xF000 + smbus.HST_CNT, 1, smbus.CNT_START)
        self.assertEqual(self.read_byte(device, 0x50, 0x00)[0], 0xEE)

    def test_a_missing_slave_sets_the_device_error_status(self):
        _, device = self.spd_bus(bytes(256))
        self.assertEqual(self.read_byte(device, 0x51, 0x00)[1], smbus.STS_DEV_ERR)

    def test_an_spd_image_must_be_a_whole_number_of_pages(self):
        with self.assertRaises(replay.ReplayError) as caught:
            smbus.SpdEeprom(bytes(100))
        self.assertIn("spd size: expected 256 | 512 bytes | received 100", str(caught.exception))

    # -- trace and output -----------------------------------------------------------------

    def test_the_trace_digest_is_stable_for_equal_runs(self):
        digests = []
        for _ in range(2):
            machine, image = self.load(bytes([0x66, 0xBA, 0x04, 0x04, 0x66, 0xED, 0xC3]))
            machine.ports.attach(replay.PortRegisters({0x404: 1}), [0x404], "pm1")
            machine.call(image.entry)
            digests.append(machine.trace.digest())
        self.assertEqual(digests[0], digests[1])
        self.assertEqual(len(digests[0]), 64)

    def test_emit_appends_one_json_line_per_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "result.jsonl")
            os.environ[replay.RESULT_ENV] = path
            try:
                replay.emit({"case": 1, "blob": b"\x01\xff"})
                replay.emit({"case": 2})
            finally:
                del os.environ[replay.RESULT_ENV]
            with open(path) as handle:
                lines = [json.loads(line) for line in handle]
        self.assertEqual(lines, [{"case": 1, "blob": "01ff"}, {"case": 2}])

    def test_emit_rejects_a_value_that_is_not_json(self):
        with self.assertRaises(TypeError) as caught:
            replay.emit({"bad": object()})
        self.assertIn("emit: expected a JSON value | received object", str(caught.exception))


@unittest.skipUnless(HAVE_RUNTIME, "unicorn and pefile are not installed in this interpreter")
class ExampleHarnessTest(unittest.TestCase):
    """The B11 harness needs the vendor module for a real run; its helpers are checked here."""

    @classmethod
    def setUpClass(cls):
        import runpy

        path = os.path.join(os.path.dirname(__file__), "..", "replay", "examples", "b11_context_overread.py")
        cls.example = runpy.run_path(path, run_name="b11")

    def test_the_scenario_grid_has_23_contexts_in_four_classes(self):
        rows = self.example["payloads"]()
        self.assertEqual((len(rows), sorted({kind for kind, _, _ in rows})), (23, [1, 2, 3, 6]))
        for kind, payload, _ in rows:
            self.assertEqual(len(payload), self.example["WIDTHS"][kind], "class %d context width" % kind)

    def test_native_validation_ranges_mark_rejected_values(self):
        accepted = {(kind, payload.hex()): ok for kind, payload, ok in self.example["payloads"]()}
        self.assertTrue(accepted[(1, "0300000001000000")])  # Sx S3, phase 1
        self.assertFalse(accepted[(1, "0600000000000000")])  # Sx type 6
        self.assertFalse(accepted[(2, "0001000000000000")])  # software value 0x100
        self.assertTrue(accepted[(2, "ffffffffffffffff")])  # automatic assignment
        self.assertFalse(accepted[(3, "1000000000000000")])  # GPI 16
        self.assertFalse(accepted[(6, "02000000")])  # power button phase 2

    def test_a_module_without_the_reviewed_code_is_refused_by_digest(self):
        module = pe_builder.pe(True, RETURN_7)
        with self.assertRaises(replay.ReplayError) as caught:
            self.example["prepare"](module)
        self.assertIn(
            "PchSmiDispatcher %s: expected the reviewed registration code | received other bytes" % sha(module),
            str(caught.exception),
        )


@unittest.skipUnless(HAVE_RUNTIME, "unicorn and pefile are not installed in this interpreter")
class MainTest(unittest.TestCase):
    def test_parse_splits_modules_and_script_arguments(self):
        self.assertEqual(
            replay_main.parse(["h.py", "--module", "a.pe", "--module", "b.pe", "--", "x", "--y"]),
            ("h.py", ["a.pe", "b.pe"], ["x", "--y"]),
        )

    def test_parse_rejects_an_unknown_option(self):
        with self.assertRaises(SystemExit) as caught:
            replay_main.parse(["h.py", "--bogus"])
        self.assertIn("argument '--bogus': expected --module PATH or --", str(caught.exception))

    def test_a_harness_runs_with_its_modules_and_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = os.path.join(tmp, "harness.py")
            result = os.path.join(tmp, "out.jsonl")
            with open(harness, "w") as handle:
                handle.write("import sys, bme_replay as r\nr.emit({'modules': r.modules(), 'argv': sys.argv[1:]})\n")
            os.environ[replay.RESULT_ENV] = result
            try:
                replay_main.main([harness, "--module", "m.pe", "--", "one"])
            finally:
                del os.environ[replay.RESULT_ENV]
            with open(result) as handle:
                self.assertEqual(json.loads(handle.read()), {"argv": ["one"], "modules": ["m.pe"]})


if __name__ == "__main__":
    unittest.main()
