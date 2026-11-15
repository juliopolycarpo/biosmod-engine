"""PGO training workload and archive.sh orchestration, with named fakes for Cargo and rustc.

Set BME_PGO_TRAIN_BIN to a built `bme` to also run the real workload against it.
"""

import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TRAIN = ROOT / "packaging/linux/pgo-train.sh"
ARCHIVE = ROOT / "packaging/linux/archive.sh"
HOST = "x86_64-unknown-linux-gnu"
REAL_BME = os.environ.get("BME_PGO_TRAIN_BIN")


def write_script(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class BmeFake:
    """A `bme` that exits 0 except for one command, and records nothing else.

    Example: BmeFake(directory, fail_on="verify", status=3) makes `bme verify ...` exit 3.
    """

    def __init__(self, directory, fail_on=None, status=0):
        self.path = directory / "bme-fake"
        write_script(self.path, f"""#!/usr/bin/env bash
if [[ "$1" == {fail_on or "NEVER"!r} ]]; then
  echo "BmeFake: {fail_on} refused" >&2
  exit {status}
fi
""")


class ArchiveToolchainFake:
    """Fake cargo, rustc and llvm-profdata that log every call to calls.jsonl.

    cargo build leaves a `bme` at $CARGO_TARGET_DIR/<target>/release; when RUSTFLAGS holds
    -Cprofile-generate=DIR, that `bme` writes DIR/default.profraw, as an instrumented one does
    (unless write_profraw is false). `cargo metadata` fails so archive.sh stops after its builds.
    Example: ArchiveToolchainFake(directory, with_profdata=False) models a toolchain without
    the llvm-tools component.
    """

    def __init__(self, directory, with_profdata=True, write_profraw=True):
        self.bin = directory / "fake-bin"
        self.bin.mkdir()
        self.calls = directory / "calls.jsonl"
        sysroot = directory / "sysroot"
        profdata_dir = sysroot / "lib/rustlib" / HOST / "bin"
        profdata_dir.mkdir(parents=True)
        self.sysroot = sysroot
        self.profdata_tool = profdata_dir / "llvm-profdata"
        log = f"""import json, os, sys
with open({str(self.calls)!r}, "a") as out:
    out.write(json.dumps({{"tool": TOOL, "argv": sys.argv[1:], "rustflags": os.environ.get("RUSTFLAGS"),
        "target_dir": os.environ.get("CARGO_TARGET_DIR")}}) + "\\n")
"""
        write_script(self.bin / "rustc", f"""#!/usr/bin/env python3
TOOL = "rustc"
{log}
import sys
if sys.argv[1:] == ["-vV"]:
    print("host: {HOST}")
elif sys.argv[1:] == ["--print", "sysroot"]:
    print({str(sysroot)!r})
else:
    raise SystemExit("ArchiveToolchainFake: unexpected rustc " + repr(sys.argv))
""")
        write_script(self.bin / "cargo", f"""#!/usr/bin/env python3
TOOL = "cargo"
{log}
import os, sys
if sys.argv[1] == "build":
    flags = os.environ.get("RUSTFLAGS") or ""
    directory = os.environ["CARGO_TARGET_DIR"] if "CARGO_TARGET_DIR" in os.environ else "target"
    release = os.path.join(directory, {HOST!r}, "release")
    os.makedirs(release, exist_ok=True)
    marker = "-Cprofile-generate="
    raw = flags.split(marker)[1].split()[0] if marker in flags else ""
    with open(os.path.join(release, "bme"), "w") as binary:
        binary.write("#!/usr/bin/env bash\\n")
        if raw and {write_profraw!r}:
            binary.write("echo raw > " + raw + "/default.profraw\\n")
    os.chmod(os.path.join(release, "bme"), 0o755)
else:
    sys.stderr.write("ArchiveToolchainFake: cargo " + sys.argv[1] + " stops the script here\\n")
    raise SystemExit(1)
""")
        if with_profdata:
            write_script(self.profdata_tool, f"""#!/usr/bin/env python3
TOOL = "llvm-profdata"
{log}
import sys
open(sys.argv[sys.argv.index("-o") + 1], "w").write("merged")
""")

    def recorded(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def builds(self):
        return [call for call in self.recorded() if call["tool"] == "cargo" and call["argv"][0] == "build"]


@unittest.skipUnless(platform.system() == "Linux", "the scripts target Linux")
class PgoTrainTests(unittest.TestCase):
    def run_train(self, *arguments):
        return subprocess.run(
            [str(TRAIN), *arguments], capture_output=True, text=True, check=False
        )

    def test_argument_errors_name_the_received_value(self):
        with tempfile.TemporaryDirectory() as directory:
            bme = BmeFake(Path(directory)).path
            cases = [
                ([], "expected <bme-binary> [rounds] | received 0 arguments"),
                ([directory], f"expected an executable bme binary | received {directory}"),
                ([str(bme), "0"], "expected rounds to be a positive integer | received 0"),
                ([str(bme), "x1"], "expected rounds to be a positive integer | received x1"),
            ]
            for arguments, message in cases:
                with self.subTest(arguments=arguments):
                    result = self.run_train(*arguments)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(message, result.stderr)

    def test_all_commands_exit_zero_for_a_passing_fake(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_train(str(BmeFake(Path(directory)).path), "3")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("pgo-train: 3 rounds done", result.stdout)

    def test_failing_command_names_round_status_command_and_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            bme = BmeFake(Path(directory), fail_on="verify", status=3).path
            result = self.run_train(str(bme), "2")
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn(
                "round 1: expected exit 0 | received exit 3 from: bme verify", result.stderr
            )
            self.assertIn("stderr: BmeFake: verify refused", result.stderr)
            self.assertNotIn("round 2", result.stderr)

    def test_scratch_directory_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory) / "tmp"
            scratch.mkdir()
            bme = BmeFake(Path(directory), fail_on="scan", status=1).path
            env = {**os.environ, "TMPDIR": str(scratch)}
            subprocess.run([str(TRAIN), str(bme), "1"], env=env, capture_output=True, check=False)
            self.assertEqual(list(scratch.iterdir()), [])

    @unittest.skipUnless(REAL_BME, "set BME_PGO_TRAIN_BIN to a built bme to run the real workload")
    def test_every_command_exits_zero_against_the_real_bme(self):
        self.assertTrue(
            os.access(REAL_BME, os.X_OK),
            f"BME_PGO_TRAIN_BIN: expected an executable bme | received {REAL_BME}",
        )
        result = self.run_train(REAL_BME, "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("pgo-train: 2 rounds done", result.stdout)


@unittest.skipUnless(
    platform.system() == "Linux" and platform.machine() == "x86_64", "archive.sh targets Linux x86_64"
)
class ArchiveScriptTests(unittest.TestCase):
    def prepare(self, **toolchain_options):
        """Copy the scripts into a throwaway checkout root and fake the toolchain."""
        directory = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, directory, True)
        checkout = directory / "checkout"
        (checkout / "packaging/linux").mkdir(parents=True)
        for script in (ARCHIVE, TRAIN):
            shutil.copy2(script, checkout / "packaging/linux" / script.name)
        scratch = directory / "tmp"
        scratch.mkdir()
        toolchain = ArchiveToolchainFake(directory, **toolchain_options)
        env = {**os.environ, "PATH": f"{toolchain.bin}:{os.environ['PATH']}", "TMPDIR": str(scratch)}
        env.pop("RUSTFLAGS", None)
        env.pop("CARGO_TARGET_DIR", None)
        return checkout, scratch, toolchain, env

    def run_archive(self, checkout, env, *arguments):
        return subprocess.run(
            [str(checkout / "packaging/linux/archive.sh"), *arguments],
            capture_output=True, text=True, env=env, check=False,
        )

    def test_unknown_argument_is_rejected_before_any_build(self):
        checkout, _, toolchain, env = self.prepare()
        result = self.run_archive(checkout, env, "--bogus")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("expected [--pgo] | received --bogus", result.stderr)
        self.assertFalse(toolchain.calls.exists())

    def test_missing_llvm_tools_names_the_path_and_the_install_command(self):
        checkout, _, toolchain, env = self.prepare(with_profdata=False)
        result = self.run_archive(checkout, env, "--pgo")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"expected llvm-profdata at {toolchain.profdata_tool}", result.stderr)
        self.assertIn("rustup component add llvm-tools", result.stderr)
        self.assertEqual(toolchain.builds(), [])

    def test_missing_raw_profiles_name_the_directory(self):
        checkout, _, toolchain, env = self.prepare(write_profraw=False)
        result = self.run_archive(checkout, env, "--pgo")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertRegex(result.stderr, r"expected \*\.profraw files in \S+/pgo/raw \| received none")
        self.assertEqual(len(toolchain.builds()), 1)

    def test_plain_build_is_one_cargo_call_without_rustflags(self):
        checkout, _, toolchain, env = self.prepare()
        self.run_archive(checkout, env)
        builds = toolchain.builds()
        self.assertEqual(len(builds), 1, builds)
        self.assertEqual(
            builds[0]["argv"],
            ["build", "--locked", "--release", "--target", HOST, "-p", "biosmod-cli", "-p", "biosmod-gui"],
        )
        self.assertIsNone(builds[0]["rustflags"])
        self.assertIsNone(builds[0]["target_dir"])

    def test_pgo_build_order_flags_and_target_directories(self):
        checkout, scratch, toolchain, env = self.prepare()
        self.run_archive(checkout, env, "--pgo")
        generate, use, gui = toolchain.builds()
        profile = checkout / "target/pgo/bme.profdata"
        # The shipped flag string is the build fingerprint's input: it must hold the checkout-relative
        # profile path and nothing machine-specific.
        self.assertEqual(use["rustflags"], f"-Cprofile-use={profile}")
        self.assertRegex(generate["rustflags"], r"^-Cprofile-generate=\S+/pgo/raw$")
        self.assertEqual(generate["argv"][-2:], ["-p", "biosmod-cli"])
        self.assertEqual(use["argv"][-2:], ["-p", "biosmod-cli"])
        self.assertEqual(gui["argv"][-2:], ["-p", "biosmod-gui"])
        self.assertIsNone(gui["rustflags"], "bme-gui must stay on the plain build")
        self.assertIsNone(gui["target_dir"])
        # Instrumented and profile-use artifacts live outside the cached target directory and are
        # distinct from each other.
        directories = {generate["target_dir"], use["target_dir"]}
        self.assertEqual(len(directories), 2, directories)
        for directory in directories:
            self.assertTrue(directory.startswith(str(scratch)), directory)
        merge = [call for call in toolchain.recorded() if call["tool"] == "llvm-profdata"]
        self.assertEqual(len(merge), 1, merge)
        self.assertEqual(merge[0]["argv"][:3], ["merge", "-o", str(profile)])
        self.assertTrue(merge[0]["argv"][3].endswith("/pgo/raw/default.profraw"), merge)
        self.assertFalse(
            (checkout / "target/pgo").exists(),
            "the merged profile must not stay in the cached target directory",
        )

    def test_pgo_flags_keep_existing_rustflags_first(self):
        checkout, _, toolchain, env = self.prepare()
        self.run_archive(checkout, {**env, "RUSTFLAGS": "-Dwarnings"}, "--pgo")
        generate, use, _ = toolchain.builds()
        self.assertTrue(generate["rustflags"].startswith("-Dwarnings -Cprofile-generate="))
        self.assertEqual(use["rustflags"], f"-Dwarnings -Cprofile-use={checkout / 'target/pgo/bme.profdata'}")


if __name__ == "__main__":
    unittest.main()
