"""Check release boundaries in temporary source copies; never start QEMU."""

import argparse
import contextlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import native_milestone as milestone


class NativeMilestoneBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original, cls.checked = milestone.verify_public()
        cls.workspace = tempfile.TemporaryDirectory(prefix="z62-native-release-")
        cls.root = Path(cls.workspace.name)
        files = [r["path"] for r in cls.original["files"]] + [str(milestone.BASELINE / "manifest.json")]
        for relative in files:
            target = cls.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def args(self, **values):
        args = argparse.Namespace(check_only=False, print_command=False, preflight_only=False,
                                  persistent_input=None, mcu_rtc_backup_input=None, seconds=1800)
        for key, value in values.items():
            setattr(args, key, value)
        return args

    def reject_changed_file(self, relative, body):
        path = self.root / relative
        before = path.read_bytes()
        try:
            path.write_bytes(body)
            with self.assertRaises(ValueError):
                milestone.verify_public(self.root)
        finally:
            path.write_bytes(before)

    def test_source_copy_needs_no_private_runtime_or_firmware(self):
        manifest, checked = milestone.verify_public(self.root)
        self.assertFalse((self.root / "runtime").exists())
        self.assertFalse((self.root / "inputs").exists())
        self.assertFalse(checked["runtime_verified"])
        self.assertEqual(len(manifest["model_sources"]), 119)

    def test_changed_compiled_model_is_rejected(self):
        relative = self.original["model_sources"][0]
        self.reject_changed_file(relative, (self.root / relative).read_bytes() + b"\n/* drift */\n")

    def test_changed_observer_windows_are_rejected(self):
        relative = str(milestone.BASELINE / "ui-observation-plan.json")
        changed = json.loads((self.root / relative).read_text())
        changed["windows"][0]["start_virtual_ns"] = 1
        self.reject_changed_file(relative, json.dumps(changed).encode())

    def test_changed_button_deadline_is_rejected(self):
        relative = str(milestone.BASELINE / "external-pad-schedule.json")
        changed = json.loads((self.root / relative).read_text())
        changed["schedule"].pop()
        self.reject_changed_file(relative, json.dumps(changed).encode())

    def test_added_harness_execution_source_is_rejected(self):
        path = self.root / "src/harness/extra-execution.py"
        try:
            path.write_text("# unexpected source\n")
            with self.assertRaises(ValueError):
                milestone.verify_public(self.root)
        finally:
            path.unlink()

    def test_input_symlink_cannot_escape_package(self):
        path = self.root / "external-link"
        try:
            path.symlink_to(ROOT / "VERSION")
            with self.assertRaises(ValueError):
                milestone.contained_file(self.root, path)
        finally:
            path.unlink()

    def test_parent_traversal_is_rejected(self):
        with self.assertRaises(ValueError):
            milestone.contained_file(self.root, "../VERSION")

    def test_exact_recipe_preserves_explicit_models_and_timebases(self):
        values = milestone.selected_inputs(self.args(), self.original, self.root)
        command = milestone.command(self.original, values, 1800)
        for option, expected in (("--seconds", "1800"), ("--virtual-seconds", "34"),
                                 ("--isp-commit-model", "next-frame-ae-v4"),
                                 ("--image-status-model", "pending-v1")):
            self.assertEqual(command[command.index(option) + 1], expected)
        self.assertIn("--persistent-output", command)
        self.assertIn("--mcu-rtc-backup-output", command)

    def test_source_check_cannot_invoke_runtime_or_launch(self):
        def forbidden(*args, **kwargs):
            self.fail("Source check invoked a runtime action")
        with contextlib.redirect_stdout(io.StringIO()):
            code = milestone.run_milestone(self.args(check_only=True), forbidden, forbidden, self.root)
        self.assertEqual(code, 0)

    def test_missing_retained_inputs_cannot_launch(self):
        def forbidden(*args, **kwargs):
            self.fail("Missing inputs reached runtime launch")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = milestone.run_milestone(self.args(), forbidden, forbidden, self.root)
        self.assertEqual(code, 1)

    def test_failed_runtime_binding_cannot_launch(self):
        def forbidden(*args, **kwargs):
            self.fail("Failed binding reached runtime launch")
        # The two placeholders exist only in the temporary fixture. No payload
        # is accepted; the independent validator deliberately rejects the call.
        values = milestone.selected_inputs(self.args(), self.original, self.root)
        created = []
        try:
            for value in values.values():
                path = self.root / value
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}\n")
                created.append(path)
            with patch.object(milestone, "verify_runtime", side_effect=ValueError("compiled source mismatch")):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    code = milestone.run_milestone(self.args(), forbidden, forbidden, self.root)
            self.assertEqual(code, 1)
        finally:
            for path in created:
                path.unlink()
            shutil.rmtree(self.root / 'inputs')

    def test_nonfinite_host_budget_cannot_launch(self):
        def forbidden(*args, **kwargs):
            self.fail("Nonfinite budget reached launch")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = milestone.run_milestone(self.args(seconds=float("nan")), forbidden, forbidden, self.root)
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
