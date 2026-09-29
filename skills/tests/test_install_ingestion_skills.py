"""Filesystem behavior and installed dependency checks; no provider/store access."""

import importlib.util
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("installer", REPO / "scripts/install-ingestion-skills.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.dest = self.root / "harness" / "skills"

    def test_selection_includes_shared_contract_and_is_repeatable(self):
        plans = installer.install(self.dest, ["hc-ingest-codex"])
        self.assertEqual({name for name, _ in plans}, {"hc-ingest", "hc-ingest-codex"})
        self.assertTrue((self.dest / "hc-ingest/references/records.md").is_file())
        before = {p: p.stat().st_mtime_ns for p in self.dest.rglob("*") if p.is_file()}
        self.assertTrue(all(action == "unchanged" for _, action in installer.install(self.dest, ["hc-ingest-codex"])))
        self.assertEqual(before, {p: p.stat().st_mtime_ns for p in before})

    def test_customized_skill_rejects_entire_plan_before_writes(self):
        target = self.dest / "hc-ingest-codex"
        target.mkdir(parents=True)
        (target / "SKILL.md").write_text("User's customized instructions")
        with self.assertRaises(ValueError):
            installer.install(self.dest, ["hc-ingest-codex", "hc-ingest-claude"])
        self.assertEqual(list(self.dest.iterdir()), [target])
        self.assertEqual((target / "SKILL.md").read_text(), "User's customized instructions")

    def test_dry_run_does_not_create_destination(self):
        installer.install(self.dest, [], dry_run=True)
        self.assertFalse(self.dest.exists())

    def test_unknown_name_cannot_escape_destination(self):
        with self.assertRaises(ValueError):
            installer.install(self.dest, ["../outside"])
        self.assertFalse(self.dest.exists())

    def test_target_symlink_is_preserved_and_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        self.dest.mkdir(parents=True)
        (self.dest / "hc-ingest").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            installer.install(self.dest, ["hc-ingest-slack"])
        self.assertEqual(list(outside.iterdir()), [])
        self.assertTrue((self.dest / "hc-ingest").is_symlink())

    def test_unrelated_skills_are_untouched(self):
        self.dest.mkdir(parents=True)
        unrelated = self.dest / "my-skill.txt"
        unrelated.write_text("keep this")
        installer.install(self.dest, ["hc-ingest-claude"])
        self.assertEqual(unrelated.read_text(), "keep this")

    def test_source_symlink_or_executable_cannot_be_copied(self):
        source = self.root / "source"
        core = source / "hc-ingest"
        core.mkdir(parents=True)
        (core / "SKILL.md").write_text("instructions")
        payload = core / "run.py"
        payload.write_text("raise RuntimeError('must not run')")
        with self.assertRaises(ValueError):
            installer.install(self.dest, [], source=source)
        payload.unlink()
        (core / "outside.md").symlink_to(REPO / "README.md")
        with self.assertRaises(ValueError):
            installer.install(self.dest, [], source=source)
        self.assertFalse(self.dest.exists())

    def test_all_installed_local_links_resolve_and_metadata_matches(self):
        plans = installer.install(self.dest, [])
        self.assertGreaterEqual(len(plans), 3)
        for name, _ in plans:
            entry = self.dest / name / "SKILL.md"
            text = entry.read_text()
            self.assertTrue(text.startswith(f"---\nname: {name}\ndescription: "))
            self.assertIn("\n---\n", text[4:])
            metadata = (entry.parent / "agents/openai.yaml").read_text()
            self.assertIn("$" + name, metadata)
            for document in entry.parent.rglob("*.md"):
                for target in re.findall(r"\]\(([^)]+)\)", document.read_text()):
                    if "://" not in target and not target.startswith("#"):
                        self.assertTrue((document.parent / target.split("#")[0]).is_file(), target)

    def test_documented_cli_installs_only_selected_instructions(self):
        result = subprocess.run(
            [sys.executable, str(REPO / "scripts/install-ingestion-skills.py"),
             "--dest", str(self.dest), "--skill", "hc-ingest-codex",
             "--skill", "hc-ingest-claude"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({p.name for p in self.dest.iterdir()},
                         {"hc-ingest", "hc-ingest-codex", "hc-ingest-claude"})
        self.assertFalse((self.root / ".brain").exists())


if __name__ == "__main__":
    unittest.main()
