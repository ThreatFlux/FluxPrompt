"""Exercise the proposal source policy without making GitHub writes."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import check_release_source as source


class ProposalSourceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Release source fixture")
        self.git("config", "user.email", "release-source@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.parent = self.commit_manifest("0.2.5", "chore: baseline")
        self.git("checkout", "-b", "automation/release")
        self.head = self.commit_manifest("0.2.6", "chore(release): v0.2.6")
        self.git("checkout", "main")
        self.git("merge", "--no-ff", "--no-edit", "automation/release")
        self.origin = self.git("rev-parse", "HEAD")
        # A feature lands after the release merge, and also touches the manifest.
        self.later = self.commit_manifest("0.2.6", "feat: later change", "# feature\n")
        tree = self.git("rev-parse", f"{self.origin}^{{tree}}")
        self.repo = "ThreatFlux/FluxPrompt"
        self.author = "threatflux-automation[bot]"
        repo = {"full_name": self.repo}
        self.pr = {
            "merged_at": "2026-01-01T00:00:00Z",
            "merge_commit_sha": self.origin,
            "base": {"ref": "main", "repo": repo},
            "head": {"ref": "automation/release", "repo": repo, "sha": self.head},
            "user": {"login": self.author},
            "title": "chore(release): v0.2.6",
        }
        self.proof = {
            "parents": [{"sha": self.parent}],
            "commit": {"tree": {"sha": tree}, "verification": {"verified": True}},
        }

    def git(self, *args):
        return subprocess.check_output(
            ("git", *args), cwd=self.root, stderr=subprocess.PIPE,
            text=True, encoding="utf-8",
        ).strip()

    def commit_manifest(self, version, message, suffix=""):
        (self.root / "Cargo.toml").write_text(
            f'[package]\nversion = "{version}"\n{suffix}', encoding="utf-8",
        )
        self.git("add", "Cargo.toml")
        self.git("commit", "-m", message)
        return self.git("rev-parse", "HEAD")

    def verify(self, responses):
        with patch.object(source, "git", self.git), patch.object(
            source, "api", side_effect=responses
        ) as api:
            source.verify_source(self.repo, self.later, self.author)
            return [call.args[1] for call in api.call_args_list]

    def test_later_main_commit_can_reach_runtime_recalculation(self):
        paths = self.verify([[[]], [[self.pr]], [self.proof], [self.proof]])
        self.assertEqual(paths[1], f"commits/{self.origin}/pulls")

    def test_untagged_version_needs_matching_merged_proposal(self):
        with self.assertRaisesRegex(ValueError, "did not originate"):
            self.verify([[[]], [[{**self.pr, "merge_commit_sha": self.later}]]])

    def test_reviewed_source_tree_must_match_merge(self):
        different = {**self.proof, "parents": [{"sha": self.later}]}
        with self.assertRaisesRegex(ValueError, "different base or tree"):
            self.verify([[[]], [[self.pr]], [self.proof], [different]])

    def test_tagged_version_does_not_require_proposal_history(self):
        paths = self.verify([[[{"ref": "refs/tags/v0.2.6"}]]])
        self.assertEqual(paths, ["git/matching-refs/tags/v0.2.6"])


if __name__ == "__main__":
    unittest.main()
