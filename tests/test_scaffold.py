"""Step 1: the scaffold imports cleanly and the CLI's --help works."""

import subprocess
import sys

import hound
import hound.agents
import hound.budget
import hound.cli
import hound.codebase
import hound.corpus
import hound.knowledge
import hound.llm
import hound.pipeline
import hound.schema
import hound.score
import hound.verify


def test_version():
    assert hound.__version__


def test_help_runs():
    result = subprocess.run(
        [sys.executable, "-m", "hound", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "scan" in result.stdout
