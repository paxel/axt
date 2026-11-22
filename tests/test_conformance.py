# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The checks of the repository as tests, so that CI runs them with every change.

Each test starts a script as a process of its own, the way a reader of the READMEs does:
the conformance suite against the reference adapter and against the reference relay, the
vector generator's comparison with the committed vectors, every example script of the
specification, and the changelog check.
"""

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "conformance" / "tools"
RUNNER = REPO / "conformance" / "run.py"
EXAMPLE_SCRIPTS = [
    "envelope_examples",
    "example_types",
    "time_examples",
    "metadata_examples",
    "fields_examples",
    "keys_examples",
    "manifest_examples",
    "protocol_examples",
    "transports_examples",
    "sync_examples",
    "shares_examples",
]


def run(*arguments: str | Path) -> subprocess.CompletedProcess[str]:
    """Run a script of this repository with the interpreter of the tests."""
    command = [sys.executable, *(str(a) for a in arguments)]
    return subprocess.run(command, cwd=REPO, capture_output=True, text=True, check=False)  # noqa: S603


def last_line(text: str) -> str:
    lines = text.strip().splitlines()
    return lines[-1] if lines else ""


def test_the_reference_adapter_passes_every_vector() -> None:
    done = run(RUNNER, "--", sys.executable, REPO / "conformance" / "reference" / "adapter.py")
    assert done.returncode == 0, done.stdout[-2000:] + done.stderr[-2000:]
    assert " vectors passed in 16 categories" in last_line(done.stdout)


def test_the_reference_relay_passes_the_relay_server_vectors() -> None:
    done = run(RUNNER, "--category", "relay-server", "--", sys.executable, REPO / "relay" / "adapter.py")
    assert done.returncode == 0, done.stdout[-2000:] + done.stderr[-2000:]
    assert " vectors passed in 1 categories" in last_line(done.stdout)


def test_the_committed_vectors_are_the_generators_output() -> None:
    done = run(TOOLS / "generate_vectors.py", "--check")
    assert done.returncode == 0, done.stdout[-2000:] + done.stderr[-2000:]


def test_the_brick_schemas_are_the_generators_output() -> None:
    done = run(TOOLS / "field_schema.py", "--check")
    assert done.returncode == 0, done.stdout + done.stderr


def test_the_example_schemas_are_derived_from_their_descriptions() -> None:
    done = run(TOOLS / "example_schemas.py", "--check")
    assert done.returncode == 0, done.stdout + done.stderr


@pytest.mark.parametrize("name", EXAMPLE_SCRIPTS)
def test_the_examples_of_the_specification_hold(name: str) -> None:
    done = run(TOOLS / f"{name}.py")
    assert done.returncode == 0, done.stdout[-2000:] + done.stderr[-2000:]


def test_the_changelog_keeps_its_rule() -> None:
    done = run(REPO / "tools" / "changelog_check.py", "CHANGELOG.md")
    assert done.returncode == 0, done.stdout + done.stderr
