# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Fuzzes the checks of spec/metadata.md that read text a sender chose: I-Regexp patterns and formats.

A pattern is either parsed or refused with IRegexpError, never with another exception, and
`iregexp_problem` agrees with the parser on which patterns are refused. The format checks
answer for every text without raising.

    uv run python fuzz/fuzz_metadata.py -max_total_time=300
"""

import importlib.util
import sys
from pathlib import Path

import atheris

TOOLS = Path(__file__).resolve().parent.parent / "conformance" / "tools"

with atheris.instrument_imports():
    _spec = importlib.util.spec_from_file_location("metadata_rules", TOOLS / "metadata_rules.py")
    if _spec is None or _spec.loader is None:
        raise ImportError("cannot load conformance/tools/metadata_rules.py")
    rules = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(rules)


def test_one(data: bytes) -> None:
    text = atheris.FuzzedDataProvider(data).ConsumeUnicodeNoSurrogates(256)
    try:
        rules.iregexp(text)
        refused = False
    except rules.IRegexpError:
        refused = True
    if (rules.iregexp_problem(text) is not None) != refused:
        raise AssertionError("iregexp_problem and iregexp disagree on a pattern")
    for check in (rules.ipv6, rules.uri, rules.email, rules.url, rules.iban):
        check(text)


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one)
    atheris.Fuzz()
