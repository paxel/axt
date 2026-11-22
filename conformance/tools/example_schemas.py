# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Write the schema of each example type, derived from its description, next to it.

Each example type of spec/types.md, section 7, is published as its description: a datum of axt.Field in
the JSON form of spec/fields.md, section 10.3, in types/axt/example/v1/<Type>.<version>.json. The
description is the source; its schema, derived by the rule of spec/fields.md, section 9.2, is written to
<Type>.<version>.avsc, for the apps and libraries that read a schema file.

    python3 conformance/tools/example_schemas.py          # write the .avsc files
    python3 conformance/tools/example_schemas.py --check  # fail if one is not what it writes
"""

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
EXAMPLES = HERE.parents[1] / "types" / "axt" / "example" / "v1"

_spec = importlib.util.spec_from_file_location("fields_examples", HERE / "fields_examples.py")
if _spec is None or _spec.loader is None:
    raise ImportError(f"cannot load {HERE / 'fields_examples.py'}")
fe: Any = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fe)


def wanted() -> dict[Path, str]:
    """The text of each derived schema file, by its path."""
    out: dict[Path, str] = {}
    for path in sorted(EXAMPLES.glob("*.json")):
        d = fe.from_json_form(json.loads(path.read_text(encoding="utf-8")))
        problems = fe.description_problems(d)
        if problems:
            sys.exit(f"{path.name}: not a valid description: {problems[0]}")
        full, version = fe.type_of(d)
        name = full.rpartition(".")[2]
        if path.name != f"{name}.{version}.json" or not full.startswith("axt.example.v1."):
            sys.exit(f"{path.name}: describes {full} version {version}")
        out[path.with_suffix(".avsc")] = json.dumps(fe.derive(d), indent=2, ensure_ascii=False) + "\n"
    return out


def main() -> None:
    files = wanted()
    stray = sorted(p.name for p in EXAMPLES.glob("*.avsc") if p not in files)
    if sys.argv[1:] == ["--check"]:
        stale = [p.name for p, t in files.items() if not p.exists() or p.read_text(encoding="utf-8") != t]
        if stale or stray:
            sys.exit(f"not what conformance/tools/example_schemas.py writes: {', '.join(stale + stray)}")
        print(f"the {len(files)} schemas of the example types are derived from their descriptions")
        return
    if stray:
        sys.exit(f"a schema without a description: {', '.join(stray)}")
    for path, text in files.items():
        path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
