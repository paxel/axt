# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Check the example types of spec/types.md and print their fingerprints.

For every schema under types/axt/example/ this script:

- checks the rules of spec/types.md, section 5, that a program can check:
  a doc on the type, every named type and every field; the namespace and
  axt.version matching the file's path; names in the required case; only
  ["null", T] unions with the default null; an enum default; only the
  logical types of spec/envelope.md; axt.title naming a string field;
  axt.unit only on numbers; no recursion; the schema size and depth limits
  of spec/envelope.md; nested type names unique across all files;
- computes the Parsing Canonical Form and the CRC-64-AVRO fingerprint, and
  checks both against fastavro and the Apache avro package;
- encodes one example datum with fastavro, decodes it back and compares
  it, decodes the same bytes with the Apache avro package and encodes them
  again, and checks that the bytes are the same;
- uses every default once in schema resolution, with both libraries:
  it writes a datum with the schema without its defaulted fields, then
  one with the schema whose nested records lack their defaulted fields,
  and reads both with the full schema as reader schema; and for every
  enum it writes a symbol the full schema does not have and checks that
  the reader gets the enum's default symbol (fastavro only: the avro
  package 1.12.2 raises instead, which the script reports).

Run from anywhere, with fastavro and avro (1.12) installed:

    python3 conformance/tools/example_types.py

conformance/tools/manifest_examples.py imports the checks below to apply them
to the manifest's schema, types/axt/Manifest.avsc; importing this file
runs only the self-test of the CRC-64-AVRO implementation, none of the
checks of the example types.
"""

import copy
import datetime
import io
import json
import re
import warnings
from pathlib import Path

import avro.errors
import avro.io
import avro.schema
import fastavro
from fastavro.schema import fingerprint as fa_fingerprint
from fastavro.schema import to_parsing_canonical_form

REPO = Path(__file__).resolve().parents[2]
EXAMPLES = REPO / "types" / "axt" / "example"

# avro 1.12.2 for Python does not know local-timestamp-millis and warns that
# it reads it as a long; spec/envelope.md, section 7, allows that.
warnings.filterwarnings("ignore", message="Unknown local-timestamp-millis")

UTC = datetime.timezone.utc
LOGICAL_TYPES = {
    ("long", "timestamp-millis"),
    ("long", "local-timestamp-millis"),
    ("int", "date"),
    ("string", "uuid"),
}
NUMBERS = {"int", "long", "float", "double"}
MAX_SCHEMA_BYTES = 262144  # spec/envelope.md, section 8
MAX_JSON_DEPTH = 64  # spec/envelope.md, section 8
MAX_DATA_DEPTH = 32  # spec/types.md, section 5.7
SNAKE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")
CAMEL = re.compile(r"^[A-Z][A-Za-z0-9]*$")
UPPER = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$")
FILE = re.compile(r"^([A-Z][A-Za-z0-9]*)\.([1-9][0-9]*)\.avsc$")

# One example datum per type, as fastavro takes and returns it.
DATA = {
    "Note": {
        "title": "Cat food",
        "text": "Mimi eats the **salmon** one, not the chicken.",
        "format": "MARKDOWN",
        "created": datetime.datetime(2026, 11, 15, 9, 30, tzinfo=UTC),
        "updated": None,
        "tags": ["cat", "shopping"],
    },
    "Task": {
        "title": "Give Mimi her worm tablet",
        "notes": "",
        "due": datetime.datetime(2026, 12, 1, 8, 0),
        "due_all_day": False,
        "time_zone": "Europe/Berlin",
        "repeat": "FREQ=MONTHLY;INTERVAL=3",
        "done": False,
        "done_at": None,
        "priority": "HIGH",
    },
    "Appointment": {
        "title": "Vet: vaccination",
        "start": datetime.datetime(2026, 11, 24, 10, 0),
        "end": datetime.datetime(2026, 11, 24, 10, 30),
        "time_zone": "Europe/Berlin",
        "all_day": False,
        "location": "Tierarztpraxis, Hauptstraße 1",
        "notes": "Bring the vaccination certificate.",
        "reminders": [1440, 60],
    },
    "Person": {
        "display_name": "Dr. Anna Maria Schmidt",
        "prefix": "Dr.",
        "given_name": "Anna",
        "middle_name": "Maria",
        "family_name": "Schmidt",
        "suffix": "",
        "birthday": datetime.date(2000, 2, 29),
        "birthday_year_known": False,
        "phones": [{"label": "mobile", "number": "+49 30 1234567"}],
        "emails": [{"label": "work", "address": "anna@example.org"}],
        "addresses": [
            {
                "label": "work",
                "street": "Hauptstraße 1",
                "postal_code": "10115",
                "locality": "Berlin",
                "region": "",
                "country": "Germany",
            }
        ],
        "notes": "Mimi's vet.",
    },
    "Car": {
        "make": "Volkswagen",
        "model": "Golf",
        "year": 2019,
        "plate": "B-AB 1234",
        "vin": "WVWZZZ1KZAW000000",
        "odometer": 84210,
        "odometer_unit": "KILOMETRE",
        "notes": "",
    },
    "Pet": {
        "name": "Mimi",
        "species": "cat",
        "breed": "Maine Coon",
        "sex": "FEMALE",
        "neutered": True,
        "birthday": datetime.date(2021, 5, 3),
        "microchip": "276098100000000",
        "notes": "",
    },
    "Measurement": {
        "quantity": "Weight",
        "value": 5.4,
        "unit": "kg",
        "measured_at": datetime.datetime(2026, 11, 15, 18, 0, tzinfo=UTC),
        "subject": "Mimi",
        "notes": "",
    },
    "Document": {
        "title": "Vet invoice",
        "file_name": "invoice-2026-11.pdf",
        "media_type": "application/pdf",
        "content": b"%PDF-1.7\n%placeholder\n",
        "dated": datetime.date(2026, 11, 24),
        "notes": "",
    },
}

# --- CRC-64-AVRO, as given in the Avro specification -------------------------

EMPTY = 0xC15D213AA4D7A795
TABLE = []
for i in range(256):
    fp = i
    for _ in range(8):
        fp = (fp >> 1) ^ (EMPTY & -(fp & 1))
    TABLE.append(fp)


def crc64_avro(data: bytes) -> int:
    fp = EMPTY
    for b in data:
        fp = (fp >> 8) ^ TABLE[(fp ^ b) & 0xFF]
    return fp


# Published in Apache Avro, share/test/data/schema-tests.txt (cases 000, 004).
assert crc64_avro(b'"null"') == 7195948357588979594
assert crc64_avro(b'"int"') == 8247732601305521295


def apache_fingerprint(schema_json: str) -> bytes:
    # avro 1.12.2 for Python writes a primitive that carries a logicalType as
    # {"type":"long"} in its canonical form, against the specification; parsing
    # its canonical form again drops the logical types (see envelope_examples.py).
    canonical = avro.schema.parse(schema_json).canonical_form
    return avro.schema.parse(canonical).fingerprint("CRC-64-AVRO")


# --- the rules ----------------------------------------------------------------

failures = []
findings = set()  # library behaviour that differs from the Avro specification


def fail(where, message):
    failures.append(f"{where}: {message}")


def json_depth(value, depth=1):
    if isinstance(value, dict):
        return max([depth] + [json_depth(v, depth + 1) for v in value.values()])
    if isinstance(value, list):
        return max([depth] + [json_depth(v, depth + 1) for v in value])
    return depth


def check_type(t, where, top, path, defined):
    """Check a schema node; return the data depth it adds (record, array, map count 1)."""
    if isinstance(t, str):
        if t in path or f"{top['namespace']}.{t}" in path:
            fail(where, f"recursive reference to {t}")
        elif t not in {"null", "boolean", "int", "long", "float", "double", "bytes", "string"}:
            fail(where, f"reference to the named type {t}; an example type defines each nested type once, in place")
        return 0
    if isinstance(t, list):
        if len(t) != 2 or t[0] != "null" or t[1] == "null":
            fail(where, 'a union other than ["null", T]')
        return max(check_type(b, where, top, path, defined) for b in t)
    kind = t["type"]
    if "logicalType" in t and (kind, t["logicalType"]) not in LOGICAL_TYPES:
        fail(where, f"logical type {t['logicalType']} on {kind} is not allowed")
    if kind in {"record", "enum", "fixed"}:
        name = t["name"]
        if not CAMEL.match(name):
            fail(where, f"type name {name} is not UpperCamelCase")
        if t is not top and not name.startswith(top["name"]):
            fail(where, f"nested type name {name} does not start with {top['name']}")
        if t is not top and t.get("namespace", top["namespace"]) != top["namespace"]:
            fail(where, f"nested type {name} has another namespace")
        if not t.get("doc"):
            fail(where, f"type {name} has no doc")
        defined.append(f"{top['namespace']}.{name}")
    if kind == "enum":
        for symbol in t["symbols"]:
            if not UPPER.match(symbol):
                fail(where, f"enum symbol {symbol} is not UPPER_SNAKE_CASE")
        if t.get("default") not in t["symbols"]:
            fail(where, f"enum {t['name']} has no default symbol")
        return 0
    if kind == "array":
        return 1 + check_type(t["items"], where + "[]", top, path, defined)
    if kind == "map":
        return 1 + check_type(t["values"], where + "{}", top, path, defined)
    if kind == "record":
        full = f"{top['namespace']}.{t['name']}"
        depth = 0
        for field in t["fields"]:
            here = f"{where}.{field['name']}"
            if not SNAKE.match(field["name"]):
                fail(here, "field name is not snake_case")
            if not field.get("doc"):
                fail(here, "field has no doc")
            ft = field["type"]
            if isinstance(ft, list) and field.get("default", ...) is not None:
                fail(here, "an optional field has a default other than null")
            if "axt.unit" in field:
                base = ft[1] if isinstance(ft, list) else ft
                base = base["items"] if isinstance(base, dict) and base["type"] == "array" else base
                base = base["type"] if isinstance(base, dict) else base
                if base not in NUMBERS:
                    fail(here, "axt.unit on a field that is not a number")
            depth = max(depth, check_type(ft, here, top, path | {full}, defined))
        return 1 + depth
    return 0


def check_schema(path: Path, schema: dict, text: str):
    where = str(path.relative_to(REPO))
    m = FILE.match(path.name)
    if not m:
        fail(where, "file name is not <Type>.<version>.avsc")
        return
    namespace = "axt." + ".".join(path.parent.relative_to(REPO / "types" / "axt").parts)
    if schema.get("type") != "record":
        fail(where, "not a record")
    if schema.get("name") != m.group(1):
        fail(where, f"name {schema.get('name')} does not match the file name")
    if schema.get("namespace") != namespace or not re.match(r"^axt\.example\.v[1-9][0-9]*$", namespace):
        fail(where, f"namespace {schema.get('namespace')} does not match the directory {namespace}")
    if schema.get("axt.version") != int(m.group(2)):
        fail(where, "axt.version does not match the file name")
    title = schema.get("axt.title")
    if title is not None:
        target = [f for f in schema["fields"] if f["name"] == title]
        if not target or target[0]["type"] not in ("string", ["null", "string"]):
            fail(where, f"axt.title names {title}, which is not a string field")
    if len(text.encode("utf-8")) > MAX_SCHEMA_BYTES:
        fail(where, "schema above the size limit")
    if json_depth(schema) > MAX_JSON_DEPTH:
        fail(where, "schema JSON nested above the depth limit")
    defined = []
    depth = check_type(schema, where, schema, set(), defined)
    if depth > MAX_DATA_DEPTH:
        fail(where, f"data depth {depth} above {MAX_DATA_DEPTH}")
    return defined, depth


# --- defaults through schema resolution ---------------------------------------


def without_defaults(t, nested_only=False):
    """The schema with every field that has a default removed.

    With nested_only, the fields of the type's own record are all kept and
    only the fields of nested records are removed, so that the nested
    records are written and their defaults are used."""
    if isinstance(t, list):
        return [without_defaults(b) for b in t]
    if isinstance(t, dict):
        t = copy.copy(t)
        if t["type"] == "record":
            keep = [f for f in t["fields"] if nested_only or "default" not in f]
            t["fields"] = [dict(f, type=without_defaults(f["type"])) for f in keep]
        elif t["type"] == "array":
            t["items"] = without_defaults(t["items"])
        elif t["type"] == "map":
            t["values"] = without_defaults(t["values"])
    return t


def project(t, datum, nested_only=False):
    """The part of a datum that a reduced writer schema keeps."""
    if isinstance(t, dict) and t["type"] == "record":
        keep = [f for f in t["fields"] if nested_only or "default" not in f]
        return {f["name"]: project(f["type"], datum[f["name"]]) for f in keep}
    if isinstance(t, dict) and t["type"] == "array":
        return [project(t["items"], d) for d in datum]
    return datum


def resolve(writer, schema, parsed, datum):
    """Write datum with the writer schema; read it with the full schema, with both libraries."""
    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, fastavro.parse_schema(writer, _write_hint=False), datum)
    data = buf.getvalue()
    back = fastavro.schemaless_reader(io.BytesIO(data), fastavro.parse_schema(writer, _write_hint=False), parsed)
    apache = avro.io.DatumReader(avro.schema.parse(json.dumps(writer)), avro.schema.parse(json.dumps(schema)))
    return back, apache.read(avro.io.BinaryDecoder(io.BytesIO(data)))


def expect_defaults(name, where, record_schema, values, library):
    for field in record_schema["fields"]:
        if "default" not in field:
            continue
        expected = field["default"].encode("latin-1") if field["type"] == "bytes" else field["default"]
        got = values[field["name"]]
        # fastavro 1.13.1 returns the default of a bytes field as the JSON
        # string itself; Avro defines it as the bytes of its code points.
        if field["type"] == "bytes" and isinstance(got, str):
            got = got.encode("latin-1")
        if got != expected:
            fail(name, f"{library} read {got!r} for the default of {where}{field['name']}")


def check_defaults(name, schema, parsed):
    """Use every default once: of the fields, of nested records' fields, of every enum."""
    checked = 0
    # 1. The type's own fields.
    back, apache_back = resolve(without_defaults(schema), schema, parsed, project(schema, DATA[name]))
    for library, values in (("fastavro", back), ("avro", apache_back)):
        expect_defaults(name, "", schema, values, library)
    checked += sum("default" in f for f in schema["fields"])
    # 2. The fields of nested records, inside arrays, with one item each.
    nested = [f for f in schema["fields"] if isinstance(f["type"], dict) and f["type"]["type"] == "array"
              and isinstance(f["type"]["items"], dict) and f["type"]["items"]["type"] == "record"]
    if nested:
        datum = dict(DATA[name], **{f["name"]: DATA[name][f["name"]][:1] for f in nested})
        assert all(datum[f["name"]] for f in nested), f"{name}: the example datum needs an item in every array of records"
        back, apache_back = resolve(without_defaults(schema, nested_only=True), schema, parsed,
                                    project(schema, datum, nested_only=True))
        for library, values in (("fastavro", back), ("avro", apache_back)):
            for f in nested:
                expect_defaults(name, f"{f['name']}[0].", f["type"]["items"], values[f["name"]][0], library)
        checked += sum("default" in g for f in nested for g in f["type"]["items"]["fields"])
    # 3. Every enum: a writer with one symbol more, which the reader does not know.
    for i, f in enumerate(schema["fields"]):
        if isinstance(f["type"], dict) and f["type"]["type"] == "enum":
            writer = copy.deepcopy(schema)
            writer["fields"][i]["type"]["symbols"].append("SYMBOL_OF_A_LATER_VERSION")
            datum = dict(DATA[name], **{f["name"]: "SYMBOL_OF_A_LATER_VERSION"})
            try:
                back, apache_back = resolve(writer, schema, parsed, datum)
                results = (("fastavro", back), ("avro", apache_back))
            except avro.errors.SchemaResolutionException:
                # avro 1.12.2 for Python does not apply the enum default of
                # the Avro specification and raises instead; fastavro does.
                findings.add("avro 1.12.2 raises SchemaResolutionException for an enum symbol the reader "
                             "does not know, instead of reading the enum's default symbol")
                buf = io.BytesIO()
                fastavro.schemaless_writer(buf, fastavro.parse_schema(writer, _write_hint=False), datum)
                back = fastavro.schemaless_reader(io.BytesIO(buf.getvalue()), fastavro.parse_schema(writer, _write_hint=False), parsed)
                results = (("fastavro", back),)
            for library, values in results:
                if values[f["name"]] != f["type"]["default"]:
                    fail(name, f"{library} read {values[f['name']]!r} for an unknown symbol of {f['name']}")
            checked += 1
    return [f["name"] for f in schema["fields"] if "default" not in f], checked


# --- run ----------------------------------------------------------------------


def main():
    rows = []
    all_defined = {}
    named_schemas = {}
    for path in sorted(EXAMPLES.rglob("*.avsc")):
        text = path.read_text(encoding="utf-8")
        schema = json.loads(text)
        name = schema["name"]
        defined, depth = check_schema(path, schema, text)
        for full in defined:
            if full in all_defined:
                fail(str(path.relative_to(REPO)), f"{full} is also defined in {all_defined[full]}")
            all_defined[full] = path.name

        # All files into one set of named types, as an app that knows them all would.
        parsed = fastavro.parse_schema(schema, named_schemas=named_schemas)

        pcf = to_parsing_canonical_form(parsed)
        assert avro.schema.parse(pcf).canonical_form == pcf, f"{name}: the two libraries disagree on the canonical form"
        fp = crc64_avro(pcf.encode())
        assert fa_fingerprint(pcf, "CRC-64-AVRO") == fp.to_bytes(8, "little").hex(), f"{name}: fastavro fingerprint differs"
        assert apache_fingerprint(text) == fp.to_bytes(8, "little"), f"{name}: avro fingerprint differs"

        # The example datum: fastavro round trip, then the same bytes through avro.
        buf = io.BytesIO()
        fastavro.schemaless_writer(buf, parsed, DATA[name])
        data = buf.getvalue()
        back = fastavro.schemaless_reader(io.BytesIO(data), parsed, parsed)
        if back != DATA[name]:
            fail(name, f"fastavro decoded {back!r}")
        apache_schema = avro.schema.parse(text)
        apache_datum = avro.io.DatumReader(apache_schema).read(avro.io.BinaryDecoder(io.BytesIO(data)))
        out = io.BytesIO()
        avro.io.DatumWriter(apache_schema).write(apache_datum, avro.io.BinaryEncoder(out))
        if out.getvalue() != data:
            fail(name, "avro encodes the decoded datum to other bytes")

        required, defaults = check_defaults(name, schema, parsed)
        rows.append((schema["namespace"], name, schema["axt.version"], path, pcf, fp, len(data), required, depth, defaults))

    if failures:
        raise SystemExit("\n".join(["checks failed:"] + failures))

    for namespace, name, version, path, pcf, fp, size, required, depth, defaults in rows:
        print(f"{namespace}.{name} {version}: {path.relative_to(REPO)}")
        print(f"  canonical form: {pcf}")
        print(f"  CRC-64-AVRO 0x{fp:016x}, bytes {fp.to_bytes(8, 'little').hex(' ')}")
        print(f"  example datum: {size} bytes; data depth {depth}; defaults resolved: {defaults}; "
              f"fields without a default: {', '.join(required) or 'none'}")
    print()
    print("| Type | Version | Schema | CRC-64-AVRO | As bytes |")
    print("| --- | --- | --- | --- | --- |")
    for namespace, name, version, path, pcf, fp, size, required, depth, defaults in rows:
        link = "../" + path.relative_to(REPO).as_posix()  # relative to spec/types.md
        print(f"| `{namespace}.{name}` | {version} | [{path.name}]({link}) | `0x{fp:016x}` | `{fp.to_bytes(8, 'little').hex(' ')}` |")
    for finding in sorted(findings):
        print(f"library finding: {finding}")
    print("all checks passed")


if __name__ == "__main__":
    main()
