# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Check the example types of spec/types.md and print their fingerprints.

For every schema under types/axt/example/ this script:

- checks the rules of spec/types.md, section 5, that a program can check:
  a doc on the type, every named type and every field; the namespace and
  axt.version matching the file's path; names in the required case; only
  ["null", T] unions with the default null; an enum default; only the
  logical type uuid; the time types of spec/time.md defined in place at
  their first occurrence, as their published schemas, and referred to by
  full name after it; axt.title naming a string field; axt.unit only on
  numbers; every axt.* attribute known, in its place and keeping its
  rules, with the code of metadata_rules.py (spec/metadata.md), axt.anchor
  among them; axt.label and axt.emoji on every record and field and
  axt.symbols with a label for every enum symbol (section 5.9); no
  recursion; the schema size and depth limits of spec/envelope.md; nested
  type names unique across all files, the time types aside;
- checks that every example datum keeps the rules of the time types
  (spec/time.md, sections 4 to 7) and every check of its schema
  (spec/metadata.md, section 6), and that each zoned time has the offset
  of its zone at its instant by this system's zone rules;
- checks further records that keep every rule (VALID), such as all-day
  and floating times and an offset that is not the zone's, and records
  with a value that breaks a rule (BREACHES), each with the field path and
  the rule of the first such value in the order of the encoding;
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

Run from anywhere, with fastavro and avro (1.12) installed, and a time zone
database where Python's zoneinfo finds it:

    python3 conformance/tools/example_types.py

conformance/tools/manifest_examples.py imports the checks below to apply them
to the manifest's schema, types/axt/Manifest.avsc; importing this file
runs only the self-test of the CRC-64-AVRO implementation, none of the
checks of the example types.
"""

import calendar
import contextlib
import copy
import importlib.util
import io
import json
import re
from pathlib import Path

import avro.errors
import avro.io
import avro.schema
import fastavro
from fastavro.schema import fingerprint as fa_fingerprint
from fastavro.schema import to_parsing_canonical_form

REPO = Path(__file__).resolve().parents[2]
EXAMPLES = REPO / "types" / "axt" / "example"

# The rules of the attributes of spec/metadata.md; a module that imports none of the other scripts.
_spec = importlib.util.spec_from_file_location("metadata_rules", Path(__file__).resolve().parent / "metadata_rules.py")
mr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mr)

LOGICAL_TYPES = {("string", "uuid")}  # spec/types.md, section 5.5
# The published schemas of the time types, which a type defines in place (spec/time.md, section 3.1).
TIME_TYPES = {f"axt.{n}": json.loads((REPO / "types" / "axt" / f"{n}.avsc").read_text(encoding="utf-8"))
              for n in ("Date", "Time", "DateTime", "Duration")}
NUMBERS = {"int", "long", "float", "double"}
MAX_SCHEMA_BYTES = 262144  # spec/envelope.md, section 8
MAX_JSON_DEPTH = 64  # spec/envelope.md, section 8
MAX_DATA_DEPTH = 32  # spec/types.md, section 5.7
SNAKE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")
CAMEL = re.compile(r"^[A-Z][A-Za-z0-9]*$")
UPPER = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$")
FILE = re.compile(r"^([A-Z][A-Za-z0-9]*)\.([1-9][0-9]*)\.avsc$")



def zoned(y, mo, d, h, mi, zone, offset):
    """An axt.DateTime in a zone, with its instant computed from the wall clock and the offset (spec/time.md, section 6.2)."""
    instant = calendar.timegm((y, mo, d, h, mi, 0)) * 1000 - offset * 1000
    return {"year": y, "month": mo, "day": d, "hour": h, "minute": mi, "second": 0, "millisecond": 0,
            "zone": zone, "offset_seconds": offset, "instant_ms": instant}


def date(year=None, month=None, day=None):
    return {"year": year, "month": month, "day": day}


BERLIN, CET = "Europe/Berlin", 3600
HOUR = 3600000

# One example datum per type, as fastavro takes and returns it. Every value keeps the checks of its field.
DATA = {
    "Note": {
        "title": "Cat food",
        "text": "Mimi eats the **salmon** one, not the chicken.",
        "format": "MARKDOWN",
        "created": zoned(2026, 11, 15, 10, 30, BERLIN, CET),
        "updated": None,
        "tags": ["cat", "shopping"],
    },
    "Task": {
        "title": "Give Mimi her worm tablet",
        "notes": "",
        "due": zoned(2026, 12, 1, 8, 0, BERLIN, CET),
        "due_all_day": False,
        "repeat": "FREQ=MONTHLY;INTERVAL=3",
        "done": False,
        "done_at": None,
        "priority": "HIGH",
    },
    "Appointment": {
        "title": "Vet: vaccination",
        "start": zoned(2026, 11, 24, 10, 0, BERLIN, CET),
        "end": zoned(2026, 11, 24, 10, 30, BERLIN, CET),
        "all_day": False,
        "location": "Tierarztpraxis, Hauptstraße 1",
        "notes": "Bring the vaccination certificate.",
        "reminders": [{"months": 0, "days": -1, "millis": 0}, {"months": 0, "days": 0, "millis": -HOUR}],
    },
    "Person": {
        "display_name": "Dr. Anna Maria Schmidt",
        "prefix": "Dr.",
        "given_name": "Anna",
        "middle_name": "Maria",
        "family_name": "Schmidt",
        "suffix": "",
        "birthday": date(None, 2, 29),
        "phones": [{"label": "mobile", "number": "+49301234567"}],
        "emails": [{"label": "work", "address": "anna@example.org"}],
        "addresses": [
            {
                "label": "work",
                "street": "Hauptstraße 1",
                "postal_code": "10115",
                "locality": "Berlin",
                "region": "",
                "country": "DE",
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
        "birthday": date(2021, 5, 3),
        "microchip": "276098100000000",
        "notes": "",
    },
    "Measurement": {
        "quantity": "Weight",
        "value": 5.4,
        "unit": "kg",
        "measured_at": zoned(2026, 11, 15, 19, 0, BERLIN, CET),
        "subject": "Mimi",
        "notes": "",
    },
    "Document": {
        "title": "Vet invoice",
        "file_name": "invoice-2026-11.pdf",
        "media_type": "application/pdf",
        "content": b"%PDF-1.7\n%placeholder\n",
        "dated": date(2026, 11, 24),
        "notes": "",
    },
}

def floating(y, mo, d, h, mi):
    """A floating axt.DateTime: a wall clock without zone, offset and instant (spec/time.md, section 6.5)."""
    return {"year": y, "month": mo, "day": d, "hour": h, "minute": mi, "second": 0, "millisecond": 0,
            "zone": None, "offset_seconds": None, "instant_ms": None}


def duration(months=0, days=0, millis=0):
    return {"months": months, "days": days, "millis": millis}


CEST = 7200


def variant(name, **fields):
    """The example datum of the type with some fields replaced."""
    return dict(copy.deepcopy(DATA[name]), **fields)


def nested(name, field, index, **fields):
    """The example datum with fields of one item of an array of nested records replaced."""
    datum = copy.deepcopy(DATA[name])
    datum[field][index] = dict(datum[field][index], **fields)
    return datum


# Further records of the example types that keep every rule: (label, type, datum).
VALID = [
    ("an all-day appointment: floating times at 00:00, the end at 00:00 of the day after", "Appointment",
     variant("Appointment", start=floating(2026, 11, 24, 0, 0), end=floating(2026, 11, 25, 0, 0), all_day=True,
             reminders=[duration(days=-1)])),
    ("an appointment over two days, its end in another zone", "Appointment",
     variant("Appointment", end=zoned(2026, 11, 25, 9, 0, "Europe/London", 0))),
    ("an appointment whose offset is not that of its zone at the instant, but whose instant is that of its offset",
     "Appointment", variant("Appointment", start=zoned(2026, 11, 24, 10, 0, BERLIN, CEST),
                            end=zoned(2026, 11, 24, 10, 30, BERLIN, CEST))),
    ("a task due all day: a floating time at 00:00", "Task",
     variant("Task", due=floating(2026, 12, 1, 0, 0), due_all_day=True)),
    ("a task due at 08:00 wherever its user is: a floating time", "Task", variant("Task", due=floating(2026, 12, 1, 8, 0))),
    ("a task done, with the instant it was done", "Task",
     variant("Task", done=True, done_at=zoned(2026, 11, 30, 19, 12, BERLIN, CET))),
    ("a pet born in March 2021, the day not known", "Pet", variant("Pet", birthday=date(2021, 3))),
    ("a document dated 2026 only", "Document", variant("Document", dated=date(2026))),
    ("a measurement taken in summer time", "Measurement", variant("Measurement", measured_at=zoned(2026, 7, 1, 8, 0, BERLIN, CEST))),
    ("a car of the year 1886 and an odometer of 0", "Car", variant("Car", year=1886, odometer=0)),
]

# Records of the example types with a value that breaks a rule: (label, type, datum, path, rule). The rule is a
# time type, for a time value that is not valid, which every receiver rejects (spec/time.md, section 8), or the
# attribute of a check, which a receiver that checks reports (spec/metadata.md, section 7.1). The path and the
# rule are those of the first value in the order of the encoding.
start = DATA["Appointment"]["start"]
BREACHES = [
    ("an appointment whose start has an instant an hour off", "Appointment",
     variant("Appointment", start=dict(start, instant_ms=start["instant_ms"] + HOUR)), "start", "axt.DateTime"),
    ("an appointment whose start has the offset 7200, which Berlin does not have then, and the instant of 3600",
     "Appointment", variant("Appointment", start=dict(start, offset_seconds=CEST)), "start", "axt.DateTime"),
    ("an appointment that ends on 31 November", "Appointment",
     variant("Appointment", end=dict(DATA["Appointment"]["end"], day=31)), "end", "axt.DateTime"),
    ("an appointment whose start has a zone but no offset and no instant", "Appointment",
     variant("Appointment", start=dict(start, offset_seconds=None, instant_ms=None)), "start", "axt.DateTime"),
    ("an appointment whose second reminder has parts of both signs", "Appointment",
     variant("Appointment", reminders=[duration(days=-1), duration(days=-1, millis=HOUR)]), "reminders[1]", "axt.Duration"),
    ("a person born on 29 February 2027", "Person", variant("Person", birthday=date(2027, 2, 29)), "birthday", "axt.Date"),
    ("a pet whose birthday has a day and a year but no month", "Pet", variant("Pet", birthday=date(2021, None, 3)),
     "birthday", "axt.Date"),
    ("a task done at the second 60", "Task",
     variant("Task", done=True, done_at=dict(zoned(2026, 11, 30, 19, 12, BERLIN, CET), second=60)), "done_at", "axt.DateTime"),
    ("a person whose phone number has spaces", "Person", nested("Person", "phones", 0, number="+49 30 1234567"),
     "phones[0].number", "axt.format"),
    ("a person whose country is a name, not a code", "Person", nested("Person", "addresses", 0, country="Germany"),
     "addresses[0].country", "axt.format"),
    ("a person whose e-mail address has no domain", "Person", nested("Person", "emails", 0, address="anna"),
     "emails[0].address", "axt.format"),
    ("a car whose VIN holds the letter O", "Car", variant("Car", vin="WVWZZZ1KZAW00000O"), "vin", "axt.pattern"),
    ("a car of the year 1800", "Car", variant("Car", year=1800), "year", "axt.min"),
    ("a car with a negative odometer", "Car", variant("Car", odometer=-1), "odometer", "axt.min"),
    ("a document whose media type has no subtype", "Document", variant("Document", media_type="pdf"), "media_type", "axt.format"),
    ("a measurement with a time that is not valid, after a unit with a space", "Measurement",
     variant("Measurement", unit="kg m", measured_at=dict(DATA["Measurement"]["measured_at"], month=13)), "unit", "axt.format"),
    ("a document with a date that is not valid, after a media type without a subtype", "Document",
     variant("Document", media_type="pdf", dated=date(2026, 2, 30)), "media_type", "axt.format"),
]
del start


def check_cases(schemas):
    """The records of VALID keep every rule; each of BREACHES breaks the rule named, first at the path named."""
    tm = time_rules()
    for label, name, datum in VALID:
        if mr.breaches(schemas[name], datum, tm.time_check):
            fail(name, f"{label}: {mr.breaches(schemas[name], datum, tm.time_check)}")
    # Each zoned time has the offset of its zone at its instant, except in the third case, whose offsets are not
    # those of Berlin at the instant: a receiver does not reject such a value (spec/time.md, section 6.2).
    for i, (label, name, datum) in enumerate(VALID):
        for v in zoned_values(datum):
            if (tm.offset_at(v["zone"], v["instant_ms"]) == v["offset_seconds"]) != (i != 2):
                fail(name, f"{label}: the offset {v['offset_seconds']} at {v['instant_ms']}")
    for label, name, datum, path, rule in BREACHES:
        found = mr.breaches(schemas[name], datum, tm.time_check)
        if not found or found[0][:2] != (path, rule):
            fail(name, f"{label}: {found}")
        elif rule.startswith("axt.") and rule[4:] in ("Date", "Time", "DateTime", "Duration") and \
                tm.value_breaches(schemas[name], datum)[0][:2] != (path, rule):
            fail(name, f"{label}: not the first time value that is not valid")
    for label, name, datum in VALID + [b[:3] for b in BREACHES]:
        buf = io.BytesIO()  # every case is a value of the schema, whatever rule it breaks
        fastavro.schemaless_writer(buf, fastavro.parse_schema(schemas[name], _write_hint=False), datum)


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


def time_type(t):
    """The full name of the time type that the node defines in place, or None (spec/time.md, section 3.1)."""
    if isinstance(t, dict) and t.get("type") == "record":
        name = t["name"]
        full = name if "." in name else f"{t['namespace']}.{name}" if "namespace" in t else None
        return full if full in TIME_TYPES else None
    return None


def check_type(t, where, top, path, defined):
    """Check a schema node; return the data depth it adds (record, array, map count 1)."""
    if t is top:
        # The axt.* attributes of the whole schema (spec/metadata.md; spec/types.md, section 5.9).
        for here, message in mr.schema_problems(top):
            fail(f"{where}.{here}" if here else where, message)
    elif time_type(t):
        # A time type, defined in place at its first occurrence as its published schema (spec/time.md, section 3.1).
        full = time_type(t)
        if full in defined:
            fail(where, f"{full} defined a second time; a later occurrence refers to it by its full name")
        if t != TIME_TYPES[full]:
            fail(where, f"{full} is not defined as its published schema, types/axt/{full[4:]}.avsc")
        defined.append(full)
        return 1
    if isinstance(t, str) and t in TIME_TYPES:
        if t not in defined:
            fail(where, f"reference to {t} before it is defined in place (spec/time.md, section 3.1)")
        return 1
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
    for here, message in presence_problems(schema):
        fail(f"{where}.{here}" if here else where, message)
    return defined, depth


def presence_problems(schema):
    """What spec/types.md, section 5.9, requires of an example type beyond the rules of the attributes:
    axt.label and axt.emoji on its record, on each nested record and on each field, except the time types
    and their fields; axt.symbols on each enum, with a label for each symbol. Returns (where, why)."""
    out = []

    def walk(t, where):
        if isinstance(t, list):
            for b in t:
                walk(b, where)
            return
        if not isinstance(t, dict) or time_type(t):
            return  # a primitive, a reference by name, or a time type, which keeps its published schema
        kind = t["type"]
        if kind == "record":
            for a in ("axt.label", "axt.emoji"):
                if a not in t:
                    out.append((where, f"record {t['name']} has no {a}"))
            for f in t["fields"]:
                here = f"{where}.{f['name']}" if where else f["name"]
                for a in ("axt.label", "axt.emoji"):
                    if a not in f:
                        out.append((here, f"field has no {a}"))
                walk(f["type"], here)
        elif kind == "enum":
            entries = t.get("axt.symbols")
            if not isinstance(entries, dict):
                out.append((where, f"enum {t['name']} has no axt.symbols"))
            else:
                for symbol in t["symbols"]:
                    if not isinstance(entries.get(symbol), dict) or "label" not in entries[symbol]:
                        out.append((where, f"enum {t['name']}: symbol {symbol} has no label in axt.symbols"))
        elif kind == "array":
            walk(t["items"], where)
        elif kind == "map":
            walk(t["values"], where)

    walk(schema, "")
    return out


# --- defaults through schema resolution ---------------------------------------


def without_defaults(t, nested_only=False):
    """The schema with every field that has a default removed.

    With nested_only, the fields of the type's own record are all kept and
    only the fields of nested records are removed, so that the nested
    records are written and their defaults are used. A time type keeps
    every field: its schema is the published one (spec/time.md, section 3.1)."""
    if isinstance(t, list):
        return [without_defaults(b) for b in t]
    if isinstance(t, dict) and not time_type(t):
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
    if isinstance(t, dict) and t["type"] == "record" and not time_type(t):
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


def nested_arrays(schema):
    """The fields of the type's record that hold an array of nested records other than a time type."""
    return [f for f in schema["fields"] if isinstance(f["type"], dict) and f["type"]["type"] == "array"
            and isinstance(f["type"]["items"], dict) and f["type"]["items"]["type"] == "record"
            and not time_type(f["type"]["items"])]


def check_defaults(name, schema, parsed):
    """Use every default once: of the fields, of nested records' fields, of every enum."""
    checked = 0
    # 1. The type's own fields.
    back, apache_back = resolve(without_defaults(schema), schema, parsed, project(schema, DATA[name]))
    for library, values in (("fastavro", back), ("avro", apache_back)):
        expect_defaults(name, "", schema, values, library)
    checked += sum("default" in f for f in schema["fields"])
    # 2. The fields of nested records, inside arrays, with one item each; a time type is not one.
    nested = nested_arrays(schema)
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


# --- the example data ---------------------------------------------------------

_time = []


def time_rules():
    """time_examples.py, loaded on first use: it imports this file, so it cannot be imported at the top."""
    if not _time:
        spec = importlib.util.spec_from_file_location("time_examples", Path(__file__).resolve().parent / "time_examples.py")
        module = importlib.util.module_from_spec(spec)
        with contextlib.redirect_stdout(io.StringIO()):
            spec.loader.exec_module(module)
        _time.append(module)
    return _time[0]


def zoned_values(value):
    """Every zoned axt.DateTime inside a value, as fastavro gives it."""
    if isinstance(value, dict):
        if value.keys() >= {"zone", "offset_seconds", "instant_ms"} and value["zone"] is not None:
            yield value
        for v in value.values():
            yield from zoned_values(v)
    elif isinstance(value, list):
        for v in value:
            yield from zoned_values(v)


def check_datum(name, schema):
    """The example datum keeps the rules of the time types and every check of its schema; each zoned time
    has the offset of its zone at its instant by this system's zone rules (spec/time.md, section 6.3)."""
    tm = time_rules()
    for path, rule, why in mr.breaches(schema, DATA[name], tm.time_check):
        fail(f"{name}.{path}" if path else name, f"the example datum breaks {rule}: {why}")
    for v in zoned_values(DATA[name]):
        if tm.offset_at(v["zone"], v["instant_ms"]) != v["offset_seconds"]:
            fail(name, f"the offset {v['offset_seconds']} is not that of {v['zone']} at {v['instant_ms']}")


# --- run ----------------------------------------------------------------------


def main():
    rows = []
    all_defined = {}
    named_schemas = {}
    schemas = {}
    for path in sorted(EXAMPLES.rglob("*.avsc")):
        text = path.read_text(encoding="utf-8")
        schema = json.loads(text)
        name = schema["name"]
        defined, depth = check_schema(path, schema, text)
        for full in defined:
            if full in TIME_TYPES:
                continue  # defined in each type that holds it, always as its published schema
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

        check_datum(name, schema)
        schemas[name] = schema
        required, defaults = check_defaults(name, schema, parsed)
        rows.append((schema["namespace"], name, schema["axt.version"], path, pcf, fp, len(data), required, depth, defaults))

    check_cases(schemas)
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
    print()
    print(f"{len(VALID)} further records that keep every rule:")
    for label, name, datum in VALID:
        print(f"  {name}: {label}")
    print(f"{len(BREACHES)} records with a value that breaks a rule, the first such value:")
    for label, name, datum, path, rule in BREACHES:
        print(f"  {name}: {label}: {path}, {rule}")
    for finding in sorted(findings):
        print(f"library finding: {finding}")
    print("all checks passed")


if __name__ == "__main__":
    main()
