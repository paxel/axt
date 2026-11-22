# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Check the example types of spec/types.md and print their fingerprints.

Each example type is published as its description, types/axt/example/v1/<Type>.<version>.json, from which
conformance/tools/example_schemas.py derives the schema <Type>.<version>.avsc. For every example type this
script:

- checks that its description is valid (spec/fields.md, section 6), derives the schema of its file, and
  carries the texts of spec/types.md, section 5.9: a label and an emoji, and the label and the help in
  German, on the type and on each typed field except the items and values of a list or a map that are not
  objects, and a label in both languages on each enum symbol and each group;
- checks the rules of spec/types.md, section 5, that a program can check on the derived schema:
  a doc on the type, every named type and every field; the namespace and
  axt.version matching the file's path; names in the required case; only
  ["null", T] unions with the default null, and the union of the targets
  of axt.Relation; an enum default; only the logical type uuid; the time
  types of spec/time.md and axt.Relation of spec/fields.md, section 11,
  defined in place at their first occurrence, as their published schemas
  with every named type defined before them by its full name, and referred
  to by full name after it; no recursion; the schema size and depth limits
  of spec/envelope.md; nested type names unique across the types, the
  published types aside; and the published schema types/axt/Relation.avsc
  under the same rules, with the attributes of spec/metadata.md;
- checks that every example datum keeps the rules of the time types
  (spec/time.md, sections 4 to 7) and of the relations, and every check of
  its description (spec/fields.md, section 7), and that each zoned time has
  the offset of its zone at its instant by this system's zone rules;
- checks further records that keep every rule (VALID), such as all-day
  and floating times and an offset that is not the zone's, and records
  with a value that breaks a rule (BREACHES), each with the field path and
  the rule or the check of the first such value in the order of the
  encoding; and the same for records with relations (RELATION_VALID and
  RELATION_BREACHES), with the rules of spec/fields.md, section 11.4;
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
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import avro.errors
import avro.io
import avro.schema
import fastavro
from fastavro.schema import fingerprint as fa_fingerprint
from fastavro.schema import to_parsing_canonical_form

REPO = Path(__file__).resolve().parents[2]
EXAMPLES = REPO / "types" / "axt" / "example"

# The rules of the attributes of spec/metadata.md; a module that imports none of the other scripts.
_spec = importlib.util.spec_from_file_location(
    "metadata_rules", Path(__file__).resolve().parent / "metadata_rules.py"
)
if _spec is None or _spec.loader is None:
    raise ImportError("metadata_rules.py cannot be loaded")
mr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mr)

# The bricks of spec/fields.md, which hold the published descriptions of the example types.
_spec = importlib.util.spec_from_file_location(
    "fields_examples", Path(__file__).resolve().parent / "fields_examples.py"
)
if _spec is None or _spec.loader is None:
    raise ImportError("fields_examples.py cannot be loaded")
fe: Any = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fe)

LOGICAL_TYPES = {("string", "uuid")}  # spec/types.md, section 5.5
# The published schemas of the time types, which a type defines in place (spec/time.md, section 3.1).
TIME_TYPES = {
    f"axt.{n}": json.loads((REPO / "types" / "axt" / f"{n}.avsc").read_text(encoding="utf-8"))
    for n in ("Date", "Time", "DateTime", "Duration")
}
# The published types that a type defines in place, the time types and axt.Relation (spec/fields.md, 11.6).
RELATION = json.loads((REPO / "types" / "axt" / "Relation.avsc").read_text(encoding="utf-8"))
EXTENSION_PUBLISHED = json.loads((REPO / "types" / "axt" / "Extension.avsc").read_text(encoding="utf-8"))
PUBLISHED: dict[str, Any] = dict(
    TIME_TYPES, **{"axt.Relation": RELATION, "axt.Extension": EXTENSION_PUBLISHED}
)
NUMBERS = {"int", "long", "float", "double"}
MAX_SCHEMA_BYTES = 262144  # spec/envelope.md, section 8
MAX_JSON_DEPTH = 64  # spec/envelope.md, section 8
MAX_DATA_DEPTH = 32  # spec/types.md, section 5.7
SNAKE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")
CAMEL = re.compile(r"^[A-Z][A-Za-z0-9]*$")
UPPER = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$")
FILE = re.compile(r"^([A-Z][A-Za-z0-9]*)\.([1-9][0-9]*)\.avsc$")


def zoned(y: int, mo: int, d: int, h: int, mi: int, zone: str, offset: int) -> dict[str, Any]:
    """An axt.DateTime in a zone, with its instant computed from the wall clock and the offset
    (spec/time.md, section 6.2)."""
    instant = calendar.timegm((y, mo, d, h, mi, 0)) * 1000 - offset * 1000
    return {
        "year": y,
        "month": mo,
        "day": d,
        "hour": h,
        "minute": mi,
        "second": 0,
        "millisecond": 0,
        "zone": zone,
        "offset_seconds": offset,
        "instant_ms": instant,
    }


def date(year: int | None = None, month: int | None = None, day: int | None = None) -> dict[str, Any]:
    return {"year": year, "month": month, "day": day}


BERLIN, CET = "Europe/Berlin", 3600
CEST = 7200
HOUR = 3600000

# One example datum per type, as fastavro takes and returns it. Every value keeps the checks of its field.
DATA: dict[str, dict[str, Any]] = {
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


# --- relations (spec/fields.md, section 11) ------------------------------------------------------

# The public key of the test key "cat-a-log, old phone, Ed25519" of spec/keys.md, section 7.1: the sender of
# records that another app's records relate to. generate_vectors.py compares it with keys_examples.py.
OTHER_SENDER = bytes.fromhex("1b84a600f3503e22bbcc99e63202a7194bf6bd69aff1471cce6410d53c26ec4a")
PET_ID = "0b6f4a3e-8c1d-4f27-9e5a-2d7c41b8e093"  # the ids of the records and relations below
VET_ID = "5d2e9c71-3a4b-4e8f-b6d0-7f1a2c9e4b58"
VISIT_ID = "9a4c1e07-6b2d-4d3f-8e91-c5f7a0b2d164"


def record_target(rid: str, type_: str = "", text: str = "", sender: bytes | None = None) -> dict[str, Any]:
    """The target of a relation that is a record (spec/fields.md, section 11.3)."""
    return {"id": rid, "sender": sender, "type": type_, "text": text}


def outside(uri: str, text: str = "") -> dict[str, Any]:
    """The target of a relation that is a thing outside AXT (spec/fields.md, section 11.3)."""
    return {"uri": uri, "text": text}


def relation(
    rid: str,
    target: dict[str, Any],
    kind: str = "axt.related",
    note: str = "",
    start: dict[str, Any] | None = None,
    end: dict[str, Any] | None = None,
    attributes: dict[str, str] | None = None,
) -> dict[str, Any]:
    """An axt.Relation as fastavro takes and returns it."""
    return {
        "id": rid,
        "kind": kind,
        "target": target,
        "note": note,
        "start": start,
        "end": end,
        "attributes": {} if attributes is None else attributes,
    }


MIMI = record_target(PET_ID, "axt.example.v1.Pet", "Mimi")
VET = record_target(VET_ID, "axt.example.v1.Person", "Dr. Anna Maria Schmidt", OTHER_SENDER)
RELATIONS: dict[str, list[dict[str, Any]]] = {
    "Note": [relation("3e8a5b14-7c29-4d6e-a0f3-1b9d2c7e5a46", MIMI)],
    "Task": [relation("c47d2e90-1f5a-4b38-9d6c-e2a8b0f31c75", MIMI)],
    "Appointment": [
        relation("f1b3d5a7-2c4e-4f60-8a1b-3c5d7e9f0a2b", MIMI, note="Her yearly vaccination."),
        relation(
            "6c8e0a2b-4d6f-4a81-9c3e-5f7a9b1d3e60",
            VET,
            kind="org.example.catalog.vet",
            attributes={"org.example.catalog.role": "vet", "org.example.catalog.paid_by": "owner"},
        ),
        relation(
            "a2c4e6f8-0b1d-4e3f-8a5c-7e9f1b3d5a70",
            outside("https://tierarzt.example/praxis", "Tierarztpraxis"),
        ),
    ],
    "Person": [
        relation(
            "d5f7a9b1-3c5e-4708-9b2d-4f6a8c0e2b81",
            record_target(PET_ID, "axt.example.v1.Pet", "Mimi", OTHER_SENDER),
            kind="org.example.catalog.patient",
            start=zoned(2021, 7, 1, 9, 0, BERLIN, CEST),
        )
    ],
    "Car": [
        relation(
            "8e0a2c4d-6f8b-4a1c-9e3f-5a7c9e1b3d92", outside("urn:example:parking:14", "Parking space 14")
        )
    ],
    "Pet": [
        relation(
            "1a3c5e7f-9b0d-4c2e-8f4a-6c8e0a2c4e13",
            VET,
            kind="org.example.catalog.vet",
            start=zoned(2021, 7, 1, 9, 0, BERLIN, CEST),
            end=None,
        )
    ],
    "Measurement": [relation("4b6d8f0a-2c4e-4061-9a3b-5d7f9b1c3e24", MIMI)],
    "Document": [
        relation(
            "7f9b1d3e-5a7c-4e92-8b0d-2f4a6c8e0b35",
            record_target(VISIT_ID, "axt.example.v1.Appointment", "Vet: vaccination"),
            kind="org.example.secondbrain.invoice_for",
        )
    ],
}
for _n, _rs in RELATIONS.items():
    DATA[_n]["relations"] = _rs  # the relations of the example datum, its last field

# --- extensions (spec/fields.md, section 12) ------------------------------------------------------

for _n in DATA:
    DATA[_n]["extensions"] = []  # the example data have no extension, the last field
# The extension of cat-a-log for a pet, a type of its own namespace: a schema that the app offers beside Pet.
CAT_EXTENSION_SCHEMA: dict[str, Any] = {
    "type": "record",
    "name": "CatExtension",
    "namespace": "org.example.catalog",
    "doc": "What cat-a-log adds to a pet that is a cat.",
    "fields": [
        {
            "name": "tasso_id",
            "type": "string",
            "default": "",
            "doc": "The TASSO registration; empty if none.",
        },
        {"name": "fur", "type": "string", "default": "", "doc": "The colour of the fur; empty if not known."},
    ],
}
CAT_EXTENSION_TEXT = json.dumps(CAT_EXTENSION_SCHEMA, separators=(",", ":"))
CAT_EXTENSION = "org.example.catalog.CatExtension"


def single_object_of(schema: dict[str, Any], datum: dict[str, Any]) -> bytes:
    """The single-object encoding of a datum: C3 01, the fingerprint of the schema in little-endian order,
    and the datum's Avro binary encoding (spec/envelope.md, section 3)."""
    out = io.BytesIO()
    fastavro.schemaless_writer(out, fastavro.parse_schema(schema), datum)
    fp = fa_fingerprint(to_parsing_canonical_form(schema), "CRC-64-AVRO")
    return b"\xc3\x01" + bytes.fromhex(fp) + out.getvalue()


def extension(name: str = CAT_EXTENSION, data: bytes | None = None, **values: str) -> dict[str, Any]:
    """An axt.Extension: by default cat-a-log's, with the values given."""
    if data is None:
        data = single_object_of(CAT_EXTENSION_SCHEMA, {"tasso_id": "", "fur": "", **values})
    return {"name": name, "data": data}


MIMI_CAT = extension(tasso_id="276098100123456", fur="tabby")
EXTENSION_VALID = [
    ("a pet with cat-a-log's extension", "Pet", dict(copy.deepcopy(DATA["Pet"]), extensions=[MIMI_CAT])),
    (
        "a pet with 32 extensions of types that no receiver knows, carried as bytes",
        "Pet",
        dict(
            copy.deepcopy(DATA["Pet"]),
            extensions=[
                extension(f"org.example.app{i}.Extra", b"\xc3\x01" + bytes(8) + b"\x00") for i in range(32)
            ],
        ),
    ),
]
EXT = "axt.Extension"
EXTENSION_BREACHES = [
    (
        "a pet with 33 extensions",
        "Pet",
        dict(
            copy.deepcopy(DATA["Pet"]),
            extensions=[extension(f"org.example.app{i}.Extra", b"\xc3\x01" + bytes(8)) for i in range(33)],
        ),
        "extensions",
        EXT,
    ),
    (
        "a pet with two extensions of one type",
        "Pet",
        dict(copy.deepcopy(DATA["Pet"]), extensions=[MIMI_CAT, extension(fur="black")]),
        "extensions[1].name",
        EXT,
    ),
    (
        "an extension whose name has no namespace",
        "Pet",
        dict(copy.deepcopy(DATA["Pet"]), extensions=[dict(MIMI_CAT, name="CatExtension")]),
        "extensions[0].name",
        EXT,
    ),
    (
        "an extension whose data is no single-object encoding",
        "Pet",
        dict(copy.deepcopy(DATA["Pet"]), extensions=[dict(MIMI_CAT, data=b"\x00" * 12)]),
        "extensions[0].data",
        EXT,
    ),
]


def floating(y: int, mo: int, d: int, h: int, mi: int) -> dict[str, Any]:
    """A floating axt.DateTime: a wall clock without zone, offset and instant (spec/time.md, section 6.5)."""
    return {
        "year": y,
        "month": mo,
        "day": d,
        "hour": h,
        "minute": mi,
        "second": 0,
        "millisecond": 0,
        "zone": None,
        "offset_seconds": None,
        "instant_ms": None,
    }


def duration(months: int = 0, days: int = 0, millis: int = 0) -> dict[str, int]:
    return {"months": months, "days": days, "millis": millis}


def variant(name: str, **fields: Any) -> dict[str, Any]:
    """The example datum of the type with some fields replaced."""
    return dict(copy.deepcopy(DATA[name]), **fields)


def nested(name: str, field: str, index: int, **fields: Any) -> dict[str, Any]:
    """The example datum with fields of one item of an array of nested records replaced."""
    datum = copy.deepcopy(DATA[name])
    datum[field][index] = dict(datum[field][index], **fields)
    return datum


# Further records of the example types that keep every rule: (label, type, datum).
VALID = [
    (
        "an all-day appointment: floating times at 00:00, the end at 00:00 of the day after",
        "Appointment",
        variant(
            "Appointment",
            start=floating(2026, 11, 24, 0, 0),
            end=floating(2026, 11, 25, 0, 0),
            all_day=True,
            reminders=[duration(days=-1)],
        ),
    ),
    (
        "an appointment over two days, its end in another zone",
        "Appointment",
        variant("Appointment", end=zoned(2026, 11, 25, 9, 0, "Europe/London", 0)),
    ),
    (
        "an appointment whose offset is not that of its zone at the instant, "
        "but whose instant is that of its offset",
        "Appointment",
        variant(
            "Appointment",
            start=zoned(2026, 11, 24, 10, 0, BERLIN, CEST),
            end=zoned(2026, 11, 24, 10, 30, BERLIN, CEST),
        ),
    ),
    (
        "a task due all day: a floating time at 00:00",
        "Task",
        variant("Task", due=floating(2026, 12, 1, 0, 0), due_all_day=True),
    ),
    (
        "a task due at 08:00 wherever its user is: a floating time",
        "Task",
        variant("Task", due=floating(2026, 12, 1, 8, 0)),
    ),
    (
        "a task done, with the instant it was done",
        "Task",
        variant("Task", done=True, done_at=zoned(2026, 11, 30, 19, 12, BERLIN, CET)),
    ),
    ("a pet born in March 2021, the day not known", "Pet", variant("Pet", birthday=date(2021, 3))),
    ("a document dated 2026 only", "Document", variant("Document", dated=date(2026))),
    (
        "a measurement taken in summer time",
        "Measurement",
        variant("Measurement", measured_at=zoned(2026, 7, 1, 8, 0, BERLIN, CEST)),
    ),
    ("a car of the year 1886 and an odometer of 0", "Car", variant("Car", year=1886, odometer=0)),
]

# Records of the example types with a value that breaks a rule: (label, type, datum, path, rule). The rule is
# a time type, for a time value that is not valid, which every receiver rejects (spec/time.md, section 8), or
# the attribute of a check, which a receiver that checks reports (spec/metadata.md, section 7.1). The path and
# the rule are those of the first value in the order of the encoding.
start = DATA["Appointment"]["start"]
BREACHES = [
    (
        "an appointment whose start has an instant an hour off",
        "Appointment",
        variant("Appointment", start=dict(start, instant_ms=start["instant_ms"] + HOUR)),
        "start",
        "axt.DateTime",
    ),
    (
        "an appointment whose start has the offset 7200, which Berlin does not have then, "
        "and the instant of 3600",
        "Appointment",
        variant("Appointment", start=dict(start, offset_seconds=CEST)),
        "start",
        "axt.DateTime",
    ),
    (
        "an appointment that ends on 31 November",
        "Appointment",
        variant("Appointment", end=dict(DATA["Appointment"]["end"], day=31)),
        "end",
        "axt.DateTime",
    ),
    (
        "an appointment whose start has a zone but no offset and no instant",
        "Appointment",
        variant("Appointment", start=dict(start, offset_seconds=None, instant_ms=None)),
        "start",
        "axt.DateTime",
    ),
    (
        "an appointment whose second reminder has parts of both signs",
        "Appointment",
        variant("Appointment", reminders=[duration(days=-1), duration(days=-1, millis=HOUR)]),
        "reminders[1]",
        "axt.Duration",
    ),
    (
        "a person born on 29 February 2027",
        "Person",
        variant("Person", birthday=date(2027, 2, 29)),
        "birthday",
        "axt.Date",
    ),
    (
        "a pet whose birthday has a day and a year but no month",
        "Pet",
        variant("Pet", birthday=date(2021, None, 3)),
        "birthday",
        "axt.Date",
    ),
    (
        "a task done at the second 60",
        "Task",
        variant("Task", done=True, done_at=dict(zoned(2026, 11, 30, 19, 12, BERLIN, CET), second=60)),
        "done_at",
        "axt.DateTime",
    ),
    (
        "a person whose phone number has spaces",
        "Person",
        nested("Person", "phones", 0, number="+49 30 1234567"),
        "phones[0].number",
        "format",
    ),
    (
        "a person whose country is a name, not a code",
        "Person",
        nested("Person", "addresses", 0, country="Germany"),
        "addresses[0].country",
        "format",
    ),
    (
        "a person whose e-mail address has no domain",
        "Person",
        nested("Person", "emails", 0, address="anna"),
        "emails[0].address",
        "format",
    ),
    (
        "a car whose VIN holds the letter O",
        "Car",
        variant("Car", vin="WVWZZZ1KZAW00000O"),
        "vin",
        "pattern",
    ),
    ("a car of the year 1800", "Car", variant("Car", year=1800), "year", "min"),
    ("a car with a negative odometer", "Car", variant("Car", odometer=-1), "odometer", "min"),
    (
        "a document whose media type has no subtype",
        "Document",
        variant("Document", media_type="pdf"),
        "media_type",
        "format",
    ),
    (
        "a measurement with a time that is not valid, after a unit with a space",
        "Measurement",
        variant("Measurement", unit="kg m", measured_at=dict(DATA["Measurement"]["measured_at"], month=13)),
        "unit",
        "format",
    ),
    (
        "a document with a date that is not valid, after a media type without a subtype",
        "Document",
        variant("Document", media_type="pdf", dated=date(2026, 2, 30)),
        "media_type",
        "format",
    ),
]
del start


def many(n: int, **fields: Any) -> list[dict[str, Any]]:
    """n relations to Mimi with ids of their own, and the fields given."""
    return [dict(relation(f"00000000-0000-4000-8000-{i + 1:012x}", MIMI), **fields) for i in range(n)]


def variant2(name: str, *relations: dict[str, Any], **fields: Any) -> dict[str, Any]:
    """The example datum of the type, with the relations given and some fields replaced."""
    return dict(copy.deepcopy(DATA[name]), relations=list(relations), **fields)


def attributes(n: int, key: int = 1, value: int = 0) -> dict[str, str]:
    """n attributes, each name of key bytes or more and each value of value bytes."""
    return {f"{i:02d}".ljust(key, "k"): "v" * value for i in range(n)}


R0 = RELATIONS["Pet"][0]
RELATION_VALID = [
    ("an appointment without relations", "Appointment", variant2("Appointment")),
    (
        "a note with a relation of a kind in the namespace axt that AXT does not define, which is taken",
        "Note",
        variant2("Note", dict(R0, kind="axt.later_kind")),
    ),
    ("a pet with 256 relations", "Pet", variant2("Pet", *many(256))),
    (
        "a pet with a relation at every limit of its lengths and 32 attributes",
        "Pet",
        variant2(
            "Pet",
            relation(
                "0f1e2d3c-4b5a-4968-8776-655443322110",
                record_target(PET_ID, "org.example." + "t" * 244, "ä" * 128, OTHER_SENDER),
                kind="org.example." + "k" * 244,
                note="n" * 4096,
                attributes=attributes(32, 256, 1024),
            ),
            relation("1f2e3d4c-5b6a-4978-8a96-a5b4c3d2e1f0", outside("urn:" + "u" * 2044, "t" * 256)),
        ),
    ),
    (
        "a relation whose target has no type and no display text, and an id in upper case",
        "Pet",
        variant2("Pet", dict(R0, id=R0["id"].upper(), target=record_target(VET_ID))),
    ),
    (
        "a relation from a floating start to a floating end",
        "Task",
        variant2("Task", dict(R0, start=floating(2026, 1, 1, 0, 0), end=floating(2026, 2, 1, 0, 0))),
    ),
]

# Records of version 2 whose relations break a rule of spec/fields.md, section 11.4, which every receiver
# rejects, or a check, which a receiver that checks reports: (label, type, datum, path, rule).
REL = "axt.Relation"
RELATION_BREACHES = [
    ("a pet with 257 relations", "Pet", variant2("Pet", *many(257)), "relations", REL),
    (
        "a pet with two relations of the same id, the second in upper case",
        "Pet",
        variant2("Pet", R0, dict(R0, id=R0["id"].upper(), kind="org.example.catalog.other")),
        "relations[1].id",
        REL,
    ),
    (
        "a relation whose id is the nil UUID",
        "Pet",
        variant2("Pet", dict(R0, id="00000000-0000-0000-0000-000000000000")),
        "relations[0].id",
        REL,
    ),
    (
        "a relation whose kind has no namespace",
        "Pet",
        variant2("Pet", dict(R0, kind="vet")),
        "relations[0].kind",
        REL,
    ),
    ("a relation whose kind is empty", "Pet", variant2("Pet", dict(R0, kind="")), "relations[0].kind", REL),
    (
        "a relation whose kind has 257 bytes",
        "Pet",
        variant2("Pet", dict(R0, kind="org.example." + "k" * 245)),
        "relations[0].kind",
        REL,
    ),
    (
        "a relation whose target's id is not a UUID",
        "Pet",
        variant2("Pet", dict(R0, target=dict(VET, id="Dr. Schmidt"))),
        "relations[0].target.id",
        REL,
    ),
    (
        "a relation whose target's type is not a full name",
        "Pet",
        variant2("Pet", dict(R0, target=dict(VET, type="Person (vet)"))),
        "relations[0].target.type",
        REL,
    ),
    (
        "a relation whose display text has 257 bytes",
        "Pet",
        variant2("Pet", dict(R0, target=dict(VET, text="ä" * 128 + "t"))),
        "relations[0].target.text",
        REL,
    ),
    (
        "a relation to an outside thing with an empty URI",
        "Pet",
        variant2("Pet", dict(R0, target=outside("", "Tierarztpraxis"))),
        "relations[0].target.uri",
        REL,
    ),
    (
        "a relation to an outside thing whose URI has 2,049 bytes",
        "Pet",
        variant2("Pet", dict(R0, target=outside("urn:" + "u" * 2045))),
        "relations[0].target.uri",
        REL,
    ),
    (
        "a relation whose note has 4,097 bytes",
        "Pet",
        variant2("Pet", dict(R0, note="n" * 4097)),
        "relations[0].note",
        REL,
    ),
    (
        "a relation with 33 attributes",
        "Pet",
        variant2("Pet", dict(R0, attributes=attributes(33))),
        "relations[0].attributes",
        REL,
    ),
    (
        "a relation with an attribute whose name is empty",
        "Pet",
        variant2("Pet", dict(R0, attributes={"": "vet"})),
        "relations[0].attributes",
        REL,
    ),
    (
        "a relation whose start is not a valid time",
        "Pet",
        variant2("Pet", dict(R0, start=dict(zoned(2021, 7, 1, 9, 0, BERLIN, CEST), month=13))),
        "relations[0].start",
        "axt.DateTime",
    ),
    (
        "a relation of a kind without a namespace, before a start that is not a valid time",
        "Pet",
        variant2("Pet", dict(R0, kind="vet", start=dict(zoned(2021, 7, 1, 9, 0, BERLIN, CEST), month=13))),
        "relations[0].kind",
        REL,
    ),
    (
        "an appointment whose start is not a valid time, before a relation without a valid id",
        "Appointment",
        variant2(
            "Appointment",
            dict(R0, id="not a UUID"),
            start=dict(DATA["Appointment"]["start"], day=31, month=11),
        ),
        "start",
        "axt.DateTime",
    ),
    (
        "a relation to an outside thing whose URI has a space, which breaks only a check",
        "Pet",
        variant2("Pet", dict(R0, target=outside("https://tierarzt.example/a b"))),
        "relations[0].target.uri",
        "format",
    ),
]
del R0


def description(name: str) -> dict[str, Any]:
    """The published description of the example type (spec/types.md, section 7)."""
    return cast(dict[str, Any], fe.EXAMPLE_DESCRIPTIONS[f"axt.example.v1.{name}"])


def check_cases(schemas: dict[str, Any]) -> None:
    """The records of VALID and RELATION_VALID keep every rule; each of BREACHES and RELATION_BREACHES breaks
    the rule named, first at the path named: a check of the type's description (spec/fields.md, section 7),
    or a rule that every receiver checks, of a time type or of a relation."""
    tm = time_rules()
    for label, name, datum in VALID + RELATION_VALID:
        if fe.breaches(description(name), datum, tm.time_check):
            fail(name, f"{label}: {fe.breaches(description(name), datum, tm.time_check)}")
    # Each zoned time has the offset of its zone at its instant, except in the third case, whose offsets are
    # not those of Berlin at the instant: a receiver does not reject such a value (spec/time.md, section 6.2).
    for i, (label, name, datum) in enumerate(VALID + RELATION_VALID):
        for v in zoned_values(datum):
            if (tm.offset_at(v["zone"], v["instant_ms"]) == v["offset_seconds"]) != (i != 2):
                fail(name, f"{label}: the offset {v['offset_seconds']} at {v['instant_ms']}")
    for label, name, datum, path, rule in BREACHES + RELATION_BREACHES:
        found = fe.breaches(description(name), datum, tm.time_check)
        if not found or found[0] != (path, rule):
            fail(name, f"{label}: {found}")
        elif (
            rule.startswith("axt.")
            and rule[4:] in ("Date", "Time", "DateTime", "Duration", "Relation", "Extension")
            and tm.value_breaches(schemas[name], datum)[0][:2] != (path, rule)
        ):
            fail(name, f"{label}: not the first time value that is not valid")
    for _label, name, datum in VALID + RELATION_VALID + [b[:3] for b in BREACHES + RELATION_BREACHES]:
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

failures: list[str] = []
findings: set[str] = set()  # library behaviour that differs from the Avro specification


def fail(where: str, message: str) -> None:
    failures.append(f"{where}: {message}")


def json_depth(value: Any, depth: int = 1) -> int:
    if isinstance(value, dict):
        return max([depth] + [json_depth(v, depth + 1) for v in value.values()])
    if isinstance(value, list):
        return max([depth] + [json_depth(v, depth + 1) for v in value])
    return depth


def time_type(t: Any) -> str | None:
    """The full name of the time type that the node defines in place, or None (spec/time.md, section 3.1)."""
    if isinstance(t, dict) and t.get("type") == "record":
        name = t["name"]
        full = name if "." in name else f"{t['namespace']}.{name}" if "namespace" in t else None
        return full if full in TIME_TYPES else None
    return None


def published_type(t: Any) -> str | None:
    """The full name of the published type, a time type or axt.Relation, that the node defines in place."""
    if isinstance(t, dict) and t.get("type") == "record":
        full = mr.full_name(t, "")[0]
        return full if full in PUBLISHED else None
    return None


def in_place(t: Any, defined: set[str], namespace: str = "") -> Any:
    """A published schema as a type defines it in place: every named type that an earlier occurrence in the
    type already defined replaced by its full name (spec/fields.md, section 11.6). defined grows with the
    names it defines."""
    if isinstance(t, list):
        return [in_place(b, defined, namespace) for b in t]
    if isinstance(t, dict):
        kind = t["type"]
        if kind in ("record", "enum", "fixed"):
            full, namespace = mr.full_name(t, namespace)
            if full in defined:
                return full
            defined.add(full)
            if kind == "record":
                return dict(
                    t, fields=[dict(f, type=in_place(f["type"], defined, namespace)) for f in t["fields"]]
                )
        elif kind == "array":
            return dict(t, items=in_place(t["items"], defined, namespace))
        elif kind == "map":
            return dict(t, values=in_place(t["values"], defined, namespace))
    return t


def inner(t: Any) -> tuple[list[str], int]:
    """The full names a published type defines in place, and the data depth it adds."""
    names: list[str] = []

    def walk(t: Any, namespace: str) -> int:
        if isinstance(t, list):
            return max(walk(b, namespace) for b in t)
        if isinstance(t, str):
            return 1 if t in PUBLISHED else 0  # a published type by its full name: a record
        kind = t["type"]
        if kind in ("record", "enum", "fixed"):
            full, namespace = mr.full_name(t, namespace)
            names.append(full)
        if kind == "record":
            return 1 + max([walk(f["type"], namespace) for f in t["fields"]], default=0)
        if kind == "array":
            return 1 + walk(t["items"], namespace)
        if kind == "map":
            return 1 + walk(t["values"], namespace)
        return 0

    return names, walk(t, "")


def check_type(t: Any, where: str, top: Any, path: set[str], defined: list[str]) -> int:
    """Check a schema node; return the data depth it adds (record, array, map count 1)."""
    if t is top:
        # The axt.* attributes of the whole schema (spec/metadata.md; spec/types.md, section 5.9).
        for here, message in mr.schema_problems(top):
            fail(f"{where}.{here}" if here else where, message)
    elif published_type(t):
        # A time type or axt.Relation, defined in place at its first occurrence as its published schema, with
        # every named type defined before it by its full name (spec/time.md, section 3.1; spec/types.md,
        # section 8.6).
        full = cast(str, published_type(t))
        if full in defined:
            fail(where, f"{full} defined a second time; a later occurrence refers to it by its full name")
        if t != in_place(PUBLISHED[full], set(defined)):
            fail(where, f"{full} is not defined as its published schema, types/axt/{full[4:]}.avsc")
        names, depth = inner(t)
        defined.extend(names)
        return depth
    if isinstance(t, str) and t in PUBLISHED:
        if t not in defined:
            fail(where, f"reference to {t} before it is defined in place (spec/time.md, section 3.1)")
        return inner(PUBLISHED[t])[1]
    if isinstance(t, str):
        if t in path or f"{top['namespace']}.{t}" in path:
            fail(where, f"recursive reference to {t}")
        elif t not in {"null", "boolean", "int", "long", "float", "double", "bytes", "string"}:
            fail(
                where,
                f"reference to the named type {t}; an example type defines each nested type once, in place",
            )
        return 0
    if isinstance(t, list):
        if t != RELATION["fields"][2]["type"] and (len(t) != 2 or t[0] != "null" or t[1] == "null"):
            fail(where, 'a union other than ["null", T] and the targets of axt.Relation')
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
            if isinstance(ft, list) and ft[0] == "null" and field.get("default", ...) is not None:
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


def check_schema(path: Path, schema: dict[str, Any], text: str) -> tuple[list[str], int] | None:
    where = str(path.relative_to(REPO))
    m = FILE.match(path.name)
    if not m:
        fail(where, "file name is not <Type>.<version>.avsc")
        return None
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
    defined: list[str] = []
    depth = check_type(schema, where, schema, set(), defined)
    if depth > MAX_DATA_DEPTH:
        fail(where, f"data depth {depth} above {MAX_DATA_DEPTH}")
    return defined, depth


def presence_problems(schema: Any) -> list[tuple[str, str]]:
    """What spec/types.md, section 5.9, requires of an example type beyond the rules of the attributes:
    axt.label and axt.emoji on its record, on each nested record and on each field, except the time types
    and their fields; axt.symbols on each enum, with a label for each symbol. Returns (where, why)."""
    out: list[tuple[str, str]] = []

    def walk(t: Any, where: str) -> None:
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


def without_defaults(t: Any, nested_only: bool = False) -> Any:
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


def project(t: Any, datum: Any, nested_only: bool = False) -> Any:
    """The part of a datum that a reduced writer schema keeps."""
    if isinstance(t, dict) and t["type"] == "record" and not time_type(t):
        keep = [f for f in t["fields"] if nested_only or "default" not in f]
        return {f["name"]: project(f["type"], datum[f["name"]]) for f in keep}
    if isinstance(t, dict) and t["type"] == "array":
        return [project(t["items"], d) for d in datum]
    return datum


def resolve(writer: Any, schema: Any, parsed: Any, datum: Any) -> tuple[Any, Any]:
    """Write datum with the writer schema; read it with the full schema, with both libraries."""
    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, fastavro.parse_schema(writer, _write_hint=False), datum)
    data = buf.getvalue()
    back = fastavro.schemaless_reader(
        io.BytesIO(data), fastavro.parse_schema(writer, _write_hint=False), parsed
    )
    apache = avro.io.DatumReader(avro.schema.parse(json.dumps(writer)), avro.schema.parse(json.dumps(schema)))
    return back, apache.read(avro.io.BinaryDecoder(io.BytesIO(data)))


def expect_defaults(name: str, where: str, record_schema: Any, values: Any, library: str) -> None:
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


def nested_arrays(schema: Any) -> list[Any]:
    """The fields of the type's record that hold an array of nested records other than a time type."""
    return [
        f
        for f in schema["fields"]
        if isinstance(f["type"], dict)
        and f["type"]["type"] == "array"
        and isinstance(f["type"]["items"], dict)
        and f["type"]["items"]["type"] == "record"
        and not time_type(f["type"]["items"])
        and f["type"]["items"]["name"] != "Extension"  # axt.Extension has no defaults to use
    ]


def check_defaults(name: str, schema: Any, parsed: Any) -> tuple[list[str], int]:
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
        assert all(datum[f["name"]] for f in nested), (
            f"{name}: the example datum needs an item in every array of records"
        )
        back, apache_back = resolve(
            without_defaults(schema, nested_only=True),
            schema,
            parsed,
            project(schema, datum, nested_only=True),
        )
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
            results: tuple[tuple[str, Any], ...]
            try:
                back, apache_back = resolve(writer, schema, parsed, datum)
                results = (("fastavro", back), ("avro", apache_back))
            except avro.errors.SchemaResolutionException:
                # avro 1.12.2 for Python does not apply the enum default of
                # the Avro specification and raises instead; fastavro does.
                findings.add(
                    "avro 1.12.2 raises SchemaResolutionException for an enum symbol the reader "
                    "does not know, instead of reading the enum's default symbol"
                )
                buf = io.BytesIO()
                fastavro.schemaless_writer(buf, fastavro.parse_schema(writer, _write_hint=False), datum)
                back = cast(
                    dict[str, Any],
                    fastavro.schemaless_reader(
                        io.BytesIO(buf.getvalue()), fastavro.parse_schema(writer, _write_hint=False), parsed
                    ),
                )
                results = (("fastavro", back),)
            for library, values in results:
                if values[f["name"]] != f["type"]["default"]:
                    fail(name, f"{library} read {values[f['name']]!r} for an unknown symbol of {f['name']}")
            checked += 1
    return [f["name"] for f in schema["fields"] if "default" not in f], checked


# --- the example data ---------------------------------------------------------

_time: list[ModuleType] = []


def time_rules() -> ModuleType:
    """time_examples.py, loaded on first use: it imports this file, so it cannot be imported at the top."""
    if not _time:
        spec = importlib.util.spec_from_file_location(
            "time_examples", Path(__file__).resolve().parent / "time_examples.py"
        )
        if spec is None or spec.loader is None:
            raise ImportError("time_examples.py cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        with contextlib.redirect_stdout(io.StringIO()):
            spec.loader.exec_module(module)
        _time.append(module)
    return _time[0]


def zoned_values(value: Any) -> Iterator[dict[str, Any]]:
    """Every zoned axt.DateTime inside a value, as fastavro gives it."""
    if isinstance(value, dict):
        if value.keys() >= {"zone", "offset_seconds", "instant_ms"} and value["zone"] is not None:
            yield value
        for v in value.values():
            yield from zoned_values(v)
    elif isinstance(value, list):
        for v in value:
            yield from zoned_values(v)


def check_datum(name: str, schema: Any) -> None:
    """The example datum keeps the rules of the time types and every check of its schema; each zoned time
    has the offset of its zone at its instant by this system's zone rules (spec/time.md, section 6.3)."""
    tm = time_rules()
    for path, rule, why in tm.receiver_breaches(schema, DATA[name]):
        fail(f"{name}.{path}" if path else name, f"the example datum breaks {rule}: {why}")
    for path, rule in fe.breaches(description(name), DATA[name], tm.time_check):
        fail(f"{name}.{path}" if path else name, f"the example datum breaks {rule}")
    for v in zoned_values(DATA[name]):
        if tm.offset_at(v["zone"], v["instant_ms"]) != v["offset_seconds"]:
            fail(name, f"the offset {v['offset_seconds']} is not that of {v['zone']} at {v['instant_ms']}")


# --- run ----------------------------------------------------------------------


def uuids_as_text(value: Any) -> Any:
    """A value as fastavro decodes it, with each uuid.UUID as its text, as the example data hold ids."""
    if isinstance(value, dict):
        return {k: uuids_as_text(v) for k, v in value.items()}
    if isinstance(value, list):
        return [uuids_as_text(v) for v in value]
    return str(value) if isinstance(value, uuid.UUID) else value


def check_relation() -> tuple[str, int]:
    """The published schema of axt.Relation keeps the rules of spec/types.md, section 5, for a schema of the
    specification, and the labels and emoji of section 5.9; returns its canonical form and fingerprint."""
    where = "types/axt/Relation.avsc"
    text = (REPO / where).read_text(encoding="utf-8")
    assert RELATION["namespace"] == "axt" and "axt.version" not in RELATION
    assert len(text.encode("utf-8")) <= MAX_SCHEMA_BYTES and json_depth(RELATION) <= MAX_JSON_DEPTH
    defined: list[str] = []
    check_type(RELATION, where, RELATION, set(), defined)
    assert defined == [
        "axt.Relation",
        "axt.RelationRecordTarget",
        "axt.RelationRecordTargetSender",
        "axt.RelationOutsideTarget",
        "axt.DateTime",
    ], defined
    for here, message in presence_problems(RELATION):
        fail(f"{where}.{here}" if here else where, message)
    pcf = to_parsing_canonical_form(fastavro.parse_schema(RELATION))
    fp = crc64_avro(pcf.encode())
    assert apache_fingerprint(text) == fp.to_bytes(8, "little"), "axt.Relation: avro fingerprint differs"
    # The branch of a target is the record whose fields the value has, in both libraries.
    for target in (RELATIONS["Appointment"][1]["target"], RELATIONS["Appointment"][2]["target"]):
        datum = dict(RELATIONS["Appointment"][0], target=target)
        buf = io.BytesIO()
        fastavro.schemaless_writer(buf, fastavro.parse_schema(RELATION), datum)
        out = io.BytesIO()
        apache = avro.schema.parse(text)
        avro.io.DatumWriter(apache).write(datum, avro.io.BinaryEncoder(out))
        assert out.getvalue() == buf.getvalue(), "the two libraries write a target in other branches"
        back = avro.io.DatumReader(apache).read(avro.io.BinaryDecoder(io.BytesIO(buf.getvalue())))
        fa_back = fastavro.schemaless_reader(io.BytesIO(buf.getvalue()), fastavro.parse_schema(RELATION))
        assert back == datum == uuids_as_text(fa_back), "a target does not read back in its branch"
    return pcf, fp


def text_problems(d: dict[str, Any]) -> list[tuple[str, str]]:
    """What spec/types.md, section 5.9, requires of the description of an example type beyond the rules of
    spec/fields.md: a label and an emoji, and the label and the help in German, on the type and on each
    typed field except the items and values of a list or a map that are not objects, and a label and its
    German translation on each enum symbol and each group. Returns (path in the description, why)."""
    out: list[tuple[str, str]] = []

    def need(t: dict[str, Any], where: str, what: tuple[str, ...]) -> None:
        for member in what:
            if member.endswith("_translations"):
                if not t[member].get("de"):
                    out.append((where, f"no German {member.split('_')[0]}"))
            elif t[member] == "":
                out.append((where, f"no {member}"))

    def walk(f: dict[str, Any], where: str, item: bool) -> None:
        name, b = fe.kind_of(f)
        if not item or name == "axt.ObjectField":
            need(
                f["texts"],
                mr.path_join(where, "texts"),
                ("label", "emoji", "label_translations", "help_translations"),
            )
        at = mr.path_join(where, "kind")
        if name == "axt.ObjectField":
            for i, g in enumerate(b["groups"]):
                need(g["texts"], f"{at}.groups[{i}].texts", ("label", "label_translations"))
            for i, sub in enumerate(b["fields"]):
                walk(sub, f"{at}.fields[{i}]", False)
        elif name == "axt.EnumField":
            for i, x in enumerate(b["symbols"]):
                need(x["texts"], f"{at}.symbols[{i}].texts", ("label", "label_translations"))
        elif name in ("axt.ListField", "axt.MapField"):
            member = "items" if name == "axt.ListField" else "values"
            walk(b[member], f"{at}.{member}", True)

    walk(d, "", False)
    return out


def main() -> None:
    rows = []
    all_defined: dict[str, str] = {}
    named_schemas: dict[int, dict[str, Any]] = {}
    schemas: dict[str, Any] = {}
    pcfs: dict[str, str] = {}
    relation_pcf, relation_fp = check_relation()
    published = {n for t in PUBLISHED.values() for n in inner(t)[0]}
    for path in sorted(EXAMPLES.rglob("*.avsc")):
        text = path.read_text(encoding="utf-8")
        schema = json.loads(text)
        name = schema["name"]  # one version of each type, which the example datum and the cases go by
        # The type is published as its description, from which example_schemas.py derives the schema file.
        d = description(name)
        if fe.description_problems(d) or fe.derive(d) != schema or fe.type_of(d)[1] != schema["axt.version"]:
            fail(str(path.relative_to(REPO)), "not the schema derived from its description")
        for here, message in text_problems(d):
            fail(f"{name}.json: {here}", message)
        defined, depth = cast(tuple[list[str], int], check_schema(path, schema, text))
        for full in defined:
            if full in published:
                continue  # defined in each type that holds it, always as its published schema
            if full in all_defined and all_defined[full].split(".")[0] != schema["name"]:
                fail(str(path.relative_to(REPO)), f"{full} is also defined in {all_defined[full]}")
            all_defined[full] = path.name

        # All files of one version into one set of named types, as an app that knows them all would.
        parsed = fastavro.parse_schema(
            schema, named_schemas=named_schemas.setdefault(schema["axt.version"], {})
        )

        pcf = to_parsing_canonical_form(parsed)
        assert avro.schema.parse(pcf).canonical_form == pcf, (
            f"{name}: the two libraries disagree on the canonical form"
        )
        pcfs[name] = pcf
        fp = crc64_avro(pcf.encode())
        assert fa_fingerprint(pcf, "CRC-64-AVRO") == fp.to_bytes(8, "little").hex(), (
            f"{name}: fastavro fingerprint differs"
        )
        assert apache_fingerprint(text) == fp.to_bytes(8, "little"), f"{name}: avro fingerprint differs"

        # The example datum: fastavro round trip, then the same bytes through avro.
        buf = io.BytesIO()
        fastavro.schemaless_writer(buf, parsed, DATA[name])
        data = buf.getvalue()
        back = uuids_as_text(fastavro.schemaless_reader(io.BytesIO(data), parsed, parsed))
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
        rows.append(
            (
                schema["namespace"],
                name,
                schema["axt.version"],
                path,
                pcf,
                fp,
                len(data),
                required,
                depth,
                defaults,
            )
        )

    check_cases(schemas)
    if failures:
        raise SystemExit("\n".join(["checks failed:"] + failures))

    for namespace, name, version, path, pcf, fp, size, required, depth, defaults in rows:
        print(f"{namespace}.{name.split('.')[0]} {version}: {path.relative_to(REPO)}")
        print(f"  canonical form: {pcf}")
        print(f"  CRC-64-AVRO 0x{fp:016x}, bytes {fp.to_bytes(8, 'little').hex(' ')}")
        print(
            f"  example datum: {size} bytes; data depth {depth}; defaults resolved: {defaults}; "
            f"fields without a default: {', '.join(required) or 'none'}"
        )
    print()
    print("| Type | Version | Schema | CRC-64-AVRO | As bytes |")
    print("| --- | --- | --- | --- | --- |")
    for namespace, name, version, path, _pcf, fp, _size, _required, _depth, _defaults in sorted(
        rows, key=lambda r: (r[1].split(".")[0], r[2])
    ):
        link = "../" + path.relative_to(REPO).as_posix()  # relative to spec/types.md
        print(
            f"| `{namespace}.{name.split('.')[0]}` | {version} | [{path.name}]({link}) | `0x{fp:016x}` | "
            f"`{fp.to_bytes(8, 'little').hex(' ')}` |"
        )
    print(
        f"| `axt.Relation` | | [Relation.avsc](../types/axt/Relation.avsc) | `0x{relation_fp:016x}` | "
        f"`{relation_fp.to_bytes(8, 'little').hex(' ')}` |"
    )
    print(f"  axt.Relation canonical form: {relation_pcf}")
    print()
    for title, valid, breaches in (
        ("", VALID, BREACHES),
        (" with relations", RELATION_VALID, RELATION_BREACHES),
    ):
        print(f"{len(valid)} further records{title} that keep every rule:")
        for label, name, _datum in valid:
            print(f"  {name}: {label}")
        print(f"{len(breaches)} records{title} with a value that breaks a rule, the first such value:")
        for label, name, _datum, breach_path, rule in breaches:
            print(f"  {name}: {label}: {breach_path}, {rule}")
    for finding in sorted(findings):
        print(f"library finding: {finding}")
    print("all checks passed")


if __name__ == "__main__":
    main()
