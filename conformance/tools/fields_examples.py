# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The rules of spec/fields.md, the typed fields of types/axt/Field.avsc, and its examples.

A description is a datum of axt.Field: a typed field whose member kind holds one brick. It is
written as the record is, except that the union kind is an object with one member, named by the
full name of the brick, such as {"axt.EmailField": {...}}, as in Avro's JSON encoding. A value is
the plain value of a record: an object of its fields, a list, a map, a string, a number, bytes (or
hexadecimal in the JSON form of spec/conformance.md, section 3.3), an enum symbol or a time value.

The module provides, for other scripts to load:

- BRICKS: the full names of the bricks, in the order of the union kind;
- description_problems(field): every rule of spec/fields.md, sections 3 to 6, that a description
  breaks, as (path in the description datum, problem), with the field paths of spec/metadata.md,
  section 7.2;
- breaches(field, value): the values that break a check of the description (section 7), as
  (field path, check), at most one for each value, in the order of the encoding.

Run as a script, it checks the schema types/axt/Field.avsc by the rules of spec/types.md, section 5,
with fastavro and the Apache avro package, and the examples of spec/fields.md, section 8: a
description of com.example.Vet, descriptions that each break one rule, and values that keep or
break the checks; each description is encoded with fastavro and decoded again with both libraries.

    python3 conformance/tools/fields_examples.py

Loading this file runs none of the checks.
"""

import copy
import importlib.util
import io
import json
import math
import re
from pathlib import Path
from typing import Any

import avro.io
import avro.schema
import fastavro
from fastavro.schema import fingerprint, to_parsing_canonical_form

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
_spec = importlib.util.spec_from_file_location("metadata_rules", HERE / "metadata_rules.py")
if _spec is None or _spec.loader is None:
    raise ImportError(f"cannot load {HERE / 'metadata_rules.py'}")
mr: Any = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mr)

FIELD_TEXT = (REPO / "types" / "axt" / "Field.avsc").read_text(encoding="utf-8")
FIELD_SCHEMA: dict[str, Any] = json.loads(FIELD_TEXT)
FINGERPRINT = "0x4ed0f338fe0961c6"  # CRC-64-AVRO of axt.Field, shown in spec/fields.md, section 2

SNAKE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*")
CAMEL = re.compile(r"[A-Z][A-Za-z0-9]*")
UPPER = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*")
MAX_GROUP_KEY = 64


def named_records(schema: Any, out: dict[str, Any]) -> dict[str, Any]:
    """Every named type of the schema by full name; all of Field.avsc is in the namespace axt."""
    if isinstance(schema, list):
        for branch in schema:
            named_records(branch, out)
    elif isinstance(schema, dict):
        if schema["type"] in {"record", "enum"}:
            out[f"axt.{schema['name']}"] = schema
            for f in schema.get("fields", []):
                named_records(f["type"], out)
        elif schema["type"] in {"array", "map"}:
            named_records(schema.get("items", schema.get("values")), out)
    return out


NAMED = named_records(FIELD_SCHEMA, {})
BRICKS: tuple[str, ...] = tuple(
    f"axt.{b['name']}" for b in next(f for f in FIELD_SCHEMA["fields"] if f["name"] == "kind")["type"]
)
# The semantic bricks and the format of spec/metadata.md, section 6.3, each has built in (section 5).
SEMANTIC = {
    "axt.MarkdownField": "markdown",
    "axt.EmailField": "email",
    "axt.PhoneField": "phone",
    "axt.UrlField": "url",
    "axt.UriField": "uri",
    "axt.ColourField": "colour",
    "axt.IbanField": "iban",
    "axt.BicField": "bic",
    "axt.CountryField": "country",
    "axt.LanguageField": "language",
    "axt.CurrencyField": "currency",
    "axt.MediaTypeField": "media-type",
    "axt.UcumField": "ucum",
}
STRINGS = {"axt.StringField"} | set(SEMANTIC)
NUMBERS = {"axt.IntField", "axt.LongField", "axt.DoubleField"}


# --- building a datum ---------------------------------------------------------------------------


def complete(full: str, members: dict[str, Any]) -> dict[str, Any]:
    """A record of Field.avsc with the members given and the defaults of the others."""
    fields = NAMED[full]["fields"]
    unknown = set(members) - {f["name"] for f in fields}
    assert not unknown, f"{full} has no member {unknown}"
    return {
        f["name"]: members[f["name"]] if f["name"] in members else copy.deepcopy(f["default"]) for f in fields
    }


def texts(
    label: str = "", de: str = "", emoji: str = "", help_text: str = "", help_de: str = ""
) -> dict[str, Any]:
    return complete(
        "axt.FieldTexts",
        {
            "label": label,
            "label_translations": {"de": de} if de else {},
            "help": help_text,
            "help_translations": {"de": help_de} if help_de else {},
            "emoji": emoji,
        },
    )


def brick(which: str, /, **members: Any) -> dict[str, Any]:
    return {f"axt.{which}": complete(f"axt.{which}", members)}


def field(
    name: str, doc: str, kind: dict[str, Any], the_texts: dict[str, Any], **common: Any
) -> dict[str, Any]:
    return complete("axt.Field", {"name": name, "doc": doc, "texts": the_texts, "kind": kind, **common})


def kind_of(f: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    ((name, b),) = f["kind"].items()
    return name, b


# --- valid descriptions (spec/fields.md, sections 3 to 6) ---------------------------------------


def texts_problems(t: dict[str, Any], where: str, out: list[tuple[str, str]]) -> None:
    """Section 3.2, with the rules of spec/metadata.md, sections 4.1 to 4.3."""
    for name, limit in (("label", mr.MAX_LABEL), ("help", mr.MAX_HELP)):
        if t[name] != "" and not mr.one_line(t[name], limit):
            out.append((mr.path_join(where, name), f"not one line of at most {limit:,} bytes"))
        translations = t[f"{name}_translations"]
        if not mr.translations_ok(translations, limit):
            out.append((mr.path_join(where, f"{name}_translations"), "a key or a text breaks its rules"))
        elif translations and t[name] == "":
            out.append(
                (mr.path_join(where, f"{name}_translations"), f"translations without an English {name}")
            )
    if t["emoji"] != "" and not mr.emoji_ok(t["emoji"]):
        out.append((mr.path_join(where, "emoji"), "not an emoji of 1 to 10 code points"))


def length_problems(b: dict[str, Any], where: str, out: list[tuple[str, str]]) -> None:
    low, high = b["min_length"], b["max_length"]
    for name in ("min_length", "max_length"):
        if b[name] is not None and b[name] < 0:
            out.append((mr.path_join(where, name), "below 0"))
    if low is not None and high is not None and 0 <= high < low:
        out.append((mr.path_join(where, "min_length"), "larger than max_length"))


def input_problems(b: dict[str, Any], where: str, out: list[tuple[str, str]]) -> None:
    """placeholder and example (section 3.4)."""
    if b["placeholder"] != "" and not mr.one_line(b["placeholder"], mr.MAX_PLACEHOLDER):
        out.append((mr.path_join(where, "placeholder"), "not one line of at most 256 bytes"))
    example = b["example"]
    if len(example.encode("utf-8")) > mr.MAX_EXAMPLE or any(mr.control(c) and c != "\n" for c in example):
        out.append(
            (mr.path_join(where, "example"), "more than 1,024 bytes, or a control character other than LF")
        )


def brick_problems(f: dict[str, Any], where: str, out: list[tuple[str, str]]) -> None:
    name, b = kind_of(f)
    at = mr.path_join(where, "kind")
    before = len(out)
    if name in STRINGS | {"axt.BytesField"} and "min_length" in b:
        length_problems(b, at, out)
    if (
        name == "axt.StringField"
        and b["pattern"] is not None
        and mr.iregexp_problem(b["pattern"]) is not None
    ):
        out.append((mr.path_join(at, "pattern"), "not an I-Regexp within its limits"))
    if name in STRINGS:
        preferred = b["preferred_length"]
        if preferred is not None and (
            preferred < 1 or (b["max_length"] is not None and preferred > b["max_length"])
        ):
            out.append((mr.path_join(at, "preferred_length"), "below 1 or above max_length"))
    if name in NUMBERS:
        for limit in ("min", "max"):
            if b[limit] is not None and not math.isfinite(b[limit]):
                out.append((mr.path_join(at, limit), "not a finite number"))
        if b["min"] is not None and b["max"] is not None and b["min"] > b["max"]:
            out.append((mr.path_join(at, "min"), "larger than max"))
        if b["unit"] != "" and not mr.FORMATS["ucum"](b["unit"]):
            out.append((mr.path_join(at, "unit"), "not a UCUM code"))
    if "placeholder" in b:
        input_problems(b, at, out)
    # An example and a default are judged by the field's checks only when the checks keep their rules.
    if (
        len(out) == before
        and name in STRINGS
        and b["example"] != ""
        and breaches(as_optional(f), b["example"])
    ):
        out.append((mr.path_join(at, "example"), "breaks a check of the field"))
    if name == "axt.EnumField":
        enum_problems(b, at, out)
    elif name in {"axt.ListField", "axt.MapField"}:
        member = "items" if name == "axt.ListField" else "values"
        item_problems(b[member], f["name"], mr.path_join(at, member), out)
    elif name == "axt.ObjectField":
        object_problems(b, at, out)
    elif len(out) == before and "default" in b and b["default"] is not None and breaches(f, b["default"]):
        out.append((mr.path_join(at, "default"), "breaks a check of the field"))


def as_optional(f: dict[str, Any]) -> dict[str, Any]:
    return {**f, "required": False}


def enum_problems(b: dict[str, Any], at: str, out: list[tuple[str, str]]) -> None:
    if not CAMEL.fullmatch(b["name"]):
        out.append((mr.path_join(at, "name"), "not an Avro name in UpperCamelCase"))
    if not b["symbols"]:
        out.append((mr.path_join(at, "symbols"), "no symbol"))
    seen: set[str] = set()
    before = len(out)
    for i, s in enumerate(b["symbols"]):
        here = mr.path_join(mr.path_join(at, "symbols"), i)
        if not UPPER.fullmatch(s["symbol"]) or s["symbol"] in seen:
            out.append((mr.path_join(here, "symbol"), "not a symbol in UPPER_SNAKE_CASE, or a second time"))
        seen.add(s["symbol"])
        texts_problems(s["texts"], mr.path_join(here, "texts"), out)
    if len(out) > before or not seen:
        return  # the fallback and the default are judged only by symbols that keep their rules
    if b["fallback"] not in seen:
        out.append((mr.path_join(at, "fallback"), "not one of the symbols"))
    if b["default"] is not None and b["default"] not in seen:
        out.append((mr.path_join(at, "default"), "not one of the symbols"))


def item_problems(item: dict[str, Any], owner: str, where: str, out: list[tuple[str, str]]) -> None:
    """Section 4.5: an item is named as its list or map and has no hints of its own."""
    field_problems(item, where, out)
    if item["name"] != owner:
        out.append((mr.path_join(where, "name"), "not the name of its list or map"))
    if item["order"] is not None or item["group"] != "" or item["sensitive"] or item["advanced"]:
        out.append((where, "an order, group, sensitive or advanced of its own"))


def object_problems(b: dict[str, Any], at: str, out: list[tuple[str, str]]) -> None:
    *space, last = b["name"].split(".")
    if not CAMEL.fullmatch(last) or not all(re.fullmatch(mr.AVRO_NAME, part) for part in space):
        out.append(
            (mr.path_join(at, "name"), "not an Avro name in UpperCamelCase, with or without a namespace")
        )
    if not b["fields"]:
        out.append((mr.path_join(at, "fields"), "no field"))
    keys: set[str] = set()
    for i, g in enumerate(b["groups"]):
        here = mr.path_join(mr.path_join(at, "groups"), i)
        if not mr.KEY.match(g["key"]) or len(g["key"]) > MAX_GROUP_KEY or g["key"] in keys:
            out.append((mr.path_join(here, "key"), "not a group key of at most 64 bytes, or a second time"))
        keys.add(g["key"])
        texts_problems(g["texts"], mr.path_join(here, "texts"), out)
    names: set[str] = set()
    for i, sub in enumerate(b["fields"]):
        here = mr.path_join(mr.path_join(at, "fields"), i)
        field_problems(sub, here, out)
        if sub["name"] in names:
            out.append((mr.path_join(here, "name"), "a second field of this name"))
        names.add(sub["name"])
        if sub["group"] != "" and sub["group"] not in keys:
            out.append((mr.path_join(here, "group"), "not a key of the object's groups"))
    used = {sub["group"] for sub in b["fields"]}
    for i, g in enumerate(b["groups"]):
        if g["key"] in keys - used:
            out.append((mr.path_join(mr.path_join(at, "groups"), i), "a group that no field names"))


def field_problems(f: dict[str, Any], where: str, out: list[tuple[str, str]]) -> None:
    if not SNAKE.fullmatch(f["name"]):
        out.append((mr.path_join(where, "name"), "not a field name in snake_case"))
    if f["doc"].strip() == "":
        out.append((mr.path_join(where, "doc"), "empty"))
    texts_problems(f["texts"], mr.path_join(where, "texts"), out)
    brick_problems(f, where, out)


def description_problems(f: dict[str, Any]) -> list[tuple[str, str]]:
    """The rules of spec/fields.md, sections 3 to 6, that a description breaks; the root's path is empty."""
    out: list[tuple[str, str]] = []
    field_problems(f, "", out)
    return out


# --- checking a value (spec/fields.md, section 7) -----------------------------------------------


def length_breach(b: dict[str, Any], n: int) -> str | None:
    if b.get("min_length") is not None and n < b["min_length"]:
        return "min_length"
    if b.get("max_length") is not None and n > b["max_length"]:
        return "max_length"
    return None


def value_breach(f: dict[str, Any], value: Any) -> str | None:
    """The first check that one value of a field that is not a list, map or object breaks."""
    name, b = kind_of(f)
    if value is None:
        return "required" if f["required"] else None
    if name in STRINGS or name == "axt.BytesField":
        if f["required"] and len(value) == 0:
            return "required"
        if value != "" and name in SEMANTIC and not mr.FORMATS[SEMANTIC[name]](value):
            return "format"
        if value != "" and b.get("pattern") is not None and not mr.iregexp(b["pattern"]).fullmatch(value):
            return "pattern"
        return length_breach(b, mr.length_of(value, "bytes" if name == "axt.BytesField" else "string"))
    if name in NUMBERS:
        nan = isinstance(value, float) and math.isnan(value)
        if b["min"] is not None and (nan or value < b["min"]):
            return "min"
        if b["max"] is not None and (nan or value > b["max"]):
            return "max"
    return None  # booleans, enums and the time types have no check of their own


def walk(f: dict[str, Any], value: Any, path: str, out: list[tuple[str, str]]) -> None:
    name, b = kind_of(f)
    if name in {"axt.ListField", "axt.MapField", "axt.ObjectField"} and value is not None:
        if name == "axt.ObjectField":
            for sub in b["fields"]:
                walk(sub, value.get(sub["name"]), mr.path_join(path, sub["name"]), out)
            return
        if f["required"] and len(value) == 0:
            out.append((path, "required"))
        if name == "axt.ListField":
            for i, item in enumerate(value):
                walk(b["items"], item, mr.path_join(path, i), out)
        else:
            for key, item in value.items():
                walk(b["values"], item, mr.path_join(path, (key,)), out)
        return
    check = value_breach(f, value)
    if check is not None:
        out.append((path, check))


def breaches(f: dict[str, Any], value: Any) -> list[tuple[str, str]]:
    """The values that break a check, as (field path, check), in the order of the encoding (section 7)."""
    out: list[tuple[str, str]] = []
    walk(f, value, "", out)
    return out


# --- the schema and the encoding ----------------------------------------------------------------


def check_schema() -> str:
    """types/axt/Field.avsc by the rules of spec/types.md, sections 5.1 and 5.2; returns its fingerprint."""
    assert FIELD_SCHEMA["namespace"] == "axt"
    for full, t in NAMED.items():
        assert t.get("doc"), f"{full} has no doc"
        assert CAMEL.fullmatch(t["name"]), f"{full} is not in UpperCamelCase"
        assert "namespace" not in t or t is FIELD_SCHEMA, f"{full} has a namespace of its own"
        for f in t.get("fields", []):
            assert f.get("doc"), f"{full}.{f['name']} has no doc"
            assert SNAKE.fullmatch(f["name"]), f"{full}.{f['name']} is not in snake_case"
        if t["type"] == "enum":
            assert all(UPPER.fullmatch(s) for s in t["symbols"]) and t["default"] in t["symbols"], full
    assert all(b.endswith("Field") for b in BRICKS) and len(BRICKS) == len(set(BRICKS)) == 27
    assert set(SEMANTIC) <= set(BRICKS) and set(SEMANTIC.values()) == set(mr.FORMATS) - {"plain"}
    canonical = to_parsing_canonical_form(FIELD_SCHEMA)
    assert avro.schema.parse(FIELD_TEXT).canonical_form == canonical, "avro and fastavro differ"
    fp = "0x" + bytes.fromhex(fingerprint(canonical, "CRC-64-AVRO"))[::-1].hex()
    assert avro.schema.parse(canonical).fingerprint("CRC-64-AVRO")[::-1].hex() == fp[2:]
    return fp


PARSED = fastavro.parse_schema(FIELD_SCHEMA)


def to_fastavro(f: Any) -> Any:
    """The description with each kind as fastavro's tuple of branch name and record."""
    if isinstance(f, dict) and "kind" in f and "texts" in f:
        name, b = kind_of(f)
        b = {k: to_fastavro(v) for k, v in b.items()}
        return {**f, "kind": (name, b)}
    if isinstance(f, list):
        return [to_fastavro(x) for x in f]
    return f


def from_fastavro(f: Any, names: bool) -> Any:
    """A decoded description back in the form of this module; without names for the avro package's result."""
    if isinstance(f, dict) and "kind" in f and "texts" in f:
        kind = f["kind"]
        name, b = kind if names else (None, kind)
        b = {k: from_fastavro(v, names) for k, v in b.items()}
        return {**f, "kind": {name: b} if names else b}
    if isinstance(f, list):
        return [from_fastavro(x, names) for x in f]
    return f


def without_names(f: Any) -> Any:
    if isinstance(f, dict) and "kind" in f and "texts" in f:
        _, b = kind_of(f)
        return {**f, "kind": {k: without_names(v) for k, v in b.items()}}
    if isinstance(f, list):
        return [without_names(x) for x in f]
    return f


def round_trip(description: dict[str, Any]) -> int:
    """Encode with fastavro and decode with fastavro and the avro package; returns the size in bytes."""
    buffer = io.BytesIO()
    fastavro.schemaless_writer(buffer, PARSED, to_fastavro(description))
    data = buffer.getvalue()
    read = fastavro.schemaless_reader(
        io.BytesIO(data), PARSED, return_record_name=True, return_record_name_override=True
    )
    assert from_fastavro(read, names=True) == description, "fastavro does not read the description back"
    apache = avro.io.DatumReader(avro.schema.parse(FIELD_TEXT)).read(avro.io.BinaryDecoder(io.BytesIO(data)))
    assert from_fastavro(apache, names=False) == without_names(description), "avro does not read it back"
    return len(data)


# --- the examples of spec/fields.md, section 8 --------------------------------------------------


def vet() -> dict[str, Any]:
    """com.example.Vet, an illustration only, not an example type."""

    def s(name: str, doc: str, kind: dict[str, Any], label: str, de: str, emoji: str, **common: Any) -> Any:
        return field(name, doc, kind, texts(label, de, emoji), **common)

    address = brick(
        "ObjectField",
        name="VetAddress",
        fields=[
            s(
                "street",
                "The street and house number.",
                brick("StringField", max_length=100),
                "Street",
                "Straße",
                "🛣️",
            ),
            s(
                "postal_code",
                "The postal code of five digits; empty when not known.",
                brick("StringField", pattern="[0-9]{5}", preferred_length=5, placeholder="10115"),
                "Postal code",
                "Postleitzahl",
                "📮",
            ),
            s(
                "country",
                "The country.",
                brick("CountryField", default="DE"),
                "Country",
                "Land",
                "🏳️",
                order=0,
            ),
        ],
    )
    symbols = [
        complete(
            "axt.EnumSymbol", {"symbol": "GENERAL", "texts": texts("General practice", "Allgemeinpraxis")}
        ),
        complete(
            "axt.EnumSymbol", {"symbol": "EMERGENCY", "texts": texts("Emergency service", "Notdienst", "🚑")}
        ),
        complete("axt.EnumSymbol", {"symbol": "CLINIC", "texts": texts("Clinic", "Tierklinik")}),
    ]
    tag = field(
        "tags",
        "One tag.",
        brick("StringField", min_length=1, max_length=32),
        texts("Tag", "Schlagwort", "🔖"),
    )
    fee = field("extra_fees", "One fee.", brick("DoubleField", min=0.0), texts("Fee", "Gebühr"))
    fields = [
        s(
            "name",
            "The name of the practice.",
            brick("StringField", max_length=100, preferred_length=40),
            "Name",
            "Name",
            "🏷️",
            required=True,
        ),
        s(
            "kind",
            "The kind of practice.",
            brick("EnumField", name="VetKind", symbols=symbols, fallback="GENERAL", default="GENERAL"),
            "Kind",
            "Art",
            "🗂️",
            required=True,
        ),
        s(
            "phone",
            "The phone number; empty when none.",
            brick("PhoneField", placeholder="+49301234567", example="+49301234567"),
            "Phone",
            "Telefon",
            "📞",
            group="contact",
        ),
        s(
            "email",
            "The email address; empty when none.",
            brick("EmailField"),
            "Email",
            "E-Mail",
            "📧",
            group="contact",
        ),
        s(
            "website",
            "The website; empty when none.",
            brick("UrlField"),
            "Website",
            "Webseite",
            "🌐",
            group="contact",
        ),
        s("address", "The address of the practice.", address, "Address", "Anschrift", "📮"),
        s(
            "visit_minutes",
            "The length of a visit in minutes.",
            brick("IntField", default=15, min=5, max=240, unit="min"),
            "Length of a visit",
            "Dauer eines Besuchs",
            "⏱️",
        ),
        s(
            "fee",
            "The fee for a check-up; null when not known.",
            brick("DoubleField", min=0.0),
            "Fee",
            "Gebühr",
            "💶",
        ),
        s(
            "currency",
            "The currency of the fees.",
            brick("CurrencyField", default="EUR"),
            "Currency",
            "Währung",
            "💱",
        ),
        s(
            "iban",
            "The account for invoices; empty when none.",
            brick("IbanField", example="DE89370400440532013000"),
            "IBAN",
            "",
            "🏦",
            sensitive=True,
            advanced=True,
        ),
        s(
            "founded",
            "The day the practice opened; null when not known.",
            brick("DateField"),
            "Founded",
            "Gegründet",
            "📅",
        ),
        s(
            "notes",
            "Notes, in CommonMark.",
            brick("MarkdownField", max_length=4000),
            "Notes",
            "Notizen",
            "📝",
        ),
        s("tags", "Tags; empty when none.", brick("ListField", items=tag), "Tags", "Schlagwörter", "🔖"),
        s(
            "extra_fees",
            "Fees for other services, by service; empty when none.",
            brick("MapField", values=fee),
            "Extra fees",
            "Zusatzgebühren",
            "💶",
        ),
    ]
    groups = [complete("axt.FieldGroup", {"key": "contact", "texts": texts("Contact", "Kontakt", "📞")})]
    return field(
        "vet",
        "A veterinary practice; an illustration of spec/fields.md, not an example type.",
        brick("ObjectField", name="com.example.Vet", fields=fields, groups=groups),
        texts(
            "Vet practice",
            "Tierarztpraxis",
            "🏥",
            "A practice that treats animals.",
            "Eine Praxis, die Tiere behandelt.",
        ),
    )


VALUE: dict[str, Any] = {
    "name": "Tierarztpraxis am Park",
    "kind": "GENERAL",
    "phone": "+49301234567",
    "email": "praxis@example.org",
    "website": "https://example.org/praxis",
    "address": {"street": "Parkstraße 1", "postal_code": "10115", "country": "DE"},
    "visit_minutes": 15,
    "fee": 45.5,
    "currency": "EUR",
    "iban": "DE89370400440532013000",
    "founded": {"year": 1998, "month": None, "day": None},
    "notes": "Open on **Saturdays**.",
    "tags": ["cats", "dogs"],
    "extra_fees": {"x-ray": 80.0},
}

# (what, changes of VALUE, the breaches expected)
VALUE_CASES: list[tuple[str, dict[str, Any], list[tuple[str, str]]]] = [
    ("every value meets its checks", {}, []),
    (
        "the empty string in phone, email, website, iban and postal_code",
        {
            "phone": "",
            "email": "",
            "website": "",
            "iban": "",
            "address": {"street": "", "postal_code": "", "country": ""},
        },
        [],
    ),
    (
        "no fee, no founding day, no tags and no extra fees",
        {"fee": None, "founded": None, "tags": [], "extra_fees": {}},
        [],
    ),
    ("an empty name", {"name": ""}, [("name", "required")]),
    ("no kind", {"kind": None}, [("kind", "required")]),
    ("a name of 101 code points", {"name": "ä" * 101}, [("name", "max_length")]),
    ("a phone number with spaces", {"phone": "+49 30 1234567"}, [("phone", "format")]),
    ("an email address with two @", {"email": "a@b@example.org"}, [("email", "format")]),
    ("a website of the scheme ftp", {"website": "ftp://example.org"}, [("website", "format")]),
    ("an IBAN whose check digits do not match", {"iban": "DE88370400440532013000"}, [("iban", "format")]),
    (
        "a postal code of four digits",
        {"address": {"street": "", "postal_code": "1011", "country": "DE"}},
        [("address.postal_code", "pattern")],
    ),
    (
        "a postal code followed by LF",
        {"address": {"street": "", "postal_code": "10115\n", "country": "DE"}},
        [("address.postal_code", "pattern")],
    ),
    (
        "a country in lower case",
        {"address": {"street": "", "postal_code": "", "country": "de"}},
        [("address.country", "format")],
    ),
    ("a visit of 4 minutes", {"visit_minutes": 4}, [("visit_minutes", "min")]),
    ("a visit of 241 minutes", {"visit_minutes": 241}, [("visit_minutes", "max")]),
    ("a fee that is NaN", {"fee": math.nan}, [("fee", "min")]),
    ("a currency of two letters", {"currency": "EU"}, [("currency", "format")]),
    ("notes of 4,001 code points", {"notes": "x" * 4001}, [("notes", "max_length")]),
    ("a tag of 33 times 𝄞, 66 UTF-16 units", {"tags": ["cats", "𝄞" * 33]}, [("tags[1]", "max_length")]),
    ("a tag of 32 times 𝄞", {"tags": ["cats", "𝄞" * 32]}, []),
    ("an empty tag", {"tags": [""]}, [("tags[0]", "min_length")]),
    ("an extra fee below 0", {"extra_fees": {"x-ray": -1.0}}, [('extra_fees["x-ray"]', "min")]),
    (
        "a phone number with spaces and a visit of 241 minutes",
        {"phone": "+49 30 1234567", "visit_minutes": 241},
        [("phone", "format"), ("visit_minutes", "max")],
    ),
]


def mutate(path: list[Any], value: Any) -> dict[str, Any]:
    """The Vet description with the member at path set to value; a step "kind" goes into the brick."""
    d = vet()
    node: Any = d
    for step in path[:-1]:
        node = kind_of(node)[1] if step == "kind" else node[step]
    node[path[-1]] = value
    return d


F = ["kind", "fields"]  # the fields of the root object
NAME, KIND, PHONE, ADDRESS, VISIT, FEE, CURRENCY, IBAN, NOTES, TAGS, EXTRA = (
    0,
    1,
    2,
    5,
    6,
    7,
    8,
    9,
    11,
    12,
    13,
)
SYMBOLS = [*F, KIND, "kind", "symbols"]
POSTAL = [*F, ADDRESS, "kind", "fields", 1]

# (what, the path of the change, the new value, where the one problem is)
DESCRIPTION_CASES: list[tuple[str, list[Any], Any, str]] = [
    ("a field name in UpperCamelCase", [*F, NAME, "name"], "Name", "kind.fields[0].name"),
    ("an empty doc", [*F, NAME, "doc"], " ", "kind.fields[0].doc"),
    ("a label with LF", [*F, NAME, "texts", "label"], "Na\nme", "kind.fields[0].texts.label"),
    ("a help text of 1,025 bytes", ["texts", "help"], "x" * 1025, "texts.help"),
    ("a translation into en", ["texts", "label_translations"], {"en": "Vet"}, "texts.label_translations"),
    (
        "a translation without English help",
        [*F, NAME, "texts", "help_translations"],
        {"de": "Hilfe"},
        "kind.fields[0].texts.help_translations",
    ),
    ("an emoji of two letters", [*F, NAME, "texts", "emoji"], "ab", "kind.fields[0].texts.emoji"),
    ("a group the object does not have", [*F, PHONE, "group"], "billing", "kind.fields[2].group"),
    (
        "a group that no field names",
        ["kind", "groups"],
        [
            complete("axt.FieldGroup", {"key": "contact", "texts": texts("Contact")}),
            complete("axt.FieldGroup", {"key": "billing", "texts": texts("Billing")}),
        ],
        "kind.groups[1]",
    ),
    (
        "a group key twice",
        ["kind", "groups"],
        [complete("axt.FieldGroup", {"key": "contact", "texts": texts()})] * 2,
        "kind.groups[1].key",
    ),
    ("a min_length below 0", [*F, NAME, "kind", "min_length"], -1, "kind.fields[0].kind.min_length"),
    ("a max_length below 0", [*F, NOTES, "kind", "max_length"], -1, "kind.fields[11].kind.max_length"),
    (
        "a min_length above max_length",
        [*F, NAME, "kind", "min_length"],
        101,
        "kind.fields[0].kind.min_length",
    ),
    (
        "a pattern with \\d",
        [*POSTAL, "kind", "pattern"],
        "\\d{5}",
        "kind.fields[5].kind.fields[1].kind.pattern",
    ),
    (
        "a preferred_length of 0",
        [*POSTAL, "kind", "preferred_length"],
        0,
        "kind.fields[5].kind.fields[1].kind.preferred_length",
    ),
    (
        "a preferred_length above max_length",
        [*F, NAME, "kind", "preferred_length"],
        101,
        "kind.fields[0].kind.preferred_length",
    ),
    (
        "a placeholder with LF",
        [*F, PHONE, "kind", "placeholder"],
        "+49\n30",
        "kind.fields[2].kind.placeholder",
    ),
    ("an example with a tab", [*F, NOTES, "kind", "example"], "a\tb", "kind.fields[11].kind.example"),
    (
        "an example that breaks the pattern",
        [*POSTAL, "kind", "example"],
        "1011",
        "kind.fields[5].kind.fields[1].kind.example",
    ),
    (
        "an example that breaks the format",
        [*F, IBAN, "kind", "example"],
        "DE88370400440532013000",
        "kind.fields[9].kind.example",
    ),
    ("a default above max", [*F, VISIT, "kind", "default"], 300, "kind.fields[6].kind.default"),
    (
        "a default that breaks the format",
        [*F, CURRENCY, "kind", "default"],
        "eur",
        "kind.fields[8].kind.default",
    ),
    ("a min above max", [*F, VISIT, "kind", "min"], 241, "kind.fields[6].kind.min"),
    ("a min that is infinite", [*F, FEE, "kind", "min"], -math.inf, "kind.fields[7].kind.min"),
    ("a unit with a space", [*F, VISIT, "kind", "unit"], "m in", "kind.fields[6].kind.unit"),
    ("an enum name in lower case", [*F, KIND, "kind", "name"], "vetKind", "kind.fields[1].kind.name"),
    ("an enum without symbols", [*F, KIND, "kind", "symbols"], [], "kind.fields[1].kind.symbols"),
    (
        "a symbol in lower case",
        [*SYMBOLS],
        [
            complete("axt.EnumSymbol", {"symbol": "GENERAL", "texts": texts()}),
            complete("axt.EnumSymbol", {"symbol": "clinic", "texts": texts()}),
        ],
        "kind.fields[1].kind.symbols[1].symbol",
    ),
    (
        "a symbol without a label but with a translation",
        [*SYMBOLS],
        [complete("axt.EnumSymbol", {"symbol": "GENERAL", "texts": texts("", "Allgemein")})],
        "kind.fields[1].kind.symbols[0].texts.label_translations",
    ),
    (
        "a fallback that is not a symbol",
        [*F, KIND, "kind", "fallback"],
        "OTHER",
        "kind.fields[1].kind.fallback",
    ),
    ("a default that is not a symbol", [*F, KIND, "kind", "default"], "OTHER", "kind.fields[1].kind.default"),
    (
        "an item named otherwise",
        [*F, TAGS, "kind", "items", "name"],
        "tag",
        "kind.fields[12].kind.items.name",
    ),
    ("an item with an order", [*F, EXTRA, "kind", "values", "order"], 1, "kind.fields[13].kind.values"),
    ("an object name with a space", [*F, ADDRESS, "kind", "name"], "Vet Address", "kind.fields[5].kind.name"),
    ("an object without fields", [*F, ADDRESS, "kind", "fields"], [], "kind.fields[5].kind.fields"),
    ("a field name twice", [*POSTAL, "name"], "street", "kind.fields[5].kind.fields[1].name"),
]


def formats_description() -> dict[str, Any]:
    """One field of each semantic brick, with a value that has its format and one that does not."""
    fields = [
        field(b[4:-5].lower(), f"A value of {b}.", {b: complete(b, {})}, texts(b[4:-5]))
        for b in SEMANTIC
        if b != "axt.MarkdownField"
    ]
    return field(
        "formats",
        "One field of each semantic brick.",
        brick("ObjectField", name="Formats", fields=fields),
        texts(),
    )


FORMAT_VALUES = {
    "email": ("praxis@example.org", "praxis.example.org"),
    "phone": ("+49301234567", "030 1234567"),
    "url": ("https://example.org", "mailto:praxis@example.org"),
    "uri": ("urn:isbn:0451450523", "no scheme"),
    "colour": ("#1a2B3c", "#12345"),
    "iban": ("DE89370400440532013000", "DE89 3704 0044 0532 0130 00"),
    "bic": ("DEUTDEFF500", "DEUTDEF"),
    "country": ("DE", "DEU"),
    "language": ("de-AT", "de_AT"),
    "currency": ("EUR", "Euro"),
    "mediatype": ("text/plain", "text"),
    "ucum": ("km/h", "km h"),
}


def kinds_description() -> dict[str, Any]:
    """The bricks that the Vet does not use, each required, for the rule of section 3.3."""

    def r(name: str, kind: dict[str, Any]) -> dict[str, Any]:
        return field(name, f"A value of {next(iter(kind))}.", kind, texts(), required=True)

    item = field("photos", "One photo.", brick("BytesField", max_length=4), texts())
    value = field("counts", "One count.", brick("LongField", min=0), texts())
    return field(
        "kinds",
        "One field of the other bricks.",
        brick(
            "ObjectField",
            name="Kinds",
            fields=[
                r("photo", brick("BytesField", min_length=1, max_length=4)),
                r("photos", brick("ListField", items=item)),
                r("counts", brick("MapField", values=value)),
                r("done", brick("BooleanField", default=False)),
                r("big", brick("LongField", max=2**40)),
                r("at", brick("DateTimeField", anchor="INSTANT")),
                r("takes", brick("DurationField")),
                r("opens", brick("TimeField")),
            ],
        ),
        texts(),
    )


KINDS_VALUE: dict[str, Any] = {
    "photo": b"\x89PNG",
    "photos": [b"\x89PNG"],
    "counts": {"cats": 3},
    "done": True,
    "big": 2**40,
    "at": {"local": 0},
    "takes": {"months": 0},
    "opens": {"hour": 8},
}
KINDS_CASES: list[tuple[dict[str, Any], list[tuple[str, str]]]] = [
    ({}, []),
    (
        {"photo": b"", "photos": [], "counts": {}},
        [("photo", "required"), ("photos", "required"), ("counts", "required")],
    ),
    ({"photo": "89504e470d"}, [("photo", "max_length")]),  # five bytes as hexadecimal, the JSON form
    (
        {"photos": [b"12345"], "counts": {"dogs": -1}},
        [("photos[0]", "max_length"), ('counts["dogs"]', "min")],
    ),
    ({"done": None, "big": 2**40 + 1}, [("done", "required"), ("big", "max")]),
    (
        {"at": None, "takes": None, "opens": None},
        [("at", "required"), ("takes", "required"), ("opens", "required")],
    ),
]


def main() -> None:
    fp = check_schema()
    assert fp == FINGERPRINT, fp
    print(f"axt.Field: types/axt/Field.avsc, {len(BRICKS)} bricks, fingerprint {fp}")

    description = vet()
    assert description_problems(description) == [], description_problems(description)
    size = round_trip(description)
    print(f"com.example.Vet: a description of {size} bytes, {len(VALUE_CASES)} values checked")
    for what, changes, expected in VALUE_CASES:
        got = breaches(description, {**VALUE, **changes})
        assert got == expected, (what, got)
        print(f"  {what}: {got[0] if got else 'no breach'}")

    for what, path, new, where in DESCRIPTION_CASES:
        changed = mutate(path, new)
        problems = description_problems(changed)
        assert [w for w, _ in problems] == [where], (what, problems)
        round_trip(changed)
        print(f"  invalid, {what}: {problems[0][0]}: {problems[0][1]}")

    formats = formats_description()
    assert description_problems(formats) == []
    round_trip(formats)
    good = {name: v[0] for name, v in FORMAT_VALUES.items()}
    assert breaches(formats, good) == []
    bad = {name: v[1] for name, v in FORMAT_VALUES.items()}
    assert breaches(formats, bad) == [(name, "format") for name in FORMAT_VALUES]

    kinds = kinds_description()
    assert description_problems(kinds) == []
    round_trip(kinds)
    for changes, expected in KINDS_CASES:
        assert breaches(kinds, {**KINDS_VALUE, **changes}) == expected, (changes, expected)
    print(f"{len(FORMAT_VALUES)} semantic bricks and {len(KINDS_CASES)} values of the other bricks checked")

    root = kind_of(description)[1]["fields"][ADDRESS]
    print("The field address of com.example.Vet:")
    print(json.dumps(root, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
