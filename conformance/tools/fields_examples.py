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
import types
import uuid
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
FINGERPRINT = "0xbaed02035d879fb5"  # CRC-64-AVRO of axt.Field, shown in spec/fields.md, section 2

SNAKE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*")
CAMEL = re.compile(r"[A-Z][A-Za-z0-9]*")
UPPER = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*")
MAX_GROUP_KEY = 64
MAX_EXACT = 2**53  # the largest magnitude of a default of a number that JSON writes exactly (section 9.1)
MAX_TYPED_DEPTH = 64  # spec/fields.md, section 9.1
MAX_JSON_DEPTH = 64  # of a schema, spec/envelope.md, section 8
MAX_DESCRIPTION = (
    262144  # bytes of the encoding of a description, as of a schema (spec/envelope.md, section 8)
)
TIME_NAMES = ("Date", "Time", "DateTime", "Duration")
TIME_SCHEMAS: dict[str, Any] = {
    f"axt.{n}": json.loads((REPO / "types" / "axt" / f"{n}.avsc").read_text(encoding="utf-8"))
    for n in TIME_NAMES
}
TIME_BRICKS = {f"axt.{n}Field": f"axt.{n}" for n in TIME_NAMES}


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
        default = b["default"]
        if default is not None and not (
            math.isfinite(default) and (name != "axt.LongField" or abs(default) <= MAX_EXACT)
        ):
            # JSON has no NaN and no infinity; RFC 8785 writes an integer above 2^53 rounded (9.3).
            out.append(
                (mr.path_join(at, "default"), "not a finite number, or a long above 2^53 in magnitude")
            )
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
    """The rules of spec/fields.md, sections 3 to 6 and 9.1, that a description breaks; the root is ""."""
    out: list[tuple[str, str]] = []
    if typed_depth(f) > MAX_TYPED_DEPTH:
        return [
            ("", f"typed fields nested deeper than {MAX_TYPED_DEPTH}")
        ]  # section 9.1, before any other rule
    field_problems(f, "", out)
    root_problems(f, out)
    if not out:
        schema = derive(f)
        if json_depth(schema) > MAX_JSON_DEPTH:
            out.append(("", f"a derived schema nested deeper than {MAX_JSON_DEPTH}"))
        if len(binary(f)) > MAX_DESCRIPTION or len(derived_text(f).encode()) > MAX_DESCRIPTION:
            out.append(("", "a description or its derived schema of more than 256 KiB"))
    return out


def typed_depth(f: dict[str, Any]) -> int:
    """The depth of the typed fields: the root at 1, a field of an object, an item or a value one deeper."""
    name, b = kind_of(f)
    inner = b["fields"] if name == "axt.ObjectField" else [b[m] for m in ("items", "values") if m in b]
    return 1 + max((typed_depth(x) for x in inner), default=0)


def root_problems(f: dict[str, Any], out: list[tuple[str, str]]) -> None:
    """Section 9.1: the root is an object with a full name, a version and a title; names are unique."""
    name, b = kind_of(f)
    clean = not out  # a title is judged only by fields that keep their rules
    if f["required"] or f["order"] is not None or f["group"] != "" or f["sensitive"] or f["advanced"]:
        out.append(("", "a root with required, an order, a group, sensitive or advanced"))
    if name != "axt.ObjectField":
        out.append(("kind", "the root is not an object"))
        return
    if "." not in b["name"]:
        out.append(("kind.name", "the root's name has no namespace"))
    if b["version"] is None or b["version"] < 1:
        out.append(("kind.version", "the root has no version of at least 1"))
    seen: set[str] = set()
    for where, full, version, title, subs in named_types(f, "", mr.path_join("", "kind")):
        if where != "kind" and "." in full.split("#")[1]:
            out.append((mr.path_join(where, "name"), "a nested name with a namespace"))
        key = full.replace("#", ".")
        if key in seen or key in TIME_SCHEMAS or key in RELATION_NAMES:
            out.append((mr.path_join(where, "name"), "a full name that another object or enum has"))
        seen.add(key)
        if where != "kind" and version is not None:
            out.append((mr.path_join(where, "version"), "a version in a nested object"))
        if clean and title and not any(x["name"] == title and kind_of(x)[0] in STRINGS for x in subs):
            out.append((mr.path_join(where, "title"), "not the name of a field of text of the object"))


def named_types(f: dict[str, Any], namespace: str, at: str) -> list[tuple[str, str, Any, str, list[Any]]]:
    """Each object and enum of the description, in the order of the encoding: (path, namespace#name,
    version, title, fields); the namespace is that of the root."""
    name, b = kind_of(f)
    found: list[tuple[str, str, Any, str, list[Any]]] = []
    if name == "axt.ObjectField":
        space = namespace or b["name"].rpartition(".")[0]
        short = b["name"].rpartition(".")[2] if not namespace else b["name"]
        found.append((at, f"{space}#{short}", b["version"], b["title"], b["fields"]))
        for i, sub in enumerate(b["fields"]):
            found += named_types(
                sub, space, mr.path_join(mr.path_join(mr.path_join(at, "fields"), i), "kind")
            )
    elif name == "axt.EnumField":
        found.append((at, f"{namespace}#{b['name']}", None, "", []))
    elif name in {"axt.ListField", "axt.MapField"}:
        member = "items" if name == "axt.ListField" else "values"
        found += named_types(b[member], namespace, mr.path_join(mr.path_join(at, member), "kind"))
    return found


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


def walk(
    f: dict[str, Any], value: Any, path: str, out: list[tuple[str, str]], time_check: Any = None
) -> None:
    name, b = kind_of(f)
    if name == "axt.RelationField":
        # The check required; the rules of section 11.4 are rules every receiver checks, not checks.
        if f["required"] and (value is None or len(value) == 0):
            out.append((path, "required"))
        elif time_check is not None and value is not None:
            out.extend(relation_breaches(value, path, time_check))
        return
    if name in {"axt.ListField", "axt.MapField", "axt.ObjectField"} and value is not None:
        if name == "axt.ObjectField":
            for sub in b["fields"]:
                walk(sub, value.get(sub["name"]), mr.path_join(path, sub["name"]), out, time_check)
            return
        if f["required"] and len(value) == 0:
            out.append((path, "required"))
        if name == "axt.ListField":
            for i, item in enumerate(value):
                walk(b["items"], item, mr.path_join(path, i), out, time_check)
        else:
            for key, item in value.items():
                walk(b["values"], item, mr.path_join(path, (key,)), out, time_check)
        return
    check = value_breach(f, value)
    if check is not None:
        out.append((path, check))
    elif (
        name in TIME_BRICKS
        and time_check is not None
        and value is not None
        and time_check(TIME_BRICKS[name], value)
    ):
        out.append((path, TIME_BRICKS[name]))


def relation_breaches(value: list[Any], path: str, time_check: Any) -> list[tuple[str, str]]:
    """The values of a list of relations that break a rule of section 11.4, as (field path, axt.Relation), or
    a time value in it that is not valid, or the URI of a target that does not have the format uri, which the
    published schema of axt.Relation gives it, as (field path, format)."""
    schema = {"type": "array", "items": RELATION_SCHEMA}
    found = mr.breaches(schema, value, time_check, True, RELATION_RULES)
    out = []
    for where, rule, _why in found:
        here = path + where if where.startswith("[") or not where else mr.path_join(path, where)
        out.append((here, "format" if rule == "axt.format" else rule))
    return out


def breaches(f: dict[str, Any], value: Any, time_check: Any = None) -> list[tuple[str, str]]:
    """The values that break a check, as (field path, check), in the order of the encoding (section 7). With
    time_check, as time_examples.py has it, also the values that break a rule that every receiver checks: a
    time value that is not valid, as (field path, its time type), and a relation that breaks a rule of section
    11.4, as (field path, axt.Relation)."""
    out: list[tuple[str, str]] = []
    walk(f, value, "", out, time_check)
    return out


# --- relations (spec/fields.md, section 11) -----------------------------------------------------

RELATION = "axt.Relation"
RELATION_SCHEMA: dict[str, Any] = json.loads(
    (REPO / "types" / "axt" / "Relation.avsc").read_text(encoding="utf-8")
)
TARGETS = ("axt.RelationRecordTarget", "axt.RelationOutsideTarget")
# The named types that axt.Relation defines besides axt.DateTime; no object or enum of a description has one.
RELATION_NAMES = (RELATION, *TARGETS, "axt.RelationRecordTargetSender")
# The limits of section 11.4, in bytes of UTF-8.
MAX_RELATIONS = 256  # items of a list of relations
MAX_RELATION_ATTRIBUTES = 32  # entries of attributes
MAX_RELATION_NAME = 256  # kind, and the type of a record target
MAX_RELATION_TEXT = 256  # the display text of a target
MAX_RELATION_URI = 2048
MAX_RELATION_NOTE = 4096
MAX_RELATION_KEY = 256  # a name in attributes
MAX_RELATION_VALUE = 1024  # a value in attributes
FULL_NAME = re.compile(rf"{mr.AVRO_NAME}(?:\.{mr.AVRO_NAME})*")  # a full name of Avro 1.12, Names
KIND_NAME = re.compile(rf"{mr.AVRO_NAME}(?:\.{mr.AVRO_NAME})+")  # a full name with a namespace
UUID_TEXT = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def uuid_problem(v: Any) -> bool:
    """Not a UUID in text form, or the nil or the max UUID (spec/records.md, section 2); a value that a
    library decoded with the logical type uuid is taken as its text."""
    v = str(v) if isinstance(v, uuid.UUID) else v
    return (
        not isinstance(v, str)
        or not UUID_TEXT.fullmatch(v)
        or v.replace("-", "").lower() in ("0" * 32, "f" * 32)
    )


def utf8(v: Any) -> int:
    return len(v.encode("utf-8")) if isinstance(v, str) else 0


def relation_problem(record: str, field: str, v: Any) -> str | None:
    """The rule of section 11.4 that the value v of the field of a record of axt.Relation or of one of its
    targets breaks, or None."""
    if record == RELATION:
        if field == "id" and uuid_problem(v):
            return "the id is no UUID in text form, or the nil or the max UUID"
        if field == "kind" and not (KIND_NAME.fullmatch(v) and utf8(v) <= MAX_RELATION_NAME):
            return "the kind is no full name with a namespace of at most 256 bytes"
        if field == "note" and utf8(v) > MAX_RELATION_NOTE:
            return "the note is above 4,096 bytes"
        if field == "attributes":
            if len(v) > MAX_RELATION_ATTRIBUTES:
                return "more than 32 attributes"
            if any(
                not 1 <= utf8(k) <= MAX_RELATION_KEY or utf8(x) > MAX_RELATION_VALUE for k, x in v.items()
            ):
                return "an attribute name not of 1 to 256 bytes, or a value above 1,024 bytes"
    elif record == "axt.RelationRecordTarget":
        if field == "id" and uuid_problem(v):
            return "the target's id is no UUID in text form, or the nil or the max UUID"
        if field == "type" and not (v == "" or (FULL_NAME.fullmatch(v) and utf8(v) <= MAX_RELATION_NAME)):
            return "the type is neither empty nor a full name of at most 256 bytes"
    elif record == "axt.RelationOutsideTarget" and field == "uri" and not 1 <= utf8(v) <= MAX_RELATION_URI:
        return "the URI is not of 1 to 2,048 bytes"
    if record in TARGETS and field == "text" and utf8(v) > MAX_RELATION_TEXT:
        return "the display text is above 256 bytes"
    return None


def list_problem(relations: list[Any]) -> str | None:
    """The rule of section 11.4 that a list of relations as a whole breaks, or None."""
    return "more than 256 relations" if len(relations) > MAX_RELATIONS else None


def repeated_ids(relations: list[Any]) -> set[int]:
    """The indexes of the relations whose id, a valid one, an earlier relation of the list has, compared as
    128-bit values (section 11.4)."""
    seen: set[str] = set()
    found: set[int] = set()
    for i, item in enumerate(relations):
        rid = item.get("id") if isinstance(item, dict) else None
        rid = str(rid) if isinstance(rid, uuid.UUID) else rid
        if isinstance(rid, str) and not uuid_problem(rid):
            if rid.lower() in seen:
                found.add(i)
            seen.add(rid.lower())
    return found


# --- the derived schema (spec/fields.md, section 9) ---------------------------------------------


def json_depth(value: Any, depth: int = 1) -> int:
    """The nesting of a JSON value as spec/envelope.md, section 8, counts it: in an object, a scalar is 2."""
    if isinstance(value, dict):
        return max([depth] + [json_depth(v, depth + 1) for v in value.values()])
    if isinstance(value, list):
        return max([depth] + [json_depth(v, depth + 1) for v in value])
    return depth


EMPTY: dict[str, Any] = {"axt.ListField": [], "axt.MapField": {}, "axt.RelationField": []}


def nullable(f: dict[str, Any]) -> bool:
    """Section 9.2: a field of no value is null when it is not required and its brick gives no default."""
    name, b = kind_of(f)
    if name in EMPTY:
        return False
    return not f["required"] and b.get("default") is None


def avro_default(f: dict[str, Any]) -> tuple[bool, Any]:
    """Whether the derived field has a default, and its JSON value (section 9.2)."""
    name, b = kind_of(f)
    if name in EMPTY:
        return True, copy.deepcopy(EMPTY[name])
    if b.get("default") is not None:
        value = b["default"]
        return True, value.decode("latin-1") if isinstance(value, bytes) else value
    return (True, None) if nullable(f) else (False, None)


def avro_type(f: dict[str, Any], defined: list[str], namespace: str) -> Any:
    name, b = kind_of(f)
    t: Any
    if name in STRINGS:
        t = "string"
    elif name in {"axt.IntField", "axt.LongField", "axt.DoubleField", "axt.BooleanField", "axt.BytesField"}:
        t = name[4:-5].lower()
    elif name in TIME_BRICKS:
        full = TIME_BRICKS[name]
        t = full if full in defined else copy.deepcopy(TIME_SCHEMAS[full])
        if full not in defined:
            defined.append(full)
            defined.extend(f"axt.{n}" for n in inner_time_names(t))
    elif name == "axt.EnumField":
        symbols = [x["symbol"] for x in b["symbols"]]
        t = {"type": "enum", "name": b["name"], "doc": f["doc"], "symbols": symbols, "default": b["fallback"]}
    elif name == "axt.RelationField":
        t = {"type": "array", "items": in_place(RELATION_SCHEMA, defined)}
    elif name == "axt.ListField":
        t = {"type": "array", "items": avro_type(b["items"], defined, namespace)}
    elif name == "axt.MapField":
        t = {"type": "map", "values": avro_type(b["values"], defined, namespace)}
    else:
        t = {
            "type": "record",
            "name": b["name"],
            "doc": f["doc"],
            "fields": avro_fields(b, defined, namespace),
        }
    return ["null", t] if nullable(f) else t


def in_place(t: Any, defined: list[str]) -> Any:
    """A published schema of the namespace axt at an occurrence: every named type that an earlier occurrence
    already defined replaced by its full name (section 11.6); defined grows with the names it defines."""
    if isinstance(t, list):
        return [in_place(x, defined) for x in t]
    if not isinstance(t, dict):
        return t
    if t["type"] in {"record", "enum", "fixed"}:
        full = t["name"] if "." in t["name"] else f"axt.{t['name']}"
        if full in defined:
            return full
        defined.append(full)
        if t["type"] != "record":
            return copy.deepcopy(t)
        return dict(t, fields=[dict(x, type=in_place(x["type"], defined)) for x in t["fields"]])
    if t["type"] == "array":
        return dict(t, items=in_place(t["items"], defined))
    if t["type"] == "map":
        return dict(t, values=in_place(t["values"], defined))
    return copy.deepcopy(t)


def inner_time_names(t: Any) -> list[str]:
    """The time types that a published time schema defines inside itself, such as axt.Time in axt.DateTime."""
    found: list[str] = []
    for x in t.get("fields", []):
        for branch in x["type"] if isinstance(x["type"], list) else [x["type"]]:
            if isinstance(branch, dict) and branch.get("type") == "record" and branch["name"] in TIME_NAMES:
                found += [branch["name"], *inner_time_names(branch)]
    return found


def avro_fields(b: dict[str, Any], defined: list[str], namespace: str) -> list[dict[str, Any]]:
    out = []
    for f in b["fields"]:
        entry: dict[str, Any] = {"name": f["name"], "type": avro_type(f, defined, namespace)}
        has, value = avro_default(f)
        if has:
            entry["default"] = value
        entry["doc"] = f["doc"]
        out.append(entry)
    return out


def derive(f: dict[str, Any]) -> dict[str, Any]:
    """The Avro schema of a valid description (section 9.2), as a JSON value."""
    _, b = kind_of(f)
    namespace, _, short = b["name"].rpartition(".")
    head: dict[str, Any] = {"type": "record", "name": short, "namespace": namespace, "doc": f["doc"]}
    head["axt.version"] = b["version"]
    head["fields"] = avro_fields(b, [], namespace)
    return head


def es_number(x: float | int) -> str:
    """A number as ECMAScript writes it, the form of RFC 8785, section 3.2.2.3."""
    if isinstance(x, bool) or not isinstance(x, float):
        return str(int(x))
    if not math.isfinite(x):
        raise ValueError("no JSON number")
    if x == 0:
        return "0"
    shortest = repr(abs(x))  # the shortest digits that read back to x
    mantissa, _, e = shortest.partition("e")
    whole, _, frac = mantissa.partition(".")
    frac = "" if frac == "0" else frac
    point = len(whole.lstrip("0") or "0") + (int(e) if e else 0)
    if whole.strip("0") == "":
        lead = len(frac) - len(frac.lstrip("0"))
        digits, point = frac.lstrip("0"), -lead + (int(e) if e else 0)
    else:
        digits = (whole.lstrip("0") + frac).rstrip("0") or "0"
    k, n = len(digits), point
    sign = "-" if x < 0 else ""
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * -n + digits
    e_text = f"{'+' if n - 1 >= 0 else '-'}{abs(n - 1)}"
    return sign + digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + e_text


def jcs(value: Any) -> str:
    """The JSON Canonicalization Scheme of RFC 8785: members sorted by their UTF-16 code units, no white
    space, the strings and numbers as ECMAScript writes them."""
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v) for k, v in items) + "}"
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, str) or value is None or isinstance(value, bool):
        return json.dumps(value, ensure_ascii=False)
    return es_number(value)


def derived_text(f: dict[str, Any]) -> str:
    """The derived schema as text: its JSON in the canonical form of RFC 8785 (section 9.3)."""
    return jcs(derive(f))


# The descriptions that the models of the other scripts hold for a derived text: a model keeps schema texts,
# and a device offers the description it got or made for a text, never one made again from the text.
REGISTRY: dict[str, dict[str, Any]] = {}


def register(f: dict[str, Any]) -> str:
    """The derived text of a valid description, which the registry then holds it for."""
    text = derived_text(f)
    REGISTRY.setdefault(text, f)
    return text


def source(text: str) -> str:
    """The derived text of a schema of a model, such as an example type: its description is the one that
    describe_schema makes, which keeps the schema's attributes as the bricks hold them."""
    return register(describe_schema(json.loads(text)))


def description_of(text: str) -> dict[str, Any]:
    """The description the registry holds for a derived text."""
    return REGISTRY[text]


# The example types of spec/types.md, section 7, published as their descriptions (section 10.3), by full name.
EXAMPLES = REPO / "types" / "axt" / "example" / "v1"
EXAMPLE_DESCRIPTIONS: dict[str, dict[str, Any]] = {}


def load_examples() -> None:
    """Read the published descriptions and register each for its derived text, so that a model that holds
    the schema of an example type offers its published description."""
    for path in sorted(EXAMPLES.glob("*.json")):
        d = from_json_form(json.loads(path.read_text(encoding="utf-8")))
        EXAMPLE_DESCRIPTIONS[type_of(d)[0]] = d
        register(d)


def canonical(schema: Any) -> tuple[str, bytes]:
    """The Parsing Canonical Form and the CRC-64-AVRO, as its 8 bytes in little-endian order."""
    pcf = to_parsing_canonical_form(schema)
    return pcf, bytes.fromhex(fingerprint(pcf, "CRC-64-AVRO"))


def type_of(f: dict[str, Any]) -> tuple[str, int]:
    """The full name and the version of the type a description describes."""
    _, b = kind_of(f)
    return b["name"], b["version"]


# --- a schema with the attributes of spec/metadata.md as a description ----------------------------


class NotDescribable(ValueError):
    """A schema that no description derives, such as a recursive one or one with another union."""


TEXT_ATTRIBUTES = {
    "axt.label": "label",
    "axt.label_translations": "label_translations",
    "axt.help": "help",
    "axt.help_translations": "help_translations",
    "axt.emoji": "emoji",
}
COMMON_ATTRIBUTES = {
    "axt.order": "order",
    "axt.group": "group",
    "axt.sensitive": "sensitive",
    "axt.advanced": "advanced",
}
BRICK_ATTRIBUTES = {
    "axt.pattern": "pattern",
    "axt.multiline": "multiline",
    "axt.preferred_length": "preferred_length",
    "axt.placeholder": "placeholder",
    "axt.example": "example",
    "axt.min_length": "min_length",
    "axt.max_length": "max_length",
    "axt.min": "min",
    "axt.max": "max",
    "axt.unit": "unit",
}
FORMAT_BRICKS = {fmt: b for b, fmt in SEMANTIC.items()} | {"plain": "axt.StringField"}


def texts_of(node: dict[str, Any]) -> dict[str, Any]:
    return complete("axt.FieldTexts", {v: node[k] for k, v in TEXT_ATTRIBUTES.items() if k in node})


def kind_from(t: Any, attrs: dict[str, Any], default: Any, names: dict[str, Any]) -> dict[str, Any]:
    """The brick of a field of type t (null taken away) with the field's attributes and default."""
    members: dict[str, Any] = {k2: attrs[k] for k, k2 in BRICK_ATTRIBUTES.items() if k in attrs}
    if isinstance(t, str) and t in names:
        t = names[t]
    if isinstance(t, dict) and t.get("type") == "record" and f"axt.{t['name']}" in TIME_SCHEMAS:
        which = f"axt.{t['name']}Field"
        if which == "axt.DateTimeField" and attrs.get("axt.anchor") == "instant":
            members["anchor"] = "INSTANT"
        return {which: complete(which, members)}
    if isinstance(t, str) and t in TIME_SCHEMAS:
        return kind_from(TIME_SCHEMAS[t], attrs, default, names)
    if isinstance(t, dict) and "logicalType" in t:
        raise NotDescribable(f"a logical type {t['logicalType']}")
    if t == "string":
        which = FORMAT_BRICKS[attrs.get("axt.format", "plain")]
    elif isinstance(t, str) and t in {"int", "long", "double", "boolean", "bytes"}:
        which = f"axt.{str(t).capitalize()}Field"
    elif isinstance(t, dict) and t["type"] == "enum":
        which = "axt.EnumField"
        entries = t.get("axt.symbols", {})
        symbols = [
            complete("axt.EnumSymbol", {"symbol": x, "texts": texts_of(prefix(entries.get(x, {})))})
            for x in t["symbols"]
        ]
        members |= {"name": t["name"], "symbols": symbols, "fallback": t["default"]}
    elif isinstance(t, dict) and t["type"] in {"array", "map"}:
        raise NotDescribable("a list or a map is described by describe_field")
    elif isinstance(t, dict) and t["type"] == "record":
        names[t["name"]] = t
        groups = [
            complete("axt.FieldGroup", {"key": k, "texts": texts_of(prefix(v))})
            for k, v in t.get("axt.groups", {}).items()
        ]
        fields = [describe_field(x, names) for x in t["fields"]]
        members |= {"name": t["name"], "fields": fields, "groups": groups, "title": t.get("axt.title", "")}
        which = "axt.ObjectField"
    else:
        raise NotDescribable(f"the type {json.dumps(t)[:60]}")
    if default is not None:
        members["default"] = default.encode("latin-1") if t == "bytes" else default
    return {which: complete(which, members)}


def prefix(entry: dict[str, Any]) -> dict[str, Any]:
    """An entry of axt.symbols or axt.groups with the names of the attributes."""
    return {f"axt.{k}": v for k, v in entry.items()}


def describe_field(x: dict[str, Any], names: dict[str, Any]) -> dict[str, Any]:
    """A field of a schema with the attributes of spec/metadata.md as a typed field."""
    t, attrs = x["type"], {k: v for k, v in x.items() if k.startswith("axt.")}
    common = {v: attrs[k] for k, v in COMMON_ATTRIBUTES.items() if k in attrs}
    if isinstance(t, list):
        if len(t) != 2 or t[0] != "null" or "default" not in x or x["default"] is not None:
            raise NotDescribable(f"the union of {x['name']}")
        kind = kind_from(t[1], attrs, None, names)
        required = False
    elif isinstance(t, dict) and t["type"] == "array" and of_relations(t["items"]):
        if x.get("default") != []:
            raise NotDescribable(f"a list of relations without an empty default in {x['name']}")
        kind, required = {"axt.RelationField": {}}, False
    elif isinstance(t, dict) and t["type"] in {"array", "map"}:
        if x.get("default") != EMPTY["axt.ListField" if t["type"] == "array" else "axt.MapField"]:
            raise NotDescribable(f"a list or map without an empty default in {x['name']}")
        inner = t["items"] if t["type"] == "array" else t["values"]
        item = describe_item(x["name"], x["doc"], inner, attrs, names)
        member = "items" if t["type"] == "array" else "values"
        which = "axt.ListField" if t["type"] == "array" else "axt.MapField"
        kind, required = {which: complete(which, {member: item})}, False
    else:
        kind = kind_from(t, attrs, x.get("default"), names)
        required = "default" not in x
    f = field(x["name"], x["doc"], kind, texts_of(attrs), required=required, **common)
    if isinstance(t, list) != nullable(f):
        raise NotDescribable(f"{x['name']} does not derive back to its type")
    return f


def of_relations(items: Any) -> bool:
    """The items of an array are axt.Relation, by its full name or defined in place."""
    if isinstance(items, str):
        return items == RELATION
    return (
        isinstance(items, dict)
        and items.get("type") == "record"
        and items.get("name") == "Relation"
        and (items.get("namespace") == "axt")
    )


def describe_item(
    name: str, doc: str, t: Any, attrs: dict[str, Any], names: dict[str, Any]
) -> dict[str, Any]:
    """The typed field of the items of an array or the values of a map."""
    optional = isinstance(t, list)
    inner = t[1] if optional else t
    if isinstance(inner, dict) and inner.get("type") in {"array", "map"}:
        x: dict[str, Any] = {
            "name": name,
            "type": inner,
            "default": [] if inner["type"] == "array" else {},
            "doc": doc,
        }
        return describe_field(x, names)
    record = (
        isinstance(inner, dict)
        and inner.get("type") == "record"
        and f"axt.{inner['name']}" not in TIME_SCHEMAS
    )
    empty = {"string": "", "bytes": ""}.get(inner) if isinstance(inner, str) else None
    kind = kind_from(inner, attrs, None if optional else empty, names)
    texts = texts_of(inner) if record else texts_of({})
    required = not optional and empty is None
    return field(name, inner["doc"] if record else doc, kind, texts, required=required)


def describe_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """The description whose derived schema has the canonical form of the schema; raises NotDescribable."""
    if not isinstance(schema, dict) or schema.get("type") != "record":
        raise NotDescribable("not a record")
    names: dict[str, Any] = {}
    kind = kind_from(schema, {}, None, names)
    b = kind["axt.ObjectField"]
    b["name"] = f"{schema['namespace']}.{schema['name']}" if "namespace" in schema else schema["name"]
    b["version"] = schema.get("axt.version", 1)
    root = field(
        re.sub(r"(?<!^)(?=[A-Z])", "_", schema["name"]).lower(), schema["doc"], kind, texts_of(schema)
    )
    if canonical(derive(root))[0] != canonical(schema)[0]:
        raise NotDescribable("the derived schema has another canonical form")
    return root


# --- the types of a file (spec/fields.md, section 10.2) -----------------------------------------


def file_entries(schemas: list[Any]) -> list[dict[str, Any]]:
    """The value of axt.schemas for the writer schemas of a model: for each, its description and the schema
    derived from it."""
    out = []
    for schema in schemas:
        d = description_of(source(json.dumps(schema)))
        out.append({"description": json_form(d), "schema": derive(d)})
    return out


def file_schemas(value: bytes) -> list[str]:
    """The derived schema texts of the types of a file, from the value of axt.schemas; ValueError for one
    that is not a list of entries, each a valid description and the schema derived from it."""
    entries = json.loads(value)
    if not isinstance(entries, list):
        raise ValueError("axt.schemas is not a JSON array")
    texts = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"description", "schema"}:
            raise ValueError("an entry of axt.schemas without a description and a schema")
        d = from_json_form(entry["description"])
        try:
            binary(d)  # a datum of axt.Field
        except Exception:
            raise ValueError("a description that is no datum of axt.Field") from None
        if description_problems(d):
            raise ValueError("a description that is not valid")
        if canonical(entry["schema"])[0] != canonical(derive(d))[0]:
            raise ValueError("a schema that is not the one derived from its description")
        texts.append(register(d))
    return texts


# --- the encoding of a description --------------------------------------------------------------


def avro_form(value: Any) -> Any:
    """A value with each description's kind as fastavro's tuple of branch name and record."""
    if isinstance(value, dict) and "kind" in value and "texts" in value:
        name, b = kind_of(value)
        return {**value, "kind": (name, {k: avro_form(v) for k, v in b.items()})}
    if isinstance(value, dict):
        return {k: avro_form(v) for k, v in value.items()}
    if isinstance(value, list):
        return [avro_form(x) for x in value]
    return value


def named(value: Any) -> Any:
    """A value that fastavro read with return_record_name, with each tuple as an object of one member."""
    if isinstance(value, tuple):
        return {value[0]: named(value[1])}
    if isinstance(value, dict):
        return {k: named(v) for k, v in value.items()}
    if isinstance(value, list):
        return [named(x) for x in value]
    return value


def without_names(value: Any) -> Any:
    """A value with each kind as the record of its branch alone, as the Apache avro package reads it."""
    if isinstance(value, dict) and "kind" in value and "texts" in value:
        _, b = kind_of(value)
        return {**value, "kind": {k: without_names(v) for k, v in b.items()}}
    if isinstance(value, dict):
        return {k: without_names(v) for k, v in value.items()}
    if isinstance(value, list):
        return [without_names(x) for x in value]
    return value


def read(data: bytes, schema: Any) -> Any:
    """A datum read with fastavro, with the branch of each kind named (spec/conformance.md, section 3.3)."""
    buf = io.BytesIO(data)
    value = fastavro.schemaless_reader(
        buf, schema, schema, return_record_name=True, return_record_name_override=True
    )
    if buf.tell() != len(data):
        raise ValueError("bytes left over")
    return named(value)


def binary(f: dict[str, Any]) -> bytes:
    """The Avro binary encoding of a description as a datum of axt.Field."""
    buffer = io.BytesIO()
    fastavro.schemaless_writer(buffer, PARSED, avro_form(f))
    return buffer.getvalue()


def json_form(value: Any) -> Any:
    """A description in the JSON form of spec/conformance.md, section 3.3: bytes as hexadecimal."""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {k: json_form(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_form(x) for x in value]
    return value


def from_json_form(value: Any) -> Any:
    """The inverse of json_form: the default of a bytes brick back to bytes."""
    if isinstance(value, dict) and "axt.BytesField" in value and isinstance(value["axt.BytesField"], dict):
        b = dict(value["axt.BytesField"])
        if isinstance(b["default"], str):
            b["default"] = bytes.fromhex(b["default"])
        return {"axt.BytesField": b}
    if isinstance(value, dict):
        return {k: from_json_form(v) for k, v in value.items()}
    if isinstance(value, list):
        return [from_json_form(x) for x in value]
    return value


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
    assert all(b.endswith("Field") for b in BRICKS) and len(BRICKS) == len(set(BRICKS)) == 28
    assert BRICKS[-1] == "axt.RelationField" and not NAMED["axt.RelationField"]["fields"]
    assert set(SEMANTIC) <= set(BRICKS) and set(SEMANTIC.values()) == set(mr.FORMATS) - {"plain"}
    canonical = to_parsing_canonical_form(FIELD_SCHEMA)
    assert avro.schema.parse(FIELD_TEXT).canonical_form == canonical, "avro and fastavro differ"
    fp = "0x" + bytes.fromhex(fingerprint(canonical, "CRC-64-AVRO"))[::-1].hex()
    assert avro.schema.parse(canonical).fingerprint("CRC-64-AVRO")[::-1].hex() == fp[2:]
    return fp


PARSED = fastavro.parse_schema(FIELD_SCHEMA)


def same(a: Any, b: Any) -> bool:
    """Equal as values, NaN equal to NaN."""
    return json.dumps(a, sort_keys=True, default=repr) == json.dumps(b, sort_keys=True, default=repr)


def round_trip(description: dict[str, Any]) -> int:
    """Encode with fastavro and decode with fastavro and the avro package; returns the size in bytes."""
    data = binary(description)
    assert same(read(data, PARSED), description), "fastavro does not read the description back"
    apache = avro.io.DatumReader(avro.schema.parse(FIELD_TEXT)).read(avro.io.BinaryDecoder(io.BytesIO(data)))
    assert same(apache, without_names(description)), "avro does not read it back"
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
        brick("ObjectField", name="com.example.Vet", fields=fields, groups=groups, version=1, title="name"),
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
    ("a default that is NaN", [*F, FEE, "kind", "default"], math.nan, "kind.fields[7].kind.default"),
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
    ("a root without a version", ["kind", "version"], None, "kind.version"),
    ("a root without a namespace", ["kind", "name"], "Vet", "kind.name"),
    ("a root that is required", ["required"], True, ""),
    ("a version in a nested object", [*F, ADDRESS, "kind", "version"], 1, "kind.fields[5].kind.version"),
    (
        "a nested name with a namespace",
        [*F, ADDRESS, "kind", "name"],
        "com.example.VetAddress",
        "kind.fields[5].kind.name",
    ),
    ("an enum named as an object", [*F, KIND, "kind", "name"], "VetAddress", "kind.fields[5].kind.name"),
    ("a title that is not a field of text", ["kind", "title"], "visit_minutes", "kind.title"),
    ("a root that is not an object", ["kind"], brick("StringField"), "kind"),
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
        brick("ObjectField", name="com.example.Formats", fields=fields, version=1),
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
            name="com.example.Kinds",
            version=1,
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


def numbers_description() -> dict[str, Any]:
    """Defaults that the canonical form of RFC 8785 writes in its own way: numbers, bytes and texts."""

    def d(name: str, kind: dict[str, Any], doc: str) -> dict[str, Any]:
        return field(name, doc, kind, texts())

    fields = [
        d("tenth", brick("DoubleField", default=0.1), "A tenth."),
        d("large", brick("DoubleField", default=1e21), "A large number, written with an exponent."),
        d(
            "below",
            brick("DoubleField", default=1e21 - 2**17),
            "The largest number below it, written in full.",
        ),
        d("small", brick("DoubleField", default=1e-7), "A small number, written with an exponent."),
        d(
            "whole",
            brick("DoubleField", default=-2.0),
            "A whole number of double precision, written without a point.",
        ),
        d("long", brick("LongField", default=2**53), "A long."),
        d("raw", brick("BytesField", default=bytes([0, 0x7F, 0x80, 0xFF])), "Bytes, written as code points."),
        d(
            "text",
            brick("StringField", default='"\\\t\u0001\u007fé\u2028😀'),
            'A text with "quotes", a tab\tand é.',
        ),
    ]
    return field(
        "numbers",
        "Defaults.",
        brick("ObjectField", name="com.example.Numbers", fields=fields, version=3),
        texts(),
    )


def links_description() -> dict[str, Any]:
    """Relation fields in every place a typed field can be: first, after a date and time, twice, as the items
    of a list and in a nested object (spec/fields.md, sections 11 and 11.6)."""
    rel = brick("RelationField")
    place = brick(
        "ObjectField",
        name="LinksPlace",
        fields=[
            field("name", "The name of the place.", brick("StringField", default=""), texts("Name", "Name")),
            field("links", "The links of the place.", rel, texts("Links", "Verknüpfungen", "🔗")),
        ],
    )
    fields = [
        field(
            "links",
            "The links of the record, at least one.",
            rel,
            texts("Links", "Verknüpfungen", "🔗"),
            required=True,
        ),
        field("seen", "When the links were last seen; null when not known.", brick("DateTimeField"), texts()),
        field("sources", "The links to where the record comes from.", rel, texts("Sources", "Quellen")),
        field(
            "history",
            "Earlier lists of links, the latest last.",
            brick("ListField", items=field("history", "One earlier list of links.", rel, texts("Earlier"))),
            texts(),
        ),
        field("place", "The place of the record; null when there is none.", place, texts("Place", "Ort")),
    ]
    return field(
        "links",
        "A record with relation fields.",
        brick("ObjectField", name="com.example.Links", fields=fields, version=1),
        texts(),
    )


# The rules of section 11.4 for the walk of metadata_rules.breaches, as time_examples.py gives it this module.
RELATION_RULES = types.SimpleNamespace(
    RELATION=RELATION, relation_problem=relation_problem, list_problem=list_problem, repeated_ids=repeated_ids
)


def vector_descriptions() -> tuple[list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any], str]]]:
    """The descriptions of the vectors of the category bricks: valid ones, and invalid ones with the path of
    their problem."""
    valid = [
        ("com.example.Vet of spec/fields.md, section 8", vet()),
        ("one field of each semantic brick", formats_description()),
        ("one field of each other brick, each required", kinds_description()),
        ("defaults of numbers, bytes and texts", numbers_description()),
    ]
    for name, d in EXAMPLE_DESCRIPTIONS.items():
        valid.append((f"the example type {name}, {name.rpartition('.')[2]}.1.json", d))
    valid.append(
        (
            "relation fields first, after a date and time, twice, in a list and in an object",
            links_description(),
        )
    )
    invalid = [(what, mutate(path, new), where) for what, path, new, where in DESCRIPTION_CASES]
    deep = field("v", "Lists in lists.", brick("LongField"), texts())
    for _ in range(MAX_TYPED_DEPTH - 1):
        deep = field("v", "Lists in lists.", brick("ListField", items=deep), texts())
    root = brick("ObjectField", name="com.example.Deep", fields=[deep], version=1)
    invalid.append(("typed fields nested 65 deep", field("deep", "Deep.", root, texts()), ""))
    shallower = copy.deepcopy(root)
    shallower["axt.ObjectField"]["fields"] = [kind_of(deep)[1]["items"]]
    invalid.append(("a derived schema nested deeper than 64", field("deep", "Deep.", shallower, texts()), ""))
    invalid.append(("a description above 256 KiB", dict(vet(), doc="x" * MAX_DESCRIPTION), ""))
    clash = links_description()
    kind_of(clash)[1]["name"] = "axt.Links"
    kind_of(kind_of(clash)[1]["fields"][4])[1]["name"] = "RelationOutsideTarget"
    invalid.append(("an object named as a type of axt.Relation", clash, "kind.fields[4].kind.name"))
    item = links_description()
    kind_of(kind_of(item)[1]["fields"][3])[1]["items"]["advanced"] = True
    invalid.append(("relations as items that are advanced", item, "kind.fields[3].kind.items"))
    beyond = numbers_description()
    kind_of(kind_of(beyond)[1]["fields"][5])[1]["default"] = 2**63 - 1
    invalid.append(("a default of a long above 2^53", beyond, "kind.fields[5].kind.default"))
    for what, d, where in invalid:
        assert [w for w, _ in description_problems(d)] == [where], what
    return valid, invalid


load_examples()


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

    deep = field("v", "Lists in lists.", brick("LongField"), texts())
    for _ in range(MAX_TYPED_DEPTH - 1):
        deep = field("v", "Lists in lists.", brick("ListField", items=deep), texts())
    at_limit = field(
        "deep", "Deep.", brick("ObjectField", name="com.example.Deep", fields=[deep], version=1), texts()
    )
    assert typed_depth(at_limit) == MAX_TYPED_DEPTH + 1
    assert description_problems(at_limit) == [("", "typed fields nested deeper than 64")]
    kind_of(at_limit)[1]["fields"] = [kind_of(deep)[1]["items"]]
    assert typed_depth(at_limit) == MAX_TYPED_DEPTH
    assert [w for w, _ in description_problems(at_limit)] == [""]  # the derived schema nests deeper than 64

    for name, d in EXAMPLE_DESCRIPTIONS.items():
        avsc = EXAMPLES / f"{name.rpartition('.')[2]}.{type_of(d)[1]}.avsc"
        schema = json.loads(avsc.read_text(encoding="utf-8"))
        assert description_problems(d) == [], (name, description_problems(d))
        assert derive(d) == schema, avsc.name  # example_schemas.py writes it
        assert derive(describe_schema(derive(d))) == derive(d), avsc.name
        assert kind_of(kind_of(d)[1]["fields"][-1])[0] == "axt.RelationField", name
        assert description_of(derived_text(d)) is d, name  # the registry holds the published description
        print(f"{name} version {type_of(d)[1]}: a description of {round_trip(d)} bytes derives {avsc.name}")
    links = links_description()
    assert description_problems(links) == [], description_problems(links)
    round_trip(links)
    derived = derive(links)
    one = derived["fields"][0]["type"]
    assert one["type"] == "array" and one["items"]["name"] == "Relation", "axt.Relation in place at first"
    assert one["items"]["fields"][4]["type"][1]["name"] == "DateTime", "axt.DateTime in place in axt.Relation"
    assert [x["type"] for x in derived["fields"][1:4]] == [
        ["null", "axt.DateTime"],
        {"type": "array", "items": "axt.Relation"},
        {"type": "array", "items": {"type": "array", "items": "axt.Relation"}},
    ]
    assert [x.get("default") for x in derived["fields"][:4]] == [[], None, [], []]
    assert derived["fields"][4]["type"][1]["fields"][1]["type"] == {"type": "array", "items": "axt.Relation"}
    fastavro.parse_schema(derived)
    assert canonical(derive(describe_schema(derived))) == canonical(derived)
    assert breaches(links, {"links": []}) == [("links", "required")]
    assert breaches(links, {"links": None}) == [("links", "required")]
    assert breaches(links, {"links": [{"id": ""}], "sources": []}) == []  # the rules of 11.4 are not checks
    mimi: dict[str, Any] = {
        "id": "0b6f4a3e-8c1d-4f27-9e5a-2d7c41b8e093",
        "sender": None,
        "type": "axt.example.v1.Pet",
        "text": "",
    }
    relation: dict[str, Any] = {
        "id": "3e8a5b14-7c29-4d6e-a0f3-1b9d2c7e5a46",
        "kind": "axt.related",
        "target": mimi,
        "note": "",
    }
    relation |= {"start": None, "end": None, "attributes": {}}
    value: dict[str, Any] = {
        "links": [relation],
        "seen": None,
        "sources": [],
        "history": [[relation, relation]],
        "place": None,
    }
    assert mr.breaches(derived, value, None, False, RELATION_RULES) == [
        ("history[0][1].id", RELATION, "an id of an earlier relation")
    ]
    value = dict(value, history=[], sources=[relation] * 257, links=[dict(relation, kind="related")])
    assert [p for p, _, _ in mr.breaches(derived, value, None, False, RELATION_RULES)] == [
        "links[0].kind",
        "sources",
        *[f"sources[{i}].id" for i in range(1, 257)],
    ]
    print(f"com.example.Links: relation fields derived, a description of {round_trip(links)} bytes")

    vet_schema = derive(description)
    assert describe_schema(vet_schema) is not None and canonical(
        derive(describe_schema(vet_schema))
    ) == canonical(vet_schema)
    print(
        f"com.example.Vet derives a schema of {len(derived_text(description).encode())} bytes, "
        f"fingerprint 0x{canonical(vet_schema)[1][::-1].hex()}"
    )

    root = kind_of(description)[1]["fields"][ADDRESS]
    print("The field address of com.example.Vet:")
    print(json.dumps(root, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
