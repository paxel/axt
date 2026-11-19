# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Produce and check the examples of spec/metadata.md.

With the rules of metadata_rules.py, this script:

- checks com.example.Vet, an illustration that carries every attribute of spec/metadata.md, by the
  rules of spec/types.md, section 5, with the code of example_types.py, which includes the rules of
  every attribute; and that its Parsing Canonical Form, and so its fingerprint, is that of the same
  schema without any attribute;
- checks that a schema whose attributes break their rules is reported attribute by attribute for
  a sender, and that a receiver ignores each of those attributes;
- shows the type and some of its fields as a receiver does, in English, German and a language the
  type has no text in: labels, help, emoji, the order of the fields, the groups and the symbols;
- checks a valid record, and records that each break one check, against the field path and the
  attribute expected: every format, I-Regexp patterns that match the whole value, lengths in code
  points, numbers, an item of an array, a field of a nested record, and the first of two breaches;
- checks I-Regexp patterns that are valid, with values that match and values that do not, and
  patterns outside RFC 9485 or its limits, which a receiver ignores;
- encodes each record with fastavro and decodes it again with fastavro and the Apache avro package.

Run from anywhere, with fastavro and avro (1.12) installed:

    python3 conformance/tools/metadata_examples.py

conformance/tools/generate_vectors.py imports this file; importing it runs the checks and prints nothing.
"""

import copy
import importlib.util
import io
import json
import math
from collections.abc import Callable
from pathlib import Path
from typing import Any

import avro.io
import avro.schema
import fastavro
from fastavro.schema import to_parsing_canonical_form

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("example_types", HERE / "example_types.py")
if _spec is None or _spec.loader is None:
    raise ImportError(f"cannot load {HERE / 'example_types.py'}")
rules = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rules)  # runs none of the checks of the example types
mr = rules.mr


def compact(schema: Any) -> str:
    return json.dumps(schema, separators=(",", ":"), ensure_ascii=False)


def without_attributes(t: Any) -> Any:
    if isinstance(t, list):
        return [without_attributes(b) for b in t]
    if isinstance(t, dict):
        return {k: without_attributes(v) for k, v in t.items() if not k.startswith("axt.")}
    return t


# --- the illustration: com.example.Vet ---------------------------------------------------------

DE = "de"
VET = {
    "type": "record",
    "name": "Vet",
    "namespace": "com.example",
    "doc": "An illustration for spec/metadata.md; not an AXT example type. A veterinary practice.",
    "axt.label": "Vet practice",
    "axt.label_translations": {DE: "Tierarztpraxis"},
    "axt.help": "A practice that treats animals.",
    "axt.help_translations": {DE: "Eine Praxis, die Tiere behandelt."},
    "axt.emoji": "🏥",
    "axt.groups": {
        "contact": {"label": "Contact", "label_translations": {DE: "Kontakt"}, "emoji": "📞"},
        "billing": {
            "label": "Billing",
            "label_translations": {DE: "Abrechnung"},
            "emoji": "💶",
            "help": "Only for invoices.",
            "help_translations": {DE: "Nur für Rechnungen."},
        },
    },
    "fields": [
        {
            "name": "name",
            "type": "string",
            "default": "",
            "doc": "The name of the practice.",
            "axt.label": "Name",
            "axt.label_translations": {DE: "Name"},
            "axt.emoji": "🏷️",
            "axt.min_length": 1,
            "axt.max_length": 200,
            "axt.preferred_length": 40,
            "axt.order": 1,
        },
        {
            "name": "kind",
            "type": {
                "type": "enum",
                "name": "VetKind",
                "doc": "PRACTICE: a practice. CLINIC: a clinic with a ward. EMERGENCY: an emergency service.",
                "symbols": ["PRACTICE", "CLINIC", "EMERGENCY"],
                "default": "PRACTICE",
                "axt.symbols": {
                    "PRACTICE": {"label": "Practice", "label_translations": {DE: "Praxis"}, "emoji": "🩺"},
                    "CLINIC": {"label": "Clinic", "label_translations": {DE: "Klinik"}, "emoji": "🏥"},
                    "EMERGENCY": {
                        "label": "Emergency service",
                        "label_translations": {DE: "Notdienst"},
                        "emoji": "🚑",
                        "help": "Open at night and on holidays.",
                        "help_translations": {DE: "Nachts und an Feiertagen geöffnet."},
                    },
                },
            },
            "default": "PRACTICE",
            "doc": "What kind of practice it is.",
            "axt.label": "Kind",
            "axt.label_translations": {DE: "Art"},
            "axt.emoji": "🗂️",
            "axt.order": 2,
        },
        {
            "name": "phone",
            "type": "string",
            "default": "",
            "doc": "The phone number, in E.164; empty when not known.",
            "axt.label": "Phone",
            "axt.label_translations": {DE: "Telefon"},
            "axt.emoji": "📞",
            "axt.format": "phone",
            "axt.placeholder": "+49301234567",
            "axt.example": "+49301234567",
            "axt.group": "contact",
            "axt.order": 3,
        },
        {
            "name": "email",
            "type": "string",
            "default": "",
            "doc": "The email address; empty when not known.",
            "axt.label": "Email",
            "axt.label_translations": {DE: "E-Mail"},
            "axt.emoji": "📧",
            "axt.format": "email",
            "axt.example": "praxis@example.org",
            "axt.group": "contact",
        },
        {
            "name": "address",
            "type": {
                "type": "record",
                "name": "VetAddress",
                "doc": "A postal address.",
                "axt.label": "Address",
                "axt.label_translations": {DE: "Anschrift"},
                "axt.emoji": "📮",
                "fields": [
                    {
                        "name": "street",
                        "type": "string",
                        "default": "",
                        "doc": "The street and number.",
                        "axt.label": "Street",
                        "axt.label_translations": {DE: "Straße"},
                        "axt.emoji": "🛣️",
                    },
                    {
                        "name": "postal_code",
                        "type": "string",
                        "default": "",
                        "doc": "The postal code; empty when not known.",
                        "axt.label": "Postal code",
                        "axt.label_translations": {DE: "Postleitzahl"},
                        "axt.emoji": "🔢",
                        "axt.pattern": "[0-9]{5}",
                        "axt.help": "Five digits.",
                        "axt.help_translations": {DE: "Fünf Ziffern."},
                        "axt.example": "10115",
                        "axt.preferred_length": 5,
                    },
                    {
                        "name": "locality",
                        "type": "string",
                        "default": "",
                        "doc": "The town or city.",
                        "axt.label": "Town",
                        "axt.label_translations": {DE: "Ort"},
                        "axt.emoji": "🏙️",
                    },
                    {
                        "name": "country",
                        "type": "string",
                        "default": "",
                        "doc": "The country, ISO 3166-1 alpha-2.",
                        "axt.label": "Country",
                        "axt.label_translations": {DE: "Land"},
                        "axt.emoji": "🌍",
                        "axt.format": "country",
                        "axt.example": "DE",
                        "axt.order": 0,
                    },
                ],
            },
            "doc": "Where the practice is.",
            "axt.label": "Address",
            "axt.label_translations": {DE: "Anschrift"},
            "axt.emoji": "📮",
        },
        {
            "name": "colour",
            "type": "string",
            "default": "",
            "doc": "The colour of its appointments in a calendar.",
            "axt.label": "Colour in the calendar",
            "axt.label_translations": {DE: "Farbe im Kalender"},
            "axt.emoji": "🎨",
            "axt.format": "colour",
            "axt.example": "#2e7d32",
        },
        {
            "name": "rating",
            "type": ["null", "int"],
            "default": None,
            "doc": "The user's rating; null when not rated.",
            "axt.label": "Rating",
            "axt.label_translations": {DE: "Bewertung"},
            "axt.emoji": "⭐",
            "axt.help": "From 1 to 5 stars.",
            "axt.help_translations": {DE: "Von 1 bis 5 Sternen."},
            "axt.min": 1,
            "axt.max": 5,
        },
        {
            "name": "visit_minutes",
            "type": "int",
            "default": 15,
            "doc": "How long a visit takes, in minutes.",
            "axt.label": "Length of a visit",
            "axt.label_translations": {DE: "Dauer eines Besuchs"},
            "axt.emoji": "⏱️",
            "axt.unit": "min",
            "axt.min": 5,
            "axt.max": 240,
        },
        {
            "name": "fee",
            "type": ["null", "double"],
            "default": None,
            "doc": "The fee for a check-up; null when not known.",
            "axt.label": "Fee for a check-up",
            "axt.label_translations": {DE: "Gebühr für eine Untersuchung"},
            "axt.emoji": "💶",
            "axt.min": 0,
        },
        {
            "name": "currency",
            "type": "string",
            "default": "EUR",
            "doc": "The currency of the fee, ISO 4217.",
            "axt.label": "Currency",
            "axt.label_translations": {DE: "Währung"},
            "axt.emoji": "💱",
            "axt.format": "currency",
        },
        {
            "name": "iban",
            "type": "string",
            "default": "",
            "doc": "The account for invoices; empty when not known.",
            "axt.label": "IBAN",
            "axt.emoji": "🏦",
            "axt.format": "iban",
            "axt.sensitive": True,
            "axt.advanced": True,
            "axt.group": "billing",
            "axt.example": "DE89370400440532013000",
        },
        {
            "name": "bic",
            "type": "string",
            "default": "",
            "doc": "The BIC of the account; empty when not known.",
            "axt.label": "BIC",
            "axt.emoji": "🏦",
            "axt.format": "bic",
            "axt.advanced": True,
            "axt.group": "billing",
        },
        {
            "name": "notes",
            "type": "string",
            "default": "",
            "doc": "Notes in CommonMark.",
            "axt.label": "Notes",
            "axt.label_translations": {DE: "Notizen"},
            "axt.emoji": "📝",
            "axt.format": "markdown",
            "axt.multiline": True,
            "axt.max_length": 10000,
        },
        {
            "name": "tags",
            "type": {"type": "array", "items": "string"},
            "default": [],
            "doc": "Words to find the practice by.",
            "axt.label": "Tags",
            "axt.label_translations": {DE: "Schlagwörter"},
            "axt.emoji": "🔖",
            "axt.min_length": 1,
            "axt.max_length": 32,
        },
        {
            "name": "website",
            "type": ["null", "string"],
            "default": None,
            "doc": "The practice's website; null when none.",
            "axt.label": "Website",
            "axt.label_translations": {DE: "Webseite"},
            "axt.emoji": "🌐",
            "axt.format": "url",
            "axt.example": "https://example.org/",
            "axt.group": "contact",
        },
    ],
}
VET_TEXT = compact(VET)
VET_VALUE = {
    "name": "Tierarztpraxis am Park",
    "kind": "EMERGENCY",
    "phone": "+49301234567",
    "email": "praxis@example.org",
    "address": {"street": "Hauptstraße 1", "postal_code": "10115", "locality": "Berlin", "country": "DE"},
    "colour": "#2E7D32",
    "rating": 5,
    "visit_minutes": 20,
    "fee": 45.5,
    "currency": "EUR",
    "iban": "DE89370400440532013000",
    "bic": "COBADEFFXXX",
    "notes": "Open **24 hours**.\nParking behind the house.",
    "tags": ["cats", "dogs", "𝄞𝄞"],
    "website": "https://example.org/vet",
}

# What a receiver shows, by spec/metadata.md, sections 4 and 5.
VET_ORDER = [
    "name",
    "kind",
    "phone",
    "email",
    "website",
    "address",
    "colour",
    "rating",
    "visit_minutes",
    "fee",
    "currency",
    "iban",
    "bic",
    "notes",
    "tags",
]

# --- a schema whose attributes break their rules, each of which a receiver ignores ----------------

LOOSE = {
    "type": "record",
    "name": "Loose",
    "namespace": "com.example",
    "doc": "Attributes that break their rules.",
    "axt.label": 7,
    "axt.emoji": "hello",
    "axt.colour": "red",
    "axt.groups": {"misc": {"label": "Other", "label_translations": {DE: "Anderes"}, "emoji": "two words"}},
    "fields": [
        {
            "name": "code",
            "type": "string",
            "default": "",
            "doc": "A pattern outside I-Regexp.",
            "axt.pattern": "\\d{5}",
            "axt.order": 2,
        },
        {
            "name": "count",
            "type": "int",
            "default": 0,
            "doc": "A format on a number.",
            "axt.format": "email",
            "axt.min": 10,
            "axt.max": 1,
            "axt.order": 2,
        },
        {
            "name": "title",
            "type": "string",
            "default": "",
            "doc": "English under the tag en.",
            "axt.label": "Title",
            "axt.label_translations": {"en": "Title", DE: "Titel"},
            "axt.order": 1.5,
        },
        {
            "name": "mood",
            "type": "string",
            "default": "",
            "doc": "An emoji that is a word.",
            "axt.emoji": "happy",
            "axt.format": "zip-code",
            "axt.min_length": -1,
            "axt.group": "Not A Key",
        },
        {
            "name": "address",
            "type": {"type": "string", "axt.format": "email"},
            "default": "",
            "doc": "A format on the field's type, not on the field.",
            "axt.order": 1,
            "axt.multiline": "yes",
        },
        {
            "name": "size",
            "type": "int",
            "default": 0,
            "doc": "An unknown attribute.",
            "axt.colour": "red",
            "axt.max": "9",
            "axt.group": "misc",
        },
        {
            "name": "rank",
            "type": "string",
            "default": "",
            "doc": "A pattern that is not a string.",
            "axt.pattern": ["[0-9]"],
        },
        {
            "name": "level",
            "type": {
                "type": "enum",
                "name": "LooseLevel",
                "doc": "LOW: low. HIGH: high.",
                "symbols": ["LOW", "HIGH"],
                "default": "LOW",
                "axt.symbols": {"LOW": {"label": "Low", "emoji": "x"}, "HIGH": {"label": "", "emoji": "🔺"}},
            },
            "default": "LOW",
            "doc": "Symbols whose entries break a rule each.",
        },
    ],
}
LOOSE_TEXT = compact(LOOSE)
LOOSE_PROBLEMS = [
    ("", "axt.colour is not an attribute of this specification"),
    (
        "",
        "axt.emoji: not an emoji: 1 to 10 code points, no control character or space, ASCII only in a keycap",
    ),
    ("", "axt.label: not one line of 1 to 256 bytes"),
    (
        "",
        "axt.groups: misc: emoji: not an emoji: 1 to 10 code points, no control character or space, "
        "ASCII only in a keycap",
    ),
    ("rank", "axt.pattern: not a string"),
    (
        "level",
        "axt.symbols: LOW: emoji: not an emoji: 1 to 10 code points, no control character or space, "
        "ASCII only in a keycap",
    ),
    ("code", "axt.pattern: \\d is not an escape of RFC 9485"),
    ("count", "axt.format: on a field whose value type is not string"),
    ("count", "axt.max: axt.min above axt.max"),
    ("count", "axt.min: axt.min above axt.max"),
    (
        "title",
        "axt.label_translations: not a map of up to 64 language tags of RFC 5646, other than en and each "
        "once, to one line of text",
    ),
    ("title", "axt.order: not an integer of 32 bits"),
    (
        "mood",
        "axt.emoji: not an emoji: 1 to 10 code points, no control character or space, ASCII only in a keycap",
    ),
    ("mood", "axt.group: not a key of the form of a field name"),
    ("mood", "axt.min_length: not an integer of at least 0"),
    ("mood", "axt.format 'zip-code' is not a format of this specification"),
    ("address", "axt.multiline: not a boolean"),
    ("address", "axt.format does not belong on a type"),
    ("size", "axt.colour is not an attribute of this specification"),
    ("size", "axt.max: not a finite number"),
]
LOOSE_VALUE = {
    "code": "abc",
    "count": 5,
    "title": "x",
    "mood": "",
    "address": "not an email",
    "size": 99,
    "rank": "x",
    "level": "HIGH",
}
LOOSE_ORDER = [
    "address",
    "code",
    "count",
    "title",
    "mood",
    "size",
    "rank",
    "level",
]  # order 1, 2, 2 (schema order), then the rest

# Three results of describe written out from spec/metadata.md, sections 3.3 to 5, rather than computed.
F = {
    "format": None,
    "placeholder": None,
    "example": None,
    "multiline": False,
    "sensitive": False,
    "advanced": False,
    "group": None,
    "preferred_length": None,
    "unit": None,
    "symbols": None,
    "record": None,
}
PINNED = [
    (
        (LOOSE, None, ["de"]),
        {
            "label": None,
            "help": None,
            "emoji": None,
            "fields": ["address", "code", "count", "title", "mood", "size", "rank", "level"],
            "groups": {"misc": {"label": "Anderes", "help": None, "emoji": None}},
        },
    ),
    ((LOOSE, "title", ["de"]), dict(F, label="Title", help=None, emoji=None, format="plain")),
    (
        (VET, "phone", ["en"]),
        dict(
            F,
            label="Phone",
            help=None,
            emoji="📞",
            format="phone",
            placeholder="+49301234567",
            example="+49301234567",
            group="contact",
        ),
    ),
]

# --- checks: a record per breach --------------------------------------------------------------------
# (label, the change to VET_VALUE, the path expected, the attribute expected); None for a record that passes.


def change(**fields: Any) -> Callable[[dict[str, Any]], dict[str, Any]]:
    return lambda v: dict(v, **fields)


def address(**fields: Any) -> Callable[[dict[str, Any]], dict[str, Any]]:
    return lambda v: dict(v, address=dict(v["address"], **fields))


CHECKS = [
    ("every value meets its checks", change(), None, None),
    (
        "an empty string meets a format and a pattern",
        lambda v: dict(
            v,
            phone="",
            email="",
            colour="",
            iban="",
            bic="",
            address=dict(v["address"], postal_code="", country=""),
        ),
        None,
        None,
    ),
    ("null meets every check", change(rating=None, fee=None, website=None), None, None),
    (
        "an email address with non-ASCII letters, RFC 6532",
        change(email="jörg.müller@bücher.example"),
        None,
        None,
    ),
    ("a colour in upper and lower case", change(colour="#a1B2c3"), None, None),
    ("a URL with port, query and fragment", change(website="https://example.org:8443/a/b?c=d#e"), None, None),
    (
        "a value at the maximum length in code points, of which each takes two UTF-16 units",
        change(tags=["𝄞" * 32]),
        None,
        None,
    ),
    ("a number at both limits", change(rating=1, visit_minutes=240), None, None),
    ("a phone number with spaces", change(phone="+49 30 1234567"), "phone", "axt.format"),
    ("a phone number without its plus", change(phone="49301234567"), "phone", "axt.format"),
    ("a phone number of 16 digits", change(phone="+4930123456789012"), "phone", "axt.format"),
    ("an email address without a domain", change(email="praxis@"), "email", "axt.format"),
    ("an email address with two dots in a row", change(email="pra..xis@example.org"), "email", "axt.format"),
    ("a URL with another scheme", change(website="ftp://example.org/"), "website", "axt.format"),
    ("a URL without a host", change(website="https:///vet"), "website", "axt.format"),
    ("a URL with a space", change(website="https://example.org/a b"), "website", "axt.format"),
    ("a colour of five digits", change(colour="#2e7d3"), "colour", "axt.format"),
    ("a colour without its #", change(colour="2e7d32"), "colour", "axt.format"),
    ("an IBAN whose check digits do not match", change(iban="DE89370400440532013001"), "iban", "axt.format"),
    ("an IBAN in groups of four", change(iban="DE89 3704 0044 0532 0130 00"), "iban", "axt.format"),
    ("a BIC of nine characters", change(bic="COBADEFFX"), "bic", "axt.format"),
    ("a country code in lower case", address(country="de"), "address.country", "axt.format"),
    ("a currency code in lower case", change(currency="eur"), "currency", "axt.format"),
    ("a postal code of four digits", address(postal_code="1011"), "address.postal_code", "axt.pattern"),
    (
        "a postal code that holds five digits and more",
        address(postal_code="10115 Berlin"),
        "address.postal_code",
        "axt.pattern",
    ),
    (
        "a postal code followed by a line feed",
        address(postal_code="10115\n"),
        "address.postal_code",
        "axt.pattern",
    ),
    ("an empty name below its minimum length", change(name=""), "name", "axt.min_length"),
    (
        "a tag above its maximum length of 32 code points",
        change(tags=["cats", "𝄞" * 33]),
        "tags[1]",
        "axt.max_length",
    ),
    ("an empty tag, the second item", change(tags=["cats", ""]), "tags[1]", "axt.min_length"),
    ("a rating below its minimum", change(rating=0), "rating", "axt.min"),
    ("a rating above its maximum", change(rating=6), "rating", "axt.max"),
    ("a visit longer than its maximum in minutes", change(visit_minutes=241), "visit_minutes", "axt.max"),
    ("a fee that is not a number", change(fee=math.nan), "fee", "axt.min"),
    ("a negative fee", change(fee=-0.5), "fee", "axt.min"),
    (
        "two values that break a check: the first in the order of the encoding",
        change(phone="030 1234567", rating=9),
        "phone",
        "axt.format",
    ),
]

# Every format of spec/metadata.md, section 6.3, with values that have it and values that do not.
FORMAT_VALUES = {
    "plain": (["any text", "a\nb"], []),
    "markdown": (["# Title\n\n*text*"], []),
    "email": (
        ["anna@example.org", "a.b+c@sub.example.org", "jörg@bücher.example"],
        [
            "anna",
            "anna@@example.org",
            ".anna@example.org",
            "anna@example.org.",
            "anna smith@example.org",
            "a" * 65 + "@example.org",
        ],
    ),
    "phone": (["+49301234567", "+12"], ["+0301234567", "+1", "0049 30 1234567", "+49-30-1234567"]),
    "url": (
        ["http://example.org", "HTTPS://example.org/a?b#c", "https://[2001:db8::1]:8443/"],
        [
            "mailto:anna@example.org",
            "https://",
            "https://exa mple.org/",
            "https://example.org/ä",
            "//example.org/",
        ],
    ),
    "uri": (
        [
            "tel:+49301234567",
            "urn:isbn:9783161484100",
            "mailto:anna@example.org",
            "https://example.org/%C3%A4",
        ],
        ["example.org", "1http://example.org", "https://example.org/%zz", "https://[fe80::1%25eth0]/"],
    ),
    "colour": (["#000000", "#FFFFFF", "#2e7D32"], ["#fff", "#2e7d32ff", "#gggggg"]),
    "iban": (
        ["DE89370400440532013000", "GB82WEST12345698765432"],
        ["DE89370400440532013001", "de89370400440532013000", "DE8937040044", "DE89 3704 0044 0532 0130 00"],
    ),
    "bic": (["COBADEFF", "COBADEFFXXX"], ["COBADEF", "cobadeff", "COBADEFFXX"]),
    "country": (["DE", "AT"], ["DEU", "de", "D"]),
    "language": (["de", "de-AT", "zh-Hant-TW", "de-CH-1996"], ["de_AT", "x-private", "i-klingon", "de-"]),
    "currency": (["EUR", "CHF"], ["eur", "EURO", "€"]),
    "media-type": (
        ["application/pdf", "image/svg+xml", "text/vnd.a"],
        ["application", "application/pdf; charset=utf-8", "/pdf"],
    ),
    "ucum": (["kg", "{glass}", "mm[Hg]", "10*3/uL"], ["k g", "°C"]),
}

# I-Regexp: valid patterns with values that match the whole value and values that do not.
PATTERNS = [
    ("[0-9]{5}", ["10115"], ["1011", "101150", "10115\n", " 10115"]),
    ("^[0-9]+$", ["^12$"], ["12"]),
    ("a.c", ["abc", "a c"], ["a\nc", "a\rc", "ac"]),
    ("colou?r|grey", ["color", "colour", "grey"], ["colours", "greyish", "colorgrey"]),
    ("\\p{Lu}\\p{Ll}+", ["Mimi", "Ärger"], ["mimi", "MIMI", "Mimi2"]),
    ("[^0-9]*", ["", "Mimi"], ["Mimi2"]),
    ("(ab){2,3}", ["abab", "ababab"], ["ab", "abababab"]),
    ("[\\p{L} \\-]{1,20}", ["Anna-Lena Müller"], ["Anna_Lena", "A" * 21]),
    ("\\P{N}+", ["Mimi"], ["Mimi1", "Ⅻ"]),
    ("[a-c-]+", ["a-b", "-"], ["d"]),
    ("\\.\\*\\{\\}", [".*{}"], ["x*{}"]),
]
# Patterns that are not an I-Regexp or exceed its limits in spec/metadata.md; a receiver ignores them.
BAD_PATTERNS = [
    ("\\d{5}", "the escape \\d"),
    ("\\w+", "the escape \\w"),
    ("(?:ab)+", "a group with ?:"),
    ("a*?", "a lazy quantifier"),
    ("a{2,1}", "a range quantifier whose maximum is below its minimum"),
    ("[z-a]", "a range whose end is below its start"),
    ("[^]", "the class [^]"),
    ("a{1001}", "a range quantifier above 1000"),
    ("\\$", "an escaped $, which is a NormalChar"),
    ("(a", "a group that does not end"),
    ("\\p{IsBasicLatin}", "a Unicode block"),
    ("[a-z-[aeiou]]", "class subtraction"),
    ("x" * 1025, "a pattern above 1,024 bytes"),
]
CODE: dict[str, Any] = {
    "type": "record",
    "name": "Code",
    "namespace": "com.example",
    "doc": "One field with a pattern.",
    "fields": [{"name": "code", "type": "string", "default": "", "doc": "A code."}],
}
FORMATTED: dict[str, Any] = {
    "type": "record",
    "name": "Formatted",
    "namespace": "com.example",
    "doc": "One field with a format.",
    "fields": [{"name": "value", "type": "string", "default": "", "doc": "A value."}],
}


def with_pattern(pattern: Any) -> dict[str, Any]:
    s = copy.deepcopy(CODE)
    s["fields"][0]["axt.pattern"] = pattern
    return s


def with_format(name: str) -> dict[str, Any]:
    s = copy.deepcopy(FORMATTED)
    s["fields"][0]["axt.format"] = name
    return s


# A field path into a map, for time values (spec/metadata.md, section 7.2).
DATE_TEXT = (HERE.parents[1] / "types" / "axt" / "Date.avsc").read_text(encoding="utf-8")
DUE = {
    "type": "record",
    "name": "Due",
    "namespace": "com.example",
    "doc": "Dates by name.",
    "fields": [
        {
            "name": "due",
            "type": {"type": "map", "values": json.loads(DATE_TEXT)},
            "default": {},
            "doc": "When each thing is due.",
        }
    ],
}
DUE_VALUE = {
    "due": {
        "tax": {"year": 2027, "month": 5, "day": 31},
        'vet "check"': {"year": 2027, "month": 2, "day": 30},
    }
}


# --- checks -----------------------------------------------------------------------------------------


def encode(schema: Any, value: Any) -> bytes:
    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, fastavro.parse_schema(schema, _write_hint=False), value)
    return buf.getvalue()


def roundtrip(schema: Any, value: dict[str, Any]) -> bytes:
    data = encode(schema, value)
    parsed = fastavro.parse_schema(schema, _write_hint=False)
    back: Any = fastavro.schemaless_reader(io.BytesIO(data), parsed, parsed)
    apache = avro.schema.parse(compact(schema))
    datum = avro.io.DatumReader(apache).read(avro.io.BinaryDecoder(io.BytesIO(data)))
    out = io.BytesIO()
    avro.io.DatumWriter(apache).write(datum, avro.io.BinaryEncoder(out))
    assert out.getvalue() == data

    def same(a: Any, b: Any) -> bool:
        return (isinstance(a, float) and math.isnan(a) and math.isnan(b)) or a == b

    assert all(same(back[k], value[k]) for k in value)
    return data


def first(schema: Any, value: Any) -> tuple[str | None, str | None]:
    found = mr.breaches(schema, value)
    return (found[0][0], found[0][1]) if found else (None, None)


def check() -> str:
    # The illustration keeps the rules of spec/types.md, section 5, and of every attribute.
    rules.check_type(VET, "com.example.Vet", VET, set(), [])
    rules.check_type(LOOSE_CLEAN, "com.example.Loose", LOOSE_CLEAN, set(), [])
    if rules.failures:
        raise SystemExit("\n".join(["checks failed:"] + rules.failures))
    assert mr.schema_problems(VET) == []
    pcf = to_parsing_canonical_form(fastavro.parse_schema(VET, _write_hint=False))
    assert pcf == to_parsing_canonical_form(fastavro.parse_schema(without_attributes(VET), _write_hint=False))
    assert avro.schema.parse(pcf).canonical_form == pcf
    roundtrip(VET, VET_VALUE)

    # A sender's schema whose attributes break their rules; a receiver ignores each of them.
    assert sorted(mr.schema_problems(LOOSE)) == sorted(LOOSE_PROBLEMS), sorted(mr.schema_problems(LOOSE))
    assert mr.breaches(LOOSE, LOOSE_VALUE) == []
    assert mr.describe(LOOSE, None, ["de"])["fields"] == LOOSE_ORDER
    shown = mr.describe(LOOSE, None, ["de"])
    assert (shown["label"], shown["emoji"]) == (None, None)
    assert mr.describe(LOOSE, "title", ["de"])["label"] == "Title"
    assert mr.describe(LOOSE, "count", ["en"])["format"] is None
    assert (
        mr.describe(LOOSE, "mood", ["en"])["format"] == "plain"
        and mr.describe(LOOSE, "mood", ["en"])["group"] is None
    )
    assert mr.describe(LOOSE, "address", ["en"])["format"] == "plain"
    # A member of an entry that breaks its rules is ignored on its own.
    assert shown["groups"] == {"misc": {"label": "Anderes", "help": None, "emoji": None}}, shown["groups"]
    assert mr.describe(LOOSE, "level", ["en"])["symbols"] == {
        "LOW": {"label": "Low", "help": None, "emoji": None},
        "HIGH": {"label": None, "help": None, "emoji": "🔺"},
    }

    # What a receiver shows.
    for args, want in PINNED:
        assert mr.describe(*args) == want, (args[1:], mr.describe(*args))
    for languages, label in (
        (["en"], "Vet practice"),
        (["de-AT", "en"], "Tierarztpraxis"),
        (["fr-CH", "fr"], "Vet practice"),
    ):
        shown = mr.describe(VET, None, languages)
        assert shown["label"] == label and shown["fields"] == VET_ORDER, shown
    assert mr.describe(VET, None, ["de"])["groups"]["billing"]["help"] == "Nur für Rechnungen."
    assert mr.describe(VET, "kind", ["de"])["symbols"]["EMERGENCY"]["label"] == "Notdienst"
    assert mr.describe(VET, "address", ["en"])["record"]["fields"] == [
        "country",
        "street",
        "postal_code",
        "locality",
    ]
    assert (
        mr.describe(VET, "iban", ["de"])["label"] == "IBAN"
        and mr.describe(VET, "iban", ["de"])["sensitive"] is True
    )

    # Records that break one check each.
    assert len(CHECKS) == 35
    for label, how, path, attribute in CHECKS:
        value = how(copy.deepcopy(VET_VALUE))
        roundtrip(VET, value)
        assert first(VET, value) == (path, attribute), (label, first(VET, value))
    for name, (good, bad) in FORMAT_VALUES.items():
        assert name in mr.FORMATS
        for v in good:
            assert mr.FORMATS[name](v), (name, v)
        for v in bad:
            assert not mr.FORMATS[name](v), (name, v)
            assert first(with_format(name), {"value": v}) == ("value", "axt.format"), (name, v)
    assert sorted(FORMAT_VALUES) == sorted(mr.FORMATS)
    for pattern, good, bad in PATTERNS:
        assert mr.iregexp_problem(pattern) is None, pattern
        for v in good:
            assert first(with_pattern(pattern), {"code": v}) == (None, None), (pattern, v)
        for v in bad:
            assert first(with_pattern(pattern), {"code": v}) == ("code", "axt.pattern"), (pattern, v)
    for pattern, why in BAD_PATTERNS:
        assert mr.iregexp_problem(pattern), why
        assert mr.schema_problems(with_pattern(pattern)) and first(with_pattern(pattern), {"code": "?"}) == (
            None,
            None,
        ), why

    # The paths into an array, a nested record and a map, and the record itself.

    def tm_check(full: str, v: dict[str, Any]) -> str | None:
        return "the day 30 in February" if (v["month"], v["day"]) == (2, 30) else None

    assert mr.breaches(DUE, DUE_VALUE, tm_check, attributes=False) == [
        ('due["vet \\"check\\""]', "axt.Date", "the day 30 in February")
    ]
    assert (
        mr.path_join("", "a") == "a"
        and mr.path_join("a", 0) == "a[0]"
        and mr.path_join("a[0]", "b") == "a[0].b"
    )
    assert mr.error_field("x" * 1024) == "x" * 1024 and mr.error_field("x" * 1025) is None
    return pcf


LOOSE_CLEAN = without_attributes(LOOSE)  # Loose keeps the rules of section 5 apart from its attributes
PCF = check()


def main() -> None:
    print("== com.example.Vet ==")
    print(f"schema: {len(VET_TEXT.encode())} bytes")
    fp = rules.crc64_avro(PCF.encode())
    print(f"canonical form, the same without any attribute: {PCF}")
    print(f"CRC-64-AVRO 0x{fp:016x}, bytes {fp.to_bytes(8, 'little').hex(' ')}")
    print(f"value: {len(encode(VET, VET_VALUE))} bytes")
    for languages in (["en"], ["de-AT", "en"], ["fr-CH", "fr"]):
        print(f"type, {languages}: {json.dumps(mr.describe(VET, None, languages), ensure_ascii=False)}")
    for field_path in ("kind", "phone", "address", "address.postal_code", "iban", "visit_minutes"):
        print(f"{field_path}, ['de']: {json.dumps(mr.describe(VET, field_path, ['de']), ensure_ascii=False)}")
    print()
    print("| Record | Field | Attribute |")
    print("| --- | --- | --- |")
    for label, _how, path, attribute in CHECKS:
        print(
            f"| {label} | {'—' if path is None else f'`{path}`'} | "
            f"{'—' if attribute is None else f'`{attribute}`'} |"
        )
    print()
    print(f"com.example.Loose: {len(LOOSE_PROBLEMS)} attributes a sender breaks, each ignored by a receiver")
    for where, why in LOOSE_PROBLEMS:
        print(f"  {where or '(the type)'}: {why}")
    print(
        f"formats: {len(FORMAT_VALUES)}, with {sum(len(g) for g, _ in FORMAT_VALUES.values())} values "
        f"that have them and {sum(len(b) for _, b in FORMAT_VALUES.values())} that do not"
    )
    print(
        f"I-Regexp: {len(PATTERNS)} patterns with {sum(len(g) + len(b) for _, g, b in PATTERNS)} values; "
        f"{len(BAD_PATTERNS)} patterns outside RFC 9485 or its limits"
    )
    print("all checks passed")


if __name__ == "__main__":
    main()
