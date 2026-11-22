# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Write types/axt/Field.avsc, the schema of the bricks of spec/fields.md, and its copy in Offer.avsc.

axt.Offer carries a description in each offered type and defines axt.Field in place there, as
types/axt/Field.avsc defines it. This script is the source of both: it writes Field.avsc and
puts the same definition into the field description of axt.OfferType.

    python3 conformance/tools/field_schema.py          # write both files
    python3 conformance/tools/field_schema.py --check  # fail if a file is not what it writes
"""

import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
FIELD_FILE = REPO / "types" / "axt" / "Field.avsc"
OFFER_FILE = REPO / "types" / "axt" / "Offer.avsc"
S = "spec/fields.md"


def f(name: str, type_: Any, doc: str, **kw: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"name": name, "type": type_}
    if "default" in kw:
        out["default"] = kw["default"]
    out["doc"] = doc
    return out


def rec(name: str, doc: str, fields: list[dict[str, Any]]) -> dict[str, Any]:
    return {"type": "record", "name": name, "doc": doc, "fields": fields}


def nullable(name: str, t: str, doc: str) -> dict[str, Any]:
    return f(name, ["null", t], doc, default=None)


def text(name: str, doc: str) -> dict[str, Any]:
    return f(name, "string", doc, default="")


def default(t: str, what: str) -> dict[str, Any]:
    return nullable(
        "default",
        t,
        f"The value the field starts with when its user gives none, {what}, which meets the field's "
        f"checks; null for none ({S}, section 3.3).",
    )


def lengths(unit: str) -> list[dict[str, Any]]:
    return [
        nullable(
            "min_length",
            "int",
            f"The fewest {unit} a value has, at least 0; null for no limit ({S}, section 4.1).",
        ),
        nullable(
            "max_length",
            "int",
            f"The most {unit} a value has, at least 0 and at least min_length; null for no limit "
            f"({S}, section 4.1).",
        ),
    ]


PLACEHOLDER = text(
    "placeholder",
    f"A text that an empty input for the field shows, such as +49301234567; the empty string for none "
    f"({S}, section 3.4).",
)
EXAMPLE = text(
    "example",
    f"An example value as text, which meets the field's checks; the empty string for none ({S}, "
    f"section 3.4).",
)
PREFERRED = nullable(
    "preferred_length",
    "int",
    f"The number of code points an input for the field has room for, at least 1 and at most max_length; "
    f"null for none. Not a limit ({S}, section 4.1).",
)


def number(name: str, t: str, what: str) -> dict[str, Any]:
    return rec(
        name,
        f"A field of {what} ({S}, section 4.2).",
        [
            default(t, f"a {t}"),
            nullable("min", t, f"The smallest value the field holds; null for no limit ({S}, section 4.2)."),
            nullable(
                "max",
                t,
                f"The largest value the field holds, at least min; null for no limit ({S}, section 4.2).",
            ),
            text(
                "unit",
                f"The unit of the value, a case-sensitive code of UCUM such as min for minutes; the empty "
                f"string when the field has no fixed unit ({S}, section 4.2).",
            ),
            PLACEHOLDER,
            EXAMPLE,
        ],
    )


SEMANTIC = [
    ("EmailField", "email", "an email address"),
    ("PhoneField", "phone", "a phone number in E.164 form"),
    ("UrlField", "url", "a web address of the scheme http or https"),
    ("UriField", "uri", "a URI of any scheme"),
    ("ColourField", "colour", "a colour of sRGB"),
    ("IbanField", "iban", "an IBAN"),
    ("BicField", "bic", "a BIC"),
    ("CountryField", "country", "a country code of ISO 3166-1 alpha-2"),
    ("LanguageField", "language", "a language tag"),
    ("CurrencyField", "currency", "a currency code of ISO 4217"),
    ("MediaTypeField", "media-type", "a media type"),
    ("UcumField", "ucum", "a unit code of UCUM"),
]


def semantic(name: str, fmt: str, what: str) -> dict[str, Any]:
    return rec(
        name,
        f"A field of strings that each hold {what}: the format {fmt} of spec/metadata.md, section 6.3, "
        f"built in ({S}, section 5).",
        [
            default("string", f"a string of the format {fmt}"),
            *lengths("code points"),
            PREFERRED,
            PLACEHOLDER,
            EXAMPLE,
        ],
    )


def translations(what: str) -> dict[str, Any]:
    return f(
        f"{what}_translations",
        {"type": "map", "values": "string"},
        f"The {what} in other languages, by language tag; empty when it is not translated ({S}, "
        f"section 3.2).",
        default={},
    )


TEXTS = rec(
    "FieldTexts",
    f"The texts a receiver shows for a field, an enum symbol or a group, in English and in other "
    f"languages ({S}, section 3.2).",
    [
        text(
            "label",
            f"The name shown for it, in English, one line of at most 256 bytes; the empty string for none, "
            f"when its name is shown ({S}, section 3.2).",
        ),
        translations("label"),
        text(
            "help",
            f"One or two sentences in English that say what the value is or how to enter it, one line of at "
            f"most 1,024 bytes; the empty string for none ({S}, section 3.2).",
        ),
        translations("help"),
        text(
            "emoji",
            f"An emoji shown next to the label, 1 to 10 code points; the empty string for none "
            f"({S}, section 3.2).",
        ),
    ],
)

STRING = rec(
    "StringField",
    f"A field of plain text ({S}, section 4.1).",
    [
        default("string", "a string"),
        *lengths("code points"),
        nullable(
            "pattern",
            "string",
            f"An I-Regexp of RFC 9485 that a non-empty value matches as a whole, at most 1,024 bytes; null "
            f"for none ({S}, section 4.1).",
        ),
        f(
            "multiline",
            "boolean",
            f"True when a value may hold several lines, separated by LF, so that an input of several lines "
            f"is offered ({S}, section 4.1).",
            default=False,
        ),
        PREFERRED,
        PLACEHOLDER,
        EXAMPLE,
    ],
)

MARKDOWN = rec(
    "MarkdownField",
    f"A field of text read as CommonMark: the format markdown of spec/metadata.md, section 6.3, built in "
    f"({S}, section 5).",
    [default("string", "a string"), *lengths("code points"), PREFERRED, PLACEHOLDER, EXAMPLE],
)

BOOLEAN = rec(
    "BooleanField", f"A field of true or false ({S}, section 4.3).", [default("boolean", "true or false")]
)
BYTES = rec(
    "BytesField", f"A field of bytes ({S}, section 4.3).", [default("bytes", "bytes"), *lengths("bytes")]
)

SYMBOL = rec(
    "EnumSymbol",
    f"One symbol of an enum field, with its texts ({S}, section 4.4).",
    [
        f(
            "symbol",
            "string",
            f"The symbol, an Avro name in UPPER_SNAKE_CASE such as EMERGENCY ({S}, section 4.4).",
        ),
        f(
            "texts",
            "axt.FieldTexts",
            f"The texts shown for the symbol; without a label the symbol is shown ({S}, section 4.4).",
        ),
    ],
)
ENUM = rec(
    "EnumField",
    f"A field whose value is one of a list of symbols ({S}, section 4.4).",
    [
        f(
            "name",
            "string",
            f"The name of the enum, an Avro name in UpperCamelCase, such as VetKind; the enum of the "
            f"derived schema has it ({S}, section 4.4).",
        ),
        f(
            "symbols",
            {"type": "array", "items": SYMBOL},
            f"The symbols, at least one, in their order ({S}, section 4.4).",
        ),
        f(
            "fallback",
            "string",
            f"The symbol, one of symbols, that a receiver reads a symbol it does not know as ({S}, "
            f"section 4.4).",
        ),
        default("string", "one of symbols"),
    ],
)

LIST = rec(
    "ListField",
    f"A field whose value is a list of items of one typed field ({S}, section 4.5).",
    [
        f(
            "items",
            "axt.Field",
            f"The typed field of each item: its kind and checks apply to each item, and its texts name one "
            f"item. Its name is that of the list ({S}, section 4.5).",
        )
    ],
)
MAP = rec(
    "MapField",
    f"A field whose value maps strings to values of one typed field ({S}, section 4.5).",
    [
        f(
            "values",
            "axt.Field",
            f"The typed field of each value: its kind and checks apply to each value, and its texts name one "
            f"value. Its name is that of the map ({S}, section 4.5).",
        )
    ],
)

GROUP = rec(
    "FieldGroup",
    f"A group of fields of an object, shown together under its texts ({S}, section 4.6).",
    [
        f(
            "key",
            "string",
            f"The group key that the fields of the group name in their group, at most 64 bytes "
            f"({S}, section 3.4).",
        ),
        f(
            "texts",
            "axt.FieldTexts",
            f"The texts shown for the group; without a label the key is shown ({S}, section 4.6).",
        ),
    ],
)
OBJECT = rec(
    "ObjectField",
    f"A composite field: a value made of typed fields, such as an address of a street, a postal code and "
    f"a country ({S}, section 4.6).",
    [
        f(
            "name",
            "string",
            f"The name of the object, an Avro name in UpperCamelCase such as VetAddress, or at the root of a "
            f"type a full name such as com.example.Vet; the record of the derived schema has it "
            f"({S}, section 4.6).",
        ),
        f(
            "fields",
            {"type": "array", "items": "axt.Field"},
            f"The typed fields of the object, at least one, in the order of their encoding ({S}, "
            f"section 4.6).",
        ),
        f(
            "groups",
            {"type": "array", "items": GROUP},
            f"The groups that fields of the object name; empty when it has none ({S}, section 4.6).",
            default=[],
        ),
        nullable(
            "version",
            "int",
            f"At the root of a description, the version of the type within its major version, from 1 "
            f"(spec/types.md, section 3.2); null in a nested object ({S}, section 9.1).",
        ),
        text(
            "title",
            f"The name of a field of the object whose value is the title of a value, such as display_name; "
            f"the empty string for none ({S}, section 9.1).",
        ),
    ],
)

ANCHOR = {
    "type": "enum",
    "name": "DateTimeAnchor",
    "doc": f"What a receiver keeps of a date and time when its zone rules differ from the writer's: LOCAL, "
    f"the wall clock, or INSTANT, the instant (spec/time.md, section 6.4; {S}, section 4.7).",
    "symbols": ["LOCAL", "INSTANT"],
    "default": "LOCAL",
}
DATE = rec("DateField", f"A field of axt.Date values (spec/time.md; {S}, section 4.7).", [])
TIME = rec("TimeField", f"A field of axt.Time values (spec/time.md; {S}, section 4.7).", [])
DATE_TIME = rec(
    "DateTimeField",
    f"A field of axt.DateTime values (spec/time.md; {S}, section 4.7).",
    [f("anchor", ANCHOR, f"The anchor of the field's values ({S}, section 4.7).", default="LOCAL")],
)
DURATION = rec("DurationField", f"A field of axt.Duration values (spec/time.md; {S}, section 4.7).", [])
RELATION = rec(
    "RelationField",
    f"A field whose value is a list of relations, each an axt.Relation that links the record to another "
    f"record or to a thing outside AXT ({S}, section 11).",
    [],
)
EXTENSION = rec(
    "ExtensionField",
    f"A field whose value is a list of extensions, each an axt.Extension that holds a record of an app's own "
    f"type ({S}, section 12).",
    [],
)

KINDS = [
    STRING,
    number("IntField", "int", "32-bit integers"),
    number("LongField", "long", "64-bit integers"),
    number("DoubleField", "double", "numbers of double precision"),
    BOOLEAN,
    BYTES,
    ENUM,
    LIST,
    MAP,
    OBJECT,
    DATE,
    TIME,
    DATE_TIME,
    DURATION,
    MARKDOWN,
    *[semantic(*s) for s in SEMANTIC],
    RELATION,
    EXTENSION,
]

FIELD = {
    "type": "record",
    "name": "Field",
    "namespace": "axt",
    "doc": f"A typed field: a brick that describes one field of a type, its name, texts and checks, at the "
    f"level of the schema. A type is described by an object field at its root, from which its Avro schema is "
    f"derived. Defined in {S}.",
    "fields": [
        f("name", "string", f"The name of the field, in snake_case, such as postal_code ({S}, section 3.1)."),
        f(
            "doc",
            "string",
            f"What the value is, in English, for the developer; not empty. It says what an empty or absent "
            f"value means ({S}, section 3.1).",
        ),
        f("texts", TEXTS, f"The texts a receiver shows for the field ({S}, section 3.2)."),
        f(
            "required",
            "boolean",
            f"True when the field needs a value: not null, and not an empty string, bytes, list or map "
            f"({S}, section 3.3).",
            default=False,
        ),
        nullable(
            "order",
            "int",
            f"Where the field is shown among the fields of its object, the lowest first; null to "
            f"keep the order "
            f"of the fields ({S}, section 3.4).",
        ),
        text(
            "group",
            f"The key of the group of its object that the field is shown in; the empty string for none "
            f"({S}, section 3.4).",
        ),
        f(
            "sensitive",
            "boolean",
            f"True when the value is a secret or personal data that others near the screen should not see "
            f"({S}, section 3.4).",
            default=False,
        ),
        f(
            "advanced",
            "boolean",
            f"True when most users need not see or fill in the field ({S}, section 3.4).",
            default=False,
        ),
        f("kind", KINDS, f"The brick of the field's value: its kind and its checks ({S}, sections 4 and 5)."),
    ],
}


def dump(schema: Any) -> str:
    return json.dumps(schema, indent=2, ensure_ascii=False) + "\n"


def offer_text() -> str:
    """Offer.avsc with the definition of axt.Field in place in the field description of axt.OfferType."""
    offer = json.loads(OFFER_FILE.read_text(encoding="utf-8"))
    entry = offer["fields"][2]["type"]["items"]
    description = next(x for x in entry["fields"] if x["name"] == "description")
    description["type"] = FIELD
    return dump(offer)


def main() -> None:
    wanted = {FIELD_FILE: dump(FIELD), OFFER_FILE: offer_text()}
    if sys.argv[1:] == ["--check"]:
        stale = [p.name for p, t in wanted.items() if p.read_text(encoding="utf-8") != t]
        if stale:
            sys.exit(f"not what conformance/tools/field_schema.py writes: {', '.join(stale)}")
        print("Field.avsc and Offer.avsc are what this script writes")
        return
    for path, content in wanted.items():
        path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
