# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The rules of spec/metadata.md: the axt.* attributes of a schema, the formats, I-Regexp and the checks.

This module imports none of the other scripts, so that each of them can import it. It provides:

- iregexp(pattern): the pattern of RFC 9485 translated to Python's re, or IRegexpError for a
  pattern that is not an I-Regexp within the limits of spec/metadata.md, section 6.4;
- FORMATS: for each format of spec/metadata.md, section 6.3, a function that says whether a
  non-empty string has the format;
- schema_problems(schema): every attribute that breaks a rule of sections 2 to 6, for a sender's
  schema, which MUST have none (spec/types.md, section 5.9); unknown axt.* names included;
- describe(schema, path, languages): what a receiver shows of the type or of one field, with every
  attribute that breaks its rules ignored (section 3.3) and texts chosen by the Lookup of RFC 4647;
- breaches(schema, value, time_check): the values that break a check, as (path, attribute, why), in
  the order of the encoding, with the field paths of section 7.2. time_check, if given, is asked
  about every record of a time type first, so that one walk finds the time values that are not
  valid (spec/time.md, section 8) and the values that break a check; with relations, the rules of
  the relations of spec/fields.md, section 11.4, which fields_examples.py holds, are found in the
  same walk.

A value is either as fastavro decodes it or in the JSON form of spec/conformance.md, section 3.3,
in which bytes are hexadecimal strings. Unions of null and one other type are followed, and the
union of the two targets of axt.Relation, whose branch is the record whose fields the value has:
the only unions the example types and the vectors use.
"""

import functools
import json
import math
import re
import unicodedata
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any, TypeGuard, cast

# --- limits (spec/metadata.md) ------------------------------------------------------------------

LIMITS: dict[str, int] = {  # types/axt/limits.json
    k: v["value"]
    for k, v in json.loads(
        (Path(__file__).resolve().parents[2] / "types" / "axt" / "limits.json").read_text(encoding="utf-8")
    )["limits"].items()
}

MAX_LABEL = LIMITS["metadata.label"]  # bytes of UTF-8
MAX_HELP = LIMITS["metadata.help"]
MAX_PLACEHOLDER = LIMITS["metadata.placeholder"]
MAX_EXAMPLE = LIMITS["metadata.example"]
MAX_PATTERN = LIMITS["metadata.pattern"]  # bytes of UTF-8 of an I-Regexp
MAX_QUANTIFIER = LIMITS[
    "metadata.pattern_quantifier"
]  # the largest number in a range quantifier, RE2's limit
MAX_TRANSLATIONS = LIMITS["metadata.translations"]
MAX_TAG = LIMITS["manifest.language_tag"]
MAX_EMOJI_CODE_POINTS = LIMITS["metadata.emoji"]
MAX_GROUP_KEY = LIMITS["metadata.group_key"]  # bytes
MAX_PATH = LIMITS["protocol.error_field"]  # bytes of a field path in an ERROR (spec/protocol.md, section 8.1)
MIN_INT, MAX_INT = -(2**31), 2**31 - 1

NUMBERS = {"int", "long", "float", "double"}
PRIMITIVES = {"null", "boolean", "int", "long", "float", "double", "bytes", "string"}
TIME_TYPES = {"axt.Date", "axt.Time", "axt.DateTime", "axt.Duration"}
AVRO_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
KEY = re.compile(
    r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$"
)  # a group key, as a field name (spec/types.md, section 5.2)
# The langtag production of RFC 5646, section 2.1, matched without regard to case; the same as
# manifest_examples.LANGTAG, which generate_vectors.py compares with it.
LANGTAG = re.compile(
    r"^(?:[a-z]{2,3}(?:-[a-z]{3}){0,3}|[a-z]{4}|[a-z]{5,8})"
    r"(?:-[a-z]{4})?"
    r"(?:-(?:[a-z]{2}|[0-9]{3}))?"
    r"(?:-(?:[a-z0-9]{5,8}|[0-9][a-z0-9]{3}))*"
    r"(?:-[0-9a-wyz](?:-[a-z0-9]{2,8})+)*"
    r"(?:-x(?:-[a-z0-9]{1,8})+)?$",
    re.IGNORECASE,
)

# Where each attribute may sit (spec/metadata.md, section 2): on the type's record ("type"), on a
# nested record ("record"), on a field, on an enum.
TEXTS = ("axt.label", "axt.label_translations", "axt.help", "axt.help_translations", "axt.emoji")
ON_RECORD = set(TEXTS) | {"axt.groups"}
ON_TYPE = ON_RECORD | {"axt.version", "axt.title"}
ON_FIELD = set(TEXTS) | {
    "axt.format",
    "axt.pattern",
    "axt.min_length",
    "axt.max_length",
    "axt.preferred_length",
    "axt.min",
    "axt.max",
    "axt.unit",
    "axt.anchor",
    "axt.example",
    "axt.placeholder",
    "axt.multiline",
    "axt.sensitive",
    "axt.order",
    "axt.group",
    "axt.advanced",
}
ON_ENUM = {"axt.symbols"}
KNOWN = ON_TYPE | ON_FIELD | ON_ENUM
CHECKS = ("axt.format", "axt.pattern", "axt.min_length", "axt.max_length", "axt.min", "axt.max")
ENTRY_MEMBERS = {
    "label",
    "label_translations",
    "help",
    "help_translations",
    "emoji",
}  # an entry of axt.symbols, axt.groups

# --- text (spec/metadata.md, section 4) -----------------------------------------------------------

SEPARATORS = {0x00A0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000} | set(range(0x2000, 0x200B))


def control(c: str) -> bool:
    o = ord(c)
    return o < 0x20 or 0x7F <= o <= 0x9F


def one_line(text: Any, limit: int) -> bool:
    """Not empty, at most limit bytes, no control character (Cc), no U+2028 or U+2029."""
    return (
        isinstance(text, str)
        and text != ""
        and len(text.encode("utf-8")) <= limit
        and not any(control(c) or c in "  " for c in text)
    )


def translations_ok(value: Any, limit: int) -> bool:
    if not isinstance(value, dict) or len(value) > MAX_TRANSLATIONS:
        return False
    seen: set[str] = set()
    for tag, text in value.items():
        if (
            len(tag) > MAX_TAG
            or not re.fullmatch(r"[A-Za-z0-9-]+", tag)
            or not LANGTAG.match(tag)
            or tag.lower() == "en"
            or tag.lower() in seen
        ):
            return False
        seen.add(tag.lower())
        if not one_line(text, limit):
            return False
    return True


def emoji_ok(value: Any) -> bool:
    """1 to 10 code points; no control character or white space; ASCII only as the base of a keycap."""
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_EMOJI_CODE_POINTS:
        return False
    i = 0
    while i < len(value):
        c = value[i]
        if control(c) or ord(c) in SEPARATORS or c == " ":
            return False
        if ord(c) < 0x80:
            # a keycap: 0-9, # or *, an optional U+FE0F, then U+20E3
            rest = value[i + 1 :]
            if c not in "0123456789#*":
                return False
            if rest.startswith("⃣"):
                i += 2
            elif rest.startswith("️⃣"):
                i += 3
            else:
                return False
            continue
        i += 1
    return True


def lookup(english: str, translations: dict[str, str] | None, priority_list: Iterable[str]) -> str:
    """RFC 4647, section 3.4, Lookup, as spec/manifest.md, section 3.6: English by default."""
    texts = {tag.lower(): text for tag, text in (translations or {}).items()}
    texts.setdefault("en", english)
    for language_range in priority_list:
        subtags = language_range.lower().split("-")
        while subtags and subtags != ["*"]:
            if "-".join(subtags) in texts:
                return texts["-".join(subtags)]
            subtags.pop()
            if subtags and len(subtags[-1]) == 1:
                subtags.pop()
    return english


# --- formats (spec/metadata.md, section 6.3) ------------------------------------------------------

ATEXT = r"(?:[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]|[^\x00-\x7f])"
DOT_ATOM = re.compile(rf"{ATEXT}+(?:\.{ATEXT}+)*")
PCHAR = r"(?:[A-Za-z0-9._~!$&'()*+,;=:@-]|%[0-9A-Fa-f]{2})"
USERINFO = r"(?:[A-Za-z0-9._~!$&'()*+,;=:-]|%[0-9A-Fa-f]{2})*"
REG_NAME = r"(?:[A-Za-z0-9._~!$&'()*+,;=-]|%[0-9A-Fa-f]{2})*"
IP_FUTURE = r"v[0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+"
URI = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*):"
    rf"(?:(?P<slashes>//)(?:(?P<userinfo>{USERINFO})@)?(?P<host>\[(?P<literal>[^\]]*)\]|{REG_NAME})(?::[0-9]*)?(?:/{PCHAR}*)*"
    rf"|/(?:{PCHAR}+(?:/{PCHAR}*)*)?"
    rf"|{PCHAR}+(?:/{PCHAR}*)*"
    r"|)"
    rf"(?:\?(?:{PCHAR}|[/?])*)?(?:#(?:{PCHAR}|[/?])*)?"
)
IPV6 = re.compile(r"[0-9A-Fa-f:.]+")


def ipv6(text: str) -> bool:
    import ipaddress

    if not IPV6.fullmatch(text):
        return False  # RFC 3986 has no zone index
    try:
        ipaddress.IPv6Address(text)
        return True
    except ValueError:
        return False


def uri(text: str) -> re.Match[str] | None:
    m = URI.fullmatch(text)
    if not m:
        return None
    if m.group("literal") is not None and not (
        ipv6(m.group("literal")) or re.fullmatch(IP_FUTURE, m.group("literal"))
    ):
        return None
    return m


def email(text: str) -> bool:
    if text.count("@") != 1:
        return False
    local, domain = text.split("@")
    return (
        DOT_ATOM.fullmatch(local) is not None
        and DOT_ATOM.fullmatch(domain) is not None
        and len(local.encode("utf-8")) <= 64
        and len(text.encode("utf-8")) <= 254
    )


def url(text: str) -> bool:
    m = uri(text)
    return (
        m is not None
        and m.group("scheme").lower() in ("http", "https")
        and m.group("slashes") is not None
        and m.group("host") != ""
    )


def iban(text: str) -> bool:
    if not re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}", text):
        return False
    moved = text[4:] + text[:4]
    return int("".join(str(int(c, 36)) for c in moved)) % 97 == 1


RESTRICTED_NAME = r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}"
FORMATS: dict[str, Callable[[str], bool]] = {
    "plain": lambda s: True,
    "markdown": lambda s: True,
    "email": email,
    "phone": lambda s: re.fullmatch(r"\+[1-9][0-9]{1,14}", s) is not None,
    "url": url,
    "uri": lambda s: uri(s) is not None,
    "colour": lambda s: re.fullmatch(r"#[0-9A-Fa-f]{6}", s) is not None,
    "iban": iban,
    "bic": lambda s: re.fullmatch(r"[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?", s) is not None,
    "country": lambda s: re.fullmatch(r"[A-Z]{2}", s) is not None,
    "language": lambda s: (
        len(s) <= MAX_TAG and LANGTAG.match(s) is not None and re.fullmatch(r"[A-Za-z0-9-]+", s) is not None
    ),
    "currency": lambda s: re.fullmatch(r"[A-Z]{3}", s) is not None,
    "media-type": lambda s: re.fullmatch(f"{RESTRICTED_NAME}/{RESTRICTED_NAME}", s) is not None,
    "ucum": lambda s: re.fullmatch(r"[\x21-\x7e]+", s) is not None,
}

# --- I-Regexp (RFC 9485; spec/metadata.md, section 6.4) --------------------------------------------


class IRegexpError(ValueError):
    pass


CATEGORIES = {"L": "lmotu", "M": "cen", "N": "dlo", "P": "cdefios", "Z": "lps", "S": "ckmo", "C": "cfno"}
SINGLE_ESCAPES = {
    "(": "(",
    ")": ")",
    "*": "*",
    "+": "+",
    "-": "-",
    ".": ".",
    "?": "?",
    "[": "[",
    "\\": "\\",
    "]": "]",
    "^": "^",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "{": "{",
    "|": "|",
    "}": "}",
}
NOT_NORMAL = set("()*+.?[\\]{|}")  # NormalChar is every code point but these and the surrogates
ALL = [(0, 0xD7FF), (0xE000, 0x10FFFF)]


@functools.cache
def category_ranges(prop: str) -> tuple[tuple[int, int], ...]:
    """The code points of a general category (one letter: every category that begins with it), as ranges,
    by the Unicode version of Python's unicodedata."""
    out: list[tuple[int, int]] = []
    start: int | None = None
    prev: int | None = None
    for lo, hi in ALL:
        for cp in range(lo, hi + 1):
            if unicodedata.category(chr(cp)).startswith(prop):
                if start is None or prev is None or cp != prev + 1:
                    if start is not None and prev is not None:
                        out.append((start, prev))
                    start = cp
                prev = cp
    if start is not None and prev is not None:
        out.append((start, prev))
    return tuple(out)


def complement(ranges: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    nxt = 0
    for lo, hi in sorted(ranges):
        if lo > nxt:
            out.append((nxt, lo - 1))
        nxt = max(nxt, hi + 1)
    if nxt <= 0x10FFFF:
        out.append((nxt, 0x10FFFF))
    # without the surrogates, which a well-formed string never holds
    return [(lo, hi) for a, b in out for lo, hi in ((a, min(b, 0xD7FF)), (max(a, 0xE000), b)) if lo <= hi]


def char_class(ranges: Sequence[tuple[int, int]]) -> str:
    if not ranges:
        return "(?!)"
    return (
        "[" + "".join(f"\\U{lo:08x}" if lo == hi else f"\\U{lo:08x}-\\U{hi:08x}" for lo, hi in ranges) + "]"
    )


class _Parser:
    def __init__(self, text: str) -> None:
        self.s, self.i = text, 0

    def peek(self, k: int = 0) -> str | None:
        return self.s[self.i + k] if self.i + k < len(self.s) else None

    def take(self) -> str:
        c = self.peek()
        if c is None:
            raise IRegexpError("the pattern ends early")
        self.i += 1
        return c

    def regexp(self) -> str:
        branches = [self.branch()]
        while self.peek() == "|":
            self.i += 1
            branches.append(self.branch())
        return "|".join(branches)

    def branch(self) -> str:
        out = []
        while self.peek() not in (None, "|", ")"):
            out.append(self.piece())
        return "".join(out)

    def piece(self) -> str:
        atom = self.atom()
        c = self.peek()
        if c in ("*", "+", "?"):
            self.i += 1
            return atom + c
        if c == "{":
            self.i += 1
            low = self.number()
            high: int | None = low
            if self.peek() == ",":
                self.i += 1
                high = None if self.peek() == "}" else self.number()
            if self.take() != "}":
                raise IRegexpError("a range quantifier that does not end with }")
            if high is not None and high < low:
                raise IRegexpError("a range quantifier whose maximum is below its minimum")
            return atom + (
                f"{{{low}}}" if high == low else f"{{{low},}}" if high is None else f"{{{low},{high}}}"
            )
        return atom

    def number(self) -> int:
        start = self.i
        while (c := self.peek()) is not None and c in "0123456789":
            self.i += 1
        digits = self.s[start : self.i]
        if not digits:
            raise IRegexpError("a range quantifier without a number")
        if int(digits) > MAX_QUANTIFIER:
            raise IRegexpError(f"a range quantifier above {MAX_QUANTIFIER}")
        return int(digits)

    def atom(self) -> str:
        c = self.take()
        if c == "(":
            inner = self.regexp()
            if self.take() != ")":
                raise IRegexpError("a group that does not end with )")
            return "(?:" + inner + ")"
        if c == ".":
            return "[^\\n\\r]"
        if c == "\\":
            return char_class(self.escape())
        if c == "[":
            return char_class(self.class_expr())
        if c in NOT_NORMAL or 0xD800 <= ord(c) <= 0xDFFF:
            raise IRegexpError(f"{c!r} is not a NormalChar")
        return f"\\U{ord(c):08x}"

    def escape(self) -> list[tuple[int, int]]:
        """After a backslash: a SingleCharEsc or a catEsc or complEsc, as ranges."""
        c = self.take()
        if c in ("p", "P"):
            if self.take() != "{":
                raise IRegexpError("\\p or \\P without {")
            major = self.take()
            minor = self.take()
            if minor != "}":
                if self.take() != "}":
                    raise IRegexpError("a property of more than two letters")
            else:
                minor = ""
            if major not in CATEGORIES or (minor and minor not in CATEGORIES[major]):
                raise IRegexpError(f"\\{c}{{{major}{minor}}} is not a general category of RFC 9485")
            ranges = list(category_ranges(major + minor))
            return complement(ranges) if c == "P" else ranges
        if c in SINGLE_ESCAPES:
            cp = ord(SINGLE_ESCAPES[c])
            return [(cp, cp)]
        raise IRegexpError(f"\\{c} is not an escape of RFC 9485")

    def cc_char(self) -> int:
        """A CCchar, as a code point."""
        c = self.take()
        if c == "\\":
            nxt = self.take()
            if nxt not in SINGLE_ESCAPES:
                raise IRegexpError(f"\\{nxt} is not a SingleCharEsc")
            return ord(SINGLE_ESCAPES[nxt])
        if c in "-[]" or 0xD800 <= ord(c) <= 0xDFFF:
            raise IRegexpError(f"{c!r} is not a CCchar")
        return ord(c)

    def class_expr(self) -> list[tuple[int, int]]:
        negate = False
        if self.peek() == "^":
            if self.peek(1) == "]":
                raise IRegexpError("[^] is not allowed")
            negate = True
            self.i += 1
        ranges: list[tuple[int, int]] = []
        if self.peek() == "-":
            self.i += 1
            ranges.append((0x2D, 0x2D))
        elif self.peek() == "]":
            raise IRegexpError("an empty character class")
        while True:
            c = self.peek()
            if c is None:
                raise IRegexpError("a character class that does not end with ]")
            if c == "]":
                self.i += 1
                break
            if c == "-":
                if self.peek(1) != "]":
                    raise IRegexpError("a - inside a character class that is not at its start or end")
                self.i += 2
                ranges.append((0x2D, 0x2D))
                break
            if c == "\\" and self.peek(1) in ("p", "P"):
                self.i += 1
                ranges += self.escape()
                continue
            lo = self.cc_char()
            if self.peek() == "-" and self.peek(1) not in ("]", None):
                self.i += 1
                if self.peek() == "\\" and self.peek(1) in ("p", "P"):
                    raise IRegexpError("a range that ends with a category")
                hi = self.cc_char()
                if hi < lo:
                    raise IRegexpError("a range whose end is below its start")
                ranges.append((lo, hi))
            else:
                ranges.append((lo, lo))
        merged: list[tuple[int, int]] = []
        for lo, hi in sorted(ranges):
            if merged and lo <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
            else:
                merged.append((lo, hi))
        return complement(merged) if negate else merged


@functools.lru_cache(maxsize=256)
def iregexp(pattern: str) -> re.Pattern[str]:
    """The compiled Python regular expression of an I-Regexp; fullmatch() is the match of RFC 9485."""
    if not isinstance(pattern, str) or len(pattern.encode("utf-8")) > MAX_PATTERN:
        raise IRegexpError(f"not a string of at most {MAX_PATTERN} bytes")
    p = _Parser(pattern)
    out = p.regexp()
    if p.i != len(pattern):
        raise IRegexpError(f"{pattern[p.i]!r} where none belongs")
    return re.compile(out)


def iregexp_problem(pattern: Any) -> str | None:
    if not isinstance(pattern, str):
        return "not a string"  # tested before the cache of iregexp, which needs a hashable value
    try:
        iregexp(pattern)
        return None
    except IRegexpError as e:
        return str(e)


# --- schemas: names and the value type of a field -----------------------------------------------


def full_name(node: dict[str, Any], namespace: str) -> tuple[str, str]:
    name = node["name"]
    if "." in name:
        return name, name.rpartition(".")[0]
    ns = node.get("namespace", namespace)
    return (f"{ns}.{name}" if ns else name), ns


class Names:
    """The named types of one schema, by full name, registered in the order in which Avro parses them."""

    def __init__(self, schema: Any) -> None:
        self.names: dict[str, Any] = {}
        self._walk(schema, "")

    def _walk(self, t: Any, namespace: str) -> None:
        if isinstance(t, list):
            for b in t:
                self._walk(b, namespace)
        elif isinstance(t, dict):
            kind = t.get("type")
            if kind in ("record", "error", "enum", "fixed"):
                full, namespace = full_name(t, namespace)
                self.names.setdefault(full, t)
                for f in t.get("fields", []) if kind != "enum" else []:
                    self._walk(f.get("type"), namespace)
            elif kind == "array":
                self._walk(t.get("items"), namespace)
            elif kind == "map":
                self._walk(t.get("values"), namespace)
            elif isinstance(kind, (dict, list)):
                self._walk(kind, namespace)

    def resolve(self, t: Any, namespace: str) -> tuple[Any, str]:
        """A reference by name, resolved; anything else as it is. Returns (node, namespace)."""
        if isinstance(t, str) and t not in PRIMITIVES:
            node = self.names.get(t) or self.names.get(f"{namespace}.{t}")
            if node is None:
                raise ValueError(f"unknown type {t}")
            return node, full_name(node, namespace)[1]
        if isinstance(t, dict) and t.get("type") in ("record", "error", "enum", "fixed"):
            return t, full_name(t, namespace)[1]
        return t, namespace


def kind_of(t: Any) -> str:
    """'string', 'int', ..., 'record', 'enum', 'fixed', 'array', 'map' or 'union' for a resolved node."""
    if isinstance(t, str):
        return t
    if isinstance(t, list):
        return "union"
    k = t["type"]
    return k if isinstance(k, str) else kind_of(k)


def strip(t: Any) -> Any:
    """A primitive written as an object, such as {"type": "long", "logicalType": ...}, as its primitive."""
    if isinstance(t, dict) and isinstance(t.get("type"), str) and t["type"] in PRIMITIVES:
        return t["type"]
    if isinstance(t, dict) and isinstance(t.get("type"), (dict, list)):
        return t["type"]
    return t


def optional(t: Any) -> Any:
    """The branch of ["null", T]; T for anything else."""
    if isinstance(t, list) and len(t) == 2 and "null" in t:
        return [b for b in t if b != "null"][0]
    return t


def branch(names: Names, t: list[Any], v: Any, namespace: str) -> Any:
    """The branch of a union that holds the value v: of ["null", T], T; of the targets of axt.Relation, the
    record whose fields are the members of v."""
    if len(t) == 2 and "null" in t:
        return optional(t)
    for b in t:
        node = names.resolve(strip(b), namespace)[0]
        if (
            isinstance(v, dict)
            and kind_of(node) == "record"
            and {f["name"] for f in node["fields"]} == set(v)
        ):
            return b
    raise ValueError("a value of no branch of the union")


def value_type(names: Names, t: Any, namespace: str) -> tuple[Any, str, str]:
    """The value type of a field (spec/metadata.md, section 3.2): the type without ["null", T], and of an
    array the item type, again without ["null", T]. Returns (node, kind, namespace)."""
    node, namespace = names.resolve(strip(optional(strip(t))), namespace)
    if kind_of(node) == "array":
        node, namespace = names.resolve(strip(optional(strip(node["items"]))), namespace)
    return node, kind_of(node), namespace


# --- the rules of each attribute ------------------------------------------------------------------


def is_int(v: Any) -> TypeGuard[int]:
    return isinstance(v, int) and not isinstance(v, bool)


def is_number(v: Any) -> TypeGuard[float]:
    return (isinstance(v, (int, float)) and not isinstance(v, bool)) and not (
        isinstance(v, float) and not math.isfinite(v)
    )


def entry_problems(entry: Any) -> list[str]:
    """The members of an entry of axt.symbols or axt.groups that break their rules."""
    if not isinstance(entry, dict):
        return ["not an object"]
    out = [f"unknown member {k}" for k in sorted(entry) if k not in ENTRY_MEMBERS]
    for name in sorted(set(entry) & ENTRY_MEMBERS):
        p = text_problem(name, entry[name], entry)
        if p:
            out.append(f"{name}: {p}")
    return out


def text_problem(name: str, value: Any, holder: dict[str, Any]) -> str | None:
    bare = name.removeprefix("axt.")
    if bare == "label":
        return None if one_line(value, MAX_LABEL) else f"not one line of 1 to {MAX_LABEL} bytes"
    if bare == "help":
        return None if one_line(value, MAX_HELP) else f"not one line of 1 to {MAX_HELP} bytes"
    if bare in ("label_translations", "help_translations"):
        base = name.replace("_translations", "")
        if base not in holder or text_problem(base, holder[base], holder):
            return f"without a valid {base}"
        return (
            None
            if translations_ok(value, MAX_LABEL if bare == "label_translations" else MAX_HELP)
            else (
                "not a map of up to 64 language tags of RFC 5646, other than en and each once, "
                "to one line of text"
            )
        )
    if bare == "emoji":
        return (
            None
            if emoji_ok(value)
            else "not an emoji: 1 to 10 code points, no control character or space, ASCII only in a keycap"
        )
    raise ValueError(name)


def field_attribute_problem(
    name: str, value: Any, field: dict[str, Any], vt: Any, kind: str, vt_full: str | None
) -> str | None:
    """Why the attribute name of the field breaks its rules, or None (spec/metadata.md, sections 4 to 6)."""
    if name in TEXTS:
        return text_problem(name, value, field)
    string, numeric = kind == "string", kind in NUMBERS
    if name == "axt.format":
        if not string:
            return "on a field whose value type is not string"
        return None if isinstance(value, str) and value != "" else "not a non-empty string"
    if name == "axt.pattern":
        if not string:
            return "on a field whose value type is not string"
        return iregexp_problem(value)
    if name in ("axt.min_length", "axt.max_length"):
        if kind not in ("string", "bytes"):
            return "on a field whose value type is neither string nor bytes"
        if not is_int(value) or value < 0:
            return "not an integer of at least 0"
        lo, hi = field.get("axt.min_length"), field.get("axt.max_length")
        if is_int(lo) and is_int(hi) and lo >= 0 and hi >= 0 and lo > hi:
            return "axt.min_length above axt.max_length"
        return None
    if name == "axt.preferred_length":
        if not string:
            return "on a field whose value type is not string"
        if not is_int(value) or value < 1:
            return "not an integer of at least 1"
        hi = field.get("axt.max_length")
        if (
            field_attribute_problem("axt.max_length", hi, field, vt, kind, vt_full) is None
            and "axt.max_length" in field
            and value > cast(int, hi)  # an integer: axt.max_length is there and keeps its rules
        ):
            return "above axt.max_length"
        return None
    if name in ("axt.min", "axt.max"):
        if not numeric:
            return "on a field whose value type is not a number"
        if not is_number(value):
            return "not a finite number"
        lo, hi = field.get("axt.min"), field.get("axt.max")
        if is_number(lo) and is_number(hi) and lo > hi:
            return "axt.min above axt.max"
        return None
    if name == "axt.unit":
        if not numeric:
            return "on a field whose value type is not a number"
        return None if isinstance(value, str) and FORMATS["ucum"](value) else "not a UCUM code"
    if name == "axt.anchor":
        if vt_full != "axt.DateTime":
            return "on a field that holds no axt.DateTime"
        return None if value in ("local", "instant") else "neither local nor instant"
    if name == "axt.example":
        return (
            None
            if isinstance(value, str)
            and value != ""
            and len(value.encode("utf-8")) <= MAX_EXAMPLE
            and not any(control(c) and c != "\n" for c in value)
            else f"not a text of 1 to {MAX_EXAMPLE} bytes"
        )
    if name == "axt.placeholder":
        return None if one_line(value, MAX_PLACEHOLDER) else f"not one line of 1 to {MAX_PLACEHOLDER} bytes"
    if name == "axt.multiline":
        if not string:
            return "on a field whose value type is not string"
        return None if isinstance(value, bool) else "not a boolean"
    if name in ("axt.sensitive", "axt.advanced"):
        return None if isinstance(value, bool) else "not a boolean"
    if name == "axt.order":
        return None if is_int(value) and MIN_INT <= value <= MAX_INT else "not an integer of 32 bits"
    if name == "axt.group":
        return (
            None
            if isinstance(value, str) and KEY.match(value) and len(value) <= MAX_GROUP_KEY
            else "not a key of the form of a field name"
        )
    raise ValueError(name)


def used(field: dict[str, Any], name: str, names: Names | None = None, namespace: str = "") -> bool:
    """Whether a receiver uses the attribute of the field (spec/metadata.md, section 3.3)."""
    if name not in field:
        return False
    # Every caller passes the names; without them value_type fails, as it did before the annotations.
    vt, kind, ns = value_type(cast(Names, names), field["type"], namespace)
    vt_full = full_name(vt, ns)[0] if isinstance(vt, dict) and "name" in vt else None
    return field_attribute_problem(name, field[name], field, vt, kind, vt_full) is None


def record_attribute_problem(
    name: str, value: Any, record: dict[str, Any], top: bool, members: bool = True
) -> str | None:
    """Why the attribute of a record breaks its rules, or None. With members False, only what makes a
    receiver ignore the whole attribute: a member of an entry of axt.groups that breaks its rules is ignored
    on its own."""
    if name in TEXTS:
        return text_problem(name, value, record)
    if name == "axt.groups":
        if not isinstance(value, dict):
            return "not an object"
        for key, entry in value.items():
            if not KEY.match(key) or len(key.encode("utf-8")) > MAX_GROUP_KEY:
                return f"the key {key!r} is not of the form of a field name"
            if not isinstance(entry, dict):
                return f"{key}: not an object"
            p = entry_problems(entry) if members else []
            if p:
                return f"{key}: {p[0]}"
        return None
    if name == "axt.version":
        return (
            None
            if top and is_int(value) and value >= 1
            else "not an integer of at least 1 on the type's record"
        )
    if name == "axt.title":
        if not top:
            return "on a nested record"
        target = [f for f in record["fields"] if f["name"] == value]
        return (
            None
            if target and strip(target[0]["type"]) in ("string", ["null", "string"])
            else "does not name a string field"
        )
    raise ValueError(name)


def symbols_problem(value: Any, enum: dict[str, Any], members: bool = True) -> str | None:
    """Why axt.symbols breaks its rules, or None; members as for record_attribute_problem."""
    if not isinstance(value, dict):
        return "not an object"
    for symbol, entry in value.items():
        if symbol not in enum["symbols"]:
            return f"{symbol} is not a symbol of the enum"
        if not isinstance(entry, dict):
            return f"{symbol}: not an object"
        p = entry_problems(entry) if members else []
        if p:
            return f"{symbol}: {p[0]}"
    return None


def schema_problems(schema: Any) -> list[tuple[str, str]]:
    """Every axt.* attribute of the schema that breaks a rule of spec/metadata.md, as (where, why)."""
    names = Names(schema)
    out: list[tuple[str, str]] = []

    def attrs(node: Any) -> list[str]:
        return sorted(k for k in node if isinstance(k, str) and k.startswith("axt."))

    def walk(t: Any, where: str, namespace: str, top: bool = False) -> None:
        if isinstance(t, list):
            for b in t:
                walk(b, where, namespace)
            return
        if not isinstance(t, dict):
            return  # a primitive or a reference by name, defined where it first occurs
        kind = t.get("type")
        if isinstance(kind, (dict, list)):
            walk(kind, where, namespace)
            kind = None
        if kind in ("record", "enum", "fixed"):
            namespace = full_name(t, namespace)[1]
        allowed = (
            ON_TYPE
            if (kind == "record" and top)
            else ON_RECORD
            if kind == "record"
            else ON_ENUM
            if kind == "enum"
            else set()
        )
        for a in attrs(t):
            if a not in KNOWN:
                out.append((where, f"{a} is not an attribute of this specification"))
            elif a not in allowed:
                out.append(
                    (where, f"{a} does not belong on a {kind if kind in ('record', 'enum') else 'type'}")
                )
            elif kind == "record":
                p = record_attribute_problem(a, t[a], t, top)
                if p:
                    out.append((where, f"{a}: {p}"))
            else:
                p = symbols_problem(t[a], t)
                if p:
                    out.append((where, f"{a}: {p}"))
        if kind == "record":
            groups = t.get("axt.groups")
            for key in groups if isinstance(groups, dict) else {}:
                if not any(f.get("axt.group") == key for f in t["fields"]):
                    out.append((where, f"axt.groups names {key}, which no field uses"))
            for f in t["fields"]:
                here = f"{where}.{f['name']}" if where else f["name"]
                vt, vkind, vns = value_type(names, f["type"], namespace)
                vt_full = full_name(vt, vns)[0] if isinstance(vt, dict) and "name" in vt else None
                for a in attrs(f):
                    if a not in KNOWN:
                        out.append((here, f"{a} is not an attribute of this specification"))
                    elif a not in ON_FIELD:
                        out.append((here, f"{a} does not belong on a field"))
                    else:
                        p = field_attribute_problem(a, f[a], f, vt, vkind, vt_full)
                        if p:
                            out.append((here, f"{a}: {p}"))
                if vkind == "string" and used(f, "axt.example", names, namespace):
                    why = string_breach(f, f["axt.example"])
                    if why:
                        out.append((here, f"axt.example breaks {why}"))
                if "axt.format" in f and isinstance(f["axt.format"], str) and f["axt.format"] not in FORMATS:
                    out.append(
                        (here, f"axt.format {f['axt.format']!r} is not a format of this specification")
                    )
                walk(f["type"], here, namespace)
        elif kind == "array":
            walk(t["items"], where, namespace)
        elif kind == "map":
            walk(t["values"], where, namespace)

    walk(schema, "", "", top=True)
    return out


# --- describe (spec/metadata.md, sections 4 and 5; spec/conformance.md, section 5.13) --------------


def texts_of(
    holder: dict[str, Any], languages: Iterable[str], problem: Callable[[str], str | None]
) -> dict[str, Any]:
    """label, help and emoji of a record or field, with the attributes that break their rules ignored."""
    out: dict[str, Any] = {}
    for base in ("axt.label", "axt.help"):
        if base not in holder or problem(base):
            out[base[4:]] = None
            continue
        tkey = base + "_translations"
        tr = holder[tkey] if tkey in holder and not problem(tkey) else None
        out[base[4:]] = lookup(holder[base], tr, languages)
    out["emoji"] = holder["axt.emoji"] if "axt.emoji" in holder and not problem("axt.emoji") else None
    return out


def entry_texts(entry: Any, languages: Iterable[str]) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {"label": None, "help": None, "emoji": None}
    out: dict[str, Any] = {}
    for base in ("label", "help"):
        ok = base in entry and text_problem(base, entry[base], entry) is None
        tr = (
            entry.get(base + "_translations")
            if ok
            and base + "_translations" in entry
            and text_problem(base + "_translations", entry[base + "_translations"], entry) is None
            else None
        )
        out[base] = lookup(entry[base], tr, languages) if ok else None
    out["emoji"] = entry["emoji"] if "emoji" in entry and emoji_ok(entry["emoji"]) else None
    return out


def display_order(names: Names, record: dict[str, Any], namespace: str) -> tuple[list[str], list[Any]]:
    """The fields of a record in the order of spec/metadata.md, section 5.1, with each group gathered."""
    fields = record["fields"]

    def order(i: int) -> Any:
        return fields[i]["axt.order"] if used(fields[i], "axt.order", names, namespace) else None

    ranked = sorted(range(len(fields)), key=lambda i: (order(i) is None, order(i) or 0, i))

    def group(i: int) -> Any:
        return fields[i]["axt.group"] if used(fields[i], "axt.group", names, namespace) else None

    out: list[str] = []
    placed: set[int] = set()
    for i in ranked:
        if i in placed:
            continue
        g = group(i)
        members = [j for j in ranked if g is not None and group(j) == g] or [i]
        for j in members:
            out.append(fields[j]["name"])
            placed.add(j)
    return out, [group(i) for i in ranked]


def describe_record(
    names: Names, record: dict[str, Any], namespace: str, languages: Iterable[str], top: bool
) -> dict[str, Any]:
    def problem(a: str) -> str | None:
        return record_attribute_problem(a, record[a], record, top)

    out = texts_of(record, languages, problem)
    order, groups_used = display_order(names, record, namespace)
    out["fields"] = order
    groups = (
        record["axt.groups"]
        if "axt.groups" in record
        and not record_attribute_problem("axt.groups", record["axt.groups"], record, top, members=False)
        else {}
    )
    out["groups"] = {g: entry_texts(groups.get(g), languages) for g in groups_used if g is not None}
    return out


def describe(schema: dict[str, Any], path: str | None, languages: Iterable[str]) -> dict[str, Any]:
    """What a receiver shows of the type (path None) or of the field at path (names joined by .)."""
    names = Names(schema)
    record, namespace = schema, full_name(schema, "")[1]
    if path is None:
        return describe_record(names, record, namespace, languages, True)
    parts = path.split(".")
    for n, part in enumerate(parts):
        (field,) = [f for f in record["fields"] if f["name"] == part]
        vt, kind, vns = value_type(names, field["type"], namespace)
        if n < len(parts) - 1:
            record, namespace = vt, vns
    vt_full = full_name(vt, vns)[0] if isinstance(vt, dict) and "name" in vt else None

    def problem(a: str) -> str | None:
        return field_attribute_problem(a, field[a], field, vt, kind, vt_full)

    def use(a: str) -> bool:
        return a in field and problem(a) is None

    out = texts_of(field, languages, problem)
    fmt = field["axt.format"] if use("axt.format") else None
    out["format"] = (fmt if fmt in FORMATS else "plain") if kind == "string" else None
    out["placeholder"] = field["axt.placeholder"] if use("axt.placeholder") else None
    out["example"] = field["axt.example"] if use("axt.example") else None
    for flag in ("multiline", "sensitive", "advanced"):
        out[flag] = field["axt." + flag] if use("axt." + flag) else False
    out["group"] = field["axt.group"] if use("axt.group") else None
    out["preferred_length"] = field["axt.preferred_length"] if use("axt.preferred_length") else None
    out["unit"] = field["axt.unit"] if use("axt.unit") else None
    out["symbols"] = None
    if kind == "enum":
        sym = (
            vt["axt.symbols"]
            if "axt.symbols" in vt and symbols_problem(vt["axt.symbols"], vt, members=False) is None
            else {}
        )
        out["symbols"] = {s: entry_texts(sym.get(s), languages) for s in vt["symbols"]}
    out["record"] = describe_record(names, vt, vns, languages, False) if kind == "record" else None
    return out


# --- the checks (spec/metadata.md, section 6) and field paths (section 7.2) ---------------------


def path_join(path: str, segment: int | tuple[str] | str) -> str:
    if isinstance(segment, int):
        return f"{path}[{segment}]"
    if isinstance(segment, tuple):  # a map key
        return f"{path}[{json.dumps(segment[0], ensure_ascii=False)}]"
    return f"{path}.{segment}" if path else segment


def length_of(value: Any, kind: str) -> int:
    if kind == "bytes":
        return len(value) if isinstance(value, (bytes, bytearray)) else len(value) // 2  # hexadecimal in JSON
    return len(value)  # code points


def string_breach(
    field: dict[str, Any], value: Any, names: Names | None = None, namespace: str = ""
) -> str | None:
    """The check of a string field that the value breaks, or None."""
    if not isinstance(value, str):
        return None  # a logical type that a library decoded to another kind of value, such as a UUID

    def use(a: str) -> bool:
        return used(field, a, names or Names({"type": "record", "name": "X", "fields": [field]}), namespace)

    if value != "":
        if use("axt.format") and field["axt.format"] in FORMATS and not FORMATS[field["axt.format"]](value):
            return "axt.format"
        if use("axt.pattern") and not iregexp(field["axt.pattern"]).fullmatch(value):
            return "axt.pattern"
    return length_breach(field, value, "string", use)


def length_breach(field: dict[str, Any], value: Any, kind: str, use: Callable[[str], bool]) -> str | None:
    if not isinstance(value, (str, bytes, bytearray)):
        return None
    n = length_of(value, kind)
    if use("axt.min_length") and n < field["axt.min_length"]:
        return "axt.min_length"
    if use("axt.max_length") and n > field["axt.max_length"]:
        return "axt.max_length"
    return None


def number_breach(field: dict[str, Any], value: Any, use: Callable[[str], bool]) -> str | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None  # a logical type that a library decoded to another kind of value
    nan = isinstance(value, float) and math.isnan(value)
    if use("axt.min") and (nan or value < field["axt.min"]):
        return "axt.min"
    if use("axt.max") and (nan or value > field["axt.max"]):
        return "axt.max"
    return None


def breaches(
    schema: Any,
    value: Any,
    time_check: Callable[[str, Any], str | None] | None = None,
    attributes: bool = True,
    relations: Any = None,
) -> list[tuple[str, str, str]]:
    """The values that break a rule, in the order of the encoding, as (path, rule, why).

    The rule is the full name of a time type, for a time value that time_check finds not valid; axt.Relation,
    for a relation that breaks a rule of spec/fields.md, section 11.4, which relations, if given, holds: an
    object with RELATION, relation_problem(record, field, value), list_problem(relations) and
    repeated_ids(relations), as fields_examples.py has them; or the attribute of a check that the value
    breaks."""
    names = Names(schema)
    out: list[tuple[str, str, str]] = []

    def visit(t: Any, v: Any, path: str, namespace: str, field: tuple[Any, str] | None = None) -> None:
        """field is (the field whose value v is or holds, the namespace of the record that has it)."""
        t = strip(t)
        if isinstance(t, list):
            if v is not None:
                visit(branch(names, t, v, namespace), v, path, namespace, field)
            return
        node, namespace = names.resolve(t, namespace)
        node = strip(node)
        kind = kind_of(node)
        if kind == "record":
            full, inner = full_name(node, namespace)
            if time_check is not None and full in TIME_TYPES:
                why = time_check(full, v)
                if why:
                    out.append((path, full, why))
                return
            for f in node["fields"]:
                here = path_join(path, f["name"])
                why = relations.relation_problem(full, f["name"], v[f["name"]]) if relations else None
                if why:
                    out.append((here, full if full == "axt.Extension" else relations.RELATION, why))
                visit(f["type"], v[f["name"]], here, inner, (f, inner))
            return
        if kind == "array":
            items = names.resolve(strip(node["items"]), namespace)[0]
            lists = getattr(relations, "LISTS", None) or {getattr(relations, "RELATION", ""): "id"}
            member = (
                lists.get(full_name(items, namespace)[0])
                if relations is not None and isinstance(items, dict) and "name" in items
                else None
            )
            of_relations = member is not None
            why = relations.list_problem(v) if of_relations else None
            list_rule = full_name(items, namespace)[0] if of_relations else ""
            if why:
                out.append((path, list_rule, why))
            repeated = relations.repeated_ids(v) if of_relations else set()
            for i, item in enumerate(v):
                if i in repeated:
                    out.append(
                        (
                            path_join(path_join(path, i), str(member)),
                            list_rule,
                            "an id of an earlier relation"
                            if member == "id"
                            else "a name of an earlier extension",
                        )
                    )
                visit(node["items"], item, path_join(path, i), namespace, field)
            return
        if kind == "map":
            for key, item in v.items():
                visit(node["values"], item, path_join(path, (key,)), namespace, None)
            return
        if field is None or not attributes:
            return
        f, fns = field

        def use(a: str) -> bool:
            return used(f, a, names, fns)

        rule = (
            string_breach(f, v, names, fns)
            if kind == "string"
            else length_breach(f, v, "bytes", use)
            if kind == "bytes"
            else number_breach(f, v, use)
            if kind in NUMBERS
            else None
        )
        if rule:
            out.append((path, rule, f"breaks {rule} {json.dumps(f[rule], ensure_ascii=False)}"))

    visit(schema, value, "", "")
    return out


def error_field(path: str) -> str | None:
    """The field of an ERROR for VALUE_INVALID (spec/protocol.md, section 8.1): the path, or null above
    1,024 bytes."""
    return path if len(path.encode("utf-8")) <= MAX_PATH else None


# --- self-test of the I-Regexp translation ---------------------------------------------------------

assert iregexp("[0-9]{5}").fullmatch("10115") and not iregexp("[0-9]{5}").fullmatch("10115\n")
assert iregexp("^a$").fullmatch("^a$") and not iregexp("^a$").fullmatch("a")  # ^ and $ are NormalChar
assert (
    not iregexp("a.c").fullmatch("a\nc")
    and not iregexp("a.c").fullmatch("a\rc")
    and iregexp("a.c").fullmatch("a c")
)
assert iregexp("a|bc").fullmatch("bc") and not iregexp("a|bc").fullmatch("abc")
for bad in (
    "\\d",
    "(?:a)",
    "a*?",
    "a{2,1}",
    "[z-a]",
    "[^]",
    "a{1001}",
    "[]",
    "a**",
    "\\p{Lx}",
    "(a",
    "a)",
    "[a-\\p{L}]",
    "{1}",
    "[a-b-c]",
    "\\w",
    "a{,3}",
    "\\$",
):
    assert iregexp_problem(bad), bad
for good in (
    "",
    "a{0,1000}",
    "[-a]",
    "[a-]",
    "[^^]",
    "\\p{Lu}\\P{L}*",
    "[\\p{N}\\-]+",
    "(a|b)+c?",
    "\\^$",
    "[\\n\\t]",
    "[$^]",
):
    assert iregexp_problem(good) is None, good
