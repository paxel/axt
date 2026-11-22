# SPDX-License-Identifier: Apache-2.0 OR MIT
"""The rules of spec/metadata.md that the bricks of spec/fields.md use: texts, formats, I-Regexp and
field paths, and the walk of a writer schema for the rules that every receiver checks.

This module imports none of the other scripts, so that each of them can import it. It provides:

- one_line, translations_ok, emoji_ok and lookup: the texts of spec/metadata.md, sections 4.1 to 4.3,
  and the Lookup of RFC 4647 by which a receiver chooses a language;
- iregexp(pattern): the pattern of RFC 9485 translated to Python's re, or IRegexpError for a
  pattern that is not an I-Regexp within the limits of spec/metadata.md, section 6.4;
- FORMATS: for each format of spec/metadata.md, section 6.3, a function that says whether a
  non-empty string has the format;
- path_join and error_field: the field paths of spec/metadata.md, section 7.2;
- breaches(schema, value, time_check, relations): the values of a writer schema's value that break a
  rule every receiver checks, as (path, rule, why), in the order of the encoding: the time values
  that are not valid (spec/time.md, section 8), and, with relations, the relations and extensions
  that break a rule of spec/fields.md, sections 11.4 and 12.3, which fields_examples.py holds.

A value is either as fastavro decodes it or in the JSON form of spec/conformance.md, section 3.3,
in which bytes are hexadecimal strings. Unions of null and one other type are followed, and the
union of the two targets of axt.Relation, whose branch is the record whose fields the value has:
the only unions the example types and the vectors use.
"""

import functools
import json
import re
import unicodedata
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any

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
MAX_PATH = LIMITS["protocol.error_field"]  # bytes of a field path in an ERROR (spec/protocol.md, section 8.1)

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


def breaches(
    schema: Any,
    value: Any,
    time_check: Callable[[str, Any], str | None] | None = None,
    relations: Any = None,
) -> list[tuple[str, str, str]]:
    """The values that break a rule that every receiver checks, in the order of the encoding, as (path,
    rule, why), by a walk of the writer schema.

    The rule is the full name of a time type, for a time value that time_check finds not valid; axt.Relation
    or axt.Extension, for a relation or an extension that breaks a rule of spec/fields.md, section 11.4 or
    12.3, which relations, if given, holds: an object with RELATION, relation_problem(record, field, value),
    list_problem(relations) and repeated_ids(relations), as fields_examples.py has them, and optionally
    value_check(record, field, value), a check that a value of a published record breaks, as (check, why)."""
    names = Names(schema)
    out: list[tuple[str, str, str]] = []
    value_check = getattr(relations, "value_check", None)

    def visit(t: Any, v: Any, path: str, namespace: str) -> None:
        t = strip(t)
        if isinstance(t, list):
            if v is not None:
                visit(branch(names, t, v, namespace), v, path, namespace)
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
                broken = value_check(full, f["name"], v[f["name"]]) if value_check else None
                if broken:
                    out.append((here, *broken))
                visit(f["type"], v[f["name"]], here, inner)
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
                visit(node["items"], item, path_join(path, i), namespace)
            return
        if kind == "map":
            for key, item in v.items():
                visit(node["values"], item, path_join(path, (key,)), namespace)

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
    "a{2",
    "\\pL",
    "\\q",
    "[a",
):
    assert iregexp_problem(bad), bad
assert iregexp_problem(5) == "not a string"
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

# --- self-test of the texts (spec/metadata.md, sections 4.2 and 4.3) --------------------------------

assert translations_ok({"de": "Name", "pt-BR": "Nome"}, MAX_LABEL)
assert not translations_ok({f"de-{i:03d}": "Name" for i in range(MAX_TRANSLATIONS + 1)}, MAX_LABEL)
assert not translations_ok({"de": "Name", "DE": "Name"}, MAX_LABEL)  # two keys equal without regard to case
assert not translations_ok({"de": ""}, MAX_LABEL)
assert (
    emoji_ok("📞") and emoji_ok("1\u20e3") and emoji_ok("#\ufe0f\u20e3")
)  # keycaps, with and without U+FE0F
assert not emoji_ok("a") and not emoji_ok("1") and not emoji_ok("📞 📞")
assert (
    lookup("Tag", {"de": "Schlagwort"}, ["de-x-private"]) == "Schlagwort"
)  # a singleton is dropped with its subtag
assert lookup("Tag", {"de": "Schlagwort"}, ["fr-CH", "fr"]) == "Tag"
