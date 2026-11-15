# SPDX-License-Identifier: CC0-1.0
"""Produce and check the examples of spec/manifest.md.

Checks the manifest's schema, types/axt/Manifest.avsc, and writes the two
MANIFEST messages of the example, cat-a-log's and Old Brain Fix's, as
annotated hex:

- the schema rules of spec/types.md, section 5, with the checks of
  vectors/tools/example_types.py: a doc everywhere, names in the required
  case, only ["null", T] unions with the default null, no recursion, the
  size and depth limits; and its names unique among the schemas of the
  specification. File name and namespace follow spec/manifest.md: the file
  is types/axt/Manifest.avsc, the namespace axt, and there is no
  axt.version, since the schema changes only with the envelope format;
- the Parsing Canonical Form and the CRC-64-AVRO fingerprint, against
  fastavro and the Apache avro package;
- every default once in schema resolution, with both libraries;
- the validity rules and limits of spec/manifest.md, section 4, on both
  examples and on broken manifests that each break one rule, one or more
  for every rule and limit;
- which types fit a manifest (section 5.2), with the language lookup of
  section 3.6, for every case named in the example of section 10;
- both messages, built here field by field, against fastavro's binary
  encoding; each decoded back with fastavro and with the avro package,
  which also encodes it again to the same bytes.

Neither library writes single-object framing, so the 10-byte headers
(C3 01 and the fingerprint) are assembled here from the fingerprints.

Run from anywhere, with fastavro and avro (1.12) installed:

    python3 vectors/tools/manifest_examples.py

The sender keys and the signatures are placeholders, so neither message
verifies as signed; spec/keys.md shows signed messages.
"""

import copy
import hashlib
import importlib.util
import io
import json
import re
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit

import avro.io
import avro.schema
import fastavro
from fastavro.schema import fingerprint as fa_fingerprint
from fastavro.schema import to_parsing_canonical_form

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
MANIFEST_AVSC = REPO / "types" / "axt" / "Manifest.avsc"
ENVELOPE_AVSC = REPO / "types" / "axt" / "Envelope.avsc"

# The checks of example_types.py and the X25519 check of keys_examples.py;
# importing them runs none of their checks.
_spec = importlib.util.spec_from_file_location("example_types", HERE / "example_types.py")
rules = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rules)
_spec = importlib.util.spec_from_file_location("keys_examples", HERE / "keys_examples.py")
keys = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(keys)

# --- the limits of spec/manifest.md, section 4 --------------------------------

MAX_BODY = 1048576  # bytes of the body, its single-object header included
MAX_FORMATS = 16
MAX_TYPES = 256  # entries of takes; entries of sends
MAX_FULL_NAME = 512  # bytes
MAX_APP_NAME = 256  # bytes
MAX_URL = 2048  # bytes
MAX_RELAY_URL = 256  # bytes
MAX_SENTENCE = 512  # bytes
MAX_TRANSLATIONS = 64  # per sentence
MAX_TAG = 35  # characters
MAX_MESSAGE = 16777216  # spec/envelope.md, section 8

FULL_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
# The langtag production of RFC 5646, section 2.1, matched without regard to case.
LANGTAG = re.compile(
    r"^(?:[a-z]{2,3}(?:-[a-z]{3}){0,3}|[a-z]{4}|[a-z]{5,8})"  # language, extlang
    r"(?:-[a-z]{4})?"  # script
    r"(?:-(?:[a-z]{2}|[0-9]{3}))?"  # region
    r"(?:-(?:[a-z0-9]{5,8}|[0-9][a-z0-9]{3}))*"  # variants
    r"(?:-[0-9a-wyz](?:-[a-z0-9]{2,8})+)*"  # extensions
    r"(?:-x(?:-[a-z0-9]{1,8})+)?$",  # private use
    re.IGNORECASE,
)

# --- the example manifests (spec/manifest.md, section 10) ---------------------

CAT_A_LOG = {
    "revision": 1,
    "app_name": "cat-a-log",
    "app_url": None,
    "formats": [1],
    "takes": [
        {
            "type": "axt.example.v1.Pet",
            "min_version": 1,
            "max_version": None,
            "purpose": "A Pet becomes an animal in the pet log.",
            "purpose_translations": {},
        },
    ],
    "any_type": None,
    "sends": [
        {"type": "axt.example.v1.Pet", "min_version": 1, "max_version": 1},
        {"type": "axt.example.v1.Appointment", "min_version": 1, "max_version": 1},
        {"type": "axt.example.v1.Measurement", "min_version": 1, "max_version": 1},
        {"type": "axt.example.v1.Document", "min_version": 1, "max_version": 1},
    ],
    "encryption_key": None,
    "relay": None,
}

OLD_BRAIN_FIX = {
    "revision": 1,
    "app_name": "Old Brain Fix",
    "app_url": None,
    "formats": [1],
    "takes": [
        {
            "type": "axt.example.v1.Appointment",
            "min_version": 1,
            "max_version": None,
            "purpose": "An Appointment becomes a Reminder.",
            "purpose_translations": {"de": "Ein Termin wird zu einer Erinnerung."},
        },
        {
            "type": "axt.example.v1.Task",
            "min_version": 1,
            "max_version": None,
            "purpose": "A Task becomes a Note with a Reminder.",
            "purpose_translations": {"de": "Eine Aufgabe wird zu einer Notiz mit Erinnerung."},
        },
        {
            "type": "axt.example.v1.Note",
            "min_version": 1,
            "max_version": None,
            "purpose": "A Note becomes a Note.",
            "purpose_translations": {"de": "Eine Notiz wird zu einer Notiz."},
        },
    ],
    "any_type": {
        "purpose": "Any other type becomes a searchable Note.",
        "purpose_translations": {"de": "Jeder andere Typ wird zu einer durchsuchbaren Notiz."},
    },
    "sends": None,
    "encryption_key": None,
    "relay": None,
}

SENDERS = {
    "cat-a-log": bytes(range(32)),  # placeholder; spec/keys.md shows signed messages
    "Old Brain Fix": bytes(range(32, 64)),  # placeholder
}
SIGNATURE = bytes(64)  # placeholder

# --- schema -------------------------------------------------------------------

manifest_text = MANIFEST_AVSC.read_text(encoding="utf-8")
envelope_text = ENVELOPE_AVSC.read_text(encoding="utf-8")
manifest_json = json.loads(manifest_text)
envelope_json = json.loads(envelope_text)

where = str(MANIFEST_AVSC.relative_to(REPO))
assert manifest_json["type"] == "record" and manifest_json["name"] == "Manifest"
assert manifest_json["namespace"] == "axt"
assert "axt.version" not in manifest_json, "a schema of the specification carries no axt.version"
assert len(manifest_text.encode("utf-8")) <= rules.MAX_SCHEMA_BYTES, "schema above the size limit"
assert rules.json_depth(manifest_json) <= rules.MAX_JSON_DEPTH, "schema JSON nested above the depth limit"
defined = []
data_depth = rules.check_type(manifest_json, where, manifest_json, set(), defined)
assert data_depth <= rules.MAX_DATA_DEPTH


def named_types(t, out):
    """Full names of the named types a schema defines, in the namespace axt."""
    if isinstance(t, list):
        for b in t:
            named_types(b, out)
    elif isinstance(t, dict):
        if t["type"] in {"record", "enum", "fixed"}:
            out.append("axt." + t["name"])
        for f in t.get("fields", []):
            named_types(f["type"], out)
        for key in ("items", "values"):
            if key in t:
                named_types(t[key], out)
    return out


clash = set(defined) & set(named_types(envelope_json, []))
assert not clash, f"names defined in both Envelope.avsc and Manifest.avsc: {clash}"
assert len(set(defined)) == len(defined), "a name is defined twice in Manifest.avsc"

manifest_schema = fastavro.parse_schema(manifest_json)
envelope_schema = fastavro.parse_schema(envelope_json)
apache_manifest = avro.schema.parse(manifest_text)


def fingerprint(schema_text):
    pcf = to_parsing_canonical_form(fastavro.parse_schema(json.loads(schema_text)))
    assert avro.schema.parse(pcf).canonical_form == pcf, "the two libraries disagree on the canonical form"
    fp = rules.crc64_avro(pcf.encode())
    assert fa_fingerprint(pcf, "CRC-64-AVRO") == fp.to_bytes(8, "little").hex(), "fastavro fingerprint differs"
    assert rules.apache_fingerprint(schema_text) == fp.to_bytes(8, "little"), "avro fingerprint differs"
    return pcf, fp


manifest_pcf, manifest_fp = fingerprint(manifest_text)
envelope_pcf, envelope_fp = fingerprint(envelope_text)
assert envelope_fp == 0xA2E1E84FE5E40C7D, "the envelope fingerprint is not the one of spec/envelope.md"

# Every default once in schema resolution, with both libraries. check_defaults
# reaches the fields of the record and of the records in its arrays; the two
# defaults below those, in any_type's record and in the array inside the sends
# union, are used by a writer schema without them.
rules.DATA["Manifest"] = OLD_BRAIN_FIX
required, defaults_resolved = rules.check_defaults("Manifest", manifest_json, manifest_schema)
fields = {f["name"]: f for f in manifest_json["fields"]}
writer = copy.deepcopy(manifest_json)
wfields = {f["name"]: f for f in writer["fields"]}
any_record = wfields["any_type"]["type"][1]
any_record["fields"] = [f for f in any_record["fields"] if f["name"] != "purpose_translations"]
send_record = wfields["sends"]["type"][1]["items"]
send_record["fields"] = [f for f in send_record["fields"] if f["name"] != "max_version"]
datum = dict(OLD_BRAIN_FIX, any_type={"purpose": OLD_BRAIN_FIX["any_type"]["purpose"]},
             sends=[{"type": "axt.example.v1.Note", "min_version": 1}])
for library, back in zip(("fastavro", "avro"), rules.resolve(writer, manifest_json, manifest_schema, datum)):
    expected = (fields["any_type"]["type"][1]["fields"][1]["default"],
                fields["sends"]["type"][1]["items"]["fields"][2]["default"])
    got = (back["any_type"]["purpose_translations"], back["sends"][0]["max_version"])
    if got != expected:
        rules.fail("Manifest", f"{library} read {got!r} for the defaults of any_type and sends")
defaults_resolved += 2


def count_defaults(t):
    """The number of fields with a default in a schema, nested records included."""
    if isinstance(t, list):
        return sum(count_defaults(b) for b in t)
    if not isinstance(t, dict):
        return 0
    n = sum(("default" in f) + count_defaults(f["type"]) for f in t.get("fields", []))
    return n + sum(count_defaults(t[k]) for k in ("items", "values") if k in t)


assert defaults_resolved == count_defaults(manifest_json), "not every default was used"
if rules.failures:
    raise SystemExit("\n".join(["checks failed:"] + rules.failures))

# --- validity (spec/manifest.md, section 4) -----------------------------------


def one_line(text):
    """Not empty, and no control character or line or paragraph separator."""
    return text != "" and not any(unicodedata.category(c) in {"Cc", "Zl", "Zp"} for c in text)


def check_sentences(where, entry, problems):
    s = entry["purpose"]
    if not one_line(s) or len(s.encode("utf-8")) > MAX_SENTENCE:
        problems.append(f"{where}.purpose is not one line of 1 to {MAX_SENTENCE} bytes")
    tr = entry["purpose_translations"]
    if len(tr) > MAX_TRANSLATIONS:
        problems.append(f"{where} has more than {MAX_TRANSLATIONS} translations")
    seen = set()
    for tag, text in tr.items():
        if len(tag) > MAX_TAG or not LANGTAG.match(tag):
            problems.append(f"{where}: {tag!r} is not a language tag of RFC 5646 of up to {MAX_TAG} characters")
        if tag.lower() == "en":
            problems.append(f"{where}: the English sentence belongs in purpose, not under the tag {tag!r}")
        if tag.lower() in seen:
            problems.append(f"{where}: the tag {tag!r} appears twice")
        seen.add(tag.lower())
        if not one_line(text) or len(text.encode("utf-8")) > MAX_SENTENCE:
            problems.append(f"{where}: the {tag} sentence is not one line of 1 to {MAX_SENTENCE} bytes")


def check_types(where, entries, problems):
    if len(entries) > MAX_TYPES:
        problems.append(f"{where} has more than {MAX_TYPES} entries")
    names = set()
    for i, e in enumerate(entries):
        here = f"{where}[{i}]"
        if len(e["type"].encode("utf-8")) > MAX_FULL_NAME or not FULL_NAME.match(e["type"]):
            problems.append(f"{here}.type is not an Avro full name of up to {MAX_FULL_NAME} bytes")
        if e["type"] in names:
            problems.append(f"{here}.type {e['type']} appears twice")
        names.add(e["type"])
        if e["min_version"] < 1:
            problems.append(f"{here}.min_version is below 1")
        if e["max_version"] is not None and e["max_version"] < e["min_version"]:
            problems.append(f"{here}.max_version is below min_version")


def manifest_problems(datum, body_length, envelope_format=1):
    """Every rule of section 4 the manifest breaks; empty for a valid one."""
    problems = []
    if body_length > MAX_BODY:
        problems.append(f"body of {body_length} bytes, above {MAX_BODY}")
    if datum["revision"] < 1:
        problems.append("revision is below 1")
    if not one_line(datum["app_name"]) or len(datum["app_name"].encode("utf-8")) > MAX_APP_NAME:
        problems.append(f"app_name is not one line of 1 to {MAX_APP_NAME} bytes")
    url = datum["app_url"]
    if url is not None:
        parts = urlsplit(url)
        if len(url.encode("utf-8")) > MAX_URL or parts.scheme != "https" or not parts.netloc or not one_line(url) or " " in url:
            problems.append(f"app_url is not an absolute https URL of up to {MAX_URL} bytes")
    f = datum["formats"]
    if not 1 <= len(f) <= MAX_FORMATS or len(set(f)) != len(f) or min(f, default=0) < 1:
        problems.append(f"formats is not 1 to {MAX_FORMATS} distinct formats of at least 1")
    if envelope_format not in f:
        problems.append("formats lacks the format of the envelope that carries the manifest")
    check_types("takes", datum["takes"], problems)
    for i, e in enumerate(datum["takes"]):
        check_sentences(f"takes[{i}]", e, problems)
    if datum["any_type"] is not None:
        check_sentences("any_type", datum["any_type"], problems)
    if datum["sends"] is not None:
        check_types("sends", datum["sends"], problems)
    key = datum["encryption_key"]
    if key is not None and keys.encryption_key_problem(key):
        problems.append("encryption_key is an X25519 key of small order")
    relay = datum["relay"]
    if (key is None) != (relay is None):
        problems.append("relay and encryption_key are not both present or both null")
    if relay is not None:
        url = relay["url"]
        parts = urlsplit(url)
        if (len(url.encode("utf-8")) > MAX_RELAY_URL or parts.scheme != "https" or not parts.hostname
                or "@" in parts.netloc or parts.query or parts.fragment or "?" in url or "#" in url
                or not url.endswith("/") or not one_line(url) or " " in url):
            problems.append(f"relay.url is not an absolute https base URL of up to {MAX_RELAY_URL} bytes")
    return problems


def encode_body(datum):
    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, manifest_schema, datum)
    return b"\xc3\x01" + manifest_fp.to_bytes(8, "little") + buf.getvalue()


for example in (CAT_A_LOG, OLD_BRAIN_FIX):
    problems = manifest_problems(example, len(encode_body(example)))
    assert not problems, (example["app_name"], problems)


def broken(change):
    datum = copy.deepcopy(OLD_BRAIN_FIX)
    change(datum)
    return datum


TAGS = [a + b for a in "abc" for b in "abcdefghijklmnopqrstuvwxyz"]  # well-formed, none of them en


def big(datum):
    # 256 types with 64 translations of 100 bytes each: within every count and length, above the body limit.
    datum["takes"] = [
        {"type": f"org.example.T{i}", "min_version": 1, "max_version": None, "purpose": "x" * 100,
         "purpose_translations": {tag: "y" * 100 for tag in TAGS[:64]}}
        for i in range(256)
    ]


def note_sends(**change):
    return [dict({"type": "axt.example.v1.Note", "min_version": 1, "max_version": None}, **change)]


# A valid encryption key and relay, for the cases that need one (spec/keys.md, section 7.1;
# spec/transports.md, section 5.1): Old Brain Fix's X25519 test key and its test mailbox.
X25519_KEY = bytes.fromhex("34fa7e71770d8d94c76001ac8d575609f005981f80c115bb7a8fe312687ea40b")
RELAY = {"url": "https://relay.example.org/axt/", "mailbox": bytes(range(32))}
assert not manifest_problems(dict(OLD_BRAIN_FIX, encryption_key=X25519_KEY, relay=RELAY), 0)
assert len(("https://relay.example.org/" + "a" * 229 + "/").encode()) == MAX_RELAY_URL
assert not manifest_problems(dict(OLD_BRAIN_FIX, encryption_key=X25519_KEY,
                                  relay=dict(RELAY, url="https://relay.example.org/" + "a" * 229 + "/")), 0)

# Each broken manifest breaks one rule; every problem reported must name it.
NEGATIVE = [
    ("revision 0", lambda d: d.update(revision=0), "revision"),
    ("empty app name", lambda d: d.update(app_name=""), "app_name"),
    ("app name with a line break", lambda d: d.update(app_name="Old Brain\nFix"), "app_name"),
    ("app name above the limit", lambda d: d.update(app_name="x" * 257), "app_name"),
    ("http URL", lambda d: d.update(app_url="http://example.org/"), "app_url"),
    ("relative URL", lambda d: d.update(app_url="/about"), "app_url"),
    ("URL above the limit", lambda d: d.update(app_url="https://example.org/" + "a" * 2029), "app_url"),
    ("no formats", lambda d: d.update(formats=[]), "formats"),
    ("format twice", lambda d: d.update(formats=[1, 1]), "formats"),
    ("format 0", lambda d: d.update(formats=[0, 1]), "formats"),
    ("17 formats", lambda d: d.update(formats=list(range(1, 18))), "formats"),
    ("format of the envelope missing", lambda d: d.update(formats=[2]), "lacks the format"),
    ("full name twice", lambda d: d["takes"].append(copy.deepcopy(d["takes"][0])), "appears twice"),
    ("not a full name", lambda d: d["takes"][0].update(type="axt.example.v1.Appoint ment"), "full name"),
    ("full name above the limit", lambda d: d["takes"][0].update(type="a" * 513), "full name"),
    ("min_version 0", lambda d: d["takes"][0].update(min_version=0), "min_version"),
    ("max below min", lambda d: d["takes"][0].update(min_version=3, max_version=2), "max_version"),
    ("257 types taken", lambda d: d.update(takes=[dict(d["takes"][0], type=f"org.example.T{i}") for i in range(257)]), "more than 256"),
    ("empty sentence", lambda d: d["takes"][1].update(purpose=""), "purpose"),
    ("sentence with a line separator", lambda d: d["takes"][2].update(purpose="A Note\u2028becomes a Note."), "purpose"),
    ("sentence above the limit", lambda d: d["any_type"].update(purpose="x" * 513), "purpose"),
    ("empty translation", lambda d: d["takes"][0]["purpose_translations"].update(de=""), "de sentence"),
    ("translation above the limit", lambda d: d["any_type"]["purpose_translations"].update(de="x" * 513), "de sentence"),
    ("65 translations", lambda d: d["takes"][0].update(purpose_translations={t: "Ein Termin." for t in TAGS[:65]}), "more than 64"),
    ("tag en", lambda d: d["takes"][0]["purpose_translations"].update(en="An Appointment."), "English"),
    ("tag twice", lambda d: d["takes"][0]["purpose_translations"].update(DE="Ein Termin."), "twice"),
    ("not a tag", lambda d: d["takes"][0]["purpose_translations"].update(de_DE="Ein Termin."), "language tag"),
    ("private use tag alone", lambda d: d["takes"][0]["purpose_translations"].update({"x-old": "Ein Termin."}), "language tag"),
    ("tag above the limit", lambda d: d["takes"][0]["purpose_translations"].update({"de-Latn-DE-1996-x-abcdefgh-abcdefgh-ab": "Ein Termin."}), "language tag"),
    ("sends twice", lambda d: d.update(sends=note_sends() * 2), "appears twice"),
    ("sends not a full name", lambda d: d.update(sends=note_sends(type="Note!")), "full name"),
    ("sends min_version 0", lambda d: d.update(sends=note_sends(min_version=0)), "min_version"),
    ("sends max below min", lambda d: d.update(sends=note_sends(min_version=2, max_version=1)), "max_version"),
    ("257 types sent", lambda d: d.update(sends=[dict(note_sends()[0], type=f"org.example.T{i}") for i in range(257)]), "more than 256"),
    ("encryption key of small order", lambda d: d.update(encryption_key=bytes(32), relay=RELAY), "encryption_key"),
    ("encryption key without relay", lambda d: d.update(encryption_key=X25519_KEY), "relay and encryption_key"),
    ("relay without encryption key", lambda d: d.update(relay=RELAY), "relay and encryption_key"),
    ("relay URL http", lambda d: d.update(encryption_key=X25519_KEY, relay=dict(RELAY, url="http://relay.example.org/axt/")), "relay.url"),
    ("relay URL without a slash at the end", lambda d: d.update(encryption_key=X25519_KEY, relay=dict(RELAY, url="https://relay.example.org/axt")), "relay.url"),
    ("relay URL with a query", lambda d: d.update(encryption_key=X25519_KEY, relay=dict(RELAY, url="https://relay.example.org/?a=1/")), "relay.url"),
    ("relay URL with user information", lambda d: d.update(encryption_key=X25519_KEY, relay=dict(RELAY, url="https://me@relay.example.org/")), "relay.url"),
    ("relay URL above the limit", lambda d: d.update(encryption_key=X25519_KEY, relay=dict(RELAY, url="https://relay.example.org/" + "a" * 230 + "/")), "relay.url"),
    ("body above the limit", big, "body of"),
]
for label, change, expected in NEGATIVE:
    datum = broken(change)
    problems = manifest_problems(datum, len(encode_body(datum)))
    assert problems and all(expected in p for p in problems), (label, problems)
assert LANGTAG.match("de-Latn-DE-1996-x-abcdefgh-abcdefgh-ab"), "the long tag must fail by its length alone"

# --- fit and language (spec/manifest.md, sections 3.4, 3.6 and 5.2) -----------


def schema_version(schema):
    """The version of a writer schema: its axt.version, or 1 without a valid one."""
    v = schema.get("axt.version")
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 1 else 1


def fit(manifest, full_name, version):
    """The entry of the manifest a type and version fits, or None."""
    for entry in manifest["takes"]:
        if entry["type"] == full_name:
            high = entry["max_version"]
            return entry if entry["min_version"] <= version and (high is None or version <= high) else None
    return manifest["any_type"]


def sentence(entry, priority_list):
    """RFC 4647, section 3.4, Lookup over the tags of an entry; English by default."""
    texts = {tag.lower(): text for tag, text in entry["purpose_translations"].items()}
    texts.setdefault("en", entry["purpose"])
    for language_range in priority_list:
        subtags = language_range.lower().split("-")
        while subtags and subtags != ["*"]:
            if "-".join(subtags) in texts:
                return texts["-".join(subtags)]
            subtags.pop()
            if subtags and len(subtags[-1]) == 1:
                subtags.pop()
    return entry["purpose"]


EXAMPLE_TYPES = REPO / "types" / "axt" / "example" / "v1"
appointment_version = schema_version(json.loads((EXAMPLE_TYPES / "Appointment.1.avsc").read_text()))
memo = {"type": "record", "name": "Memo", "namespace": "com.example", "fields": []}  # spec/envelope.md, 10.1
assert appointment_version == 1 and schema_version(memo) == 1
assert schema_version(dict(memo, **{"axt.version": "2"})) == 1 and schema_version(dict(memo, **{"axt.version": 0})) == 1

# cat-a-log sends to Old Brain Fix: a named entry, and any type for the rest.
walk = []
for send in CAT_A_LOG["sends"]:
    entry = fit(OLD_BRAIN_FIX, send["type"], send["min_version"])
    assert entry is not None
    walk.append((send["type"], sentence(entry, ["en-GB"]), sentence(entry, ["de-AT", "en"])))
assert fit(OLD_BRAIN_FIX, "axt.example.v1.Appointment", 1) is OLD_BRAIN_FIX["takes"][0]
assert fit(OLD_BRAIN_FIX, "axt.example.v1.Pet", 1) is OLD_BRAIN_FIX["any_type"]
assert fit(OLD_BRAIN_FIX, "com.example.Memo", schema_version(memo)) is OLD_BRAIN_FIX["any_type"]
assert sentence(OLD_BRAIN_FIX["takes"][0], ["de-AT"]) == "Ein Termin wird zu einer Erinnerung."
assert sentence(OLD_BRAIN_FIX["takes"][0], ["fr-CH", "fr"]) == "An Appointment becomes a Reminder."
# Old Brain Fix sends to cat-a-log: a named entry, and not offered.
assert fit(CAT_A_LOG, "axt.example.v1.Pet", 1) is CAT_A_LOG["takes"][0]
assert fit(CAT_A_LOG, "axt.example.v1.Note", 1) is None
assert fit(CAT_A_LOG, "com.example.Memo", 1) is None
# A listed type outside its range does not fall to any type.
narrowed = broken(lambda d: d["takes"][0].update(min_version=2))
assert fit(narrowed, "axt.example.v1.Appointment", 1) is None

# --- hand-built encoding ------------------------------------------------------


def zigzag(n):
    z = (n << 1) ^ (n >> 63)
    out = bytearray()
    while True:
        b = z & 0x7F
        z >>= 7
        if z:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def string_parts(name, text):
    raw = text.encode("utf-8")
    return [(zigzag(len(raw)), f"{name}: string length {len(raw)}"), (raw, f'"{text}"')]


def null_or(name, value, branch, parts_of):
    if value is None:
        return [(zigzag(0), f"{name}: union index 0, null")]
    return [(zigzag(1), f"{name}: union index 1, {branch}")] + parts_of(value)


def block(name, n, what):
    return [(zigzag(n), f"{name}: {what} block of {n} {'item' if what == 'array' and n == 1 else 'items' if what == 'array' else 'entry' if n == 1 else 'entries'}")]


def end(name, what):
    return [(zigzag(0), f"{name}: end of the {what}")]


def sentence_parts(name, entry):
    parts = string_parts(f"{name}.purpose", entry["purpose"])
    tr = entry["purpose_translations"]
    if tr:
        parts += block(f"{name}.purpose_translations", len(tr), "map")
        for tag, text in tr.items():
            parts += string_parts(f"{name}.purpose_translations key", tag)
            parts += string_parts(f"{name}.purpose_translations[{tag}]", text)
    parts += end(f"{name}.purpose_translations", "map")
    return parts


def version_parts(name, e):
    return [(zigzag(e["min_version"]), f"{name}.min_version: int {e['min_version']}")] + null_or(
        f"{name}.max_version", e["max_version"], "int", lambda v: [(zigzag(v), f"{name}.max_version: int {v}")])


def body_parts(m):
    parts = [
        (b"\xc3\x01", "single-object marker"),
        (manifest_fp.to_bytes(8, "little"), "fingerprint of axt.Manifest, format 1"),
        (zigzag(m["revision"]), f"revision: long {m['revision']}"),
    ]
    parts += string_parts("app_name", m["app_name"])
    parts += null_or("app_url", m["app_url"], "string", lambda u: string_parts("app_url", u))
    parts += block("formats", len(m["formats"]), "array")
    parts += [(zigzag(f), f"formats[{i}]: int {f}") for i, f in enumerate(m["formats"])]
    parts += end("formats", "array")
    if m["takes"]:
        parts += block("takes", len(m["takes"]), "array")
        for i, e in enumerate(m["takes"]):
            parts += string_parts(f"takes[{i}].type", e["type"])
            parts += version_parts(f"takes[{i}]", e)
            parts += sentence_parts(f"takes[{i}]", e)
    parts += end("takes", "array")
    parts += null_or("any_type", m["any_type"], "ManifestAnyType", lambda a: sentence_parts("any_type", a))

    def sends_parts(sends):
        out = block("sends", len(sends), "array") if sends else []
        for i, e in enumerate(sends):
            out += string_parts(f"sends[{i}].type", e["type"]) + version_parts(f"sends[{i}]", e)
        return out + end("sends", "array")

    parts += null_or("sends", m["sends"], "array", sends_parts)
    parts += null_or("encryption_key", m["encryption_key"], "ManifestEncryptionKey",
                     lambda k: [(k, "encryption_key: fixed(32)")])
    parts += null_or("relay", m["relay"], "ManifestRelay",
                     lambda r: string_parts("relay.url", r["url"]) + [(r["mailbox"], "relay.mailbox: fixed(32)")])
    return parts


def library_binary(schema, datum):
    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, schema, datum)
    return buf.getvalue()


kinds = envelope_schema["fields"][1]["type"]["symbols"]
messages = []
for m in (CAT_A_LOG, OLD_BRAIN_FIX):
    bparts = body_parts(m)
    body = b"".join(p[0] for p in bparts)
    assert body == encode_body(m), f"{m['app_name']}: the body differs from fastavro's encoding"
    # Decode the body with both libraries; avro encodes it again to the same bytes.
    assert fastavro.schemaless_reader(io.BytesIO(body[10:]), manifest_schema, manifest_schema) == m
    apache_datum = avro.io.DatumReader(apache_manifest).read(avro.io.BinaryDecoder(io.BytesIO(body[10:])))
    assert apache_datum == m, f"{m['app_name']}: avro decodes another manifest"
    out = io.BytesIO()
    avro.io.DatumWriter(apache_manifest).write(apache_datum, avro.io.BinaryEncoder(out))
    assert out.getvalue() == body[10:], f"{m['app_name']}: avro encodes the manifest to other bytes"

    sender = SENDERS[m["app_name"]]
    parts = [
        (b"\xc3\x01", "single-object marker"),
        (envelope_fp.to_bytes(8, "little"), "fingerprint of axt.Envelope, format 1"),
        (zigzag(1), "format: int 1"),
        (zigzag(kinds.index("MANIFEST")), f"kind: enum index {kinds.index('MANIFEST')}, MANIFEST"),
        (sender, "sender: fixed(32), placeholder"),
        (zigzag(0), "record: union index 0, null"),
        (zigzag(len(body)), f"body: bytes length {len(body)}"),
    ]
    parts += [(b, "body: " + meaning) for b, meaning in bparts]
    parts.append((SIGNATURE, "signature: fixed(64), placeholder"))
    message = b"".join(p[0] for p in parts)
    datum = {"format": 1, "kind": "MANIFEST", "sender": sender, "record": None, "body": body, "signature": SIGNATURE}
    assert message[10:] == library_binary(envelope_schema, datum), f"{m['app_name']}: envelope differs from fastavro"
    back = fastavro.schemaless_reader(io.BytesIO(message[10:]), envelope_schema, envelope_schema)
    assert back["kind"] == "MANIFEST" and back["record"] is None and back["body"] == body
    assert int.from_bytes(back["body"][2:10], "little") == manifest_fp
    assert len(message) <= MAX_MESSAGE and len(body) <= MAX_BODY
    messages.append((m["app_name"], parts, message, body))

# --- output -------------------------------------------------------------------


def dump(parts):
    """Annotated hex in the layout of spec/envelope.md and spec/manifest.md."""
    offset = 0
    lines = []
    for data, meaning in parts:
        if data == SIGNATURE and meaning.startswith("signature"):
            lines.append(f"{offset:04x}  {'00 ' * 8}".rstrip() + f"  {meaning}")
            lines.append("      ... (64 bytes of 00 in all)")
        else:
            for i in range(0, len(data), 8):
                hexs = data[i:i + 8].hex(" ")
                if i == 0:
                    lines.append(f"{offset:04x}  {hexs:<23}  {meaning}".rstrip())
                else:
                    lines.append(f"      {hexs}")
        offset += len(data)
    lines.append(f"{offset:04x}  end")
    return "\n".join(lines)


print(f"axt.Manifest canonical form: {manifest_pcf}")
print(f"axt.Manifest CRC-64-AVRO: 0x{manifest_fp:016x}, bytes {manifest_fp.to_bytes(8, 'little').hex(' ')}")
print(f"axt.Manifest: data depth {data_depth}; defaults resolved: {defaults_resolved}; "
      f"fields without a default: {', '.join(required)}")
print(f"axt.Envelope CRC-64-AVRO: 0x{envelope_fp:016x}")
print(f"validity: both examples valid; {len(NEGATIVE)} broken manifests rejected")
print()
print("cat-a-log sends to Old Brain Fix:")
for full_name, en, de in walk:
    print(f"  {full_name}: {en} / {de}")
for name, parts, message, body in messages:
    print()
    print(f"== {name}: MANIFEST message, {len(message)} bytes, body {len(body)} bytes, "
          f"SHA-256 {hashlib.sha256(message).hexdigest()} ==")
    print(dump(parts))
print("all checks passed")
