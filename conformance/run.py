# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Run the AXT test vectors against a library, through its adapter (spec/conformance.md).

    python3 conformance/run.py [--vectors DIR] [--category NAME ...] [--verbose] -- ADAPTER COMMAND ...

The runner starts the adapter command, asks it which categories it implements,
sends it every vector of those categories as one line of JSON on its standard
input, reads one line of JSON per vector from its standard output, and compares
the answer with the vector's expected result. It never sends the expected
result. It exits with 0 when every vector of every category the adapter
implements passed, and with 1 otherwise.

It needs Python 3.10 or later, fastavro (to decode the messages an adapter
writes) and cryptography (to open what an adapter seals). The Ed25519, X25519
and HPKE code is that of conformance/tools/keys_examples.py.
"""

import argparse
import hashlib
import importlib.util
import io
import json
import re
import subprocess
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
FILE_FORMAT = 1
CATEGORIES = ["encoding", "types", "time", "metadata", "records", "manifest", "keys", "protocol", "file", "qr", "local",
              "relay", "relay-server"]
HEX = re.compile(r"^(?:[0-9a-f]{2})*$")

_spec = importlib.util.spec_from_file_location("keys_examples", HERE / "tools" / "keys_examples.py")
keys = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(keys)  # runs none of that script's checks

# --- bytes (spec/conformance.md, section 3.2) ---------------------------------------


def is_bytes_object(v):
    return isinstance(v, dict) and set(v) == {"deflate", "length", "sha256"}


def to_bytes(v):
    """The bytes of a hex string or a deflate object."""
    if isinstance(v, str):
        if not HEX.match(v):
            raise ValueError(f"not lower-case hex: {v[:40]!r}")
        return bytes.fromhex(v)
    if is_bytes_object(v):
        d = zlib.decompressobj(-15)
        data = d.decompress(bytes.fromhex(v["deflate"]), v["length"] + 1)
        if len(data) != v["length"] or hashlib.sha256(data).hexdigest() != v["sha256"]:
            raise ValueError("a deflate object whose length or SHA-256 does not match")
        return data
    raise ValueError(f"not bytes: {v!r}"[:80])


def canonical(v):
    """A value with every deflate object replaced by the hex of its bytes, for comparison."""
    if is_bytes_object(v):
        return to_bytes(v).hex()
    if isinstance(v, dict):
        return {k: canonical(x) for k, x in v.items()}
    if isinstance(v, list):
        return [canonical(x) for x in v]
    return v


def strip_notes(v):
    if isinstance(v, dict):
        return {k: strip_notes(x) for k, x in v.items() if k != "note"}
    if isinstance(v, list):
        return [strip_notes(x) for x in v]
    return v


def diff(expected, got, path="$"):
    """The first difference between two JSON values, or None. Objects compare without regard to order;
    an expected {"one_of": [...]} is met by any of its values (spec/conformance.md, section 4.1)."""
    if isinstance(expected, dict) and set(expected) == {"one_of"}:
        if any(diff(e, got, path) is None for e in expected["one_of"]):
            return None
        return f"{path}: expected one of {short(expected['one_of'])}, got {short(got)}"
    if isinstance(expected, bool) or isinstance(got, bool):
        return None if expected is got else f"{path}: expected {expected!r}, got {got!r}"
    if isinstance(expected, dict) and isinstance(got, dict):
        for k in expected:
            if k not in got:
                return f"{path}: missing {k!r}"
            d = diff(expected[k], got[k], f"{path}.{k}")
            if d:
                return d
        extra = set(got) - set(expected)
        return f"{path}: unexpected {sorted(extra)}" if extra else None
    if isinstance(expected, list) and isinstance(got, list):
        if len(expected) != len(got):
            return f"{path}: expected {len(expected)} items, got {len(got)}"
        for i, (e, g) in enumerate(zip(expected, got)):
            d = diff(e, g, f"{path}[{i}]")
            if d:
                return d
        return None
    if type(expected) is not type(got) and not (isinstance(expected, (int, float)) and isinstance(got, (int, float))):
        return f"{path}: expected {short(expected)}, got {short(got)}"
    return None if expected == got else f"{path}: expected {short(expected)}, got {short(got)}"


def short(v):
    t = json.dumps(v, ensure_ascii=False)
    return t if len(t) <= 120 else t[:100] + f"... ({len(t)} characters)"


# --- the vector files and their schema -----------------------------------------------


def validate(value, schema, root, path="$"):
    """The subset of JSON Schema (draft 2020-12) that vectors.schema.json uses; returns a list of problems."""
    if "$ref" in schema:
        name = schema["$ref"].split("/")[-1]
        return validate(value, root["$defs"][name], root, path)
    problems = []
    t = schema.get("type")
    if t:
        types = t if isinstance(t, list) else [t]
        ok = any({"object": isinstance(value, dict), "array": isinstance(value, list),
                  "string": isinstance(value, str), "boolean": isinstance(value, bool),
                  "null": value is None,
                  "integer": isinstance(value, int) and not isinstance(value, bool),
                  "number": isinstance(value, (int, float)) and not isinstance(value, bool)}[x] for x in types)
        if not ok:
            return [f"{path}: not of type {t}"]
    if "const" in schema and value != schema["const"]:
        problems.append(f"{path}: not {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        problems.append(f"{path}: not one of {schema['enum']}")
    if "pattern" in schema and isinstance(value, str) and not re.search(schema["pattern"], value):
        problems.append(f"{path}: does not match {schema['pattern']}")
    if "minimum" in schema and isinstance(value, (int, float)) and value < schema["minimum"]:
        problems.append(f"{path}: below {schema['minimum']}")
    if isinstance(value, dict):
        for k in schema.get("required", []):
            if k not in value:
                problems.append(f"{path}: lacks {k!r}")
        props = schema.get("properties", {})
        for k, v in value.items():
            if k in props:
                problems += validate(v, props[k], root, f"{path}.{k}")
            elif schema.get("additionalProperties") is False:
                problems.append(f"{path}: has the unknown member {k!r}")
            elif isinstance(schema.get("additionalProperties"), dict):
                problems += validate(v, schema["additionalProperties"], root, f"{path}.{k}")
    if isinstance(value, list) and "items" in schema:
        for i, v in enumerate(value):
            problems += validate(v, schema["items"], root, f"{path}[{i}]")
    if isinstance(value, list) and "minItems" in schema and len(value) < schema["minItems"]:
        problems.append(f"{path}: fewer than {schema['minItems']} items")
    for sub in schema.get("allOf", []):
        problems += validate(value, sub, root, path)
    if "oneOf" in schema:
        matches = [s for s in schema["oneOf"] if not validate(value, s, root, path)]
        if len(matches) != 1:
            problems.append(f"{path}: matches {len(matches)} of the alternatives of oneOf, not 1")
    if "if" in schema and not validate(value, schema["if"], root, path):
        problems += validate(value, schema.get("then", {}), root, path)
    return problems


def load_vectors(directory, wanted):
    schema = json.loads((directory / "vectors.schema.json").read_text(encoding="utf-8"))
    files = {}
    for name in CATEGORIES:
        if wanted and name not in wanted:
            continue
        path = directory / name / f"{name}.json"
        if not path.exists():
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        problems = validate(doc, schema, schema)
        if doc.get("category") != name:
            problems.append(f"$.category is not {name!r}")
        if problems:
            raise SystemExit(f"{path}: not a valid vector file:\n  " + "\n  ".join(problems[:20]))
        files[name] = doc
    return files


# --- the adapter ----------------------------------------------------------------------


class Adapter:
    def __init__(self, command):
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                     encoding="utf-8", bufsize=1)

    def ask(self, rid, op, input):
        self.proc.stdin.write(json.dumps({"id": rid, "op": op, "input": input}, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("the adapter ended without an answer")
        answer = json.loads(line)
        if answer.get("id") != rid:
            raise RuntimeError(f"the adapter answered {answer.get('id')!r} to {rid!r}")
        return answer

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(30)
        except Exception:
            self.proc.kill()


# --- checks that need more than a comparison --------------------------------------------


def check_seal(vector, output):
    """A sealed message cannot be compared, since its ephemeral key is random: the runner opens it."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    want = vector["expected"]["accept"]["sealed"]
    if "accept" not in output or set(output["accept"]) != {"sealed"}:
        return f"expected accept with sealed, got {short(output)}"
    data = to_bytes(output["accept"]["sealed"])
    if len(data) != want["length"]:
        return f"the sealed message has {len(data)} bytes, not {want['length']}"
    if data[:1] != keys.SEALED_FORMAT:
        return "the sealed message does not begin with 01"
    try:
        shared = keys.decap(data[1:33], bytes.fromhex(want["opens_with"]))
        ctx = keys.hpke_base_context(shared, keys.HPKE_INFO)
        plain = ChaCha20Poly1305(ctx["key"]).decrypt(ctx["base_nonce"], data[33:], b"")
    except Exception as e:
        return f"the sealed message does not open: {e!r}"
    if len(plain) != keys.padded_length(len(to_bytes(want["to"]))):
        return f"the padded message has {len(plain)} bytes, not {keys.padded_length(len(to_bytes(want['to'])))}"
    try:
        message = keys.unpad(plain)
    except ValueError as e:
        return str(e)
    return None if message == to_bytes(want["to"]) else "the sealed message opens to other bytes"


# Replies in a session: the runner decodes and verifies each message the adapter writes (section 5.6).

KINDS = ["MANIFEST", "OFFER", "ACCEPT", "DECLINE", "DATA", "DELETE", "ACK", "ERROR", "KEY_MOVE"]
_schemas = {}


def schema(name):
    """A schema of the specification, with logical types removed so that ids stay text."""
    import fastavro

    def plain(t):
        if isinstance(t, list):
            return [plain(b) for b in t]
        if isinstance(t, dict):
            t = {k: plain(v) for k, v in t.items() if k != "logicalType"}
            return t["type"] if set(t) == {"type"} and isinstance(t["type"], str) else t
        return t

    if name not in _schemas:
        text = (REPO / "types" / "axt" / f"{name}.avsc").read_text(encoding="utf-8")
        _schemas[name] = fastavro.parse_schema(plain(json.loads(text)), _write_hint=False)
    return _schemas[name]


ENVELOPE_FP = bytes.fromhex("7d0ce4e54fe8e1a2")
BODY_FPS = {"Offer": "7d687acaca635441", "Accept": "ab823d91c34f246b", "Decline": "c092548411bdd222",
            "Ack": "d86e16a8ccc725ee", "Error": "1d9af93651920615"}
BODY_OF = {"OFFER": "Offer", "ACCEPT": "Accept", "DECLINE": "Decline", "ACK": "Ack", "ERROR": "Error"}


def reply(hexed, own, peer):
    """The kind and body of a message the adapter wrote; raises ValueError if it is not a valid message of
    its own key, signed, and addressed to the peer."""
    import fastavro
    m = to_bytes(hexed)
    if m[:2] != b"\xc3\x01" or m[2:10] != ENVELOPE_FP:
        raise ValueError("a reply that is not a live message of envelope format 1")
    buf = io.BytesIO(m[10:])
    env = fastavro.schemaless_reader(buf, schema("Envelope"), schema("Envelope"))
    if buf.tell() != len(m) - 10 or env["format"] != 1:
        raise ValueError("a reply with bytes left over or another format")
    if env["sender"] != own:
        raise ValueError("a reply whose sender is not the adapter's key")
    if keys.verify_problem(own, keys.MESSAGE_PREFIX + m[10:-64], m[-64:]):
        raise ValueError("a reply whose signature does not verify")
    name = BODY_OF.get(env["kind"])
    if name is None or env["record"] is not None or env["body"][:10] != b"\xc3\x01" + bytes.fromhex(BODY_FPS[name]):
        raise ValueError(f"a reply of kind {env['kind']} that is not a valid reply")
    buf = io.BytesIO(env["body"][10:])
    body = fastavro.schemaless_reader(buf, schema(name), schema(name))
    if buf.tell() != len(env["body"]) - 10:
        raise ValueError("a reply body with bytes left over")
    if body["to"] != peer:
        raise ValueError("a reply that is not addressed to the other app")
    return env["kind"], body


def check_session(vector, output):
    """None if every step meets its expected result, else every step that does not."""
    app = vector["input"]["app"]
    own, peer = keys.public_key(bytes.fromhex(app["seed"])), bytes.fromhex(app["peer"])
    steps, want = vector["input"]["steps"], vector["expected"]["steps"]
    got = output.get("steps")
    if not isinstance(got, list) or len(got) != len(steps):
        return f"expected {len(steps)} step results, got {short(got)}"
    problems = []
    for n, (step, w, g) in enumerate(zip(steps, want, got)):
        try:
            problem = check_step(step, w, g, own, peer, f"step {n}")
        except (ValueError, KeyError, TypeError) as e:
            problem = f"step {n}: {e}"
        if problem:
            problems.append(problem)
    return "; ".join(problems) if problems else None


def check_step(step, w, g, own, peer, where):
    if "receive" in step:
        answers, errors = {}, []
        for r in g["replies"]:
            kind, body = reply(r, own, peer)
            if kind in ("ACCEPT", "DECLINE"):
                for t in body["types"]:
                    name, verdict = (t, "ACCEPT") if kind == "ACCEPT" else (t["type"], t["reason"])
                    if name in answers.get(body["offer_id"], {}):
                        return f"{where}: {name} answered twice"
                    answers.setdefault(body["offer_id"], {})[name] = verdict
            elif kind == "ERROR":
                errors.append({"code": body["code"], "message_hash": body["message_hash"].hex(), "record": body["record"],
                               "fingerprint": None if body["fingerprint"] is None else body["fingerprint"].hex(),
                               "field": body["field"]})
            else:
                return f"{where}: a reply of kind {kind}"
        d = diff({k: w[k] for k in ("outcome", "close", "answers")},
                 {"outcome": g.get("outcome"), "close": g.get("close"), "answers": answers}, where)
        if d:
            return d
        if len(errors) != len(w["errors"]):
            return f"{where}: expected {len(w['errors'])} ERROR replies, got {len(errors)}"
        for e, x in zip(w["errors"], errors):
            d = diff(e, {k: x[k] for k in e}, f"{where}.errors")  # only the members the vector lists
            if d:
                return d
        return None
    if "flush_acks" in step:
        records = []
        for r in g["replies"]:
            kind, body = reply(r, own, peer)
            if kind != "ACK" or body["moved_from"] is not None:
                return f"{where}: a reply other than an ACK of records"
            records += body["records"]
        order = lambda entries: sorted(entries, key=lambda e: json.dumps(e, sort_keys=True))  # in any order (section 5.6)
        return diff(order(w["acks"]), order(records), f"{where}.acks")
    if "offer" in step:
        kind, body = reply(g["message"], own, peer)
        if kind != "OFFER":
            return f"{where}: not an OFFER"
        return diff(w["offer"], {"to": body["to"].hex(), "offer_id": body["offer_id"], "types": body["types"]}, where)
    return diff(w, g, where)


SPECIAL = {"seal": check_seal, "session": check_session}


def check(vector, output):
    """None if the output meets the vector's expected result, else what differs."""
    special = SPECIAL.get(vector["op"])
    if special:
        return special(vector, output)
    return diff(canonical(strip_notes(vector["expected"])), canonical(strip_notes(output)))


# --- run ---------------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description="Run the AXT test vectors against an adapter.")
    ap.add_argument("--vectors", type=Path, default=REPO / "vectors", help="the vector directory (default: vectors/)")
    ap.add_argument("--category", action="append", default=[], help="run only this category (repeatable)")
    ap.add_argument("--verbose", action="store_true", help="name every vector, not only the failures")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="the adapter command, after --")
    args = ap.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        ap.error("no adapter command")
    files = load_vectors(args.vectors, set(args.category))
    adapter = Adapter(command)
    try:
        hello = adapter.ask("hello", "hello", {"format": FILE_FORMAT})
        declared = hello.get("output", {}).get("categories", [])
        unknown = sorted(set(declared) - set(CATEGORIES))
        if unknown:
            raise SystemExit(f"the adapter declares unknown categories: {unknown}")
        print(f"adapter: {hello.get('output', {}).get('name', '?')}; categories: {', '.join(declared)}")
        failures, totals = [], {}
        for name, doc in files.items():
            if name not in declared:
                print(f"{name}: not implemented by the adapter, {len(doc['vectors'])} vectors not run")
                continue
            passed = 0
            for vector in doc["vectors"]:
                try:
                    answer = adapter.ask(vector["id"], vector["op"], vector["input"])
                    if "output" not in answer:
                        problem = "unsupported" if answer.get("unsupported") else f"adapter failure: {answer.get('failure')}"
                    else:
                        problem = check(vector, answer["output"])
                except (ValueError, KeyError, TypeError) as e:
                    problem = f"malformed answer: {e!r}"
                if problem:
                    failures.append((vector["id"], problem))
                    print(f"FAIL {vector['id']}: {problem}")
                else:
                    passed += 1
                    if args.verbose:
                        print(f"pass {vector['id']}")
            totals[name] = (passed, len(doc["vectors"]))
            print(f"{name}: {passed} of {len(doc['vectors'])} vectors passed")
    finally:
        adapter.close()
    ran = sum(n for _, n in totals.values())
    print(f"total: {ran - len(failures)} of {ran} vectors passed in {len(totals)} categories")
    sys.exit(1 if failures or not totals else 0)


if __name__ == "__main__":
    main()
