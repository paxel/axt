# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Produce and check the examples of spec/time.md.

For the four time types under types/axt/ (axt.Date, axt.Time, axt.DateTime and
axt.Duration) this script:

- checks the rules of spec/types.md, section 5, that a program can check, with
  the code of example_types.py, and that each type is a record of primitives
  and unions with null, without logical types and without named types inside;
- computes the Parsing Canonical Form and the CRC-64-AVRO fingerprint, and
  checks both against fastavro and the Apache avro package;
- encodes the example values of spec/time.md, section 9, with fastavro,
  decodes them back, decodes the same bytes with avro, encodes them again with
  avro and checks that the bytes are the same;
- checks the validity rules of spec/time.md, which need no time zone database,
  against values that keep them and values that break each of them, and the
  field path a receiver reports for a value that is not valid;
- checks the zoned examples against this system's time zone database with
  Python's zoneinfo: the offset is that of the zone at the instant, and the
  two readings of 02:30 on 2026-10-25 in Europe/Berlin have the two offsets;
- checks the reading of a value whose offset other zone rules gave, under both
  anchors of spec/time.md, section 6.4;
- checks the addition of a Duration to a DateTime of spec/time.md, section 7.2,
  over month ends, a change of offset and a floating time, against Python's
  datetime;
- checks that a type holding two DateTimes and a Date, with the first
  DateTime defined in place and the second referring to it by its full name
  (spec/time.md, section 3), parses in both libraries, has the same canonical
  form in both, and round-trips.

Run from anywhere, with fastavro and avro (1.12) installed and a time zone
database where Python's zoneinfo finds it:

    python3 conformance/tools/time_examples.py

conformance/tools/generate_vectors.py and conformance/reference/adapter.py
import this file; importing it runs the checks and prints nothing.
"""

import calendar
import datetime
import importlib.util
import io
import json
import re
import zoneinfo
from pathlib import Path
from typing import Any, cast

import avro.errors
import avro.io
import avro.name
import avro.schema
import fastavro
from fastavro.schema import fingerprint as fa_fingerprint
from fastavro.schema import to_parsing_canonical_form

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
AXT = REPO / "types" / "axt"

_spec = importlib.util.spec_from_file_location("example_types", HERE / "example_types.py")
if _spec is None or _spec.loader is None:
    raise ImportError(f"cannot load {HERE / 'example_types.py'}")
rules = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rules)  # runs none of the checks of the example types
_spec = importlib.util.spec_from_file_location("fields_examples", HERE / "fields_examples.py")
if _spec is None or _spec.loader is None:
    raise ImportError(f"cannot load {HERE / 'fields_examples.py'}")
fe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fe)  # for the rules of the relations of spec/fields.md, section 11.4

NAMES = ["Date", "Time", "DateTime", "Duration"]
FULL = {f"axt.{n}": n for n in NAMES}
MIN_YEAR, MAX_YEAR = 1, 9999
MAX_OFFSET = 64800  # seconds, 18 hours
DAY_MS = 86400000
INT_MIN, INT_MAX = -(1 << 31), (1 << 31) - 1
LONG_MIN, LONG_MAX = -(1 << 63), (1 << 63) - 1
ZONE_NAME = re.compile(r"^[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*$")
LIMITS: dict[str, int] = {  # types/axt/limits.json
    k: v["value"]
    for k, v in json.loads((REPO / "types" / "axt" / "limits.json").read_text(encoding="utf-8"))[
        "limits"
    ].items()
}
MAX_ZONE_BYTES = LIMITS["time.zone"]
ANCHORS = ("local", "instant")

texts = {n: (AXT / f"{n}.avsc").read_text(encoding="utf-8") for n in NAMES}
jsons = {n: json.loads(t) for n, t in texts.items()}
parsed = {n: fastavro.parse_schema(jsons[n]) for n in NAMES}
apache = {n: avro.schema.parse(texts[n]) for n in NAMES}


def compact(n: str) -> str:
    return json.dumps(jsons[n], separators=(",", ":"), ensure_ascii=False)


# --- the calendar and the local time line (spec/time.md, section 1) --------------------


def leap(y: int) -> bool:
    return y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)


def month_days(y: int | None, m: int) -> int:
    """The days of month m; of a leap year when y is None, so that 29 February is valid without a year."""
    if m == 2:
        return 29 if y is None or leap(y) else 28
    return 30 if m in (4, 6, 9, 11) else 31


def days_from_civil(y: int, m: int, d: int) -> int:
    """Days since 1970-01-01 of a date of the proleptic Gregorian calendar (H. Hinnant's algorithm)."""
    y -= m <= 2
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def civil_from_days(z: int) -> tuple[int, int, int]:
    z += 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + (3 if mp < 10 else -9)
    return yoe + era * 400 + (m <= 2), m, d


def local_ms(v: dict[str, Any]) -> int:
    """The wall clock of a DateTime read as if it were UTC, in milliseconds since 1970-01-01T00:00:00."""
    ms: int = (
        days_from_civil(v["year"], v["month"], v["day"]) * DAY_MS
        + ((v["hour"] * 60 + v["minute"]) * 60 + v["second"]) * 1000
        + v["millisecond"]
    )
    return ms


def with_local(v: dict[str, Any], ms: int) -> dict[str, Any]:
    """v with its wall clock set to ms on the local time line; zone, offset and instant unchanged."""
    days, rest = divmod(ms, DAY_MS)
    y, m, d = civil_from_days(days)
    return dict(
        v,
        year=y,
        month=m,
        day=d,
        hour=rest // 3600000,
        minute=rest // 60000 % 60,
        second=rest // 1000 % 60,
        millisecond=rest % 1000,
    )


# --- validity, without a time zone database (spec/time.md, sections 4 to 7) ----------------


def problems(name: str, v: dict[str, Any]) -> list[str]:
    """The rules of spec/time.md that the value v of axt.<name> breaks; empty when it is valid."""
    out: list[str] = []
    if name == "Date":
        y, m, d = v["year"], v["month"], v["day"]
        if y is None and m is None and d is None:
            out.append("no part")
        if y is not None and not MIN_YEAR <= y <= MAX_YEAR:
            out.append("year out of range")
        if m is not None and not 1 <= m <= 12:
            out.append("month out of range")
        if d is not None and m is None:
            out.append("a day without its month")
        if (
            d is not None
            and m is not None
            and 1 <= m <= 12
            and not 1 <= d <= month_days(y if y is not None and MIN_YEAR <= y <= MAX_YEAR else None, m)
        ):
            out.append("day out of range for the month")
        return out
    if name in ("Time", "DateTime"):
        for part, top in (("hour", 23), ("minute", 59), ("second", 59), ("millisecond", 999)):
            if not 0 <= v[part] <= top:
                out.append(f"{part} out of range")
    if name == "DateTime":
        if not MIN_YEAR <= v["year"] <= MAX_YEAR:
            out.append("year out of range")
        if not 1 <= v["month"] <= 12:
            out.append("month out of range")
        elif (
            not 1
            <= v["day"]
            <= month_days(v["year"] if MIN_YEAR <= v["year"] <= MAX_YEAR else 2000, v["month"])
        ):
            out.append("day out of range for the month")
        zone, offset, instant = v["zone"], v["offset_seconds"], v["instant_ms"]
        present = [x is not None for x in (zone, offset, instant)]
        if any(present) and not all(present):
            out.append("zone, offset_seconds and instant_ms not all null or all set")
        if zone is not None and (
            not ZONE_NAME.match(zone)
            or len(zone.encode()) > MAX_ZONE_BYTES
            or any(c in (".", "..") or c.startswith("-") for c in zone.split("/"))
        ):
            out.append("zone is not a time zone name")
        if offset is not None and not -MAX_OFFSET <= offset <= MAX_OFFSET:
            out.append("offset_seconds out of range")
        if all(present) and not out and instant != local_ms(v) - offset * 1000:
            out.append("instant_ms is not the wall clock minus offset_seconds")
    if name == "Duration":
        signs = {(x > 0) - (x < 0) for x in (v["months"], v["days"], v["millis"])} - {0}
        if len(signs) > 1:
            out.append("parts of both signs")
    return out


def time_problems(t: Any, value: Any, names: dict[str, Any] | None = None, namespace: str = "") -> list[str]:
    """The broken rules of every time value inside a value of the schema t, as fastavro decodes it.

    It handles the unions of null and one other type, the only unions the example types have."""
    names = {} if names is None else names
    if isinstance(t, str):
        if t in names or f"{namespace}.{t}" in names:
            return time_problems(names.get(t) or names[f"{namespace}.{t}"], value, names, namespace)
        return []
    if isinstance(t, list):
        if value is None:
            return []
        (branch,) = [b for b in t if b != "null"]
        return time_problems(branch, value, names, namespace)
    kind = t["type"]
    if kind in ("record", "enum", "fixed"):
        name = t["name"]
        namespace = name.rpartition(".")[0] if "." in name else t.get("namespace", namespace)
        full = name if "." in name else f"{namespace}.{name}"
        names[full] = t
    if kind == "record":
        if full in FULL:
            return [f"{full}: {p}" for p in problems(FULL[full], value)]
        return [p for f in t["fields"] for p in time_problems(f["type"], value[f["name"]], names, namespace)]
    if kind == "array":
        return [p for v in value for p in time_problems(t["items"], v, names, namespace)]
    if kind == "map":
        return [p for v in value.values() for p in time_problems(t["values"], v, names, namespace)]
    return []


mr = rules.mr  # the field paths of spec/metadata.md, section 7.2


def time_check(full: str, v: dict[str, Any]) -> str | None:
    """The first rule the value v of the time type full breaks, or None."""
    broken = problems(FULL[full], v)
    return broken[0] if broken else None


def receiver_breaches(schema: Any, value: Any, attributes: bool = True) -> list[tuple[str, str, str]]:
    """The values inside a value of the schema that break a rule, as (field path, rule, why), in the order of
    the encoding: the time values that are not valid (spec/time.md, section 8), the relations that break a
    rule of spec/fields.md, section 11.4, and, with attributes, the values that break a check."""
    found: list[tuple[str, str, str]] = mr.breaches(schema, value, time_check, attributes, relations=fe)
    return found


def value_breaches(schema: Any, value: Any) -> list[tuple[str, str, str]]:
    """The time values and relations inside a value of the schema that are not valid, as (field path, rule,
    why), in the order of the encoding: what a receiver reports with VALUE_INVALID (spec/time.md, section 8;
    spec/fields.md, section 11.4)."""
    return receiver_breaches(schema, value, attributes=False)


# --- zone rules (spec/time.md, section 6) ---------------------------------------------------


def known_zone(zone: str) -> bool:
    try:
        zoneinfo.ZoneInfo(zone)
        return True
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        return False


EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.UTC)


def offset_at(zone: str, instant: int) -> int:
    """The offset in seconds of the zone at the instant, by this system's rules."""
    at = EPOCH + datetime.timedelta(milliseconds=instant)
    offset = cast(datetime.timedelta, at.astimezone(zoneinfo.ZoneInfo(zone)).utcoffset())  # at has a zone
    return int(offset.total_seconds())


def offsets_of_local(zone: str, ms: int) -> list[int]:
    """The offsets with which the wall clock ms exists in the zone: one, two in an overlap, none in a gap."""
    z = zoneinfo.ZoneInfo(zone)
    naive = datetime.datetime(1970, 1, 1) + datetime.timedelta(milliseconds=ms)
    candidates = {
        int(cast(datetime.timedelta, naive.replace(tzinfo=z, fold=f).utcoffset()).total_seconds())
        for f in (0, 1)
    }
    return sorted((o for o in candidates if offset_at(zone, ms - o * 1000) == o), reverse=True)


def at_local(v: dict[str, Any], ms: int, preferred: int | None = None) -> dict[str, Any]:
    """The zoned DateTime v at the wall clock ms (spec/time.md, section 6.3): the preferred offset if the
    wall clock exists with it, else the earlier of two in an overlap, and in a gap the wall clock moved
    later by the length of the gap."""
    zone = v["zone"]
    valid = offsets_of_local(zone, ms)
    if preferred in valid:
        offset = preferred
    elif valid:
        offset = valid[0]  # the larger offset: the earlier instant
    else:
        z = zoneinfo.ZoneInfo(zone)
        naive = datetime.datetime(1970, 1, 1) + datetime.timedelta(milliseconds=ms)
        before = int(cast(datetime.timedelta, naive.replace(tzinfo=z, fold=0).utcoffset()).total_seconds())
        instant = ms - before * 1000
        offset = offset_at(zone, instant)
        ms = instant + offset * 1000
    return with_local(dict(v, offset_seconds=offset, instant_ms=ms - offset * 1000), ms)


def at_instant(v: dict[str, Any], instant: int) -> dict[str, Any]:
    offset = offset_at(v["zone"], instant)
    return with_local(dict(v, offset_seconds=offset, instant_ms=instant), instant + offset * 1000)


def resolve(v: dict[str, Any], anchor: str = "local") -> dict[str, Any]:
    """A DateTime as a receiver holds it under its own zone rules (spec/time.md, section 6.4)."""
    assert anchor in ANCHORS and not problems("DateTime", v)
    if v["zone"] is None or not known_zone(v["zone"]):
        return dict(v)
    if offset_at(v["zone"], v["instant_ms"]) == v["offset_seconds"]:
        return dict(v)
    if anchor == "instant":
        return at_instant(v, v["instant_ms"])
    return at_local(v, local_ms(v))


class OutOfRange(ValueError):
    pass


def add(v: dict[str, Any], d: dict[str, Any]) -> dict[str, Any]:
    """The DateTime v plus the Duration d (spec/time.md, section 7.2): months, then days on the wall
    clock, then milliseconds, on the instant for a zoned time and on the wall clock for a floating one."""
    assert not problems("DateTime", v) and not problems("Duration", d)
    months = v["year"] * 12 + (v["month"] - 1) + d["months"]
    y, m = divmod(months, 12)
    m += 1
    if not MIN_YEAR <= y <= MAX_YEAR:
        raise OutOfRange("year out of range after the months")
    out = dict(v, year=y, month=m, day=min(v["day"], month_days(y, m)))
    out = with_local(out, local_ms(out) + d["days"] * DAY_MS)
    if not MIN_YEAR <= out["year"] <= MAX_YEAR:
        raise OutOfRange("year out of range after the days")
    if out["zone"] is not None and (d["months"] or d["days"]):
        if known_zone(out["zone"]):
            out = at_local(out, local_ms(out), v["offset_seconds"])
        else:  # a zone the receiver does not know: its offset is kept
            out = dict(out, instant_ms=local_ms(out) - out["offset_seconds"] * 1000)
    if out["zone"] is None:
        out = with_local(out, local_ms(out) + d["millis"])
    elif d["millis"]:
        out = (
            at_instant(out, out["instant_ms"] + d["millis"])
            if known_zone(out["zone"])
            else with_local(
                dict(out, instant_ms=out["instant_ms"] + d["millis"]), local_ms(out) + d["millis"]
            )
        )
    if not MIN_YEAR <= out["year"] <= MAX_YEAR:
        raise OutOfRange("year out of range after the milliseconds")
    return out


# --- values -----------------------------------------------------------------------------


def date(year: int | None = None, month: int | None = None, day: int | None = None) -> dict[str, Any]:
    return {"year": year, "month": month, "day": day}


def time(hour: int, minute: int, second: int = 0, millisecond: int = 0) -> dict[str, Any]:
    return {"hour": hour, "minute": minute, "second": second, "millisecond": millisecond}


def floating(y: int, mo: int, d: int, h: int, mi: int, s: int = 0, ms: int = 0) -> dict[str, Any]:
    return {
        "year": y,
        "month": mo,
        "day": d,
        "hour": h,
        "minute": mi,
        "second": s,
        "millisecond": ms,
        "zone": None,
        "offset_seconds": None,
        "instant_ms": None,
    }


def zoned(
    y: int, mo: int, d: int, h: int, mi: int, zone: str, offset: int, s: int = 0, ms: int = 0
) -> dict[str, Any]:
    v = dict(floating(y, mo, d, h, mi, s, ms), zone=zone, offset_seconds=offset)
    v["instant_ms"] = local_ms(v) - offset * 1000
    return v


def duration(months: int = 0, days: int = 0, millis: int = 0) -> dict[str, Any]:
    return {"months": months, "days": days, "millis": millis}


BERLIN = "Europe/Berlin"
CEST, CET = 7200, 3600
MINUTE, HOUR = 60000, 3600000

# The examples of spec/time.md, section 9, in its order: (label, type, value).
EXAMPLES = [
    (
        "Vet appointment, Europe/Berlin, 2026-10-25 02:30 before the clocks go back",
        "DateTime",
        zoned(2026, 10, 25, 2, 30, BERLIN, CEST),
    ),
    (
        "The same wall clock after the clocks went back, an hour later",
        "DateTime",
        zoned(2026, 10, 25, 2, 30, BERLIN, CET),
    ),
    ("Alarm, floating, 2026-11-16 07:00 wherever the user is", "DateTime", floating(2026, 11, 16, 7, 0)),
    ("Daily alarm at 07:00", "Time", time(7, 0)),
    ("Birthday without a year, 3 May", "Date", date(None, 5, 3)),
    ("Since 2019", "Date", date(2019)),
    ("Expiry March 2027", "Date", date(2027, 3)),
    ("Born 29 February, year not known", "Date", date(None, 2, 29)),
    ("A full date, 2026-11-24", "Date", date(2026, 11, 24)),
    ("Reminder, 15 minutes before: -PT15M", "Duration", duration(millis=-15 * MINUTE)),
    ("Every month: P1M", "Duration", duration(months=1)),
    ("P1M2DT3H", "Duration", duration(months=1, days=2, millis=3 * HOUR)),
]

# Values that break one rule each: (label, type, value, the rule broken).
INVALID = [
    ("a Date without any part", "Date", date(), "no part"),
    ("a Date with the day and the year but no month", "Date", date(2026, None, 3), "a day without its month"),
    ("a Date with the day alone", "Date", date(None, None, 3), "a day without its month"),
    ("a Date in the month 13", "Date", date(2026, 13), "month out of range"),
    ("a Date in the month 0", "Date", date(None, 0), "month out of range"),
    ("a Date in the year 0", "Date", date(0, 1, 1), "year out of range"),
    ("a Date in the year 10000", "Date", date(10000), "year out of range"),
    ("31 April", "Date", date(None, 4, 31), "day out of range for the month"),
    ("29 February 2027, not a leap year", "Date", date(2027, 2, 29), "day out of range for the month"),
    ("29 February 1900, not a leap year", "Date", date(1900, 2, 29), "day out of range for the month"),
    ("the day 0", "Date", date(2026, 1, 0), "day out of range for the month"),
    ("a Time at 24:00", "Time", time(24, 0), "hour out of range"),
    ("a Time with the minute 60", "Time", time(23, 60), "minute out of range"),
    ("a Time with the leap second 60", "Time", time(23, 59, 60), "second out of range"),
    ("a Time with the millisecond 1000", "Time", time(10, 0, 0, 1000), "millisecond out of range"),
    ("a Time with a negative hour", "Time", time(-1, 0), "hour out of range"),
    ("a DateTime on 30 February", "DateTime", floating(2028, 2, 30, 10, 0), "day out of range for the month"),
    ("a DateTime in the year 0", "DateTime", floating(0, 12, 31, 10, 0), "year out of range"),
    ("a DateTime with the second 60", "DateTime", floating(2026, 12, 31, 23, 59, 60), "second out of range"),
    (
        "a floating DateTime with an offset and an instant",
        "DateTime",
        dict(
            floating(2026, 11, 16, 7, 0),
            offset_seconds=3600,
            instant_ms=local_ms(floating(2026, 11, 16, 7, 0)) - 3600000,
        ),
        "zone, offset_seconds and instant_ms not all null or all set",
    ),
    (
        "a DateTime with a zone but no offset and no instant",
        "DateTime",
        dict(floating(2026, 11, 16, 7, 0), zone=BERLIN),
        "zone, offset_seconds and instant_ms not all null or all set",
    ),
    (
        "a DateTime with a zone and an offset but no instant",
        "DateTime",
        dict(zoned(2026, 11, 16, 7, 0, BERLIN, CET), instant_ms=None),
        "zone, offset_seconds and instant_ms not all null or all set",
    ),
    (
        "a DateTime whose instant is an hour off",
        "DateTime",
        dict(
            zoned(2026, 11, 16, 7, 0, BERLIN, CET),
            instant_ms=zoned(2026, 11, 16, 7, 0, BERLIN, CET)["instant_ms"] + HOUR,
        ),
        "instant_ms is not the wall clock minus offset_seconds",
    ),
    (
        "a DateTime with an offset above 18 hours",
        "DateTime",
        zoned(2026, 11, 16, 7, 0, "Example/Far_East", MAX_OFFSET + 1),
        "offset_seconds out of range",
    ),
    (
        "a DateTime with an empty zone name",
        "DateTime",
        zoned(2026, 11, 16, 7, 0, "", 0),
        "zone is not a time zone name",
    ),
    (
        "a DateTime with a zone name that holds a space",
        "DateTime",
        zoned(2026, 11, 16, 7, 0, "Europe/Berlin ", CET),
        "zone is not a time zone name",
    ),
    (
        "a DateTime with a zone name that climbs a directory",
        "DateTime",
        zoned(2026, 11, 16, 7, 0, "../etc/passwd", 0),
        "zone is not a time zone name",
    ),
    ("a Duration of plus a month and minus a day", "Duration", duration(1, -1), "parts of both signs"),
    ("a Duration of minus a day and plus an hour", "Duration", duration(0, -1, HOUR), "parts of both signs"),
    ("a Date with the day 32 in January", "Date", date(2026, 1, 32), "day out of range for the month"),
    ("a Time with a negative millisecond", "Time", time(10, 0, 0, -1), "millisecond out of range"),
    ("a DateTime in the month 13", "DateTime", floating(2026, 13, 1, 10, 0), "month out of range"),
    ("a DateTime on the day 0", "DateTime", floating(2026, 1, 0, 10, 0), "day out of range for the month"),
    (
        "a DateTime on 29 February 2027, not a leap year",
        "DateTime",
        floating(2027, 2, 29, 10, 0),
        "day out of range for the month",
    ),
    ("a DateTime in the year 10000", "DateTime", floating(10000, 1, 1, 0, 0), "year out of range"),
    ("a DateTime at 24:00", "DateTime", floating(2026, 11, 24, 24, 0), "hour out of range"),
    ("a DateTime with the minute 60", "DateTime", floating(2026, 11, 24, 10, 60), "minute out of range"),
    (
        "a DateTime with the millisecond 1000",
        "DateTime",
        floating(2026, 11, 24, 10, 0, 0, 1000),
        "millisecond out of range",
    ),
    (
        "a DateTime with an offset below -18 hours",
        "DateTime",
        zoned(2026, 11, 16, 7, 0, "Example/Far_West", -MAX_OFFSET - 1),
        "offset_seconds out of range",
    ),
    (
        "a DateTime with a zone name of 65 bytes",
        "DateTime",
        zoned(2026, 11, 16, 7, 0, "Example/" + "A" * 57, 0),
        "zone is not a time zone name",
    ),
    (
        "a DateTime with a part of its zone name that begins with -",
        "DateTime",
        zoned(2026, 11, 16, 7, 0, "Example/-West", 0),
        "zone is not a time zone name",
    ),
    (
        "a DateTime with an empty part of its zone name",
        "DateTime",
        zoned(2026, 11, 16, 7, 0, "Europe//Berlin", CET),
        "zone is not a time zone name",
    ),
    (
        "a DateTime with an offset and an instant but no zone",
        "DateTime",
        dict(zoned(2026, 11, 16, 7, 0, BERLIN, CET), zone=None),
        "zone, offset_seconds and instant_ms not all null or all set",
    ),
    (
        "a Duration of plus a month and minus a millisecond",
        "Duration",
        duration(1, 0, -1),
        "parts of both signs",
    ),
    ("a Duration of minus a month and plus a day", "Duration", duration(-1, 1), "parts of both signs"),
]

# Valid edges, kept apart from the examples of section 9.
EDGES = [
    ("29 February 2000, a leap year", "Date", date(2000, 2, 29)),
    ("the month alone", "Date", date(None, 3)),
    ("the first day", "Date", date(1, 1, 1)),
    ("the last day", "Date", date(9999, 12, 31)),
    ("the last millisecond of a day", "Time", time(23, 59, 59, 999)),
    ("the first instant of 1970 in UTC", "DateTime", zoned(1970, 1, 1, 0, 0, "Etc/UTC", 0)),
    ("before 1970, with a negative instant", "DateTime", zoned(1969, 7, 20, 20, 17, "Etc/UTC", 0)),
    ("a zone this database does not have", "DateTime", zoned(2026, 11, 16, 7, 0, "Mars/Olympus_Mons", 0)),
    (
        "an offset with seconds, the local mean time of Berlin in 1890",
        "DateTime",
        zoned(1890, 6, 1, 12, 0, BERLIN, 3208),
    ),
    ("the largest offset", "DateTime", zoned(2026, 1, 1, 0, 0, "Example/Far_East", MAX_OFFSET)),
    ("the zero Duration", "Duration", duration()),
    ("a Duration back by a month, two days and three hours", "Duration", duration(-1, -2, -3 * HOUR)),
    ("36 hours, not converted into days", "Duration", duration(millis=36 * HOUR)),
    ("an all-day time: floating at 00:00", "DateTime", floating(2026, 11, 24, 0, 0)),
    ("29 February 2028 in a DateTime, a leap year", "DateTime", zoned(2028, 2, 29, 9, 0, BERLIN, CET)),
    (
        "a negative offset, America/New_York in winter",
        "DateTime",
        zoned(2026, 11, 24, 10, 0, "America/New_York", -18000),
    ),
    ("the smallest offset", "DateTime", zoned(2026, 1, 1, 0, 0, "Example/Far_West", -MAX_OFFSET)),
    ("a zone name of 64 bytes", "DateTime", zoned(2026, 11, 16, 7, 0, "Example/" + "A" * 56, 0)),
    ("the last millisecond of the year 9999, floating", "DateTime", floating(9999, 12, 31, 23, 59, 59, 999)),
    ("a Duration back by a week, in days only", "Duration", duration(days=-7)),
    ("the largest months and days of an int", "Duration", duration(INT_MAX, INT_MAX)),
    (
        "the smallest months and days of an int, and -(2^53 - 1) milliseconds",
        "Duration",
        duration(INT_MIN, INT_MIN, -(2**53 - 1)),
    ),
]

# Additions of spec/time.md, section 7.2: (label, DateTime, Duration, expected DateTime).
ADDITIONS = [
    (
        "31 January + 1 month is 28 February in 2027",
        floating(2027, 1, 31, 9, 0),
        duration(1),
        floating(2027, 2, 28, 9, 0),
    ),
    (
        "31 January + 1 month is 29 February in 2028",
        floating(2028, 1, 31, 9, 0),
        duration(1),
        floating(2028, 2, 29, 9, 0),
    ),
    (
        "31 January + 1 month + 1 day is 1 March in 2027, the months first",
        floating(2027, 1, 31, 9, 0),
        duration(1, 1),
        floating(2027, 3, 1, 9, 0),
    ),
    (
        "31 March - 1 month is 28 February in 2027",
        floating(2027, 3, 31, 9, 0),
        duration(-1),
        floating(2027, 2, 28, 9, 0),
    ),
    (
        "31 December 2026 + 2 months is 28 February 2027",
        floating(2026, 12, 31, 9, 0),
        duration(2),
        floating(2027, 2, 28, 9, 0),
    ),
    (
        "Europe/Berlin 2026-10-24 10:00 + 1 day is 10:00 the next day, 25 hours later",
        zoned(2026, 10, 24, 10, 0, BERLIN, CEST),
        duration(days=1),
        zoned(2026, 10, 25, 10, 0, BERLIN, CET),
    ),
    (
        "Europe/Berlin 2026-10-24 10:00 + 24 hours is 09:00 the next day",
        zoned(2026, 10, 24, 10, 0, BERLIN, CEST),
        duration(millis=24 * HOUR),
        zoned(2026, 10, 25, 9, 0, BERLIN, CET),
    ),
    (
        "Europe/Berlin 2026-10-25 02:20 after the change, -PT15M, is 02:05 after the change",
        zoned(2026, 10, 25, 2, 20, BERLIN, CET),
        duration(millis=-15 * MINUTE),
        zoned(2026, 10, 25, 2, 5, BERLIN, CET),
    ),
    (
        "Europe/Berlin 2026-10-25 03:10, -PT15M, is 02:55 after the change",
        zoned(2026, 10, 25, 3, 10, BERLIN, CET),
        duration(millis=-15 * MINUTE),
        zoned(2026, 10, 25, 2, 55, BERLIN, CET),
    ),
    (
        "Europe/Berlin 2026-10-25 02:05 after the change, -PT15M, is 02:50 before it",
        zoned(2026, 10, 25, 2, 5, BERLIN, CET),
        duration(millis=-15 * MINUTE),
        zoned(2026, 10, 25, 2, 50, BERLIN, CEST),
    ),
    (
        "Europe/Berlin 2026-09-25 02:30 + 1 month is the earlier 02:30 of 2026-10-25, its offset kept",
        zoned(2026, 9, 25, 2, 30, BERLIN, CEST),
        duration(1),
        zoned(2026, 10, 25, 2, 30, BERLIN, CEST),
    ),
    (
        "Europe/Berlin 2026-11-25 02:30 - 1 month is the later 02:30 of 2026-10-25, its offset kept",
        zoned(2026, 11, 25, 2, 30, BERLIN, CET),
        duration(-1),
        zoned(2026, 10, 25, 2, 30, BERLIN, CET),
    ),
    (
        "Europe/Berlin 2027-03-27 02:30 + 1 day falls into the gap and moves to 03:30",
        zoned(2027, 3, 27, 2, 30, BERLIN, CET),
        duration(days=1),
        zoned(2027, 3, 28, 3, 30, BERLIN, CEST),
    ),
    (
        "Europe/Berlin 2026-09-23 00:30 + P1M2DT3H is the later 02:30 of 2026-10-25, "
        "three hours elapsed across the change",
        zoned(2026, 9, 23, 0, 30, BERLIN, CEST),
        duration(1, 2, 3 * HOUR),
        zoned(2026, 10, 25, 2, 30, BERLIN, CET),
    ),
    (
        "a floating 2026-10-24 10:00 + 24 hours is 10:00 the next day",
        floating(2026, 10, 24, 10, 0),
        duration(millis=24 * HOUR),
        floating(2026, 10, 25, 10, 0),
    ),
    (
        "a floating 2026-11-16 00:05, -PT15M, is 23:50 the day before",
        floating(2026, 11, 16, 0, 5),
        duration(millis=-15 * MINUTE),
        floating(2026, 11, 15, 23, 50),
    ),
    (
        "Europe/Berlin 2027-03-27 10:00 + 1 day is 10:00 the next day, 23 hours later",
        zoned(2027, 3, 27, 10, 0, BERLIN, CET),
        duration(days=1),
        zoned(2027, 3, 28, 10, 0, BERLIN, CEST),
    ),
    (
        "Europe/Berlin 2026-10-26 10:00 - 1 day is 10:00 the day before, 25 hours earlier",
        zoned(2026, 10, 26, 10, 0, BERLIN, CET),
        duration(days=-1),
        zoned(2026, 10, 25, 10, 0, BERLIN, CET),
    ),
    (
        "Europe/Berlin 2026-12-31 23:30 + 1 hour is 00:30 on 1 January 2027",
        zoned(2026, 12, 31, 23, 30, BERLIN, CET),
        duration(millis=HOUR),
        zoned(2027, 1, 1, 0, 30, BERLIN, CET),
    ),
    (
        "a zone these rules do not have + 1 day keeps its offset",
        zoned(2026, 11, 16, 7, 0, "Mars/Olympus_Mons", 3600),
        duration(days=1),
        zoned(2026, 11, 17, 7, 0, "Mars/Olympus_Mons", 3600),
    ),
    (
        "a zone these rules do not have + 90 minutes moves the wall clock with the instant",
        zoned(2026, 11, 16, 23, 0, "Mars/Olympus_Mons", 3600),
        duration(millis=90 * MINUTE),
        zoned(2026, 11, 17, 0, 30, "Mars/Olympus_Mons", 3600),
    ),
    (
        "a floating 2028-02-29 + 12 months is 28 February 2029",
        floating(2028, 2, 29, 9, 0),
        duration(12),
        floating(2029, 2, 28, 9, 0),
    ),
]

# A writer whose rules for Europe/Berlin had no summer time in 2026 wrote this value; this system's
# rules give the zone +02:00 at that instant (spec/time.md, section 6.4).
OTHER_RULES = zoned(2026, 7, 1, 10, 0, BERLIN, CET)
RESOLUTIONS = [
    (
        "the wall clock and the zone kept, the instant an hour earlier",
        OTHER_RULES,
        "local",
        zoned(2026, 7, 1, 10, 0, BERLIN, CEST),
    ),
    (
        "the instant and the zone kept, the wall clock an hour later",
        OTHER_RULES,
        "instant",
        zoned(2026, 7, 1, 11, 0, BERLIN, CEST),
    ),
    ("a value that agrees with these rules is kept", EXAMPLES[0][2], "local", EXAMPLES[0][2]),
    ("the later reading of 02:30 on 2026-10-25 is kept", EXAMPLES[1][2], "local", EXAMPLES[1][2]),
    ("a zone these rules do not have keeps every field", EDGES[7][2], "local", EDGES[7][2]),
    ("a floating time keeps every field", EXAMPLES[2][2], "instant", EXAMPLES[2][2]),
    (
        "a wall clock in the overlap with an offset these rules do not give takes the earlier offset",
        zoned(2026, 10, 25, 2, 30, BERLIN, 0),
        "local",
        zoned(2026, 10, 25, 2, 30, BERLIN, CEST),
    ),
    (
        "a wall clock in the gap with an offset these rules do not give moves later by the gap",
        zoned(2027, 3, 28, 2, 30, BERLIN, CET),
        "local",
        zoned(2027, 3, 28, 3, 30, BERLIN, CEST),
    ),
    (
        "a wall clock in the overlap with an offset these rules do not give keeps its instant",
        zoned(2026, 10, 25, 2, 30, BERLIN, 0),
        "instant",
        zoned(2026, 10, 25, 3, 30, BERLIN, CET),
    ),
    (
        "a zone these rules do not have keeps every field, also for the instant",
        EDGES[7][2],
        "instant",
        EDGES[7][2],
    ),
]

# A type that holds two DateTimes and a Date (spec/time.md, section 3); not an example type.
HOST_TEXT = json.dumps(
    {
        "type": "record",
        "name": "Visit",
        "namespace": "com.example",
        "doc": "An illustration for spec/time.md; not an AXT example type.",
        "fields": [
            {
                "name": "start",
                "type": jsons["DateTime"],
                "doc": "When the visit starts.",
                "axt.anchor": "local",
            },
            {
                "name": "end",
                "type": ["null", "axt.DateTime"],
                "default": None,
                "doc": "When the visit ends; null when open.",
                "axt.anchor": "local",
            },
            {"name": "booked", "type": jsons["Date"], "doc": "The day the visit was booked."},
            {
                "name": "remind",
                "type": {"type": "array", "items": jsons["Duration"]},
                "default": [],
                "doc": "When to remind, each before start.",
            },
        ],
    },
    separators=(",", ":"),
    ensure_ascii=False,
)
HOST_VALUE: dict[str, Any] = {
    "start": zoned(2026, 11, 24, 10, 0, BERLIN, CET),
    "end": zoned(2026, 11, 24, 10, 30, BERLIN, CET),
    "booked": date(2026, 11, 15),
    "remind": [duration(days=-1), duration(millis=-HOUR)],
}


# --- checks -------------------------------------------------------------------------------


def encode(n: str, v: dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, parsed[n], v)
    return buf.getvalue()


def apache_roundtrip(schema: Any, data: bytes) -> tuple[Any, bytes]:
    datum = avro.io.DatumReader(schema).read(avro.io.BinaryDecoder(io.BytesIO(data)))
    out = io.BytesIO()
    avro.io.DatumWriter(schema).write(datum, avro.io.BinaryEncoder(out))
    return datum, out.getvalue()


def embedded(t: Any, found: dict[str, list[Any]]) -> dict[str, list[Any]]:
    """The definitions of time types inside a schema, by full name."""
    if isinstance(t, list):
        for b in t:
            embedded(b, found)
    elif isinstance(t, dict):
        full = (
            t.get("name", "") if "." in t.get("name", "") else f"{t.get('namespace', '')}.{t.get('name', '')}"
        )
        if t.get("type") == "record" and full in FULL:
            found.setdefault(full, []).append(t)
        for key in ("fields", "items", "values"):
            if key in t:
                embedded(t[key], found)
        if "type" in t and not isinstance(t["type"], str):
            embedded(t["type"], found)
    return found


fingerprints: dict[str, tuple[str, int]] = {}
rows: list[tuple[str, str, dict[str, Any], bytes]] = []


def check() -> tuple[str, int, bytes]:
    for n in NAMES:
        s, where = jsons[n], f"types/axt/{n}.avsc"
        assert s["type"] == "record" and s["name"] == n and s["namespace"] == "axt", where
        assert "axt.version" not in s, f"{where}: a schema of the specification carries no axt.version"
        assert "logicalType" not in texts[n], f"{where}: a time type uses no logical type"
        for f in s["fields"]:
            assert isinstance(f["type"], str) or f["type"][0] == "null" and isinstance(f["type"][1], str), (
                f"{where}.{f['name']}: a time type holds only primitives and unions of null and a primitive"
            )
        defined: list[str] = []
        assert rules.check_type(s, where, s, set(), defined) == 1 and defined == [f"axt.{n}"], where
        pcf = to_parsing_canonical_form(parsed[n])
        assert avro.schema.parse(pcf).canonical_form == pcf, (
            f"{n}: the two libraries disagree on the canonical form"
        )
        fp = rules.crc64_avro(pcf.encode())
        assert fa_fingerprint(pcf, "CRC-64-AVRO") == fp.to_bytes(8, "little").hex(), (
            f"{n}: fastavro fingerprint differs"
        )
        assert rules.apache_fingerprint(texts[n]) == fp.to_bytes(8, "little"), (
            f"{n}: avro fingerprint differs"
        )
        fingerprints[n] = (pcf, fp)
    if rules.failures:
        raise SystemExit("\n".join(["checks failed:"] + rules.failures))
    assert len({fp for _, fp in fingerprints.values()}) == len(NAMES)

    # The examples and the edges: valid, and the same bytes both ways.
    for label, n, v in EXAMPLES + EDGES:
        assert not problems(n, v), (label, problems(n, v))
        data = encode(n, v)
        assert fastavro.schemaless_reader(io.BytesIO(data), parsed[n], parsed[n]) == v, label
        datum, again = apache_roundtrip(apache[n], data)
        assert datum == v and again == data, label
        rows.append((label, n, v, data))
    # The values that break a rule: each breaks the one named, and only it; Avro still encodes them.
    for label, n, v, rule in INVALID:
        assert problems(n, v) == [rule], (label, problems(n, v))
        encode(n, v)
    # Every zone name of this database matches the syntax of section 6.1.
    for zone in sorted(zoneinfo.available_timezones()):
        assert ZONE_NAME.match(zone) and len(zone.encode()) <= MAX_ZONE_BYTES, zone

    # The zoned examples against this system's rules.
    for label, n, v in EXAMPLES + EDGES:
        if n == "DateTime" and v["zone"] is not None and known_zone(v["zone"]):
            assert offset_at(v["zone"], v["instant_ms"]) == v["offset_seconds"], label
            assert resolve(v, "local") == v and resolve(v, "instant") == v, label
    before, after = EXAMPLES[0][2], EXAMPLES[1][2]
    assert local_ms(before) == local_ms(after) and after["instant_ms"] - before["instant_ms"] == HOUR
    assert offsets_of_local(BERLIN, local_ms(before)) == [CEST, CET]
    assert offsets_of_local(BERLIN, local_ms(floating(2027, 3, 28, 2, 30))) == []
    for v in (before, after):  # zoneinfo agrees with both readings
        z = zoneinfo.ZoneInfo(BERLIN)
        at = (EPOCH + datetime.timedelta(milliseconds=v["instant_ms"])).astimezone(z)
        at_offset = cast(datetime.timedelta, at.utcoffset())  # at has a zone
        assert (at.hour, at.minute, int(at_offset.total_seconds())) == (2, 30, v["offset_seconds"])

    # Rule changes.
    assert offset_at(BERLIN, OTHER_RULES["instant_ms"]) == CEST != OTHER_RULES["offset_seconds"]
    for label, v, anchor, want in RESOLUTIONS:
        got = resolve(v, anchor)
        assert got == want and not problems("DateTime", got), (label, got)

    # Additions, checked against Python's datetime: the months by the calendar, the days on the wall
    # clock, the milliseconds on the time line.
    for label, v, d, want in ADDITIONS:
        got = add(v, d)
        assert got == want and not problems("DateTime", got), (label, got)
        y, m = divmod(v["year"] * 12 + v["month"] - 1 + d["months"], 12)
        wall = datetime.datetime(
            y, m + 1, min(v["day"], calendar.monthrange(y, m + 1)[1]), v["hour"], v["minute"]
        )
        wall += datetime.timedelta(days=d["days"])
        if v["zone"] is None or not known_zone(v["zone"]):
            # A floating time, and a zone these rules do not have, which keeps its offset: the wall clock
            # moves alone.
            wall += datetime.timedelta(milliseconds=d["millis"])
            assert (wall.year, wall.month, wall.day, wall.hour, wall.minute) == (
                got["year"],
                got["month"],
                got["day"],
                got["hour"],
                got["minute"],
            ), label
            if v["zone"] is not None:
                assert got["offset_seconds"] == v["offset_seconds"], label
                assert got["instant_ms"] == local_ms(got) - got["offset_seconds"] * 1000, label
        else:
            z = zoneinfo.ZoneInfo(v["zone"])
            if d["months"] or d["days"]:
                aware = wall.replace(
                    tzinfo=z,
                    fold=int(
                        cast(datetime.timedelta, wall.replace(tzinfo=z, fold=0).utcoffset()).total_seconds()
                        != v["offset_seconds"]
                    ),
                )
            else:
                aware = (EPOCH + datetime.timedelta(milliseconds=v["instant_ms"])).astimezone(z)
            end = (aware.astimezone(datetime.UTC) + datetime.timedelta(milliseconds=d["millis"])).astimezone(
                z
            )
            assert int(end.timestamp() * 1000) == got["instant_ms"], label
            end_offset = cast(datetime.timedelta, end.utcoffset())  # end has a zone
            assert (end.hour, end.minute, int(end_offset.total_seconds())) == (
                got["hour"],
                got["minute"],
                got["offset_seconds"],
            ), label
    day, hours = ADDITIONS[5], ADDITIONS[6]
    assert day[1] == hours[1] and day[3]["instant_ms"] - hours[3]["instant_ms"] == HOUR, (
        "1 day and 24 hours differ by an hour"
    )
    try:
        add(floating(9999, 12, 31, 23, 59), duration(millis=MINUTE))
        raise AssertionError("an addition past the year 9999")
    except OutOfRange:
        pass

    # The host type: the first DateTime defined in place, the second by its full name.
    host = json.loads(HOST_TEXT)
    found = embedded(host, {})
    assert sorted(found) == ["axt.Date", "axt.DateTime", "axt.Duration"] and all(
        len(x) == 1 for x in found.values()
    )
    for full, (t,) in found.items():
        assert (
            to_parsing_canonical_form(fastavro.parse_schema(t, _write_hint=False))
            == fingerprints[FULL[full]][0]
        ), full
    host_parsed = fastavro.parse_schema(host)
    host_apache = avro.schema.parse(HOST_TEXT)
    pcf = to_parsing_canonical_form(host_parsed)
    assert avro.schema.parse(pcf).canonical_form == pcf
    assert rules.apache_fingerprint(HOST_TEXT) == rules.crc64_avro(pcf.encode()).to_bytes(8, "little")
    assert fingerprints["DateTime"][0] in pcf and pcf.count('"name":"axt.DateTime"') == 1
    buf = io.BytesIO()
    fastavro.schemaless_writer(buf, host_parsed, HOST_VALUE)
    data = buf.getvalue()
    assert fastavro.schemaless_reader(io.BytesIO(data), host_parsed, host_parsed) == HOST_VALUE
    datum, again = apache_roundtrip(host_apache, data)
    assert datum == HOST_VALUE and again == data
    assert not time_problems(host, HOST_VALUE)
    # Two hosts in one set of names (spec/time.md, section 3.1): fastavro takes the second definition of
    # axt.DateTime, avro 1.12.2 raises; each parses with a set of its own.
    trip = dict(host, name="Trip")
    shared: dict[str, Any] = {}
    fastavro.parse_schema(host, named_schemas=shared)
    fastavro.parse_schema(trip, named_schemas=shared)
    names = avro.name.Names()
    avro.schema.make_avsc_object(json.loads(HOST_TEXT), names)
    try:
        avro.schema.make_avsc_object(json.loads(json.dumps(trip)), names)
        raise AssertionError("avro 1.12.2 took a second definition of axt.DateTime in one set of names")
    except avro.errors.SchemaParseException:
        pass
    avro.schema.make_avsc_object(json.loads(json.dumps(trip)), avro.name.Names())
    broken = dict(HOST_VALUE, end=dict(HOST_VALUE["end"], instant_ms=HOST_VALUE["end"]["instant_ms"] + 1))
    assert time_problems(host, broken) == [
        "axt.DateTime: instant_ms is not the wall clock minus offset_seconds"
    ]
    assert value_breaches(host, broken) == [
        ("end", "axt.DateTime", "instant_ms is not the wall clock minus offset_seconds")
    ]
    # axt.anchor (section 6.4; spec/metadata.md, section 2): on a field that holds axt.DateTime, local or
    # instant.
    assert mr.schema_problems(host) == []
    other = json.loads(HOST_TEXT)
    other["fields"][0]["axt.anchor"] = "utc"
    other["fields"][2]["axt.anchor"] = "instant"
    assert mr.schema_problems(other) == [
        ("start", "axt.anchor: neither local nor instant"),
        ("booked", "axt.anchor: on a field that holds no axt.DateTime"),
    ], mr.schema_problems(other)
    late = dict(HOST_VALUE, remind=[duration(days=-1), duration(days=1, millis=-HOUR)])
    assert value_breaches(host, late) == [("remind[1]", "axt.Duration", "parts of both signs")]
    for label, n, v, rule in INVALID:
        assert value_breaches(jsons[n], v) == [("", f"axt.{n}", rule)], (
            label
        )  # the record itself: the empty path
    return pcf, rules.crc64_avro(pcf.encode()), data


HOST_PCF, HOST_FP, HOST_DATA = check()


def tzdb_version() -> str:
    """The version of the time zone database zoneinfo reads, from the package tzdata or a tzdata.zi."""
    try:
        import tzdata  # type: ignore[import-untyped]  # the package tzdata has no stubs and no py.typed

        version: str = tzdata.IANA_VERSION
        return version
    except ImportError:
        pass
    for directory in zoneinfo.TZPATH:
        path = Path(directory) / "tzdata.zi"
        if path.exists():
            first = path.read_text(encoding="utf-8").split("\n", 1)[0]
            if first.startswith("# version "):
                return first[len("# version ") :]
    return "unknown"


def show(v: Any) -> str:
    return json.dumps(v, separators=(", ", ": "))


def main() -> None:
    print(f"time zone database: {tzdb_version()}")
    for n in NAMES:
        pcf, fp = fingerprints[n]
        print(f"axt.{n}: types/axt/{n}.avsc")
        print(f"  canonical form: {pcf}")
        print(f"  CRC-64-AVRO 0x{fp:016x}, bytes {fp.to_bytes(8, 'little').hex(' ')}")
    print()
    print("| Type | Schema | CRC-64-AVRO | As bytes |")
    print("| --- | --- | --- | --- |")
    for n in NAMES:
        pcf, fp = fingerprints[n]
        print(
            f"| `axt.{n}` | [{n}.avsc](../types/axt/{n}.avsc) | `0x{fp:016x}` | "
            f"`{fp.to_bytes(8, 'little').hex(' ')}` |"
        )
    print()
    print("| Value | Type | Fields | Avro binary |")
    print("| --- | --- | --- | --- |")
    for label, n, v, data in rows[: len(EXAMPLES)]:
        print(f"| {label} | `axt.{n}` | `{show(v)}` | `{data.hex(' ')}` |")
    print()
    print("edges:")
    for label, _n, _v, data in rows[len(EXAMPLES) :]:
        print(f"  {label}: {data.hex(' ')}")
    print("rejected:")
    for label, _n, _v, rule in INVALID:
        print(f"  {label}: {rule}")
    print("additions:")
    for label, _v, _d, want in ADDITIONS:
        print(f"  {label}: instant {want['instant_ms']}, offset {want['offset_seconds']}")
    print("other zone rules:")
    for label, _v, anchor, want in RESOLUTIONS:
        print(
            f"  {anchor}: {label}: {want['year']:04d}-{want['month']:02d}-{want['day']:02d} "
            f"{want['hour']:02d}:{want['minute']:02d}, offset {want['offset_seconds']}, "
            f"instant {want['instant_ms']}"
        )
    print(f"host com.example.Visit: canonical form {HOST_PCF}")
    print(f"  CRC-64-AVRO 0x{HOST_FP:016x}; value {len(HOST_DATA)} bytes: {HOST_DATA.hex(' ')}")
    print("all checks passed")


if __name__ == "__main__":
    main()
