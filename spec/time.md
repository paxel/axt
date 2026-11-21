# Time

Status: released in 0.1.0. A change to this document is a new version of AXT, with its entry in [CHANGELOG.md](../CHANGELOG.md). Section 3.3 applies to the time types.

This document defines the four time types of AXT, `axt.Date`, `axt.Time`, `axt.DateTime` and `axt.Duration`: their fields and the rules a value keeps, how a type that holds a time value carries them, what a receiver does when its time zone rules differ from the writer's, and how a duration is added to a date and time.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Calendar**: the proleptic Gregorian calendar of [ISO 8601](https://www.iso.org/iso-8601-date-and-time-format.html), extended back before 1582 with the same leap year rule: a year divisible by 4 is a leap year, except a year divisible by 100 and not by 400.
- **Wall clock**: a date and a time of day as a clock on the wall shows it, without a time zone, such as 2026-10-25 02:30.
- **Instant**: a point on the time line, as a count of milliseconds since 1970-01-01T00:00:00Z in which every day has 86,400,000 milliseconds, as in POSIX time, JavaScript's `Date` and `java.time.Instant`. Leap seconds are not counted.
- **Time zone**, or zone: a region whose wall clocks follow the same rules, named as in the [IANA time zone database](https://www.iana.org/time-zones), such as `Europe/Berlin`.
- **Offset**: the difference between a wall clock and UTC at an instant, in seconds, positive east of UTC: 3600 for the wall clock of Berlin in winter.
- **Zone rules**: the offsets a zone has had and will have, and the instants at which they change, as a copy of the IANA time zone database says. Two apps can have different copies, and a later copy can give a zone other offsets than an earlier one.
- **Zoned time**: an `axt.DateTime` with a zone. **Floating time**: an `axt.DateTime` without a zone, meant on the wall clock of wherever its user is at the time, such as an alarm that rings at 07:00 in every zone the user travels to.
- **Overlap** and **gap**: where the offset of a zone decreases, the wall clocks of an hour or other length occur twice, once with each offset, as 02:00 to 03:00 in Berlin on 2026-10-25; where it increases, the wall clocks of that length do not occur, as 02:00 to 03:00 in Berlin on 2027-03-28.
- **Host type**: a type that holds a time value in one of its fields, such as an appointment that holds its start as an `axt.DateTime`.

Avro terms such as "Parsing Canonical Form", "CRC-64-AVRO" and "schema resolution" have the meaning the [Avro 1.12 specification](https://avro.apache.org/docs/1.12.0/specification/) gives them.

## 2. The time types

| Type           | Schema                                      | Holds                                                                   | In SQL      |
| -------------- | ------------------------------------------- | ----------------------------------------------------------------------- | ----------- |
| `axt.Date`     | [Date.avsc](../types/axt/Date.avsc)         | A date, of which the year, the day, or both may be unknown (section 4)  | `DATE`      |
| `axt.Time`     | [Time.avsc](../types/axt/Time.avsc)         | A time of day, to the millisecond, without a zone (section 5)           | `TIME`      |
| `axt.DateTime` | [DateTime.avsc](../types/axt/DateTime.avsc) | A wall clock with its zone, offset and instant, or floating (section 6) | `TIMESTAMP` |
| `axt.Duration` | [Duration.avsc](../types/axt/Duration.avsc) | A length of time in months, days and milliseconds (section 7)           | `INTERVAL`  |

The schemas are normative. They are in the namespace `axt`, which is reserved for the AXT repository ([types.md](types.md), section 2), and follow the rules of [types.md](types.md), section 5. Each is a record of primitives and of unions of `null` and a primitive, with no named type and no logical type inside, so that a host type that holds several of them can define each one where it first occurs (section 3.1).

The time types are records rather than strings or the numeric time types of Avro. A record keeps the parts of a value apart, so that a receiver needs no parser of date and time texts, and a part that is not known is `null` rather than a made-up value. The numeric types of Avro cannot say a date without a year, a time zone or the offset at writing; the logical types `timestamp-millis` and `local-timestamp-millis` are a `long` in the Parsing Canonical Form, so a receiver cannot tell an instant from a wall clock by the fingerprint, and a library that does not know a logical type reads a bare number.

## 3. Using the time types in a type

### 3.1 In place, then by name

A host type MUST define each time type it holds in place, at its first occurrence in the schema in the order in which Avro parses it, as a record with the full name of the time type, such as `axt.DateTime`, and with exactly the fields of the published schema: its Parsing Canonical Form MUST be that of the published schema (section 9.1). Every later occurrence of the same time type in the schema MUST refer to it by its full name, such as `"axt.DateTime"`, not by the name alone, which Avro would read in the namespace of the host type. The definition SHOULD carry the `doc` texts of the published schema.

This is the one case in which a type defines a named type in the namespace `axt` and refers to a named type by its name; [types.md](types.md), sections 2 and 5.2, make the exception for it. Every schema then still parses on its own, and a receiver recognises a time value by the full name of its record, wherever it occurs. Section 9.3 shows a host type with two `axt.DateTime` fields.

A receiver MUST decline a type whose schema defines a record with the full name of a time type whose Parsing Canonical Form is not that of the published schema, or defines any other named type in the namespace `axt`, with `DOES_NOT_RESOLVE` ([protocol.md](protocol.md), section 5.2): it cannot read such a value as this document defines it. An app that reads several schemas into one set of names finds a time type defined in each schema that holds it, each time with the same canonical form. Some Avro parsers reject a second definition of a name in one set: fastavro 1.13.1 takes it, the Python `avro` 1.12.2 package raises an error. An app MUST NOT reject a schema because another schema it holds defines the same time type; it parses each schema with a set of names of its own, or takes a repeated definition of a time type with the published canonical form as the same type.

### 3.2 Which types use them

- The schemas of this specification and the example types ([types.md](types.md)) MUST hold every date, time of day, date and time, and length of time in one of the time types, and MUST NOT use the Avro logical types `date`, `time-millis`, `time-micros`, `timestamp-millis`, `timestamp-micros`, `timestamp-nanos`, `local-timestamp-millis`, `local-timestamp-micros`, `local-timestamp-nanos` or `duration`.
- An app type SHOULD do the same. An app type that uses one of those logical types is read by its underlying Avro type ([envelope.md](envelope.md), section 7): AXT gives such a field no meaning beyond the Avro specification, a receiver that shows it MAY show its number, and the rules of this document do not apply to it.
- A host type that holds an `axt.DateTime` for a wall clock and a separate field for its zone, or an `axt.Date` and an `axt.Time` in place of an `axt.DateTime`, SHOULD NOT do so: the zone, the offset and the instant belong into the `axt.DateTime`, so that every receiver finds them in the same place.

### 3.3 The time types do not change

The schema of a time type is part of the schema of every host type, and so of its fingerprint. A change of a time type would change every host type at once. The published schemas of the time types are therefore never changed; a later version of this specification that needs another time type publishes it under a new full name.

## 4. `axt.Date`

| Field   | Avro type         | Value                                                                   |
| ------- | ----------------- | ----------------------------------------------------------------------- |
| `year`  | `["null", "int"]` | The year of the calendar, 1 to 9999, or `null` when it is not known     |
| `month` | `["null", "int"]` | The month, 1 (January) to 12 (December), or `null` when it is not known |
| `day`   | `["null", "int"]` | The day of the month, 1 to the number of days of that month, or `null`  |

A value of `axt.Date` is valid when:

1. at least one part is not `null`;
2. `day` is `null` when `month` is `null`: a day has its month;
3. each part that is not `null` is within its range;
4. `day` is at most the number of days of its month: of that year when `year` is not `null`, otherwise of a leap year, so that 29 February is valid without a year and 29 February 2027 is not.

The parts that are allowed together are therefore the full date (2026, 11, 24), a month of a year, such as an expiry in March 2027 (2027, 3, `null`), a year alone, such as "since 2019" (2019, `null`, `null`), a day of a month without a year, such as a birthday whose year is not known (`null`, 5, 3), and a month alone (`null`, 3, `null`). A year and a day without the month, and a day alone, are not.

The years 1 to 9999 are those of SQL `DATE` and those that the date types of common platforms, such as Python's `datetime.date`, can hold; ISO 8601 writes them with four digits, without the expansion it needs for other years. A date that is not known at all is a field of the type `["null", axt.Date]` whose value is `null`, not an `axt.Date` without parts.

## 5. `axt.Time`

| Field         | Avro type | Value                     |
| ------------- | --------- | ------------------------- |
| `hour`        | `int`     | The hour, 0 to 23         |
| `minute`      | `int`     | The minute, 0 to 59       |
| `second`      | `int`     | The second, 0 to 59       |
| `millisecond` | `int`     | The millisecond, 0 to 999 |

A value of `axt.Time` is valid when each field is within its range. 24:00 is not valid; the end of a day is 00:00 of the next day, in an `axt.DateTime`.

- **Precision.** A time of day is given to the millisecond, the precision of the instant of section 6 and of `axt.Duration`. A time given to the minute or the second has `0` in the finer fields. The schema does not say to what precision a time was meant; a receiver SHOULD NOT show a `second` and a `millisecond` that are both `0`, and SHOULD NOT show a `millisecond` that is `0`.
- **Leap seconds.** A writer MUST NOT write the second 60. A time in a leap second is written within the second 59 of the same minute, as a clock that follows POSIX time shows it.
- **No time zone.** An `axt.Time` has no zone and no offset. A time of day with an offset, as SQL `TIME WITH TIME ZONE` holds it, has no defined meaning across a change of offset, since without a date it cannot say which offset applies; the SQL standard defines the type, but the documentation of PostgreSQL, which has it, calls its usefulness questionable, and an offset is not a zone. A time of day that is meant in one place, such as a daily routine that follows the clock of Berlin, is an `axt.DateTime` with a repetition rule ([types.md](types.md), section 5.6), or its host type carries the zone in a field of its own.

## 6. `axt.DateTime`

### 6.1 Fields

| Field            | Avro type            | Value                                                                                               |
| ---------------- | -------------------- | --------------------------------------------------------------------------------------------------- |
| `year`           | `int`                | The year of the calendar, 1 to 9999                                                                 |
| `month`          | `int`                | The month, 1 to 12                                                                                  |
| `day`            | `int`                | The day of the month, 1 to the number of days of that month in that year                            |
| `hour`           | `int`                | The hour on the wall clock, 0 to 23                                                                 |
| `minute`         | `int`                | The minute, 0 to 59                                                                                 |
| `second`         | `int`                | The second, 0 to 59                                                                                 |
| `millisecond`    | `int`                | The millisecond, 0 to 999                                                                           |
| `zone`           | `["null", "string"]` | The name of the zone, or `null` for a floating time                                                 |
| `offset_seconds` | `["null", "int"]`    | The offset at the instant as the writer's zone rules gave it, -64800 to 64800; `null` when floating |
| `instant_ms`     | `["null", "long"]`   | The instant; `null` when floating                                                                   |

The first seven fields are the wall clock. They are full: a date and time on the wall clock has every part, and its date and time of day keep the rules of sections 4 and 5. A date or a time of day alone is an `axt.Date` or an `axt.Time`.

`zone` is the name of a zone of the IANA time zone database, as the database spells it, such as `Europe/Berlin`, `America/Argentina/Buenos_Aires` or `Etc/UTC`, or a link name of the database, such as `UTC`. Its syntax is checked without the database: one or more parts separated by `/`, each of ASCII letters, digits, `.`, `_`, `+` and `-`, neither `.` nor `..` and not beginning with `-`; at most 64 bytes in all. Every name of the database has this form.

The offset is in seconds because the zone rules have offsets that are not whole minutes: before 1893, the database gives `Europe/Berlin` the local mean time of Berlin, +00:53:28. An offset of whole minutes could not give such a wall clock its instant. 18 hours either side, the range of `java.time.ZoneOffset`, holds every offset the database has.

### 6.2 Validity

A value of `axt.DateTime` is valid when:

1. the wall clock keeps the rules of section 6.1;
2. `zone`, `offset_seconds` and `instant_ms` are either all `null`, for a floating time, or all not `null`, for a zoned time;
3. `zone` is a name of the syntax of section 6.1, and `offset_seconds` is within -64800 to 64800;
4. for a zoned time, `instant_ms` is the wall clock read as if it were UTC, minus the offset: `instant_ms = L - 1000 × offset_seconds`, where `L` is the number of milliseconds from 1970-01-01T00:00:00 to the wall clock on the calendar, counting 86,400,000 for each day.

These rules need no time zone database. A receiver MUST NOT treat a value as invalid because its zone rules do not know the zone, or give the zone another offset at the instant; section 6.4 says what it does then.

The instant is carried although the wall clock and the offset give it, so that a receiver can sort, compare and schedule zoned times without computing them, and without zone rules at all.

### 6.3 Writing a zoned time

A writer MUST write `offset_seconds` as its own zone rules give the zone at `instant_ms`. With section 6.2, this means that the wall clock occurs in the zone, by the writer's rules, with that offset.

- **Overlap.** A wall clock in an overlap occurs twice; the offset tells the two apart. 02:30 on 2026-10-25 in Berlin is the instant `1792888200000` with the offset 7200 before the clocks go back, and `1792891800000` with the offset 3600 an hour later (section 9.2). A writer writes the offset of the occurrence its user means.
- **Gap.** A wall clock in a gap does not occur, and a writer MUST NOT write it. Where an app has to place a wall clock that its rules put into a gap, such as a daily alarm at 02:30 on 2027-03-28 in Berlin, it moves it later by the length of the gap, to 03:30 with the offset 7200, as `java.time.ZonedDateTime` does.
- **Placing a wall clock.** Where this document places a wall clock in a zone, it uses the offset given, if the wall clock occurs with it; otherwise the one offset with which the wall clock occurs; in an overlap the earlier of the two occurrences, that is, the larger offset; and in a gap the wall clock moved later by the length of the gap, with the offset after it. These are the rules of `ZonedDateTime.ofLocal` of `java.time` with a preferred offset.
- **An offset without a zone.** A date and time that a writer knows only with an offset, such as a text of [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339), has no zone. The writer writes the zone if it knows it. Otherwise it writes the same instant with the zone `Etc/UTC`, the offset 0 and the wall clock of UTC, since an offset alone does not say how the wall clock goes on.
- **The database version.** An `axt.DateTime` does not carry the version of the writer's time zone database. The offset at writing already records what the writer's rules gave, which is what a receiver needs to see that its own rules differ (section 6.4); a receiver could not use the rules of another version, and the version does not say which zones changed.

### 6.4 Zone rules that differ: the anchor

A receiver's zone rules can give a zone another offset at an instant than the writer's did, because one of the two has an older copy of the database, or because the rules of the zone changed between writing and reading. The wall clock and the instant then no longer agree, and the receiver has to keep one of them. Which one depends on what the field means, and so the host type says it, with the attribute `axt.anchor` on the field ([types.md](types.md), section 6):

| `axt.anchor` | Kept                    | For                                                                                                                 |
| ------------ | ----------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `local`      | The wall clock and zone | A time agreed on the wall clock, mostly in the future: an appointment at 10:00 stays at 10:00 when the rules change |
| `instant`    | The instant and zone    | A time at which something happened, mostly in the past: a measurement, the time a note was written                  |

The attribute sits on a field whose type is `axt.DateTime`, `["null", axt.DateTime]`, or an array of either, and applies to every `axt.DateTime` in the field's value. A field without the attribute, or with another value, has the anchor `local`: a receiver ignores attributes it does not know, and a wall clock that moves under its user misses an appointment, while an instant that moves by an hour on the wall clock is still the same instant.

A receiver that takes a zoned time:

1. If its zone rules do not know the zone, it keeps every field as received. It SHOULD show the wall clock with the zone name, and use the instant for sorting and scheduling.
2. If its zone rules give the zone the offset `offset_seconds` at `instant_ms`, the value agrees with its rules, and it keeps every field as received.
3. Otherwise, with the anchor `local`, it keeps the wall clock and the zone, places the wall clock in the zone by its own rules without a preferred offset (section 6.3), and takes the offset and the instant that gives. With the anchor `instant`, it keeps the instant and the zone, and takes the offset its rules give at the instant and the wall clock of that offset.

A value whose wall clock is in a gap by the receiver's rules is moved later by the gap under the anchor `local`. A receiver SHOULD apply these steps again to the zoned times it holds when its zone rules change. What a receiver takes by these steps is its reading of the value under its rules; it is not a change of the record by its user ([records.md](records.md), section 6).

### 6.5 Floating times

A floating time has no zone, offset or instant. It is meant on the wall clock of the zone its user is in at the time, and a receiver places it in that zone (section 6.3) where it needs an instant, for example to ring an alarm. A floating time has no instant that two apps could agree on, so a receiver SHOULD NOT sort floating and zoned times of different users together by instant. The anchor does not apply to a floating time.

## 7. `axt.Duration`

### 7.1 Fields

| Field    | Avro type | Value                                      |
| -------- | --------- | ------------------------------------------ |
| `months` | `int`     | Calendar months; a year is 12 months       |
| `days`   | `int`     | Calendar days; a week is 7 days            |
| `millis` | `long`    | Elapsed milliseconds; an hour is 3,600,000 |

The three parts are not converted into each other, since their lengths vary: a month has 28 to 31 days, and a day on the wall clock lasts 23, 24 or 25 hours where the offset changes. 1 day and 24 hours, or 1 month and 30 days, are different durations. A writer MUST NOT convert one part into another. Hours, minutes and seconds are `millis`.

A value of `axt.Duration` is valid when the parts that are not `0` all have the same sign: a duration either reaches forward, with every part at least `0`, or back, with every part at most `0`. A duration with parts of both signs, such as one month minus one day, is not valid: it has no form in the text of ISO 8601, and an app that shows "before" or "after" for a negative or a positive duration, as for a reminder before an appointment, could not say which it is. The parts may have any value of their Avro types.

A receiver MAY show a duration in the form of ISO 8601, with a leading `-` for one that reaches back: 1 month, 2 days and 10,800,000 milliseconds as `P1M2DT3H`, and -900,000 milliseconds as `-PT15M`. The text form is not part of AXT.

### 7.2 Adding a duration to a date and time

A receiver adds a duration to an `axt.DateTime`, as it holds it after section 6.4, in this order:

1. **Months.** The year and month move by `months`. If the day is beyond the last day of the new month, it becomes the last day: 31 January + 1 month is 28 February 2027 and 29 February 2028.
2. **Days.** The date moves by `days` days of the calendar; the time of day stays.
3. **Placing.** For a zoned time, if `months` or `days` is not `0`, the new wall clock is placed in the zone with the offset of the value as the preferred offset (section 6.3), which gives the offset and the instant. A receiver whose zone rules do not know the zone keeps the offset and computes the instant by section 6.2.
4. **Milliseconds.** For a zoned time, `millis` is added to the instant, and the wall clock and the offset are those the zone has at the new instant; a receiver that does not know the zone keeps the offset and moves the wall clock by the same amount. For a floating time, `millis` is added to the wall clock as if it were UTC, since a floating time has no offset that could change.

The order is that of `java.time`: `ZonedDateTime.plus` with a `Period` of the months and days, then with a `Duration` of the milliseconds; and the days are nominal and the milliseconds exact, as for the durations of [RFC 5545](https://www.rfc-editor.org/rfc/rfc5545), section 3.3.6. A duration that reaches back is added in the same order, with negative parts: subtracting a duration is adding it with every part negated. The months come first so that 31 January + 1 month + 1 day is 1 March in 2027, the same as adding 1 month and then 1 day.

The steps keep a wall clock where people expect it: 10:00 on 2026-10-24 in Berlin + 1 day is 10:00 on 2026-10-25, 25 hours later, while + 24 hours is 09:00 (section 9.2). An addition whose result, or the date after step 1 or 2, lies outside the years 1 to 9999 fails; a receiver MUST NOT write such a result.

## 8. Invalid values

A record that holds a time value that is not valid by sections 4, 5, 6.2 or 7.1 cannot be read as this document defines it. A receiver MUST reject it ([protocol.md](protocol.md), section 6.2, step 9): in a live connection and through a relay it rejects the message with `VALUE_INVALID`, whose `field` names the time value, such as `end` ([metadata.md](metadata.md), section 7.2), and from a file it does not apply that record ([transports.md](transports.md), section 2.2). A sender MUST NOT send such a record.

The bytes of such a record decode with its schema; what is wrong is the value. It is therefore `VALUE_INVALID`, which names the value, and not `UNDECODABLE`, which is for bytes that are not a value of the schema at all ([metadata.md](metadata.md), section 7.3).

A value that is valid by these sections is not rejected for its zone or its offset: a zone the receiver's rules do not know, and an offset they do not give, are handled by section 6.4.

## 9. Examples

The values below were produced with [conformance/tools/time_examples.py](../conformance/tools/time_examples.py). The script reads the schemas of the time types, encodes with the Python library fastavro 1.13.1, and checks:

- the rules of [types.md](types.md), section 5, with the code of [conformance/tools/example_types.py](../conformance/tools/example_types.py), and that each type is a record of primitives and unions of `null` and a primitive, without logical types and named types inside;
- the canonical forms and fingerprints against fastavro's and the Python `avro` 1.12.2 package's own;
- each example and 22 edges, such as 29 February 2000, a negative instant, an offset with seconds, a negative offset and a zone name of 64 bytes, by encoding it with fastavro, decoding it again with both libraries, and encoding it again with `avro` to the same bytes; and 45 values that each break one rule of sections 4 to 7, such as 29 February 1900, the second 60, a zone name of 65 bytes and a duration with parts of both signs, with the field path a receiver reports for each, also inside the host type of section 9.3;
- the zoned examples against the time zone database 2026e of the system with Python's `zoneinfo`: the offset is that of the zone at the instant, and 02:30 on 2026-10-25 occurs in Berlin with the offsets 7200 and 3600; and that every name of the database has the syntax of section 6.1;
- section 6.4 on a value written with rules that gave Berlin no summer time in 2026, under both anchors, and on a zone the database does not have;
- 22 additions of section 7.2, over the ends of months and of a year, across the changes of offset in Berlin on 2026-10-25 and 2027-03-28 and into the gap of 2027-03-28, of floating times, and of a zone the database does not have, against Python's `datetime` and `zoneinfo`; and that an addition past the year 9999 fails;
- the host type of section 9.3, by parsing it with both libraries and comparing their canonical forms, by parsing it and a second host into one set of names, which fastavro takes and `avro` rejects (section 3.1), by comparing the canonical form of each time type defined in it with that of the published schema, and by a round trip of its example with both libraries.

The test vectors of [conformance.md](conformance.md) take precedence over these values.

### 9.1 Fingerprints

| Type           | Schema                                      | CRC-64-AVRO          | As bytes                  |
| -------------- | ------------------------------------------- | -------------------- | ------------------------- |
| `axt.Date`     | [Date.avsc](../types/axt/Date.avsc)         | `0xf28393c87dae796b` | `6b 79 ae 7d c8 93 83 f2` |
| `axt.Time`     | [Time.avsc](../types/axt/Time.avsc)         | `0x6f78a0abf09914ef` | `ef 14 99 f0 ab a0 78 6f` |
| `axt.DateTime` | [DateTime.avsc](../types/axt/DateTime.avsc) | `0x598b8bc3b1a68937` | `37 89 a6 b1 c3 8b 8b 59` |
| `axt.Duration` | [Duration.avsc](../types/axt/Duration.avsc) | `0xffddd15473b3f085` | `85 f0 b3 73 54 d1 dd ff` |

The Parsing Canonical Form of `axt.DateTime`:

```json
{"name":"axt.DateTime","type":"record","fields":[{"name":"year","type":"int"},{"name":"month","type":"int"},{"name":"day","type":"int"},{"name":"hour","type":"int"},{"name":"minute","type":"int"},{"name":"second","type":"int"},{"name":"millisecond","type":"int"},{"name":"zone","type":["null","string"]},{"name":"offset_seconds","type":["null","int"]},{"name":"instant_ms","type":["null","long"]}]}
```

### 9.2 Values

Each value in Avro binary encoding, without a single-object header:

| Value                                                        | Type           | Fields                                                        | Avro binary                                                                                          |
| ------------------------------------------------------------ | -------------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| An appointment in Berlin, 2026-10-25 02:30 before the change | `axt.DateTime` | 2026-10-25 02:30:00.000, `Europe/Berlin`, 7200, 1792888200000 | `d4 1f 14 32 04 3c 00 00 02 1a 45 75 72 6f 70 65 2f 42 65 72 6c 69 6e 02 c0 70 02 80 ed b6 87 ae 68` |
| The same wall clock after the change, an hour later          | `axt.DateTime` | 2026-10-25 02:30:00.000, `Europe/Berlin`, 3600, 1792891800000 | `d4 1f 14 32 04 3c 00 00 02 1a 45 75 72 6f 70 65 2f 42 65 72 6c 69 6e 02 a0 38 02 80 a7 ee 8a ae 68` |
| An alarm, floating, 2026-11-16 07:00                         | `axt.DateTime` | 2026-11-16 07:00:00.000, `null`, `null`, `null`               | `d4 1f 16 20 0e 00 00 00 00 00 00`                                                                   |
| A daily alarm at 07:00                                       | `axt.Time`     | 7, 0, 0, 0                                                    | `0e 00 00 00`                                                                                        |
| A birthday without a year, 3 May                             | `axt.Date`     | `null`, 5, 3                                                  | `00 02 0a 02 06`                                                                                     |
| Since 2019                                                   | `axt.Date`     | 2019, `null`, `null`                                          | `02 c6 1f 00 00`                                                                                     |
| An expiry in March 2027                                      | `axt.Date`     | 2027, 3, `null`                                               | `02 d6 1f 02 06 00`                                                                                  |
| Born on 29 February, year not known                          | `axt.Date`     | `null`, 2, 29                                                 | `00 02 04 02 3a`                                                                                     |
| A full date, 2026-11-24                                      | `axt.Date`     | 2026, 11, 24                                                  | `02 d4 1f 02 16 02 30`                                                                               |
| A reminder 15 minutes before, `-PT15M`                       | `axt.Duration` | 0, 0, -900000                                                 | `00 00 bf ee 6d`                                                                                     |
| Every month, `P1M`                                           | `axt.Duration` | 1, 0, 0                                                       | `02 00 00`                                                                                           |
| `P1M2DT3H`                                                   | `axt.Duration` | 1, 2, 10800000                                                | `02 04 80 ae a6 0a`                                                                                  |

Additions of section 7.2, among the 22 the script checks:

| Date and time                  | Duration   | Result                                 |
| ------------------------------ | ---------- | -------------------------------------- |
| 2027-01-31 09:00, floating     | `P1M`      | 2027-02-28 09:00                       |
| 2028-01-31 09:00, floating     | `P1M`      | 2028-02-29 09:00                       |
| 2027-01-31 09:00, floating     | `P1M1D`    | 2027-03-01 09:00                       |
| 2026-10-24 10:00, Berlin, 7200 | `P1D`      | 2026-10-25 10:00, 3600, 25 hours later |
| 2026-10-24 10:00, Berlin, 7200 | `PT24H`    | 2026-10-25 09:00, 3600                 |
| 2026-10-25 02:05, Berlin, 3600 | `-PT15M`   | 2026-10-25 02:50, 7200                 |
| 2026-09-23 00:30, Berlin, 7200 | `P1M2DT3H` | 2026-10-25 02:30, 3600                 |
| 2027-03-27 02:30, Berlin, 3600 | `P1D`      | 2027-03-28 03:30, 7200, out of the gap |
| 2026-10-24 10:00, floating     | `PT24H`    | 2026-10-25 10:00                       |

A value written with rules that gave Berlin no summer time in 2026, 2026-07-01 10:00 with the offset 3600 and the instant `1782896400000`, is read under the system's rules, which give the offset 7200 at that instant, as 2026-07-01 10:00 with the offset 7200 and the instant `1782892800000` under the anchor `local`, and as 2026-07-01 11:00 with the offset 7200 and the same instant under the anchor `instant`.

### 9.3 A host type

`com.example.Visit` is an illustration only, not an example type. Its field `start` defines `axt.DateTime` in place, `end` refers to it by its full name, and `booked` and `remind` define `axt.Date` and `axt.Duration`:

```json
{"type":"record","name":"Visit","namespace":"com.example","doc":"An illustration for spec/time.md; not an AXT example type.","fields":[{"name":"start","type":{"type":"record","name":"DateTime","namespace":"axt","doc":"…","fields":[…]},"doc":"When the visit starts.","axt.anchor":"local"},{"name":"end","type":["null","axt.DateTime"],"default":null,"doc":"When the visit ends; null when open.","axt.anchor":"local"},{"name":"booked","type":{"type":"record","name":"Date","namespace":"axt","doc":"…","fields":[…]},"doc":"The day the visit was booked."},{"name":"remind","type":{"type":"array","items":{"type":"record","name":"Duration","namespace":"axt","doc":"…","fields":[…]}},"default":[],"doc":"When to remind, each before start."}]}
```

The `…` stand for the `doc` and the fields of the published schemas. Its Parsing Canonical Form holds the canonical form of `axt.DateTime` of section 9.1 once, at `start`, and `"axt.DateTime"` at `end`; its CRC-64-AVRO is `0x0e3e5cd48bbba990`.

## References

- [Apache Avro 1.12 specification](https://avro.apache.org/docs/1.12.0/specification/)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
- [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339): date and time on the internet
- [RFC 5545](https://www.rfc-editor.org/rfc/rfc5545): iCalendar, for nominal and exact durations
- [ISO 8601](https://www.iso.org/iso-8601-date-and-time-format.html): date and time format, for the calendar and the text of durations
- [IANA time zone database](https://www.iana.org/time-zones)
- [`java.time`](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/time/package-summary.html), for `ZonedDateTime`, `ZoneOffset`, `Period` and `Duration`
