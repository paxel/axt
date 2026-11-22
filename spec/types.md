# Example types

Status: released in 0.1.0, changed in 0.2.0. A change to this document is a new version of AXT, with its entry in [CHANGELOG.md](../CHANGELOG.md). Section 3 applies to the example types.

This document defines the example types that apps can use without agreeing first, the names and versions of types, what it means to replace an example type, the rules every example type follows, the hints a receiver may use to show a record whose type it does not know, and the relations with which a record links to other records and to things outside AXT.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Type**: an Avro record schema whose records travel as the body of `DATA` messages ([envelope.md](envelope.md), section 2.3). A type is named by its full name, the namespace and the name together, such as `axt.example.v1.Note`.
- **Example type**: a type published in this repository under [types/axt/example/](../types/axt/example/). Example types are there so that apps can exchange records without agreeing on a format first.
- **App type**: a type an app defines for itself, under a namespace of its own.
- **Version**: one published schema of a type, numbered by its `axt.version` attribute (section 3.2).

Avro terms such as "Parsing Canonical Form", "CRC-64-AVRO", "schema resolution" and "alias" have the meaning the [Avro 1.12 specification](https://avro.apache.org/docs/1.12.0/specification/) gives them.

## 2. Namespaces

The namespace `axt` and every namespace that begins with `axt.` are reserved for the AXT repository:

| Namespace        | Content                                                                                                              | Defined in                                                    |
| ---------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `axt`            | The schemas of the specification, such as `axt.Envelope`, the time types, such as `axt.DateTime`, and `axt.Relation` | [envelope.md](envelope.md), [time.md](time.md), this document |
| `axt.example.vN` | The example types in their major version N, such as `axt.example.v1`                                                 | this document                                                 |

An app MUST NOT define a type, or any named type inside one, in a reserved namespace, except a time type or `axt.Relation` with its nested types, which it defines in place as section 5.2 and [time.md](time.md), section 3.1, require. An app type SHOULD use a namespace in reverse domain name order of a domain the app's maker controls, such as `org.example.catalog`, so that two apps do not pick the same full name by accident.

The schema files mirror the namespace in their path, and their file name is the type's name and its `axt.version`: version 1 of `axt.example.v1.Note` is [types/axt/example/v1/Note.1.avsc](../types/axt/example/v1/Note.1.avsc), derived from its description [Note.1.json](../types/axt/example/v1/Note.1.json) (section 7).

## 3. Versions

### 3.1 The major version in the namespace

The last segment of an example type's namespace, `v1` in `axt.example.v1`, is the type's major version. All versions of a type within one major version are compatible with each other (section 3.3); an incompatible change publishes the type under the next major version, such as `axt.example.v2.Note`.

The segment is the major version of each type in the namespace, not of the set: when Note changes incompatibly, `axt.example.v2.Note` is published, while Task stays `axt.example.v1.Task` until Task itself changes incompatibly. The nested types of a type (section 5.2) move with it.

The major version is part of the name because Avro schema resolution matches records by full name ([envelope.md](envelope.md), section 6), and the Parsing Canonical Form contains the full name:

- Compatible versions keep their full name, so a receiver with one version reads records of any other version of the same major version, in both directions, by schema resolution alone.
- Incompatible versions have different full names, so schema resolution fails at the name, before any field is read, and their fingerprints differ even where their fields happen to be the same. A receiver can know both and take each with its own reader schema.
- A version number in the namespace for every change, compatible or not, would make every change incompatible: the names would differ, and an alias in the reader schema helps only a receiver that has the newer version, not one that has the older. A type without any version in its name could never change incompatibly without being renamed.

### 3.2 Versions within a major version

Every version of an example type carries the custom attribute `axt.version`, an `int` that is `1` for the first version of a major version and grows by one with each published version. A version is published when it is added to this repository in a release. A published version is never changed; a change is a new version in a new file ([CONTRIBUTING.md](../CONTRIBUTING.md)). A new major version starts again at `axt.version` 1.

An app type SHOULD carry `axt.version` in the same way. What a receiver assumes for a type that carries none is defined in [manifest.md](manifest.md), which names types by full name and a range of versions.

### 3.3 Compatible changes

A new version within the same major version MUST make only these changes against the version before it, in the type itself or in one of its nested records:

1. add a field that has a default (section 5.4), under a name that no earlier version of the major version used;
2. remove a field that had a default in every earlier version of the major version; its name is not used again within the major version;
3. add a symbol to an enum, which has a default symbol (section 5.4);
4. change `doc` texts, or add, change or remove `axt.title` or a hint of [metadata.md](metadata.md) other than `axt.unit` and `axt.anchor`, such as a label, a translation or the order of the fields, without changing the meaning of any value;
5. remove a check of [metadata.md](metadata.md), section 6, or widen it so that every value that kept it still does: a lower `axt.min_length` or `axt.min`, a higher `axt.max_length` or `axt.max`.

Each of these changes keeps schema resolution working in both directions: a receiver with the new version reads records of the old one, filling added fields with their defaults, and a receiver with the old version reads records of the new one, ignoring added fields, filling removed ones with its defaults, and reading unknown symbols as the enum's default. A removed field's name is not used again because a receiver with a version that still has the field would read the new field under the old field's type and meaning. Every other change, such as changing a field's type, logical type, default, `axt.unit` or `axt.anchor`, renaming a field, adding a branch to a union or removing an enum symbol, MUST be published under the next major version. A change that keeps the Avro encoding but changes what a value means is incompatible as well. So is adding a check or narrowing one, including any change of `axt.format` or `axt.pattern` other than its removal: a sender that holds records of the earlier version could not send them all under the new one, since it MUST NOT send a value that breaks a check ([metadata.md](metadata.md), section 7.1).

### 3.4 Fingerprints and the Parsing Canonical Form

The fingerprint of a schema is computed over its Parsing Canonical Form ([envelope.md](envelope.md), section 5). That form keeps only `type`, `name`, `fields`, `symbols`, `items`, `values` and `size`, and it writes names as full names. It drops `doc`, `aliases`, `default`, `logicalType`, the enum `default`, `order`, and every custom attribute, `axt.version`, `axt.title` and `axt.unit` included. For versions, this means:

- Changing a `doc` or a display attribute does not change the fingerprint. Every published version of a full name MUST have a Parsing Canonical Form that differs from the forms of all earlier versions of that full name, so that the fingerprint tells the versions apart. A change of `doc` texts or attributes alone is therefore not published as a version of its own; it waits for the next version that also adds or removes a field or a symbol (section 3.3).
- A change of a logical type or a default is not visible in the fingerprint either, but it changes what a value means or what a receiver fills in. That is why section 3.3 allows neither within a major version.
- `axt.version` is not part of the fingerprint. A receiver learns the version of a record's schema from the schema JSON it received in the offer or in the file header ([envelope.md](envelope.md), sections 3 and 4.1), or from the fingerprints listed for the example types in section 7.3.
- The `doc` texts and attributes a receiver shows (section 6) are those of the schema JSON it received with the record. That is why an offer and a file carry the full schema, not only its canonical form.

## 4. Replacing a type

The example types may be evolved or replaced at any time, at the cost of compatibility. Replacing a type means:

- An app MAY use a type of its own for the same thing as an example type, under its own namespace, such as `org.example.catalog.Pet` in place of `axt.example.v1.Pet`. It MAY start from a copy of an example type; the copy is then an app type under the app's namespace, with its own `axt.version` from 1 on, and is no longer the example type.
- A receiver MUST identify a type by its full name alone. It MUST NOT treat two types as the same because their names without namespace, their fields or their documentation are alike: `org.example.catalog.Pet` is not `axt.example.v1.Pet`, even with the same fields.
- A receiver that wants to take an app type as a type it already knows MUST map it on purpose: either with the app type's full name among the aliases of its own reader schema, so that Avro schema resolution matches the names ([envelope.md](envelope.md), section 6), or with code of its own that converts the records.
- A receiver that has no mapping for a type either declines it ([protocol.md](protocol.md), section 5.2) or, if it takes any type ([manifest.md](manifest.md)), shows its records as section 6 describes.
- Types that only one app uses belong under that app's namespace and are not added to this repository ([CONTRIBUTING.md](../CONTRIBUTING.md)).

## 5. Rules for every type

Every example type MUST follow the rules of this section. An app type SHOULD follow them, so that receivers can show and map it as well; the depth limit of section 5.7 applies to every type.

### 5.1 Documentation

The record, every nested named type (record, enum, fixed) and every field MUST carry a `doc`, in English. The `doc` of a field says what its value is and what an empty string, an empty array or `null` means in it. Avro has no `doc` for an enum symbol, so the `doc` of an enum says what each symbol means.

### 5.2 Names and nested types

Names are in English and follow these cases:

| Name                   | Case             | Example                       |
| ---------------------- | ---------------- | ----------------------------- |
| Record, enum and fixed | UpperCamelCase   | `Appointment`, `PersonPhone`  |
| Field                  | snake_case       | `display_name`, `due_all_day` |
| Enum symbol            | UPPER_SNAKE_CASE | `MARKDOWN`, `KILOMETRE`       |

A field name consists of lower-case ASCII letters, digits and single underscores and starts with a letter. snake_case is chosen because a receiver that shows an unknown field by its name (section 6) gets words by replacing each underscore with a space, and because names in lower case cannot differ from each other only in case.

An example type MUST define each of its nested named types in place, where it is used, and MUST NOT refer to a named type by its name. The name of a nested type MUST begin with the name of the type it belongs to, such as `PersonPhone` in `Person`, and it has the namespace of that type. Every schema file can then be parsed on its own, and an app that parses all example types into one set of names finds each name defined once.

The published types are the exception: the time types, such as `axt.DateTime`, and `axt.Relation` (section 8). A type holds them under their own full names, defined in place at their first occurrence and referred to by full name after it, as [time.md](time.md), section 3.1, requires. A published type defined in place is its published schema with every named type that an earlier occurrence in the same schema already defined replaced by its full name. An `axt.Relation` in a type that holds an `axt.DateTime` before it therefore has `"axt.DateTime"` in its field `start`, while in a type without one it defines `axt.DateTime` there, as its published schema does; both read as the published schema. An app that parses all example types into one set of names finds each published type defined in several of them, each time with the same canonical form, and handles that as [time.md](time.md), section 3.1, says.

### 5.3 Optional values

A field whose value may be absent MUST have the type `["null", T]`, with `null` first, and the default `null`. An example type MUST NOT use any other union, except the two targets of `axt.Relation` (section 8.3). A text that may be empty is a `string` with the default `""`; a list is an `array` with the default `[]`.

### 5.4 Defaults

- Every field added after the first version of a major version MUST have a default; without one, a receiver with the new version cannot read records of the old one.
- A field may be removed within a major version only if it had a default in every earlier version (section 3.3). Example types therefore give every field a default, except the few without which a record of the type has no meaning: `start` of Appointment, and `value` and `measured_at` of Measurement. These cannot be removed within the major version. In the same way `axt.Relation` gives no default to its `id` and `target`, to the `id` of a record target and to the `uri` of an outside target (section 8).
- Every enum MUST have a default symbol, the Avro `default` attribute of the enum, so that a symbol added in a later version resolves for a receiver that does not know it. Where reading an unknown symbol as one of the known ones would change a value, as with a unit, the enum has the symbol `UNKNOWN` and that is its default. A receiver reads an unknown symbol as the enum's default, as schema resolution requires ([envelope.md](envelope.md), section 6); not every Avro library does so (section 7.3).

### 5.5 Times and logical types

Dates, times of day, dates and times, and lengths of time are the time types `axt.Date`, `axt.Time`, `axt.DateTime` and `axt.Duration` ([time.md](time.md)). A field of an `axt.DateTime` carries the attribute `axt.anchor` (section 6) where the anchor `local` does not apply to it ([time.md](time.md), section 6.4). Ids follow [envelope.md](envelope.md), section 7. An example type MUST use only this logical type:

| Value  | Avro type and logical type                   |
| ------ | -------------------------------------------- |
| A UUID | `string` with `uuid`, lower-case hexadecimal |

A reader that does not know a logical type uses the underlying type ([envelope.md](envelope.md), section 7).

### 5.6 Times, time zones and text

These rules hold for every example type that has the fields named:

- **Time zone.** The zone of a date and time is part of its `axt.DateTime` ([time.md](time.md), section 6); a type has no field of its own for it.
- **All day.** A boolean field `all_day`, or `<name>_all_day` for the single field `<name>`, set to `true` means that only the day of the times counts: they are then floating times at 00:00 ([time.md](time.md), section 6.5), and their time of day has no meaning. Such a time stays an `axt.DateTime` rather than an `axt.Date`, since a field has one type (section 5.3) and the start of an appointment, which every Appointment has (section 5.4), is one field for both kinds.
- **End.** A field `end` is the first moment after the event, as the `DTEND` property of [RFC 5545](https://www.rfc-editor.org/rfc/rfc5545) is. For an all-day event it is 00:00 of the day after the last day.
- **Repetition.** A repetition rule is a `string` with the value of an RFC 5545 `RRULE` property without the `RRULE:` prefix, such as `FREQ=WEEKLY;BYDAY=TU`.
- **Text.** Text fields hold plain text, with lines separated by LF (U+000A), unless their `axt.format` ([metadata.md](metadata.md), section 6.3) or their `doc` says otherwise. Note's field `format` names [CommonMark](https://spec.commonmark.org/) as the only other format, for each record on its own.

### 5.7 Nesting and recursion

The data depth of a value counts the records, arrays and maps it is nested in: the record itself is at depth 1, an array in one of its fields at depth 2, and a record inside that array at depth 3.

- An example type MUST NOT be recursive, that is, it MUST NOT contain itself or one of its nested types inside itself. Every example type reaches depth 4, with the target, the times and the attributes of a relation ([fields.md](fields.md), section 11).
- A type is described by a tree of typed fields ([fields.md](fields.md), section 9.1), so no type is recursive. A sender MUST NOT send a record whose data depth exceeds 32. A receiver MUST decode records up to depth 32 and MUST stop decoding and reject a record that goes deeper, with the error `UNDECODABLE` ([protocol.md](protocol.md), section 8.2). Without this rule a small message of a deeply nested type could exhaust a decoder's stack.

The schema itself also stays within the size and nesting limits of [envelope.md](envelope.md), section 8.

### 5.8 Ids and versions of records

A type MUST NOT carry the id or the version of its records in fields of its own: the envelope carries both ([envelope.md](envelope.md), section 2; [records.md](records.md)). How one record refers to another, such as a Measurement to the Pet it was taken of, is defined in [records.md](records.md), section 8: a reference is a `uuid` string that holds the id of another record of the same sender. The example types carry no references; each links to other records with relations (section 8).

### 5.9 Metadata

The attributes of a type keep the rules of [metadata.md](metadata.md), and a type uses no attribute name beginning with `axt.` and no format that [metadata.md](metadata.md) does not define (section 3.3 there). An example type is published as its description ([fields.md](fields.md)), which holds its texts, hints and checks; its derived schema carries no attribute other than `axt.version` and those of `axt.Relation` ([fields.md](fields.md), section 9.2). In addition to the rules of [fields.md](fields.md), the description of an example type MUST carry:

- a label and an emoji, and the label and the help in German, on the type and on each typed field, except the items and values of a list or a map that are not objects, which the list or the map names;
- a label in English and in German on each enum symbol and each group.

A receiver that does not know the type can then show it with a name and an emoji for each part, and each label can be translated ([metadata.md](metadata.md), section 4.2).

## 6. Display hints

A receiver that does not know a type, or does not know some of its fields, can still show its records from the schema JSON it received with them. It MAY show the record's label or `doc`, then each field in the order of [metadata.md](metadata.md), section 5.1, by its label or, without one, by its name with underscores read as spaces, with its help text or `doc`, and its value. It SHOULD show the time types ([time.md](time.md)) and values of logical types as dates and times, and an enum value by the label of its symbol or by the symbol. It SHOULD NOT show `bytes` as text.

Avro permits attributes that its specification does not define, as long as they do not change the serialized data. AXT defines the attributes of [metadata.md](metadata.md), which tell a receiver how to show and check each field: labels, help texts and emoji in several languages, the order and groups of fields, formats, patterns and limits. [metadata.md](metadata.md), section 2, lists every attribute. This section defines these four:

| Attribute     | Where                  | Value                                                                                                                                                                                                                     |
| ------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `axt.version` | The type's record      | The version within the major version, an integer from 1 (section 3.2)                                                                                                                                                     |
| `axt.title`   | The type's record      | The name of a field of type `string` or `["null", "string"]` of that record whose value is the record's title, such as `title` in Note or `display_name` in Person. A receiver MAY show it as the record's name in a list |
| `axt.unit`    | A field (not its type) | The unit of a number field, or of each item of an array of numbers, as a case-sensitive code of [UCUM](https://ucum.org/), such as `min` for minutes. Used only where the schema fixes the unit                           |
| `axt.anchor`  | A field (not its type) | For a field of `axt.DateTime` values, what a receiver keeps when its zone rules differ from the writer's: `local`, the wall clock, or `instant`, the instant ([time.md](time.md), section 6.4). Absent means `local`      |

- Attribute names beginning with `axt.` are reserved for this specification. An app MAY add attributes of its own to its types; their names SHOULD begin with its namespace, such as `org.example.catalog.colour`.
- A receiver MUST ignore attributes it does not know, and MUST NOT reject a schema because of them. A receiver MUST also ignore an `axt.title` that does not name a string field of the record, an `axt.unit` on a field that is not a number, an `axt.anchor` on a field that holds no `axt.DateTime`, and every other attribute that breaks its rules ([metadata.md](metadata.md), section 3.3).
- `axt.unit` and `axt.anchor` sit on the field, not on the field's type, so that they describe that field only; `axt.anchor` cannot sit on the type, since the same `axt.DateTime` serves both anchors. Where the unit differs from record to record, as for an odometer reading or a measurement, it is a field of its own, not an attribute.
- No attribute is part of the fingerprint (section 3.4).

## 7. The example types

The example types are in [types/axt/example/v1/](../types/axt/example/v1/), each published as its description, `<Type>.<version>.json`, a datum of `axt.Field` in the JSON form of [fields.md](fields.md), section 10.3, with one version of each type. The descriptions are normative; the schema derived from each, `<Type>.<version>.avsc`, is written and checked by [conformance/tools/example_schemas.py](../conformance/tools/example_schemas.py). The table below summarizes them, and each field's meaning is in its `doc`. Person holds its phone numbers, e-mail addresses and postal addresses as lists of objects, each with a `label`.

### 7.1 The types

| Type          | Title field    | Fields                                                                                                                                                                           |
| ------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Note`        | `title`        | `title`, `text`, `format` (`PLAIN`, `MARKDOWN`), `created`, `updated` (`axt.DateTime`, instants), `tags`                                                                         |
| `Task`        | `title`        | `title`, `notes`, `due` (`axt.DateTime`, wall clock), `due_all_day`, `repeat` (RRULE), `done`, `done_at` (`axt.DateTime`, instant), `priority` (`NONE`, `LOW`, `MEDIUM`, `HIGH`) |
| `Appointment` | `title`        | `title`, `start`, `end` (`axt.DateTime`, wall clock), `all_day`, `location`, `notes`, `reminders` (`axt.Duration` from `start`, negative before it)                              |
| `Person`      | `display_name` | `display_name`, `prefix`, `given_name`, `middle_name`, `family_name`, `suffix`, `birthday` (`axt.Date`), `phones` (E.164), `emails`, `addresses` (each with a `label`), `notes`  |
| `Car`         | `model`        | `make`, `model`, `year`, `plate`, `vin`, `odometer`, `odometer_unit` (`KILOMETRE`, `MILE`, `UNKNOWN`), `notes`                                                                   |
| `Pet`         | `name`         | `name`, `species`, `breed`, `sex` (`UNKNOWN`, `FEMALE`, `MALE`), `neutered`, `birthday` (`axt.Date`), `microchip`, `notes`                                                       |
| `Measurement` | `quantity`     | `quantity`, `value`, `unit` (UCUM), `measured_at` (`axt.DateTime`, instant), `subject`, `notes`                                                                                  |
| `Document`    | `title`        | `title`, `file_name`, `media_type`, `content` (bytes), `dated` (`axt.Date`), `notes`                                                                                             |

Each type has, as its last field, `relations`, a field of the relation brick (section 8).

A Person's `birthday` may leave out the year, as address books often hold birthdays without one; a Pet's `birthday` and a Document's `dated` may give only a month or a year ([time.md](time.md), section 4). Car's `year` is a number rather than an `axt.Date`: a model year names a version of the model, not a date on the calendar.

### 7.2 Why these types

Note, Task, Appointment, Person and Car are the example types named when the scope of AXT was decided. Pet, Measurement and Document are added for the kinds of records around the vet appointment in the example of [README.md](../README.md), which cat-a-log, Old Brain Fix and a second-brain app exchange:

- **Pet**: the animal a pet log is about. Its other records, such as a vet appointment or a weight, concern one pet.
- **Measurement**: one value at a point in time, such as a pet's weight, a blood pressure reading or a tally of glasses of water. Its unit is a UCUM code, so that values from different apps can be compared and added up; a count has the unit `1`, or an annotation alone such as `{glass}`.
- **Document**: a file with a title and a date, such as a scanned vet invoice or a vaccination certificate. The file travels in the record, within the message limit of 16 MiB ([envelope.md](envelope.md), section 8).

### 7.3 Fingerprints

| Type | Version | Schema | CRC-64-AVRO | As bytes |
| --- | --- | --- | --- | --- |
| `axt.example.v1.Appointment` | 1 | [Appointment.1.avsc](../types/axt/example/v1/Appointment.1.avsc) | `0x49416306becfe686` | `86 e6 cf be 06 63 41 49` |
| `axt.example.v1.Car` | 1 | [Car.1.avsc](../types/axt/example/v1/Car.1.avsc) | `0xa8eaa96101d47106` | `06 71 d4 01 61 a9 ea a8` |
| `axt.example.v1.Document` | 1 | [Document.1.avsc](../types/axt/example/v1/Document.1.avsc) | `0x69594b59d2ce6dca` | `ca 6d ce d2 59 4b 59 69` |
| `axt.example.v1.Measurement` | 1 | [Measurement.1.avsc](../types/axt/example/v1/Measurement.1.avsc) | `0xa4713c50ea54b494` | `94 b4 54 ea 50 3c 71 a4` |
| `axt.example.v1.Note` | 1 | [Note.1.avsc](../types/axt/example/v1/Note.1.avsc) | `0xad64ede05937d517` | `17 d5 37 59 e0 ed 64 ad` |
| `axt.example.v1.Person` | 1 | [Person.1.avsc](../types/axt/example/v1/Person.1.avsc) | `0x05eacdcbb91f9865` | `65 98 1f b9 cb cd ea 05` |
| `axt.example.v1.Pet` | 1 | [Pet.1.avsc](../types/axt/example/v1/Pet.1.avsc) | `0xf4c8934cfd75ff20` | `20 ff 75 fd 4c 93 c8 f4` |
| `axt.example.v1.Task` | 1 | [Task.1.avsc](../types/axt/example/v1/Task.1.avsc) | `0x7d271ca0ac137ed9` | `d9 7e 13 ac a0 1c 27 7d` |
| `axt.Relation` | – | [Relation.avsc](../types/axt/Relation.avsc) | `0x190bf11052cf9f10` | `10 9f cf 52 10 f1 0b 19` |

The fingerprints were computed with [conformance/tools/example_types.py](../conformance/tools/example_types.py). For every example type, the script:

- checks that its description is valid ([fields.md](fields.md), section 6), carries the texts that section 5.9 requires, and derives the schema of its `.avsc` file;
- checks the rules of section 5 that a program can check on the derived schema, among them each time type and `axt.Relation` defined in place as its published schema with the named types defined before it by their full names, and referred to by its full name after it (section 5.2; [time.md](time.md), section 3.1); and checks the published schema of `axt.Relation` by the same rules, with the code of [conformance/tools/metadata_rules.py](../conformance/tools/metadata_rules.py) for its attributes;
- checks that the example datum, which holds relations with both kinds of target, keeps the rules of the time types and of the relations and every check of its description ([fields.md](fields.md), section 7), and that each of its zoned times has the offset of its zone at its instant by the zone rules of Python's `zoneinfo`;
- checks 10 further records that keep every rule, among them an all-day Appointment, a Task due at a floating time and an Appointment whose offset is not that of its zone at the instant, which a receiver does not reject for it ([time.md](time.md), section 6.2); and 17 records with a value that breaks a rule, such as a phone number with spaces, a country name in place of its code, a VIN with the letter O, a Car of the year 1800, a start whose instant does not match its wall clock and a reminder with parts of both signs, each with the field path and the rule or the check of the first such value in the order of the encoding ([metadata.md](metadata.md), section 7.2); and 6 further records with relations, among them 256 relations, one at every limit of its lengths and a kind it does not know, and 18 records with a relation or a value that breaks a rule, among them 257 relations, two relations with one id, a kind without a namespace and a start that is not valid inside a relation;
- computes the Parsing Canonical Form and the CRC-64-AVRO fingerprint, and compares them with those of the Python libraries fastavro 1.13.1 and `avro` 1.12.2;
- encodes one example datum with fastavro, decodes it back, and checks that `avro` decodes the same bytes and encodes them to the same bytes again; both libraries write each target of a relation in its own branch;
- uses every default once in schema resolution, with both libraries: it writes a datum with the schema without its defaulted fields, and one with the schema whose nested records lack their defaulted fields, and reads both with the full schema;
- writes, for every enum, a symbol the schema does not have and checks that the full schema reads it as the enum's default symbol. fastavro does so; the `avro` package 1.12.2 raises a schema resolution error instead, against the Avro specification, so a receiver built on it does not get the compatibility of section 3.3 for enum symbols.

One further difference from the Avro specification showed: fastavro 1.13.1 returns the default of a `bytes` field as the JSON string rather than as bytes.

The test vectors of [conformance.md](conformance.md) take precedence over these values.

### 7.4 Version 2

Removed: each example type has one version, built from bricks, with its relations (sections 7.1 and 8).

## 8. Relations

A relation links the record that holds it to another record or to a thing outside AXT, with information about the link. Relations are a brick: a type has them through a field whose brick is `axt.RelationField`, and the relation record `axt.Relation`, its kinds, targets, rules and limits and its definition in place are in [fields.md](fields.md), section 11. Every example type holds its relations in its field `relations`, the list of relations that such a field derives.

### 8.1 The relation record

Moved to [fields.md](fields.md), section 11.1.

### 8.2 Kinds

Moved to [fields.md](fields.md), section 11.2.

### 8.3 Targets

Moved to [fields.md](fields.md), section 11.3. The targets are the only union of an example type other than `["null", T]` (section 5.3).

### 8.4 Rules and limits

Moved to [fields.md](fields.md), section 11.4.

### 8.5 Relations and references

Moved to [fields.md](fields.md), section 11.5. The example types use relations only.

### 8.6 Defined in place

The rule is in [fields.md](fields.md), section 11.6, and applies to the example types as to every type: Note, Task, Appointment and Measurement hold an `axt.DateTime` before their relations, so their `axt.Relation` has `"axt.DateTime"` in `start`; Person, Car, Pet and Document hold none, so their `axt.Relation` defines `axt.DateTime` in `start`, as the published schema does.

## References

- [Apache Avro 1.12 specification](https://avro.apache.org/docs/1.12.0/specification/)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
- [RFC 5545](https://www.rfc-editor.org/rfc/rfc5545): iCalendar, for `DTEND` and `RRULE`
- [RFC 6838](https://www.rfc-editor.org/rfc/rfc6838): media types, for Document's `media_type`
- [IANA time zone database](https://www.iana.org/time-zones)
- [CommonMark](https://spec.commonmark.org/)
- [UCUM](https://ucum.org/): the Unified Code for Units of Measure
- [ITU-T E.164](https://www.itu.int/rec/T-REC-E.164): international phone numbers, for Person's phone numbers
- ISO 3779 (vehicle identification number), ISO 11784 (animal microchips) and ISO 3166-1 (country codes), named in the `doc` of Car, Pet and Person
