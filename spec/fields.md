# Typed fields

Status: new in 0.2.0. A change to this document is a new version of AXT, with its entry in [CHANGELOG.md](../CHANGELOG.md).

This document defines the bricks of AXT: typed fields that describe one field of a type, its name, the texts a receiver shows for it and the checks its values keep, as Avro records. A type is described by bricks put together, as an address is made of a street, a postal code and a country, and a person of a name, an address and other fields. The description is the source of the type: the type's Avro schema is derived from it by the rule of section 9, and offers and files carry it (section 10). The schema of the bricks, [types/axt/Field.avsc](../types/axt/Field.avsc), is normative for what each brick holds; this document says what a brick means, what its checks do to a value and how the schema is derived.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Typed field**: a datum of `axt.Field`. It describes one field: its common part (section 3) and, in its member `kind`, one brick.
- **Brick**: one branch of the union `kind`, such as `axt.StringField` or `axt.EmailField`. It names the kind of the field's values and holds the checks and hints of that kind.
- **Value brick**: a brick of a kind of value: text, a number, a boolean, bytes, an enum, a list, a map, an object, or a time type (section 4).
- **Relation brick**: `axt.RelationField`, whose value is a list of relations, each linking the record to another record or to a thing outside AXT (section 11).
- **Semantic brick**: a brick of text of one form, such as an email address, whose check of that form is built in (section 5).
- **Description**: a typed field whose brick is an `axt.ObjectField`, at the root of a type: the type's full name, version and fields, each a typed field, and so on down to the value bricks (section 9.1).
- **Derived schema**: the Avro schema of a type, derived from its description by the rule of section 9.2; its fingerprint is the type's fingerprint ([envelope.md](envelope.md), section 5).
- **Value**: what a record holds for a field. A record carries plain values only; the description says how to show and check them and travels with the type, not with each record.
- **Check**: a member of a brick, or `required` of the common part, that a value can break (section 7). Every other member is a hint: it says how to show the field or offer an input for it.

Sender, receiver and type have the meaning of [records.md](records.md), section 1, and [types.md](types.md), section 1. Field path and code point have the meaning of [metadata.md](metadata.md), section 1.

## 2. The bricks

[types/axt/Field.avsc](../types/axt/Field.avsc) defines `axt.Field` and, in place, every brick and every record a brick holds, so that the file is parsed on its own. Its CRC-64-AVRO is `0xbaed02035d879fb5`.

| Brick                | Values                                    | Section |
| -------------------- | ----------------------------------------- | ------- |
| `axt.StringField`    | plain text                                | 4.1     |
| `axt.IntField`       | 32-bit integers                           | 4.2     |
| `axt.LongField`      | 64-bit integers                           | 4.2     |
| `axt.DoubleField`    | numbers of double precision               | 4.2     |
| `axt.BooleanField`   | `true` or `false`                         | 4.3     |
| `axt.BytesField`     | bytes                                     | 4.3     |
| `axt.EnumField`      | one of a list of symbols                  | 4.4     |
| `axt.ListField`      | a list of items of one typed field        | 4.5     |
| `axt.MapField`       | a map from strings to values of one field | 4.5     |
| `axt.ObjectField`    | a value made of typed fields              | 4.6     |
| `axt.DateField`      | `axt.Date`                                | 4.7     |
| `axt.TimeField`      | `axt.Time`                                | 4.7     |
| `axt.DateTimeField`  | `axt.DateTime`                            | 4.7     |
| `axt.DurationField`  | `axt.Duration`                            | 4.7     |
| `axt.MarkdownField`  | text read as CommonMark                   | 5       |
| `axt.EmailField`     | an email address                          | 5       |
| `axt.PhoneField`     | a phone number                            | 5       |
| `axt.UrlField`       | a web address                             | 5       |
| `axt.UriField`       | a URI of any scheme                       | 5       |
| `axt.ColourField`    | a colour                                  | 5       |
| `axt.IbanField`      | an IBAN                                   | 5       |
| `axt.BicField`       | a BIC                                     | 5       |
| `axt.CountryField`   | a country code                            | 5       |
| `axt.LanguageField`  | a language tag                            | 5       |
| `axt.CurrencyField`  | a currency code                           | 5       |
| `axt.MediaTypeField` | a media type                              | 5       |
| `axt.UcumField`      | a unit code                               | 5       |
| `axt.RelationField`  | a list of relations, each `axt.Relation`  | 11      |

The union `kind` has the bricks in this order.

The bricks are one schema rather than a file each because an object, a list and a map hold typed fields of every kind: the union of the bricks is recursive, and Avro defines a named type once in a schema. A description is encoded as a datum of this schema like any other.

## 3. The common part

Every typed field has the members of `axt.Field` besides `kind`.

### 3.1 Name and doc

`name` is the field's name, by the rules of field names of [types.md](types.md), section 5.2. The fields of one object have different names. `doc` is the field's documentation for the developer, in English, not empty, with the rules of [types.md](types.md), section 5.1: it says what the value is and what an empty value or `null` means in it.

### 3.2 Texts

`texts` is an `axt.FieldTexts`: the label, the help text and the emoji that a receiver shows for the field, with their translations. An enum symbol (section 4.4) and a group (section 4.6) have texts of their own of the same record. Each text keeps the rules of [metadata.md](metadata.md), sections 4.1 to 4.3, and a receiver shows it as they say; the empty string stands for a text that is absent. A translation needs its English text: a map of translations that is not empty breaks its rules when the English text is the empty string.

### 3.3 Required

`required` true means that the field needs a value. The value breaks the check `required` when it is `null`, or when it is the empty string, empty bytes, an empty list or an empty map. A field that is not required may hold such a value, and then holds no value; the other checks of its brick do not apply to `null`, and of the checks of form, `format` and `pattern`, none applies to the empty string, as [metadata.md](metadata.md), section 6.1, says of the attributes.

The `default` of a brick, where it has one, is the value the field starts with when its user gives none. `null` there means that the brick gives no default. A default keeps the field's checks.

### 3.4 Hints

These hints of the common part, and the members `placeholder` and `example` of the bricks of text and numbers, say how to show the field, as the attributes of [metadata.md](metadata.md), sections 5.1 to 5.4, of the same names do:

- `order` and `group` place the field among the fields of its object (sections 5.1 and 5.2 there). `group` is the empty string or a key of the groups of the object that holds the field.
- `sensitive` and `advanced` (section 5.4 there).
- `placeholder` and `example` (section 5.3 there), the empty string for none. An example in a brick of text keeps the field's checks.

## 4. Value bricks

### 4.1 Text

`axt.StringField` describes plain text ([types.md](types.md), section 5.6).

- `min_length` and `max_length` are checks of the number of code points of the value, as [metadata.md](metadata.md), section 6.2, counts them; `null` is no limit. `min_length` is not larger than `max_length`.
- `pattern` is a check: a non-empty value matches it as a whole. It is an I-Regexp with the rules of [metadata.md](metadata.md), section 6.4, which a receiver implements as that section describes.
- `multiline` and `preferred_length` are hints, as [metadata.md](metadata.md), section 5.3, says of the attributes of the same names. `preferred_length` is not larger than `max_length`.

### 4.2 Numbers

`axt.IntField`, `axt.LongField` and `axt.DoubleField` describe numbers of the Avro types `int`, `long` and `double`.

- `min` and `max` are checks: the value is at least `min` and at most `max`, compared as exact numbers; `null` is no limit. NaN breaks every `min` and `max`. A limit of a `double` is finite, and `min` is not larger than `max`.
- `unit` is a hint, the unit of the value as a code of UCUM where the field fixes it, with the meaning of `axt.unit` of [types.md](types.md), section 6. The limits are in that unit.

### 4.3 Booleans and bytes

`axt.BooleanField` has no check. `axt.BytesField` has the checks `min_length` and `max_length` of section 4.1, counted in bytes. A receiver does not show bytes as text ([types.md](types.md), section 6).

### 4.4 Enums

`axt.EnumField` describes a value that is one of its `symbols`.

- `name` is the name of the enum, in UpperCamelCase ([types.md](types.md), section 5.2), and each `symbol` is in UPPER_SNAKE_CASE. An enum has at least one symbol, and no symbol twice.
- Each symbol has its texts (section 3.2); a symbol without a label is shown by its name.
- `fallback` is a symbol of the enum that a receiver reads a symbol it does not know as, as the default of an enum of [types.md](types.md), section 5.4. `default`, if not `null`, is a symbol of the enum.

### 4.5 Lists and maps

`axt.ListField` describes a list of items, `axt.MapField` a map from strings to values; `items` and `values` are the typed field of each item or value.

- The kind and the checks of `items` or `values` apply to each item or value, not to the list or the map. Its `required` says whether an item or value can be `null`.
- Its texts name one item, such as `Tag` for a list `Tags`, and its name is that of the list or the map. It has no `order` and no `group`, and `sensitive` and `advanced` are those of the list or the map: an item or value has them `null`, empty and `false`.
- An item of a list is named by its index in a field path, a value of a map by its key ([metadata.md](metadata.md), section 7.2).

### 4.6 Objects

`axt.ObjectField` is a composite field: its value is made of the values of its `fields`, each a typed field, in the order of their encoding. An object has at least one field.

- `name` is the name of the object, an Avro name in UpperCamelCase such as `VetAddress`. At the root of a description it is the full name of the type, with its namespace ([types.md](types.md), section 2).
- `version` and `title` are those of the type, at the root (section 9.1).
- `groups` gives the texts of each group of the object's fields; a group without a label is shown by its key. A key is a group key of [metadata.md](metadata.md), section 5.2, of at most 64 bytes, each key is given once, and each is used by at least one field of the object.
- A field of a nested object is named by the path of the object, a `.`, and its name, such as `address.postal_code`.

### 4.7 Times

`axt.DateField`, `axt.TimeField`, `axt.DateTimeField` and `axt.DurationField` describe values of the time types of [time.md](time.md). They have no check of their own; a time value that is not valid breaks the rules of [time.md](time.md), section 8, which every receiver checks. `anchor` of `axt.DateTimeField` is the anchor of [time.md](time.md), section 6.4, `LOCAL` or `INSTANT`.

## 5. Semantic bricks

Each semantic brick describes text of one form: a non-empty value has the format of [metadata.md](metadata.md), section 6.3, that the brick has built in, by the syntax that section gives, and a receiver shows it as that section says. The check is named `format`.

| Brick                | Format       |
| -------------------- | ------------ |
| `axt.MarkdownField`  | `markdown`   |
| `axt.EmailField`     | `email`      |
| `axt.PhoneField`     | `phone`      |
| `axt.UrlField`       | `url`        |
| `axt.UriField`       | `uri`        |
| `axt.ColourField`    | `colour`     |
| `axt.IbanField`      | `iban`       |
| `axt.BicField`       | `bic`        |
| `axt.CountryField`   | `country`    |
| `axt.LanguageField`  | `language`   |
| `axt.CurrencyField`  | `currency`   |
| `axt.MediaTypeField` | `media-type` |
| `axt.UcumField`      | `ucum`       |

Every semantic brick also has the checks `min_length` and `max_length` and the hint `preferred_length` of section 4.1. `axt.MarkdownField` takes any text, as the format `markdown` does; it is rendered with the rules of [metadata.md](metadata.md), section 8. Plain text is `axt.StringField`. The format holds the syntax only, without a registry ([metadata.md](metadata.md), section 6.3).

## 6. A valid description

A description is valid when every typed field in it keeps the rules of sections 3 to 5, and the description keeps those of its root and its limits (section 9.1): its name, doc, texts and hints, the limits of each check, and the defaults and examples that keep the field's checks. A default or an example is judged by the checks only when the checks themselves keep their rules. A sender MUST NOT send a description that is not valid.

A problem of a description is named by the field path of the member that breaks a rule, in the description as a datum of `axt.Field`: `kind.fields[1].kind.symbols` is the symbols of the enum of the second field of the type. A union adds nothing to the path ([metadata.md](metadata.md), section 7.2).

## 7. Checking a value

A value keeps every check of its typed field at once. The checks are `required` (section 3.3), `min_length`, `max_length` and `pattern` (sections 4.1 and 4.3), `min` and `max` (section 4.2) and `format` (section 5).

- A value that breaks a check is named by its field path. When it breaks several, the first in the order `required`, `format`, `pattern`, `min_length`, `max_length`, `min`, `max` is named.
- When several values break a check, the first in the order of the encoding is named: the fields of each object in their order, depth first, and the items and values in the order in which they are encoded.
- What a sender and a receiver do with a value that breaks a check, and the error `VALUE_INVALID`, are as [metadata.md](metadata.md), section 7, says of the checks of the attributes.

## 8. Example

`com.example.Vet` is an illustration only, not an example type. Its description has 14 fields, among them a phone, an email address and a website in the group `contact`, an enum `VetKind`, an object `VetAddress`, a number of minutes between 5 and 240, an IBAN that is sensitive and advanced, a date, notes in CommonMark, a list of tags and a map of fees. Encoded as a datum of `axt.Field`, it has 2,044 bytes; the schema derived from it has 2,990 bytes and the CRC-64-AVRO `0xd5e22eb4892daf4f`. Its field `address`, with the branch of each `kind` written as an object whose one member is named by the brick, as in Avro's JSON encoding:

```json
{"name":"address","doc":"The address of the practice.","texts":{"label":"Address","label_translations":{"de":"Anschrift"},"help":"","help_translations":{},"emoji":"📮"},"required":false,"order":null,"group":"","sensitive":false,"advanced":false,"kind":{"axt.ObjectField":{"name":"VetAddress","fields":[
 {"name":"street","doc":"The street and house number.","texts":{"label":"Street","label_translations":{"de":"Straße"},"help":"","help_translations":{},"emoji":"🛣️"},"required":false,"order":null,"group":"","sensitive":false,"advanced":false,"kind":{"axt.StringField":{"default":null,"min_length":null,"max_length":100,"pattern":null,"multiline":false,"preferred_length":null,"placeholder":"","example":""}}},
 {"name":"postal_code","doc":"The postal code of five digits; empty when not known.","texts":{"label":"Postal code","label_translations":{"de":"Postleitzahl"},"help":"","help_translations":{},"emoji":"📮"},"required":false,"order":null,"group":"","sensitive":false,"advanced":false,"kind":{"axt.StringField":{"default":null,"min_length":null,"max_length":null,"pattern":"[0-9]{5}","multiline":false,"preferred_length":5,"placeholder":"10115","example":""}}},
 {"name":"country","doc":"The country.","texts":{"label":"Country","label_translations":{"de":"Land"},"help":"","help_translations":{},"emoji":"🏳️"},"required":false,"order":0,"group":"","sensitive":false,"advanced":false,"kind":{"axt.CountryField":{"default":"DE","min_length":null,"max_length":null,"preferred_length":null,"placeholder":"","example":""}}}],"groups":[],"version":null,"title":""}}}
```

A receiver that checks finds, among the 23 values of the type the script checks:

| Value                                                                 | Field path            | Check        |
| --------------------------------------------------------------------- | --------------------- | ------------ |
| Every value meets its checks                                          | —                     | —            |
| The empty string in `phone`, `email`, `website`, `iban` and `address` | —                     | —            |
| An empty name, which is required                                      | `name`                | `required`   |
| A phone number with spaces, `+49 30 1234567`                          | `phone`               | `format`     |
| An IBAN whose check digits do not match                               | `iban`                | `format`     |
| A postal code of four digits                                          | `address.postal_code` | `pattern`    |
| A country in lower case, `de`                                         | `address.country`     | `format`     |
| A visit of 241 minutes                                                | `visit_minutes`       | `max`        |
| A fee that is NaN                                                     | `fee`                 | `min`        |
| A tag of 33 times `𝄞`, 33 code points and 66 UTF-16 units             | `tags[1]`             | `max_length` |
| An extra fee below 0 for `x-ray`                                      | `extra_fees["x-ray"]` | `min`        |
| A phone number with spaces and a visit of 241 minutes                 | `phone`               | `format`     |

The values were produced with [conformance/tools/fields_examples.py](../conformance/tools/fields_examples.py), which loads the rules of the formats, patterns and texts from [conformance/tools/metadata_rules.py](../conformance/tools/metadata_rules.py). The script:

- checks [types/axt/Field.avsc](../types/axt/Field.avsc) by the rules of [types.md](types.md), sections 5.1 and 5.2, and its fingerprint, with fastavro 1.13.1 and the Python `avro` 1.12.2 package;
- checks that the description of `com.example.Vet` is valid, and 45 descriptions that each break one rule, each with the path of its problem, and the limits of section 9.1;
- checks that the published description of each example type ([types.md](types.md), section 7) is valid, derives the schema of its `.avsc` file, and derives it again from that schema, and that the registry of descriptions of the models holds it for its derived schema;
- derives `com.example.Links`, with relation fields first, after a date and time, twice, as the items of a list and in a nested object (section 11.6);
- checks the 23 values of the table and the others, a value of each semantic brick that has its format and one that does not, and values of the bricks the type does not use;
- encodes each description with fastavro and decodes it again with both libraries.

The test vectors of [conformance.md](conformance.md) take precedence over these values.

## 9. Deriving the schema

### 9.1 The root and the limits

A description describes one type. In addition to the rules of sections 3 to 6, a description keeps these:

- **The root.** Its brick is `axt.ObjectField`. Its `name` is the full name of the type, with a namespace ([types.md](types.md), section 2), its `version` the version of the type within its major version, at least 1 ([types.md](types.md), section 3.2), and its `title`, if not empty, the name of one of its fields whose brick is `axt.StringField` or a semantic brick: the field whose value a receiver MAY show as the name of a record, as `axt.title` of [types.md](types.md), section 6, says. The root's `doc` and `texts` are those of the type. Its own `name` is not used. It is not `required`, and has no `order`, no `group`, and neither `sensitive` nor `advanced`.
- **Nested objects and enums.** Their names have no namespace; they take the namespace of the root. No two of the objects and enums of a description, the root among them, have the same full name, and none has the name of a time type or of a named type that `axt.Relation` defines (section 11.6). A nested object has the `version` `null`; its `title`, if not empty, names one of its own fields of text, which a receiver MAY show as the name of each of its values.
- **Depth.** Typed fields nest at most 64 deep: the root is at depth 1, and a field of an object, the items of a list and the values of a map are one deeper than the typed field that holds them. The derived schema nests at most 64 deep as JSON, as every schema does ([envelope.md](envelope.md), section 8).
- **Numbers.** A default of `axt.DoubleField` is finite, and a default of `axt.LongField` is at most 2^53 in magnitude, so that the text of section 9.3 writes it exactly.
- **Size.** A description in its Avro encoding, and the text of its derived schema (section 9.3), each have at most 256 KiB, the limit of a schema ([envelope.md](envelope.md), section 8).

A type is a tree of typed fields, so no type is recursive ([types.md](types.md), section 5.7).

### 9.2 The rule

The derived schema of a valid description is an Avro 1.12 schema of a record, written as JSON:

- **The record.** The root gives the object `{"type": "record", "name": N, "namespace": S, "doc": D, "axt.version": V, "fields": F}`, where S and N are the namespace and the last part of the root's full name, D is the root's `doc`, V its `version`, and F its fields.
- **The fields.** Each typed field of an object gives one field of its record, in the order of the object: `{"name": n, "type": T, "default": d, "doc": c}` with the typed field's `name` and `doc`, its type T, and its default d where it has one.
- **The type.** T is the type of the brick, as the table below gives it, or `["null", T]` when the field may hold no value: when its brick is none of `axt.ListField`, `axt.MapField` and `axt.RelationField`, it is not `required`, and its brick gives no default, a `default` of `null` or no member `default` at all, as `axt.ObjectField` and the time bricks have.
- **The default.** A list and a list of relations have the default `[]`, and a map `{}`. A field whose brick gives a default has that default, a default of bytes written as the string whose code points are its bytes, as Avro writes it. A field of the type `["null", T]` has the default `null`. A `required` field whose brick gives no default has none.
- **Items and values.** The items of a list and the values of a map have the type of their typed field by the same rule, and no default.

| Brick                                                                      | Type of the brick                                                                                                                    |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `axt.StringField` and the semantic bricks                                  | `"string"`                                                                                                                           |
| `axt.IntField`, `axt.LongField`, `axt.DoubleField`                         | `"int"`, `"long"`, `"double"`                                                                                                        |
| `axt.BooleanField`, `axt.BytesField`                                       | `"boolean"`, `"bytes"`                                                                                                               |
| `axt.EnumField`                                                            | `{"type": "enum", "name": its name, "doc": the field's doc, "symbols": its symbols in their order, "default": its fallback}`         |
| `axt.ListField`                                                            | `{"type": "array", "items": the type of its items}`                                                                                  |
| `axt.MapField`                                                             | `{"type": "map", "values": the type of its values}`                                                                                  |
| `axt.ObjectField`                                                          | `{"type": "record", "name": its name, "doc": the field's doc, "fields": its fields}`                                                 |
| `axt.DateField`, `axt.TimeField`, `axt.DateTimeField`, `axt.DurationField` | The published schema of `axt.Date`, `axt.Time`, `axt.DateTime` or `axt.Duration` at its first occurrence, and its full name after it |
| `axt.RelationField`                                                        | `{"type": "array", "items": axt.Relation as section 11.6 defines it in place}`                                                       |

The first occurrence is the first in the order of the JSON, the fields of each record in their order and depth first, and a time type that a published schema defines inside itself, such as `axt.Time` in a schema that holds `axt.DateTime` first, has its first occurrence there ([time.md](time.md), section 3.1), as does `axt.DateTime` in `axt.Relation` (section 11.6). The derived schema carries no attribute other than `axt.version` and those of the published schema of `axt.Relation`: what a receiver shows of a type and checks of its values is in the description, which travels with it.

The rule gives the forms that [types.md](types.md), section 5, requires of a type: a value that may be absent is `["null", T]` with the default `null`, a text that may be empty is a `string` whose brick gives the default `""`, and a list is an array with the default `[]`. Each example type is published as its description, from which the schema file next to it under [types/axt/example/v1/](../types/axt/example/v1/) is derived ([types.md](types.md), section 7).

### 9.3 The text

Where a derived schema travels as text, it is the JSON of section 9.2 in the canonical form of [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785), the JSON Canonicalization Scheme: the members of each object sorted by their names in UTF-16 code units, no white space, and every string and number written as ECMAScript writes it. Every app derives the same text from a description, so the text can be compared and hashed, as [sync.md](sync.md) does for the schema of a `FORWARD`. The fingerprint of a type is that of the Parsing Canonical Form of its derived schema ([envelope.md](envelope.md), section 5).

## 10. Descriptions in offers and files

### 10.1 Offers

An `OFFER` carries each type as its description ([protocol.md](protocol.md), section 4.1). The writer schema of the type's records under the offer is the schema derived from that description, and the type's full name, version and fingerprint are those of the description and its derived schema.

- A sender MUST offer only valid descriptions.
- An offer with a description whose root is not an `axt.ObjectField` names no type: the offer is not valid ([protocol.md](protocol.md), section 4.2).
- A receiver MUST decline a type whose description is not valid with `DESCRIPTION_INVALID` ([protocol.md](protocol.md), section 5.2), as it declines a type whose schema does not resolve. The offer stays valid, and its other types are answered as they would be without it.
- A receiver that keeps the writer schema of a type, to read its records and to show them, keeps the description it got with it. A device that passes an offer of a schema on to the other devices of its set offers the description it got, unchanged ([sync.md](sync.md), section 7.2).
- The data depth limit of 32 ([types.md](types.md), section 5.7) is that of records. A description nests deeper in the body of an `OFFER`: a receiver MUST decode the body of an `OFFER` up to a data depth of 256, which every description within the limits of section 9.1 keeps.

### 10.2 Files

A file carries its types in its header ([envelope.md](envelope.md), section 4.1): `axt.schemas` is a JSON array with one object for each type, with the members `description`, the description in the form of section 10.3, and `schema`, the schema derived from it as JSON. A reader that does not know the bricks still finds each writer schema in `schema`.

A reader MUST reject a file, as a whole, whose `axt.schemas` holds an entry without these two members, a description that is not valid, or a schema whose Parsing Canonical Form is not that of the schema derived from its description. It reads the records with the derived schema.

### 10.3 The JSON form of a description

Where a description is written as JSON, in a file and in the test vectors, it is the datum of `axt.Field` in the form of [conformance.md](conformance.md), section 3.3: bytes as lower-case hexadecimal, and the branch of each union `kind` as an object with one member, named by the full name of the brick, whose value is the brick, such as `{"axt.EmailField": {…}}`, as in the JSON encoding of Avro. The bricks with the same members, such as `axt.EmailField` and `axt.PhoneField`, differ only in their names, so the name is always written.

## 11. Relations

A relation links the record that holds it to another record or to a thing outside AXT, such as an appointment to the pets it is for, with information about the link. A type has relations through a field whose brick is `axt.RelationField`: its value is a list of relations, each a value of the published type `axt.Relation`, [types/axt/Relation.avsc](../types/axt/Relation.avsc), which is normative for what a relation holds. The brick has no member: the rules of a relation are the same in every type, and every receiver checks them (section 11.4). A type MAY have several relation fields, and a relation field MAY be the items of a list or a field of a nested object, as any typed field.

### 11.1 The relation record

| Field        | Avro type                                                 | Value                                                                                                                    |
| ------------ | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `id`         | `string` with `uuid`                                      | The id of the relation, unique among the relations of the list and kept for as long as the relation exists               |
| `kind`       | `string`, default `axt.related`                           | What kind of link it is (section 11.2)                                                                                   |
| `target`     | `axt.RelationRecordTarget` or `axt.RelationOutsideTarget` | What the relation points at: a record or a thing outside AXT (section 11.3)                                              |
| `note`       | `string`, default `""`                                    | Plain text about the link ([types.md](types.md), section 5.6); empty when there is none                                  |
| `start`      | `["null", axt.DateTime]`, default `null`                  | When the link begins; `null` when it has no beginning or it is not known                                                 |
| `end`        | `["null", axt.DateTime]`, default `null`                  | The first moment after the link, as the end of [types.md](types.md), section 5.6; `null` when it has no end or it is not known |
| `attributes` | `map` of `string`, default `{}`                           | Further values that the kind needs beyond the other fields, by names that the kind gives them; empty when there are none |

A sender creates the id of a relation as the id of a record ([records.md](records.md), section 2): a UUID of version 4 or 7, generated when the relation is created and never used for another relation of the list. The relations of a list are part of the record's value, in the order its user gave them.

### 11.2 Kinds

- **Names.** A kind is named like a type: a full name of Avro with a namespace, such as `org.example.catalog.vet`. An app introduces the kinds it needs in its own namespace ([types.md](types.md), section 2), and gives each kind its meaning, the meaning of `start` and `end` for it, and the names and values of its attributes. The namespace `axt` and every namespace that begins with `axt.` are reserved for this specification.
- **`axt.related`.** AXT defines one kind: `axt.related`, which says only that the two are related, and how is left to the user, such as in the note. It is the default of `kind`, and it has no attributes.
- **Kinds a receiver does not know.** A receiver MUST NOT reject a record or a relation because it does not know its kind, also not a kind in the namespace `axt`, which a later version of this specification may define. It keeps the relation as it received it, and SHOULD show it generically: by its kind's name, its target, its note, its times and its attributes, as it shows a field it does not know ([types.md](types.md), section 6).

### 11.3 Targets

The field `target` is a union of two records. Each has a field without a default that the other lacks, so that a value of one is never a value of the other:

- **A record**, `axt.RelationRecordTarget`: `id`, the id of the target record; `sender`, an Ed25519 public key ([keys.md](keys.md)) of the target record's sender, or `null` for a record of the sender of the record that holds the relation; `type`, the full name of the target record's type, which holds its major version, such as `axt.example.v1.Pet`, or empty when it is not known; and `text`, a display text, such as the target's title.
- **A thing outside AXT**, `axt.RelationOutsideTarget`: `uri`, a URI of [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) of any scheme, with the format `uri` of [metadata.md](metadata.md), section 6.3; and `text`, a display text, such as the thing's name.

A receiver SHOULD show the display text of a record target while it does not hold the target record, and that of an outside target in place of its URI. It shows and opens a URI as [metadata.md](metadata.md), section 6.3, says of the format `uri`.

### 11.4 Rules and limits

A relation is valid when:

1. its `id` is a UUID in text form, neither the nil UUID nor the max UUID ([records.md](records.md), section 2), and no earlier relation in the same list has the same id, compared as 128-bit values;
2. its `kind` is a full name of Avro with a namespace, of at most 256 bytes;
3. the `id` of a record target is a UUID in text form, neither the nil UUID nor the max UUID, and its `type` is empty or a full name of Avro of at most 256 bytes;
4. the `uri` of an outside target has 1 to 2,048 bytes;
5. the display text `text` of a target has at most 256 bytes, and the `note` at most 4,096 bytes;
6. it has at most 32 `attributes`, each name of 1 to 256 bytes and each value of at most 1,024 bytes;
7. its `start` and its `end` are valid time values ([time.md](time.md), section 8).

A list of relations holds at most 256 relations. Lengths are in bytes of UTF-8; a full name of Avro consists of names of an ASCII letter or `_` followed by ASCII letters, digits and `_`, separated by `.`.

A sender MUST NOT send a record with more than 256 relations in a list or with a relation that is not valid. A receiver MUST reject such a record with the error `VALUE_INVALID`, whose `field` names the first value that breaks a rule in the order of the encoding ([metadata.md](metadata.md), section 7.2): a list of more than 256 relations by its own path, such as `relations`; the second of two relations with one id by its id, such as `relations[1].id`; attributes beyond a limit by the map, such as `relations[0].attributes`; and every other value by its path, such as `relations[0].kind`. As with a time value, these are rules that every receiver checks, not checks of section 7: the only check of a relation field is `required`, which an empty list breaks (section 3.3).

The limits keep what a receiver stores and shows for the links of one record within the bounds of a list on a phone: a long text about a link belongs into a record of its own, to which the relation points. The rule on ids lets a receiver tell the relations of a list apart.

### 11.5 Relations and references

The references of [records.md](records.md), section 8, stay: a field whose value is the id of another record of the same sender. A type uses a relation for a link, unless the link is the type's own meaning, without which a record of the type is not understood, such as the pet that every record of an app type for a pet's weight is taken of; such a link MAY be a reference. Every other link, such as the pets an appointment is for, the vet of a pet or the appointment an invoice belongs to, is a relation, and a record can hold any number of them, of any kind.

### 11.6 Defined in place

The type of a relation field in the derived schema (section 9.2) is an array whose items are `axt.Relation`, defined in place at its first occurrence, as the time types are: as its published schema, with every named type that an earlier occurrence in the same schema already defined replaced by its full name, and by its full name `"axt.Relation"` after it. Its nested types, `axt.RelationRecordTarget`, `axt.RelationRecordTargetSender` and `axt.RelationOutsideTarget`, keep the names and the namespace `axt` of the published schema. A derived schema that holds an `axt.DateTime` before its first relation field has `"axt.DateTime"` in the `start` of its `axt.Relation`; otherwise its `axt.Relation` defines `axt.DateTime` in `start`, as the published schema does, and a later `axt.DateTimeField` has its full name.

A receiver MUST decline a type whose schema defines `axt.Relation` or one of its nested types otherwise, with `DOES_NOT_RESOLVE` ([protocol.md](protocol.md), section 5.2), as [time.md](time.md), section 3.1, has it decline a time type that is not defined as published.

## References

- [Apache Avro 1.12 specification](https://avro.apache.org/docs/1.12.0/specification/)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986): URIs, for the target of a relation
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): the JSON Canonicalization Scheme
- [RFC 9485](https://www.rfc-editor.org/rfc/rfc9485): I-Regexp, an interoperable regular expression format
- [CommonMark](https://spec.commonmark.org/)
- [UCUM](https://ucum.org/): the Unified Code for Units of Measure
