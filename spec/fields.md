# Typed fields

Status: new in 0.2.0. A change to this document is a new version of AXT, with its entry in [CHANGELOG.md](../CHANGELOG.md).

This document defines the bricks of AXT: typed fields that describe one field of a type, its name, the texts a receiver shows for it and the checks its values keep, as Avro records. A type is described by bricks put together, as an address is made of a street, a postal code and a country, and a person of a name, an address and other fields. The schema of the bricks, [types/axt/Field.avsc](../types/axt/Field.avsc), is normative for what each brick holds; this document says what a brick means and what its checks do to a value.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Typed field**: a datum of `axt.Field`. It describes one field: its common part (section 3) and, in its member `kind`, one brick.
- **Brick**: one branch of the union `kind`, such as `axt.StringField` or `axt.EmailField`. It names the kind of the field's values and holds the checks and hints of that kind.
- **Value brick**: a brick of a kind of value: text, a number, a boolean, bytes, an enum, a list, a map, an object, or a time type (section 4).
- **Semantic brick**: a brick of text of one form, such as an email address, whose check of that form is built in (section 5).
- **Description**: a typed field whose brick is an `axt.ObjectField`, at the root of a type: the type's fields, each a typed field, and so on down to the value bricks.
- **Value**: what a record holds for a field. A record carries plain values only; the description says how to show and check them and travels with the type, not with each record.
- **Check**: a member of a brick, or `required` of the common part, that a value can break (section 7). Every other member is a hint: it says how to show the field or offer an input for it.

Sender, receiver and type have the meaning of [records.md](records.md), section 1, and [types.md](types.md), section 1. Field path and code point have the meaning of [metadata.md](metadata.md), section 1.

## 2. The bricks

[types/axt/Field.avsc](../types/axt/Field.avsc) defines `axt.Field` and, in place, every brick and every record a brick holds, so that the file is parsed on its own. Its CRC-64-AVRO is `0x4ed0f338fe0961c6`.

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

The union `kind` has the bricks in this order. A relation is a kind of value of its own; its brick will join the union.

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

A description is valid when every typed field in it keeps the rules of sections 3 to 5: its name, doc, texts and hints, the limits of each check, and the defaults and examples that keep the field's checks. A default or an example is judged by the checks only when the checks themselves keep their rules. A sender MUST NOT send a description that is not valid.

A problem of a description is named by the field path of the member that breaks a rule, in the description as a datum of `axt.Field`: `kind.fields[1].kind.symbols` is the symbols of the enum of the second field of the type. A union adds nothing to the path ([metadata.md](metadata.md), section 7.2).

## 7. Checking a value

A value keeps every check of its typed field at once. The checks are `required` (section 3.3), `min_length`, `max_length` and `pattern` (sections 4.1 and 4.3), `min` and `max` (section 4.2) and `format` (section 5).

- A value that breaks a check is named by its field path. When it breaks several, the first in the order `required`, `format`, `pattern`, `min_length`, `max_length`, `min`, `max` is named.
- When several values break a check, the first in the order of the encoding is named: the fields of each object in their order, depth first, and the items and values in the order in which they are encoded.
- What a sender and a receiver do with a value that breaks a check, and the error `VALUE_INVALID`, are as [metadata.md](metadata.md), section 7, says of the checks of the attributes.

## 8. Example

`com.example.Vet` is an illustration only, not an example type. Its description has 14 fields, among them a phone, an email address and a website in the group `contact`, an enum `VetKind`, an object `VetAddress`, a number of minutes between 5 and 240, an IBAN that is sensitive and advanced, a date, notes in CommonMark, a list of tags and a map of fees. Encoded as a datum of `axt.Field`, it has 2,035 bytes. Its field `address`, with the branch of each `kind` written as an object whose one member is named by the brick, as in Avro's JSON encoding:

```json
{"name":"address","doc":"The address of the practice.","texts":{"label":"Address","label_translations":{"de":"Anschrift"},"help":"","help_translations":{},"emoji":"📮"},"required":false,"order":null,"group":"","sensitive":false,"advanced":false,"kind":{"axt.ObjectField":{"name":"VetAddress","fields":[
 {"name":"street","doc":"The street and house number.","texts":{"label":"Street","label_translations":{"de":"Straße"},"help":"","help_translations":{},"emoji":"🛣️"},"required":false,"order":null,"group":"","sensitive":false,"advanced":false,"kind":{"axt.StringField":{"default":null,"min_length":null,"max_length":100,"pattern":null,"multiline":false,"preferred_length":null,"placeholder":"","example":""}}},
 {"name":"postal_code","doc":"The postal code of five digits; empty when not known.","texts":{"label":"Postal code","label_translations":{"de":"Postleitzahl"},"help":"","help_translations":{},"emoji":"📮"},"required":false,"order":null,"group":"","sensitive":false,"advanced":false,"kind":{"axt.StringField":{"default":null,"min_length":null,"max_length":null,"pattern":"[0-9]{5}","multiline":false,"preferred_length":5,"placeholder":"10115","example":""}}},
 {"name":"country","doc":"The country.","texts":{"label":"Country","label_translations":{"de":"Land"},"help":"","help_translations":{},"emoji":"🏳️"},"required":false,"order":0,"group":"","sensitive":false,"advanced":false,"kind":{"axt.CountryField":{"default":"DE","min_length":null,"max_length":null,"preferred_length":null,"placeholder":"","example":""}}}],"groups":[]}}}
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
- checks that the description of `com.example.Vet` is valid, and 36 descriptions that each break one rule, each with the path of its problem;
- checks the 23 values of the table and the others, a value of each semantic brick that has its format and one that does not, and values of the bricks the type does not use;
- encodes each description with fastavro and decodes it again with both libraries.

The test vectors of [conformance.md](conformance.md) take precedence over these values.

## References

- [Apache Avro 1.12 specification](https://avro.apache.org/docs/1.12.0/specification/)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
- [RFC 9485](https://www.rfc-editor.org/rfc/rfc9485): I-Regexp, an interoperable regular expression format
- [CommonMark](https://spec.commonmark.org/)
- [UCUM](https://ucum.org/): the Unified Code for Units of Measure
