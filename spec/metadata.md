# Field metadata

Status: released in 0.1.0, changed in 0.2.0. A change to this document is a new version of AXT, with its entry in [CHANGELOG.md](../CHANGELOG.md).

This document defines the attributes that a schema carries so that a receiver which learns a type only from its schema can show and check each field: labels, help texts and emoji in English and other languages, the order and groups of fields, hints for inputs, formats, patterns and limits. It also says what a sender and a receiver do with a value that breaks a check, and how a receiver names that value.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Attribute**: a member of a schema's JSON whose name begins with `axt.`, such as `axt.label`. Avro permits members that its specification does not define, as long as they do not change the serialized data ([Avro 1.12](https://avro.apache.org/docs/1.12.0/specification/)); every attribute is one ([types.md](types.md), section 6).
- **Hint**: an attribute that says how to show a type, a field or a symbol. A value cannot break a hint.
- **Check**: an attribute that a value can break: `axt.format`, `axt.pattern`, `axt.min_length`, `axt.max_length`, `axt.min` and `axt.max` (section 6).
- **Value type** of a field: the type its values are checked and shown by (section 3.2).
- **Field path**: the name of one value inside a record, such as `address.postal_code` or `tags[1]` (section 7.2).
- **Code point**: a Unicode scalar value, U+0000 to U+D7FF or U+E000 to U+10FFFF. An Avro `string` is well-formed UTF-8 ([envelope.md](envelope.md), section 7), so it is a sequence of code points.

Sender, receiver and type have the meaning of [records.md](records.md), section 1, and [types.md](types.md), section 1.

## 2. The attributes

| Attribute                | JSON value                     | On                        | Kind  | Section                      |
| ------------------------ | ------------------------------ | ------------------------- | ----- | ---------------------------- |
| `axt.version`            | integer                        | the type's record         | hint  | [types.md](types.md), 3.2    |
| `axt.title`              | string, a field name           | the type's record         | hint  | [types.md](types.md), 6      |
| `axt.label`              | string                         | record, field             | hint  | 4.1                          |
| `axt.label_translations` | object: language tag to string | record, field             | hint  | 4.2                          |
| `axt.help`               | string                         | record, field             | hint  | 4.1                          |
| `axt.help_translations`  | object: language tag to string | record, field             | hint  | 4.2                          |
| `axt.emoji`              | string                         | record, field             | hint  | 4.3                          |
| `axt.symbols`            | object: symbol to entry        | enum                      | hint  | 4.4                          |
| `axt.groups`             | object: group key to entry     | record                    | hint  | 5.2                          |
| `axt.order`              | integer                        | field                     | hint  | 5.1                          |
| `axt.group`              | string, a group key            | field                     | hint  | 5.2                          |
| `axt.placeholder`        | string                         | field                     | hint  | 5.3                          |
| `axt.example`            | string                         | field                     | hint  | 5.3                          |
| `axt.multiline`          | boolean                        | field of strings          | hint  | 5.3                          |
| `axt.preferred_length`   | integer                        | field of strings          | hint  | 5.3                          |
| `axt.sensitive`          | boolean                        | field                     | hint  | 5.4                          |
| `axt.advanced`           | boolean                        | field                     | hint  | 5.4                          |
| `axt.unit`               | string, a UCUM code            | field of numbers          | hint  | [types.md](types.md), 6; 6.2 |
| `axt.anchor`             | string, `local` or `instant`   | field of `axt.DateTime`   | hint  | [time.md](time.md), 6.4      |
| `axt.format`             | string, a format name          | field of strings          | check | 6.3                          |
| `axt.pattern`            | string, an I-Regexp            | field of strings          | check | 6.4                          |
| `axt.min_length`         | integer                        | field of strings or bytes | check | 6.2                          |
| `axt.max_length`         | integer                        | field of strings or bytes | check | 6.2                          |
| `axt.min`                | number                         | field of numbers          | check | 6.2                          |
| `axt.max`                | number                         | field of numbers          | check | 6.2                          |

"Record" is the type's own record or a record nested in it; "field of strings" is a field whose value type (section 3.2) is `string`, and so on. Every attribute is optional. When an attribute is absent, a receiver behaves as the section of the attribute says, mostly as it would for a schema without attributes ([types.md](types.md), section 6).

The limits of the attributes:

| What                                                               | Maximum                                      |
| ------------------------------------------------------------------ | -------------------------------------------- |
| `axt.label` and each value of `axt.label_translations`             | 256 bytes                                    |
| `axt.help` and each value of `axt.help_translations`               | 1,024 bytes                                  |
| `axt.placeholder`                                                  | 256 bytes                                    |
| `axt.example`                                                      | 1,024 bytes                                  |
| Entries of one `axt.label_translations` or `axt.help_translations` | 64                                           |
| A language tag                                                     | 35 characters                                |
| `axt.emoji`                                                        | 10 code points                               |
| `axt.pattern`                                                      | 1,024 bytes; each number in it at most 1,000 |
| A group key                                                        | 64 bytes                                     |
| `axt.order`                                                        | −2,147,483,648 to 2,147,483,647              |

Lengths of texts are in bytes of UTF-8. The limits of a schema as a whole, 256 KiB and a nesting depth of 64, are those of [envelope.md](envelope.md), section 8.

## 3. Rules for every attribute

### 3.1 Where they sit

An attribute sits on one of these JSON objects of a schema:

- **The type's record** or **a nested record**: the object with `"type": "record"`. Its label, help and emoji describe the type, or the nested type, wherever it is used.
- **A field**: an object in the `fields` of a record. Its attributes describe that field only.
- **An enum**: the object with `"type": "enum"`. `axt.symbols` describes the symbols wherever the enum is used.

The attributes of a field sit on the field, not on the field's type, as `axt.unit` and `axt.anchor` do ([types.md](types.md), section 6): an attribute on a named type would apply to every field that uses it, and some Avro libraries drop the members of a primitive type written as an object, such as `{"type": "string", "axt.format": "email"}`. An attribute in any other place than the column "On" of section 2 names is not used.

### 3.2 The value type of a field

The value type of a field is the field's type with these taken away, in this order:

1. a union of `null` and one other type, `["null", T]`: its value type is T;
2. an array: its value type is the value type of its items, again without `["null", T]`.

So `string`, `["null", "string"]`, an array of `string` and an array of `["null", "string"]` all have the value type `string`. A primitive written with a logical type has the value type of the primitive. A check applies to each value of the value type in the field: to the value itself, or to each item of the array. A map is not taken away: a field whose type is a map has the value type `map`, and no check of section 6 applies to it.

### 3.3 Attributes that break their rules

An attribute breaks its rules when its JSON value is not of the kind section 2 names, when it sits elsewhere than section 2 names, or when it breaks a rule of its own section, such as a label of more than 256 bytes or a pattern that is not an I-Regexp.

- A sender MUST NOT send a schema with an attribute that breaks its rules, and MUST NOT use an attribute name beginning with `axt.` that this specification does not define, or a format name that section 6.3 does not define.
- A receiver MUST ignore an attribute that breaks its rules, as if it were absent, and uses the others. In an entry of `axt.symbols` or `axt.groups` it ignores each member that breaks its rules on its own. Translations whose English text is absent or ignored are ignored as well.
- A receiver MUST ignore attributes it does not know, and MUST NOT reject a schema or decline a type because of an attribute, whether it knows it or not ([types.md](types.md), section 6). It MAY reject a record only for a value that breaks a check it uses (section 7.1).

An `OFFER` whose schema carries a pattern that is not an I-Regexp is therefore not invalid, and the type is not declined for it: the receiver takes the type as if the field had no pattern. The attributes describe how to show and check values; they do not change how the values are encoded or what they mean, so a schema with a broken attribute still reads. Declining it would refuse records the receiver can read, for a fault in a text or a check of the sender's schema. A receiver that is stricter can still decline the type with `NOT_WANTED` ([protocol.md](protocol.md), section 5.2), as it can any type.

### 3.4 Fingerprints and versions

The Parsing Canonical Form drops every attribute ([types.md](types.md), section 3.4), so no attribute changes a schema's fingerprint. A receiver uses the attributes of the schema it received with the record: the writer schema of the offer or of the file header ([types.md](types.md), section 3.4). The attributes travel with the schema; a receiver MUST NOT take the attributes of one schema for a record written with another.

Which changes of attributes a new version of a type may make is in [types.md](types.md), section 3.3.

## 4. Labels, help and emoji

### 4.1 Label and help

`axt.label` is the name a receiver shows for a type, a nested type or a field, in English, such as `Postal code`. `axt.help` is one or two sentences in English that say what the value is or how to enter it, such as `Five digits.`, shown next to the field or on request.

- Both are one line of plain text: not empty, without control characters (Unicode general category Cc, which includes LF and CR), and without the line and paragraph separators U+2028 and U+2029, as the purpose sentences of [manifest.md](manifest.md), section 4. A label is at most 256 bytes, a help text at most 1,024 bytes.
- A receiver MUST show them as text and MUST NOT interpret markup in them.
- Without a label, a receiver shows the name, with underscores read as spaces for a field ([types.md](types.md), section 6). Without a help text, it shows none, or the `doc`.

A label and a help text are written for the user; the `doc` is written for the developer and stays the definition of what a field means ([types.md](types.md), section 5.1).

### 4.2 Languages

`axt.label_translations` and `axt.help_translations` give the label and the help text in other languages. They follow the rules of the purpose sentence and its translations of [manifest.md](manifest.md), section 3.6:

- Each key is a language tag of [BCP 47](https://www.rfc-editor.org/info/bcp47) in the `langtag` form of [RFC 5646, section 2.1](https://www.rfc-editor.org/rfc/rfc5646#section-2.1), of at most 35 characters, such as `de` or `pt-BR`. A key MUST NOT be `en`, in any case, and two keys MUST NOT be equal when compared without regard to case. A map has at most 64 entries.
- Each value is the label or the help text in that language, with the rules of section 4.1.
- A translation needs its English text: `axt.label_translations` without a valid `axt.label`, and `axt.help_translations` without a valid `axt.help`, break their rules.

A receiver chooses the language by the Lookup scheme of [RFC 4647, section 3.4](https://www.rfc-editor.org/rfc/rfc4647#section-3.4): it matches its user's language priority list against the keys of the translations and the tag `en` for the English text, without regard to case, and takes the English text when nothing matches. It chooses for the label and for the help text on their own. A user who reads `de-AT` gets the `de` label; a user who reads `fr-CH` and `fr` gets the English one if there is no `fr` label.

The English text is an attribute of its own, not an entry of the map, so that every label has a text every app can show, as with the purpose sentence.

### 4.3 Emoji

`axt.emoji` is an emoji that a receiver MAY show next to the label, such as `📞` for a phone number or `🏥` for a type of vet practices.

- It is a string of 1 to 10 code points without control characters (U+0000 to U+001F, U+007F to U+009F) and without white space or separators (U+0020, U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F, U+205F, U+3000). It holds an ASCII character only as the first of a keycap sequence: a digit, `#` or `*`, an optional U+FE0F, then U+20E3, such as `1️⃣`.
- It SHOULD be one emoji that [UTS #51](https://www.unicode.org/reports/tr51/) recommends for general interchange (an RGI emoji), and so one grapheme cluster.
- A receiver that cannot show it shows nothing in its place. It MUST NOT show it in place of the label.

The rule can be checked without Unicode data: whether a string is an RGI emoji or one grapheme cluster depends on tables of a Unicode version, which two apps need not share. The longest RGI emoji, such as a couple with two skin tones, have 10 code points.

### 4.4 Enum symbols

`axt.symbols` on an enum gives, for each symbol, an entry: an object with the members `label`, `label_translations`, `help`, `help_translations` and `emoji`, each optional, with the rules of sections 4.1 to 4.3.

```json
"axt.symbols": {"EMERGENCY": {"label": "Emergency service", "label_translations": {"de": "Notdienst"}, "emoji": "🚑"}}
```

- A key MUST be a symbol of the enum. An entry for another name breaks the rules of `axt.symbols`, and a receiver ignores the whole attribute.
- A symbol without an entry, or without a label in its entry, is shown by its name ([types.md](types.md), section 6).
- An unknown symbol that a receiver reads as the enum's default ([types.md](types.md), section 5.4) is shown as the default symbol.

The entries sit on the enum because Avro gives symbols no attributes of their own.

## 5. Showing the fields

### 5.1 Order

A receiver that shows the fields of a record shows them in this order:

1. the fields with `axt.order`, by their `axt.order`, the lowest first;
2. then the fields without it;
3. fields with the same `axt.order`, and the fields without it, in the order of the schema.

Then the fields of each group are brought together (section 5.2). The order is for display only; the encoding keeps the order of the schema. `axt.order` is an integer from −2,147,483,648 to 2,147,483,647, so a type can put a field before those it already has.

### 5.2 Groups

`axt.group` on a field is a group key: a name of the form of a field name, lower-case ASCII letters, digits and single underscores that starts with a letter ([types.md](types.md), section 5.2), of at most 64 bytes. Fields of one record with the same key form a group, shown together under the group's label. In the order of section 5.1, a group stands where its first field stands, and its fields follow each other in that order; a field without a group keeps its place.

`axt.groups` on the record gives the label of each group: an object from group key to an entry with the members of section 4.4. The label of a group is thus a key, with its own translations, rather than a text repeated on each field: the fields of a group cannot carry different texts for it, and a group is translated once. A group key without an entry is shown by its key, with underscores read as spaces. A sender MUST NOT name a key in `axt.groups` that no field of the record uses. Groups belong to one record; a nested record has groups of its own.

### 5.3 Inputs

- **`axt.placeholder`**: a text that an empty input for the field shows, such as `+49301234567`, as one line of plain text of at most 256 bytes. It is not translated; it SHOULD be a form of the value that a reader of any language understands, such as digits, a sample address or a mask. A text that needs translation belongs into the help text.
- **`axt.example`**: an example value as text, at most 1,024 bytes without control characters other than LF, such as `DE89370400440532013000`. A receiver MAY show it in the help. On a field of strings, a sender's example MUST meet the field's checks.
- **`axt.multiline`**: `true` when the value may hold several lines, separated by LF ([types.md](types.md), section 5.6), so that a receiver offers an input of several lines. Absent or `false`, a receiver SHOULD offer an input of one line. It is a hint, not a check: a receiver MUST show the line breaks of a value it received and MUST NOT reject a value because it has some.
- **`axt.preferred_length`**: the number of code points an input for the field SHOULD have room for, such as 5 for a postal code, at least 1. It is not a limit. A sender MUST NOT make it larger than `axt.max_length`.

### 5.4 Sensitive and advanced

- **`axt.sensitive`**: `true` when the value is a secret or personal data that others near the screen should not see, such as an account number. A receiver SHOULD hide it until its user asks to see it, and SHOULD NOT put it into notifications, previews, logs or error reports. It changes neither the encoding nor the protection of the value: every message is signed, and through a relay sealed, as every other ([keys.md](keys.md)).
- **`axt.advanced`**: `true` when most users need not see or fill in the field. A receiver MAY show it only when its user asks for more, in its place in the order of section 5.1.

## 6. Checks

### 6.1 What a check is

A check is a rule that each value of the field's value type keeps. A value keeps every check of its field at once.

- `null` keeps every check: a field of the type `["null", T]` holds no value then.
- The empty string keeps every `axt.format` and `axt.pattern`. In an example type, and as an app type SHOULD do, a text that may be empty is the empty string ([types.md](types.md), section 5.3), not `null`; a check of the form of a value does not apply when there is no value. A field that needs a value says so with `axt.min_length` 1. This narrows "the whole value matches" of a pattern (section 6.4) by one case, the empty string.
- A check applies to each item of an array (section 3.2), not to the array: `axt.max_length` 32 on an array of strings limits each string. The number of items is not checked.

### 6.2 Lengths and numbers

- **`axt.min_length` and `axt.max_length`**: integers of at least 0. For a `string`, the value has at least `axt.min_length` and at most `axt.max_length` code points; for `bytes`, bytes. A sender MUST NOT make `axt.min_length` larger than `axt.max_length`; if it does, both break their rules.
- **`axt.min` and `axt.max`**: finite JSON numbers. A value of `int`, `long`, `float` or `double` is at least `axt.min` and at most `axt.max`, compared as exact numbers. NaN breaks every `axt.min` and `axt.max`; infinity is compared as it is. A sender MUST NOT make `axt.min` larger than `axt.max`; if it does, both break their rules.

Lengths are counted in code points rather than in UTF-16 units or bytes of UTF-8. A code point is the same in every encoding, while UTF-8 and UTF-16 count `ä` as 2 and 1 and `𝄞` as 4 and 2, and the platforms that apps run on use either. Grapheme clusters would count as users do, but their rules change with the Unicode version, and two apps would count the same text differently.

The limits are in the field's unit: a field with `axt.unit` `min` and `axt.max` 240 holds at most 240 minutes. A receiver that shows the value in another unit converts the limits with it.

### 6.3 Formats

`axt.format` names the form of a field of strings. A receiver MAY check it, and SHOULD show and offer inputs for the value as the format suggests. The formats and what a non-empty value of each requires:

| Format       | The value                                                                                                                                                                                                                                                              | A receiver shows it                               |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| `plain`      | Any text; the same as no format                                                                                                                                                                                                                                        | as plain text ([types.md](types.md), section 5.6) |
| `markdown`   | Any text, read as [CommonMark](https://spec.commonmark.org/)                                                                                                                                                                                                           | rendered, with raw HTML shown as text (section 8) |
| `email`      | `local@domain`, each a `dot-atom-text` of [RFC 5322, section 3.2.3](https://www.rfc-editor.org/rfc/rfc5322#section-3.2.3), with the non-ASCII characters of [RFC 6532](https://www.rfc-editor.org/rfc/rfc6532); the local part at most 64 bytes, the whole at most 254 | as an address to write to                         |
| `phone`      | A number of [ITU-T E.164](https://www.itu.int/rec/T-REC-E.164): `+`, then 2 to 15 ASCII digits, the first not `0`; no spaces or other characters                                                                                                                       | grouped for reading, see below                    |
| `url`        | A `URI` of [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986), section 3, with the scheme `http` or `https`, in any case, an authority and a host that is not empty                                                                                                    | as a link that opens on its user's request        |
| `uri`        | A `URI` of RFC 3986, section 3, of any scheme, such as `tel:` or `urn:`; ASCII only                                                                                                                                                                                    | as text, or as a link for a scheme it handles     |
| `colour`     | `#` and six hexadecimal digits, in either case: red, green and blue of sRGB                                                                                                                                                                                            | MAY with a swatch of the colour                   |
| `iban`       | An IBAN of ISO 13616 in electronic form: two upper-case letters, two digits, then 11 to 30 upper-case letters or digits, without spaces, whose check of ISO 7064 MOD 97-10 gives 1                                                                                     | in groups of four characters                      |
| `bic`        | A BIC of ISO 9362: six upper-case letters, then two upper-case letters or digits, then optionally three more                                                                                                                                                           | as it is                                          |
| `country`    | Two upper-case ASCII letters, a code of ISO 3166-1 alpha-2, such as `DE`                                                                                                                                                                                               | SHOULD by the country's name                      |
| `language`   | A language tag in the `langtag` form of RFC 5646, section 2.1, of at most 35 characters, as in section 4.2, such as `de-AT`                                                                                                                                            | SHOULD by the language's name                     |
| `currency`   | Three upper-case ASCII letters, a code of ISO 4217, such as `EUR`                                                                                                                                                                                                      | SHOULD by its symbol or name                      |
| `media-type` | `type/subtype` of [RFC 6838](https://www.rfc-editor.org/rfc/rfc6838), each a `restricted-name` of its section 4.2, without parameters                                                                                                                                  | as it is                                          |
| `ucum`       | A code of [UCUM](https://ucum.org/), case-sensitive: one or more of the ASCII characters U+0021 to U+007E                                                                                                                                                              | as the unit                                       |

- **Syntax only.** Each format is checked by the syntax in the table, without a registry: whether a country code, currency or language is assigned, whether an IBAN has the length of its country, whether a domain exists or a UCUM code is valid beyond its characters, is not part of the check. A receiver MUST NOT reject a value by such a registry with `VALUE_INVALID`; it MAY tell its user. A sender SHOULD write only values that are valid by the registry as well.
- **An unknown format.** A receiver that does not know a format treats the value as `plain`: it checks nothing for it and shows the value as text.
- **Phone numbers.** A phone number is stored in E.164 form, so that every app can dial and compare it. A receiver SHOULD show it in the international notation of [ITU-T E.123](https://www.itu.int/rec/T-REC-E.123), with spaces between the country code, the area code and the number, as its own numbering-plan data groups it, such as `+49 30 1234567`; without such data it shows it as stored. It MAY offer to call it as a `tel:` URI of [RFC 3966](https://www.rfc-editor.org/rfc/rfc3966). It MUST NOT store the form it shows. An extension or a number written for one country cannot be held; such a field has no format.
- **No date or id formats.** Dates and times are the time types ([time.md](time.md)), and a UUID is the logical type `uuid` ([types.md](types.md), section 5.5). There is no format for them, so that each has one form.

### 6.4 Patterns

`axt.pattern` is a regular expression that the value matches as a whole. It is an I-Regexp of [RFC 9485](https://www.rfc-editor.org/rfc/rfc9485): an expression of the grammar of its section 3, with the semantics of its section 4, those of the regular expressions of XML Schema.

- **Whole value.** A value keeps the pattern when the whole value is in the language of the expression, not a part of it: `[0-9]{5}` takes `10115`, not `10115 Berlin` and not `10115` followed by LF. I-Regexp has no anchors: `^` and `$` are ordinary characters, and `^[0-9]+$` takes `^12$`, not `12`. `.` matches any code point except LF and CR. The empty string keeps every pattern (section 6.1).
- **The subset.** The grammar has no `\d`, `\w`, `\s` and other multi-character escapes, no groups of the form `(?…)`, no lazy or possessive quantifiers, no back references, no class subtraction and no Unicode blocks. It has `\p{…}` and `\P{…}` for the general categories of Unicode, such as `\p{Lu}`, and `[^]` is not allowed. A pattern outside the grammar breaks the rules of `axt.pattern` (section 3.3).
- **Limits.** A pattern is at most 1,024 bytes of UTF-8, and each number of a range quantifier, as in `{2,4}`, is at most 1,000. Some engines refuse larger repeats, RE2 among them, and every engine spends more time on them.
- **Validity.** A receiver decides whether a pattern is an I-Regexp with a parser of the grammar of RFC 9485, section 3, and its limits, not by whether its own engine compiles it: most engines take patterns outside the subset, such as `\d`, with a meaning of their own.
- **Unicode version.** `\p{…}` refers to the general categories of the receiver's version of Unicode. A code point that a later version assigns is in `Cn` for a receiver with an earlier one. A sender SHOULD NOT depend on categories of code points assigned in the last few years.

A library implements a pattern by translating it to the expressions of its platform, as RFC 9485, section 5, describes:

1. replace each `.` outside a character class by `[^\n\r]`;
2. write `^` and `$` outside a character class as `\^` and `\$`, since most dialects read them as anchors;
3. write an escape that the dialect refuses, or a character that it reads otherwise, so that it means the same: in ECMAScript with the flag `u`, which refuses `\-` outside a character class, as `-`; in Java, `&` inside a character class as `\&`, since `&&` there is an intersection;
4. match the whole value: in ECMAScript with `^(?:` and `)$` around the expression and the flag `u`; in PCRE, RE2 and Ruby with `\A(?:` and `)\z`; in Java with `Pattern.matches`; in Python with `re.fullmatch`, not with `$`, which matches before a final LF;
5. where the dialect has no `\p{…}`, as Python's `re`, replace each by a class of the code points of the category from its Unicode data.

These steps are those known for the dialects named; the semantics of RFC 9485, section 4, govern. The reference code in [conformance/tools/metadata_rules.py](../conformance/tools/metadata_rules.py) parses the grammar and writes every character of a pattern as an escape of its code point, which Python's `re` reads as that character only.

## 7. A value that breaks a check

### 7.1 Sender and receiver

- **Sender.** A sender MUST NOT send a record with a value that breaks a check of the schema it writes the record with. It keeps the checks of its own schema as it keeps the rules of the types, so that a receiver can rely on them.
- **Receiver.** A receiver MAY check the values of a record it gets against the checks of the record's writer schema. A receiver that checks and finds a value that breaks one MAY reject the record with the error `VALUE_INVALID` ([protocol.md](protocol.md), sections 6.2 and 8), whose `field` names the first such value in the order of the encoding (section 7.2). It reports only checks of the writer schema; rules of its own, such as those of its reader schema, are its own matter and not reported with `VALUE_INVALID`.
- **Taking it anyway.** A receiver that takes a record with a value that breaks a check MUST keep and show the value as received. It MUST NOT change it to meet the check, such as by cutting a text to its maximum length or removing the spaces of a phone number, since that would change the record without its user ([records.md](records.md), section 6). It MAY show its user that the value does not meet the check.
- **In a file.** A reader of a file that checks the values MAY leave a record with a value that breaks a check unapplied, with the result `VALUE_INVALID`, as it does for a record that fails another step of [protocol.md](protocol.md), section 6.2 ([transports.md](transports.md), section 2.2).

Checking is optional because a hint for the user is not a reason for every receiver to refuse data: a receiver that only stores and shows records loses nothing by a phone number with spaces. A receiver that acts on the values, such as one that dials numbers or sends mail, can refuse what it cannot use, and the sender learns which field it was.

A time value that is not valid ([time.md](time.md), section 8) is not a check: a receiver MUST reject it, also with `VALUE_INVALID` and the field path of the time value.

### 7.2 Field paths

A field path names one value in a record by the field names of the writer schema:

- the empty path names the record itself;
- a field of the record is named by its name, such as `phone`, and a field of a nested record by the path of the field that holds the record, a `.`, and the name, such as `address.postal_code`;
- an item of an array is named by the path of the array and the item's index, from 0, in decimal without leading zeros, in brackets, such as `tags[1]` or `phones[0].number`;
- a value of a map is named by the path of the map and the key as a JSON string ([RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)) in brackets, such as `due["tax"]`;
- a union adds nothing to the path.

When several values break a rule, the error names the first in the order of the encoding: the fields in the order of the schema, depth first, and the items and values in the order in which they are encoded. A time value is named as a whole, such as `end` for an `axt.DateTime` whose instant does not match its wall clock, not by one of its fields. The `field` of an `ERROR` holds at most 1,024 bytes; a receiver whose path is longer reports `null` instead ([protocol.md](protocol.md), section 8.1).

### 7.3 `VALUE_INVALID` and `UNDECODABLE`

The two errors about the body of a `DATA` divide by one rule:

- **`UNDECODABLE`**: the bytes are not a value of the offered schema. They end early, bytes are left over, a string is not well-formed UTF-8, an index or a length is out of range, or the data nest deeper than 32 ([types.md](types.md), section 5.7). The fault is in the sender's encoder, and nothing in the value can be named.
- **`VALUE_INVALID`**: the bytes are a value of the schema, and the value breaks a rule set for it: a rule of a time type ([time.md](time.md), section 8) or of a relation ([types.md](types.md), section 8.4), which every receiver checks, or a check of the schema's attributes, which a receiver may check. The fault is in the data, and `field` names the value, so that the sender can show its user what to correct.

## 8. Security

- **Patterns** come from the other app and are run against values from it. A backtracking engine can take time exponential in the length of the value for some patterns, such as `(a*)*b`. A receiver SHOULD match with an engine that runs in time linear in the value, such as RE2, or bound the time a match takes. A receiver that reaches its bound takes the value as if it kept the pattern; it MUST NOT reject the record for it.
- **Markdown** is rendered by a receiver of the other app's text. A receiver MUST NOT render raw HTML in it as HTML, MUST NOT run scripts from it, and SHOULD NOT load images or other resources it names without its user's consent.
- **Labels, help texts, placeholders and examples** are the sender's text. A receiver MUST show them as plain text ([manifest.md](manifest.md), section 3.6, says the same of purpose sentences). A label can say anything; it does not make a field mean what it says, and a receiver that acts on a field by its label, rather than by a type it knows, acts on the sender's word.
- **`axt.sensitive`** is a hint for showing. It does not protect a value beyond what every message has.

## 9. Example

`com.example.Vet` is an illustration only, not an example type. It carries every attribute of section 2 except `axt.version`, `axt.title` and `axt.anchor`. Its schema has 5,775 bytes of JSON without whitespace; three of its fields:

```json
{"type":"record","name":"Vet","namespace":"com.example","doc":"…","axt.label":"Vet practice","axt.label_translations":{"de":"Tierarztpraxis"},"axt.help":"A practice that treats animals.","axt.help_translations":{"de":"Eine Praxis, die Tiere behandelt."},"axt.emoji":"🏥","axt.groups":{"contact":{"label":"Contact","label_translations":{"de":"Kontakt"},"emoji":"📞"},"billing":{"label":"Billing","label_translations":{"de":"Abrechnung"},"emoji":"💶","help":"Only for invoices.","help_translations":{"de":"Nur für Rechnungen."}}},"fields":[
 {"name":"phone","type":"string","default":"","doc":"…","axt.label":"Phone","axt.label_translations":{"de":"Telefon"},"axt.emoji":"📞","axt.format":"phone","axt.placeholder":"+49301234567","axt.example":"+49301234567","axt.group":"contact","axt.order":3},
 {"name":"visit_minutes","type":"int","default":15,"doc":"…","axt.label":"Length of a visit","axt.label_translations":{"de":"Dauer eines Besuchs"},"axt.emoji":"⏱️","axt.unit":"min","axt.min":5,"axt.max":240},
 {"name":"iban","type":"string","default":"","doc":"…","axt.label":"IBAN","axt.emoji":"🏦","axt.format":"iban","axt.sensitive":true,"axt.advanced":true,"axt.group":"billing","axt.example":"DE89370400440532013000"},
 …]}
```

The `…` stand for the `doc` texts and the other fields of [conformance/tools/metadata_examples.py](../conformance/tools/metadata_examples.py). Its Parsing Canonical Form is that of the same schema without any attribute; its CRC-64-AVRO is `0xf6870cff0cc1a7e3`.

A receiver shows the type as `🏥 Vet practice` to a user who reads `en`, and as `🏥 Tierarztpraxis` to one who reads `de-AT`; a user who reads `fr-CH` and `fr` gets the English label. It shows the fields in this order, by `axt.order` for the first three and with the groups brought together, so that `website`, the last field of the schema, follows `email` in the group `contact`:

| Field           | Group     | English                | German                       | Emoji | Hints                              |
| --------------- | --------- | ---------------------- | ---------------------------- | ----- | ---------------------------------- |
| `name`          |           | Name                   | Name                         | 🏷️    |                                    |
| `kind`          |           | Kind                   | Art                          | 🗂️    |                                    |
| `phone`         | `contact` | Phone                  | Telefon                      | 📞     | format `phone`                     |
| `email`         | `contact` | Email                  | E-Mail                       | 📧     | format `email`                     |
| `website`       | `contact` | Website                | Webseite                     | 🌐     | format `url`                       |
| `address`       |           | Address                | Anschrift                    | 📮     |                                    |
| `colour`        |           | Colour in the calendar | Farbe im Kalender            | 🎨     | format `colour`                    |
| `rating`        |           | Rating                 | Bewertung                    | ⭐     |                                    |
| `visit_minutes` |           | Length of a visit      | Dauer eines Besuchs          | ⏱️    | unit `min`                         |
| `fee`           |           | Fee for a check-up     | Gebühr für eine Untersuchung | 💶     |                                    |
| `currency`      |           | Currency               | Währung                      | 💱     | format `currency`                  |
| `iban`          | `billing` | IBAN                   | IBAN                         | 🏦     | format `iban`, sensitive, advanced |
| `bic`           | `billing` | BIC                    | BIC                          | 🏦     | format `bic`, advanced             |
| `notes`         |           | Notes                  | Notizen                      | 📝     | format `markdown`, multiline       |
| `tags`          |           | Tags                   | Schlagwörter                 | 🔖     |                                    |

`kind` is an enum whose `axt.symbols` give `EMERGENCY` the label `Notdienst` and the emoji `🚑` for `de`. The nested record `address` shows its field `country` first, by its `axt.order` 0. `IBAN` has no translations, so every user gets the English label.

A receiver that checks finds, among the 35 records the script checks:

| Record                                                                                     | `field`               | Check            |
| ------------------------------------------------------------------------------------------ | --------------------- | ---------------- |
| Every value meets its checks                                                               | —                     | —                |
| The empty string in `phone`, `email`, `colour`, `iban`, `bic`, `postal_code` and `country` | —                     | —                |
| A phone number with spaces, `+49 30 1234567`                                               | `phone`               | `axt.format`     |
| An IBAN whose check digits do not match                                                    | `iban`                | `axt.format`     |
| A postal code of four digits                                                               | `address.postal_code` | `axt.pattern`    |
| A postal code followed by LF                                                               | `address.postal_code` | `axt.pattern`    |
| A tag of 33 times `𝄞`, 33 code points and 66 UTF-16 units                                  | `tags[1]`             | `axt.max_length` |
| A tag of 32 times `𝄞`                                                                      | —                     | —                |
| An empty name, below `axt.min_length` 1                                                    | `name`                | `axt.min_length` |
| A fee that is NaN                                                                          | `fee`                 | `axt.min`        |
| A phone number with spaces and a rating of 9                                               | `phone`               | `axt.format`     |

The values were produced with [conformance/tools/metadata_examples.py](../conformance/tools/metadata_examples.py), with the rules of [conformance/tools/metadata_rules.py](../conformance/tools/metadata_rules.py). The script:

- checks the type by the rules of [types.md](types.md), section 5, with the checks of [conformance/tools/example_types.py](../conformance/tools/example_types.py), which include the rules of every attribute, and that its canonical form is that of the schema without attributes, with fastavro 1.13.1 and the Python `avro` 1.12.2 package;
- checks a schema with 20 attributes that break their rules, each reported for a sender and ignored by a receiver, among them members of an entry of `axt.groups` and `axt.symbols`, which a receiver ignores one by one;
- checks what a receiver shows of the type and its fields in English, German and French, and the 35 records above and the others, each encoded with fastavro and decoded again with both libraries;
- checks each of the 14 formats with 37 values that have it and 44 that do not, 11 patterns with 41 values, and 13 patterns that are not an I-Regexp or exceed its limits.

The test vectors of [conformance.md](conformance.md) take precedence over these values.

## References

- [Apache Avro 1.12 specification](https://avro.apache.org/docs/1.12.0/specification/)
- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
- [RFC 3966](https://www.rfc-editor.org/rfc/rfc3966): the `tel` URI
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986): URIs
- [RFC 4647](https://www.rfc-editor.org/rfc/rfc4647): matching of language tags
- [RFC 5322](https://www.rfc-editor.org/rfc/rfc5322) and [RFC 6532](https://www.rfc-editor.org/rfc/rfc6532): email addresses, and their non-ASCII characters
- [RFC 5646](https://www.rfc-editor.org/rfc/rfc5646) ([BCP 47](https://www.rfc-editor.org/info/bcp47)): language tags
- [RFC 6838](https://www.rfc-editor.org/rfc/rfc6838): media types
- [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259): JSON
- [RFC 9485](https://www.rfc-editor.org/rfc/rfc9485): I-Regexp, an interoperable regular expression format
- [XML Schema 1.1 Part 2: Datatypes](https://www.w3.org/TR/xmlschema11-2/), whose regular expressions RFC 9485 takes its semantics from
- [UTS #51](https://www.unicode.org/reports/tr51/): Unicode emoji
- [CommonMark](https://spec.commonmark.org/)
- [UCUM](https://ucum.org/): the Unified Code for Units of Measure
- [ITU-T E.164](https://www.itu.int/rec/T-REC-E.164) and [ITU-T E.123](https://www.itu.int/rec/T-REC-E.123): international phone numbers and their notation
- [RE2](https://github.com/google/re2): a regular expression engine that runs in linear time
- ISO 13616 (IBAN), ISO 7064 (check characters), ISO 9362 (BIC), ISO 3166-1 (country codes) and ISO 4217 (currency codes)
