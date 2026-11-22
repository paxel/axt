# Field metadata

Status: released in 0.1.0, changed in 0.2.0. A change to this document is a new version of AXT, with its entry in [CHANGELOG.md](../CHANGELOG.md).

This document says how a receiver shows the fields of a type and checks their values, by the bricks that describe the type ([fields.md](fields.md)): labels, help texts and emoji in English and other languages, the order and groups of fields, hints for inputs, formats, patterns and limits. It also says what a sender and a receiver do with a value that breaks a check, and how a receiver names that value. What each brick holds is defined by [types/axt/Field.avsc](../types/axt/Field.avsc); a schema carries none of it as attributes ([fields.md](fields.md), section 9.2).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Typed field**, **brick**, **description**, **hint** and **check**: as [fields.md](fields.md), section 1, defines them.
- **Texts**: the label, the help text and the emoji of a typed field, an enum symbol or a group, with their translations: an `axt.FieldTexts` ([fields.md](fields.md), section 3.2). The empty string stands for a text that is absent.
- **Field path**: the name of one value inside a record, such as `address.postal_code` or `tags[1]` (section 7.2).
- **Code point**: a Unicode scalar value, U+0000 to U+D7FF or U+E000 to U+10FFFF. An Avro `string` is well-formed UTF-8 ([envelope.md](envelope.md), section 7), so it is a sequence of code points.

Sender, receiver and type have the meaning of [records.md](records.md), section 1, and [types.md](types.md), section 1.

## 2. The attributes

The attributes `axt.*` of 0.1.0 are retired: what each held is a member of a brick of [types/axt/Field.avsc](../types/axt/Field.avsc), and a derived schema carries no attribute but `axt.version` and those of the published schemas of `axt.Relation` and `axt.Extension` that it holds ([fields.md](fields.md), section 9.2).

## 3. Rules for every attribute

The rules of a description are those of [fields.md](fields.md), section 6.

### 3.1 Where they sit

The texts and hints describe the typed field, enum symbol or group that holds them ([fields.md](fields.md), sections 3 and 4).

### 3.2 The value type of a field

The checks of the items of a list or the values of a map apply to each item or value ([fields.md](fields.md), section 4.5).

### 3.3 Attributes that break their rules

A description that breaks a rule is not valid, and a receiver declines its type ([fields.md](fields.md), section 10.1).

### 3.4 Fingerprints and versions

A receiver shows and checks a record by the description that came with its writer schema, in the offer or the file header ([fields.md](fields.md), section 10); it MUST NOT take the texts and checks of one description for a record written under another. Which changes a new version of a type may make is in [types.md](types.md), section 3.3.

## 4. Labels, help and emoji

### 4.1 Label and help

The `label` is the name a receiver shows for a type, a nested object or a field, in English, such as `Postal code`. The `help` is one or two sentences in English that say what the value is or how to enter it, such as `Five digits.`, shown next to the field or on request.

- Both are one line of plain text: without control characters (Unicode general category Cc, which includes LF and CR), and without the line and paragraph separators U+2028 and U+2029, as the purpose sentences of [manifest.md](manifest.md), section 4. A label is within `metadata.label`, a help text within `metadata.help` ([types/axt/limits.json](../types/axt/limits.json)); lengths of texts are in bytes of UTF-8.
- A receiver MUST show them as text and MUST NOT interpret markup in them.
- Without a label, a receiver shows the name, with underscores read as spaces for a field ([types.md](types.md), section 6). Without a help text, it shows none, or the `doc`.

A label and a help text are written for the user; the `doc` is written for the developer and stays the definition of what a field means ([types.md](types.md), section 5.1).

### 4.2 Languages

`label_translations` and `help_translations` give the label and the help text in other languages. They follow the rules of the purpose sentence and its translations of [manifest.md](manifest.md), section 3.6:

- Each key is a language tag of [BCP 47](https://www.rfc-editor.org/info/bcp47) in the `langtag` form of [RFC 5646, section 2.1](https://www.rfc-editor.org/rfc/rfc5646#section-2.1), of at most `manifest.language_tag` characters, such as `de` or `pt-BR`. A key is not `en`, in any case, and no two keys are equal when compared without regard to case. A map has at most `metadata.translations` entries.
- Each value is the label or the help text in that language, with the rules of section 4.1.
- A translation needs its English text ([fields.md](fields.md), section 3.2).

A receiver chooses the language by the Lookup scheme of [RFC 4647, section 3.4](https://www.rfc-editor.org/rfc/rfc4647#section-3.4): it matches its user's language priority list against the keys of the translations and the tag `en` for the English text, without regard to case, and takes the English text when nothing matches. It chooses for the label and for the help text on their own. A user who reads `de-AT` gets the `de` label; a user who reads `fr-CH` and `fr` gets the English one if there is no `fr` label.

The English text is a member of its own, not an entry of the map, so that every label has a text every app can show, as with the purpose sentence.

### 4.3 Emoji

The `emoji` is an emoji that a receiver MAY show next to the label, such as `📞` for a phone number or `🏥` for a type of vet practices.

- It is a string of 1 to `metadata.emoji` code points without control characters (U+0000 to U+001F, U+007F to U+009F) and without white space or separators (U+0020, U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F, U+205F, U+3000). It holds an ASCII character only as the first of a keycap sequence: a digit, `#` or `*`, an optional U+FE0F, then U+20E3, such as `1️⃣`.
- It SHOULD be one emoji that [UTS #51](https://www.unicode.org/reports/tr51/) recommends for general interchange (an RGI emoji), and so one grapheme cluster.
- A receiver that cannot show it shows nothing in its place. It MUST NOT show it in place of the label.

The rule can be checked without Unicode data: whether a string is an RGI emoji or one grapheme cluster depends on tables of a Unicode version, which two apps need not share. The longest RGI emoji, such as a couple with two skin tones, have 10 code points.

### 4.4 Enum symbols

Each symbol of an `axt.EnumField` has its texts, with the rules of sections 4.1 to 4.3 ([fields.md](fields.md), section 4.4).

- A symbol without a label is shown by its name ([types.md](types.md), section 6).
- An unknown symbol that a receiver reads as the enum's `fallback` ([types.md](types.md), section 5.4) is shown as the fallback symbol.

## 5. Showing the fields

### 5.1 Order

A receiver that shows the fields of an object shows them in this order:

1. the fields with an `order`, by their `order`, the lowest first;
2. then the fields without it;
3. fields with the same `order`, and the fields without it, in the order of the description.

Then the fields of each group are brought together (section 5.2). The order is for display only; the encoding keeps the order of the description. The `order` is an `int`, so a type can put a field before those it already has.

### 5.2 Groups

The `group` of a field is a group key: a name of the form of a field name, lower-case ASCII letters, digits and single underscores that starts with a letter ([types.md](types.md), section 5.2), within `metadata.group_key`. Fields of one object with the same key form a group, shown together under the group's label. In the order of section 5.1, a group stands where its first field stands, and its fields follow each other in that order; a field without a group keeps its place.

The `groups` of the `axt.ObjectField` give the texts of each group. The label of a group is thus a key, with its own translations, rather than a text repeated on each field: the fields of a group cannot carry different texts for it, and a group is translated once. A group without a label is shown by its key, with underscores read as spaces. Groups belong to one object; a nested object has groups of its own.

### 5.3 Inputs

- **`placeholder`**: a text that an empty input for the field shows, such as `+49301234567`, as one line of plain text within `metadata.placeholder`. It is not translated; it SHOULD be a form of the value that a reader of any language understands, such as digits, a sample address or a mask. A text that needs translation belongs into the help text.
- **`example`**: an example value as text, within `metadata.example`, without control characters other than LF, such as `DE89370400440532013000`. A receiver MAY show it in the help. In a brick of text, it keeps the field's checks ([fields.md](fields.md), section 3.4).
- **`multiline`**: `true` when the value may hold several lines, separated by LF ([types.md](types.md), section 5.6), so that a receiver offers an input of several lines. When it is `false`, a receiver SHOULD offer an input of one line. It is a hint, not a check: a receiver MUST show the line breaks of a value it received and MUST NOT reject a value because it has some.
- **`preferred_length`**: the number of code points an input for the field SHOULD have room for, such as 5 for a postal code, at least 1. It is not a limit.

### 5.4 Sensitive and advanced

- **`sensitive`**: `true` when the value is a secret or personal data that others near the screen should not see, such as an account number. A receiver SHOULD hide it until its user asks to see it, and SHOULD NOT put it into notifications, previews, logs or error reports. It changes neither the encoding nor the protection of the value: every message is signed, and through a relay sealed, as every other ([keys.md](keys.md)).
- **`advanced`**: `true` when most users need not see or fill in the field. A receiver MAY show it only when its user asks for more, in its place in the order of section 5.1.

## 6. Checks

### 6.1 What a check is

A check is a rule that each value of a typed field keeps ([fields.md](fields.md), section 7). A value keeps every check of its field at once.

- `null` keeps every check but `required` ([fields.md](fields.md), section 3.3): a field of the type `["null", T]` holds no value then.
- The empty string keeps every `format` and `pattern`. In an example type, and as an app type SHOULD do, a text that may be empty is the empty string ([types.md](types.md), section 5.3), not `null`; a check of the form of a value does not apply when there is no value. A field that needs a value is `required`. This narrows "the whole value matches" of a pattern (section 6.4) by one case, the empty string.
- The checks of the items of a list or the values of a map apply to each item or value, not to the list or the map: a `max_length` of 32 on the items of a list of strings limits each string.

### 6.2 Lengths and numbers

- **`min_length` and `max_length`**: for text, the value has at least `min_length` and at most `max_length` code points; for bytes, bytes.
- **`min` and `max`**: a value of `axt.IntField`, `axt.LongField` or `axt.DoubleField` is at least `min` and at most `max`, compared as exact numbers. NaN breaks every `min` and `max`; infinity is compared as it is.

Lengths are counted in code points rather than in UTF-16 units or bytes of UTF-8. A code point is the same in every encoding, while UTF-8 and UTF-16 count `ä` as 2 and 1 and `𝄞` as 4 and 2, and the platforms that apps run on use either. Grapheme clusters would count as users do, but their rules change with the Unicode version, and two apps would count the same text differently.

The limits are in the field's unit: a field with the `unit` `min` and the `max` 240 holds at most 240 minutes. A receiver that shows the value in another unit converts the limits with it.

### 6.3 Formats

Each semantic brick of [fields.md](fields.md), section 5, has one of these formats built in. A receiver MAY check it, and SHOULD show and offer inputs for the value as the format suggests. The formats and what a non-empty value of each requires:

| Format       | The value                                                                                                                                                                                                                                                              | A receiver shows it                               |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
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
- **Phone numbers.** A phone number is stored in E.164 form, so that every app can dial and compare it. A receiver SHOULD show it in the international notation of [ITU-T E.123](https://www.itu.int/rec/T-REC-E.123), with spaces between the country code, the area code and the number, as its own numbering-plan data groups it, such as `+49 30 1234567`; without such data it shows it as stored. It MAY offer to call it as a `tel:` URI of [RFC 3966](https://www.rfc-editor.org/rfc/rfc3966). It MUST NOT store the form it shows. An extension or a number written for one country cannot be held; such a field is plain text, `axt.StringField`.
- **No date or id formats.** Dates and times are the time bricks ([fields.md](fields.md), section 4.7), and a UUID is the logical type `uuid` ([types.md](types.md), section 5.5). There is no format for them, so that each has one form.

### 6.4 Patterns

The `pattern` of an `axt.StringField` is a regular expression that the value matches as a whole. It is an I-Regexp of [RFC 9485](https://www.rfc-editor.org/rfc/rfc9485): an expression of the grammar of its section 3, with the semantics of its section 4, those of the regular expressions of XML Schema.

- **Whole value.** A value keeps the pattern when the whole value is in the language of the expression, not a part of it: `[0-9]{5}` takes `10115`, not `10115 Berlin` and not `10115` followed by LF. I-Regexp has no anchors: `^` and `$` are ordinary characters, and `^[0-9]+$` takes `^12$`, not `12`. `.` matches any code point except LF and CR. The empty string keeps every pattern (section 6.1).
- **The subset.** The grammar has no `\d`, `\w`, `\s` and other multi-character escapes, no groups of the form `(?…)`, no lazy or possessive quantifiers, no back references, no class subtraction and no Unicode blocks. It has `\p{…}` and `\P{…}` for the general categories of Unicode, such as `\p{Lu}`, and `[^]` is not allowed. A description with a pattern outside the grammar is not valid ([fields.md](fields.md), section 6).
- **Limits.** A pattern is within `metadata.pattern`, and each number of a range quantifier, as in `{2,4}`, is at most `metadata.pattern_quantifier` ([types/axt/limits.json](../types/axt/limits.json)). Some engines refuse larger repeats, RE2 among them, and every engine spends more time on them.
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

- **Sender.** A sender MUST NOT send a record with a value that breaks a check of the description of the schema it writes the record with. It keeps the checks of its own description as it keeps the rules of the types, so that a receiver can rely on them.
- **Receiver.** A receiver MAY check the values of a record it gets against the checks of the description of the record's writer schema. A receiver that checks and finds a value that breaks one MAY reject the record with the error `VALUE_INVALID` ([protocol.md](protocol.md), sections 6.2 and 8), whose `field` names the first such value as [fields.md](fields.md), section 7, says. It reports only checks of that description; rules of its own, such as those of its reader schema, are its own matter and not reported with `VALUE_INVALID`.
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

When several values break a rule, the error names the first in the order of the encoding: the fields in the order of the schema, depth first, and the items and values in the order in which they are encoded. A time value is named as a whole, such as `end` for an `axt.DateTime` whose instant does not match its wall clock, not by one of its fields. The `field` of an `ERROR` holds at most `protocol.error_field` bytes; a receiver whose path is longer reports `null` instead ([protocol.md](protocol.md), section 8.1).

### 7.3 `VALUE_INVALID` and `UNDECODABLE`

The two errors about the body of a `DATA` divide by one rule:

- **`UNDECODABLE`**: the bytes are not a value of the offered schema. They end early, bytes are left over, a string is not well-formed UTF-8, an index or a length is out of range, or the data nest deeper than `types.data_depth` ([types.md](types.md), section 5.7). The fault is in the sender's encoder, and nothing in the value can be named.
- **`VALUE_INVALID`**: the bytes are a value of the schema, and the value breaks a rule set for it: a rule of a time type ([time.md](time.md), section 8), of a relation or of an extension ([fields.md](fields.md), sections 11.4 and 12.3), which every receiver checks, or a check of the type's description ([fields.md](fields.md), section 7), which a receiver may check. The fault is in the data, and `field` names the value, so that the sender can show its user what to correct.

## 8. Security

- **Patterns** come from the other app and are run against values from it. A backtracking engine can take time exponential in the length of the value for some patterns, such as `(a*)*b`. A receiver SHOULD match with an engine that runs in time linear in the value, such as RE2, or bound the time a match takes. A receiver that reaches its bound takes the value as if it kept the pattern; it MUST NOT reject the record for it.
- **Markdown** is rendered by a receiver of the other app's text. A receiver MUST NOT render raw HTML in it as HTML, MUST NOT run scripts from it, and SHOULD NOT load images or other resources it names without its user's consent.
- **Labels, help texts, placeholders and examples** are the sender's text. A receiver MUST show them as plain text ([manifest.md](manifest.md), section 3.6, says the same of purpose sentences). A label can say anything; it does not make a field mean what it says, and a receiver that acts on a field by its label, rather than by a type it knows, acts on the sender's word.
- **`sensitive`** is a hint for showing. It does not protect a value beyond what every message has.

## 9. Example

The example is `com.example.Vet` of [fields.md](fields.md), section 8; the category `bricks` of [conformance.md](conformance.md) holds what a receiver shows of it and the values it checks.

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
