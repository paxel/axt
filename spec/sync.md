# Sync between the devices of one owner

Status: sections 1 to 6 written, 0.1.0. Still to come, as further sections of this document: the messages that carry field states between the devices of a set ([axt-1024](https://github.com/paxel/axt/issues/26)), and what the devices of a set do with the records they received from other apps ([axt-1025](https://github.com/paxel/axt/issues/27)). Until 0.1.0 is released, those parts may still change the details this document leaves to them.

This document defines how the devices of one owner, which [keys.md](keys.md), section 5, makes one device set, change the same records: the stamp every change carries, the state a device keeps of a record, how two states of one record merge per field, when a record counts as deleted, and which version a device gives a record toward other apps. It defines no message: sections 1 to 6 say what a device keeps and how it merges, whatever brings a state from one device to another.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

## 1. Terms

- **Device** and **device set**: as in [keys.md](keys.md), section 1. A device is one installation of an owner's app, with a signing key of its own; the devices of a set count as one sender.
- **Device key**: the 32 bytes of the Ed25519 public key of a device's signing key ([keys.md](keys.md), section 2.1).
- **Sibling** of a device: another current device of the same set.
- **Record of the set**: a record whose sender ([records.md](records.md), section 1) is the set. Every device of the set may change and delete it.
- **Stamp**: a `long` that a device gives to a change, taken from its clock in such a way that it never goes back (section 2).
- **Field state**: what a device keeps of one top-level field of a record: its value, as the bytes the changing device wrote, with the schema they were written with; the stamp of its last change; and the key of the device that made that change (section 3.1).
- **Removal**: the mark of a deletion in the state of a record: a stamp, the key of the device that set it, and whether it stands or was taken back (section 3.2).
- **State** of a record on a device: its field states, at most one removal, and its state stamp (section 3).
- **State stamp**: the stamp a device takes for a record on the occasions of section 3.3: whenever the state of the record changes on it, when it first takes the record, and when it sends the record again after `STALE`. It is the version of the record toward other apps (section 5).
- **Later**: of two field states, of two removals, or of a removal and a field state, the one with the higher stamp, and with equal stamps the one with the higher device key (sections 4.1 to 4.3).

Where this document says "a device", it means a device that stamps (section 2.4), unless it says otherwise.

## 2. Stamps

### 2.1 The stamp

A stamp is a `long` of at least 1. It orders changes: of two changes, the one with the higher stamp is the later one. A stamp comes from a hybrid logical clock. While the wall clock of a device leads, a stamp shows the time of the change: it is the time in milliseconds times 65,536, plus a random part. When the wall clock lags, because a sibling's clock ran ahead or the clock was set back, the device goes on counting from the highest stamp it knows, so its stamps keep rising.

The value 0 is not a stamp. It stands in a field state for "never stamped" (section 3.4), and for `highest` (section 2.2) while a device knows no stamp.

### 2.2 The next stamp

A device takes its next stamp from three integers:

| Input     | Type and range             | Meaning                                                                                                                                                                                          |
| --------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `now_ms`  | integer, −2^63 to 2^63 − 1 | The device's wall clock: the milliseconds since 1970-01-01T00:00:00Z, leap seconds not counted, as the instant of [time.md](time.md), section 1. It is negative for a clock set before that time |
| `highest` | integer, 0 to 2^63 − 1     | The highest stamp the device has given or seen, as listed below; 0 when there is none                                                                                                            |
| `r`       | integer, 0 to 32,767       | The random part, drawn anew for every stamp, uniformly                                                                                                                                           |

The next stamp is:

```text
base = max(now_ms × 65536, highest + 1)
next = base + r        if base + 32767 ≤ 2^63 − 1
no stamp               otherwise
```

- The arithmetic is exact, in integers of any size: `now_ms × 65536` and the sums MUST NOT wrap around. A negative product loses against `highest + 1`, which is at least 1.
- Whether a device can take a stamp depends on `now_ms` and `highest` only, not on the draw of `r`: it can while `base` is at most 2^63 − 32,768. Nothing is cut off: a stamp is `base + r` or there is none (section 2.3).
- The stamp becomes the device's `highest` at once. A device that keeps its `highest` therefore never gives a stamp twice, and each of its stamps is above every stamp it gave or saw before.
- A device MUST take each stamp in this way, one after the other. It MUST NOT keep stamps in stock and MUST NOT give one stamp to two changes; sections 3.3 and 3.5 say what takes a stamp.
- A device SHOULD draw `r` with a cryptographically secure random number generator. Two devices that drew from the same sequence would give the same stamps.

A device has seen, and counts into `highest`:

- every stamp it has given;
- every stamp of a state of a record that it merges (section 4.4): the stamp of every field state, the stamp of the removal and the state stamp;
- every version it has given a record, also the counted ones of section 2.4;
- every receiver's version that an `ACK` reported to it with the outcome `STALE` for a record of its set, whether that version is above the versions the device knows of the record or not (section 5.3).

A device MUST keep `highest` with its data, through every restart. After a restore from a backup it holds an older `highest`; [protocol.md](protocol.md), section 10, says what follows.

The random part is added while the clock leads and while the device counts. Two stamps that two devices take from the same `base`, in the same millisecond or counting from the same stamp while apart, are equal in one of 32,768 cases per pair, and differ in all others. Where two field states or removals do carry equal stamps, the device key decides (section 4.1). Where two devices give equal state stamps to different states of one record, a receiver that has the one takes the other for a duplicate ([records.md](records.md), section 5.2) until the record's next state, which has a higher state stamp, reaches it.

### 2.3 No stamp is refused

A device MUST accept every stamp of a sibling, also one that is far ahead of its own clock, the largest `long`, 2^63 − 1, included. It refuses none and caps none, and its own stamps continue above it, by counting, until its wall clock has caught up.

This has a limit near the largest `long`:

- **No stamp.** A device can take a stamp only while `max(now_ms × 65536, highest + 1) + 32767` is at most 2^63 − 1 (section 2.2). There is no clamp: beyond that it takes no stamp at all, whatever `r` would be. The highest stamp a device can give is so 2^63 − 1 itself, from a `base` of 2^63 − 32,768 with an `r` of 32,767; after it, the device takes none.
- **No change.** A device that can take no stamp MUST NOT change, create, delete or take back a record of the set, and SHOULD tell its user.
- **Two stamps for a change.** A change takes two stamps (section 3.5). A device MUST NOT begin a change unless `max(now_ms × 65536, highest + 1) + 65535` is at most 2^63 − 1 for the clock value at which it begins; both stamps can then be taken whatever is drawn for the first.
- **A merge is still made.** A device that can take no stamp still merges what its siblings hold and takes field states and the removal from them (section 4). Where the merge would need a state stamp (section 4.4), the device has none for its new state, and MUST NOT send a record message of that record any more (section 5.1): the state stamp it holds, if any, names another state.
- **A change without its state stamp.** If the clock moves on between the two stamps of a change so far that the second cannot be taken, the fields or the removal keep the first stamp, the state stamp is not taken, and the device MUST NOT send a record message of that record any more.
- **It spreads.** Every device that sees a stamp near the limit is in the same position, so the limit spreads through the set.

Only a party the owner trusts can bring a set there: a device of the set that gives such a stamp, by a fault or on purpose, or an app whose key the owner accepted and that reports such a version with `STALE` (section 5.3). The way out is a new set: new installations with new keys ([keys.md](keys.md), section 5.9), which send the records as their own. A clock that is merely wrong does not come near the limit: a clock alone stops a device from stamping only for a `now_ms` of 2^47 or more, a date beyond the year 6000.

### 2.4 Who stamps and who may go on counting

A receiver needs only a rising `long` as the version of a record ([records.md](records.md), section 3). An installation that is a set of its own, with no sibling, has no one to merge with. It MAY count the versions of each record from 1, as [records.md](records.md), section 3, describes, or stamp from its first record on. The records of an installation that counts carry no stamps.

An installation MUST stamp, that is, keep field states with stamps (section 3) and give state stamps as versions (section 5), from the first of these moments on:

- it signs a `DEVICE_ADD`, or holds a valid `DEVICE_ADD` of its own key ([keys.md](keys.md), section 5.2): its set has a second device. It goes on stamping when it is the only current device of its set again;
- it restores its data from a backup, or for another reason cannot rule out that it has given versions higher than those it holds ([protocol.md](protocol.md), section 10);
- an `ACK` reports to it, with the outcome `STALE`, a receiver's version above the highest version it knows of the record (section 5.3).

An installation that stamps MUST NOT go back to counting.

A device that restored its data from a backup and has a sibling SHOULD merge with a sibling before its first change (section 4). Its `highest` is that of the backup, and while its clock stands behind that value it can draw a stamp again that it gave before the backup was restored, for another change (section 4.1, rule 3).

When an installation begins to stamp:

- Its records keep the versions it counted until their state changes. For such a record, the counted version stands in the place of the state stamp (section 3.3).
- The fields of such a record were never stamped (section 3.4).
- For each record it deleted while it counted, it takes one stamp, each as the next stamp of section 2.2, and puts a removal that stands, with that stamp and its own key, into the state of the record (section 3.2). The version it counted for the deletion stays in the place of the state stamp, as for its other records. An installation that must begin to stamp but can take no stamp for this (section 2.3) does not begin: it changes, creates, deletes and takes back no record, and sends no record message of the records it would have had to stamp, the deleted ones without a removal, as section 2.3 says for a device at the limit.
- Every version it counted is in its `highest` (section 2.2), so its first stamp is above all of them. A stamp taken from a clock is far above any count: for a clock in the year 2025, it is above 10^17.

## 3. The state of a record

For every record of its set, a device keeps the record's id, the full name of its type ([records.md](records.md), section 4.3), and its state: a field state for each field, at most one removal, and the state stamp. Beside the state, it keeps for the record the highest state stamp of the record that it has seen from a sibling in a merge (section 4.4), and, while there is one, the version to pass (section 5.3).

### 3.1 Field states

The fields are the top-level fields of the record's writer schema, as in [records.md](records.md), section 6.1: a nested record, an array or a map is one value, with one stamp.

A field state is:

| Part     | Type and range        | Content                                                                                                                                                             |
| -------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`   | string                | The name of the field, as the writer schema of the changing device has it                                                                                           |
| `value`  | bytes                 | The value the last change gave the field: the bytes the changing device wrote, in Avro binary encoding under the type the field has in that device's writer schema  |
| `schema` | 8 bytes               | The fingerprint ([envelope.md](envelope.md), section 5) of that writer schema, which also tells its version, the `axt.version` of [types.md](types.md), section 3.2 |
| `stamp`  | `long`, 0 to 2^63 − 1 | The stamp of that change; 0 for a field never stamped (section 3.4)                                                                                                 |
| `device` | 32 bytes              | The device key of the device that made that change                                                                                                                  |

- A state holds at most one field state for a name. Two names are the same when they are the same sequence of Unicode code points; the aliases of a schema are not looked at.
- The bytes of `value` are kept and passed on unchanged, together with `schema`, by every device that holds the field state. No device encodes the value of another device's change again: Avro binary encoding of one value is not unique, since a map has no fixed order and arrays and maps can be split into blocks, and the comparison of section 4.1, rule 3, is on these bytes.
- For its own use, a device decodes the bytes with the schema that `schema` names, resolved against its own reader schema, as it decodes a record ([envelope.md](envelope.md), section 3). It keeps the text of that schema as long as it keeps a field state written with it.
- A device holds a field state for every field of its own writer schema of the type. A field of its schema for which it took no field state, such as one that its version of the type adds, has the default of the schema as its value and was never stamped (section 3.4).
- A device also holds every field state it took from a sibling for a field that its own schema does not have, and passes it on. It keeps the value as the bytes and the schema it came with; how a field state travels is defined with the parts to come.
- A state MAY hold no field state: for a type without fields, and for a deleted record whose field states the device discarded (section 4.3).

### 3.2 The removal

A removal is the mark that a record was deleted, or that a deletion was taken back:

| Part     | Type and range        | Content                                                                           |
| -------- | --------------------- | --------------------------------------------------------------------------------- |
| `stamp`  | `long`, 1 to 2^63 − 1 | The stamp of the deletion or of its taking back                                   |
| `device` | 32 bytes              | The device key of the device that deleted the record or took the deletion back    |
| `stands` | boolean               | `true` for a removal that stands: a deletion. `false` for one that was taken back |

- A state holds at most one removal. A record that was never deleted holds none.
- Deleting a record sets a removal that stands. Taking a deletion back sets a removal that was taken back, with a new stamp (section 3.5). Each takes the place of the removal the state holds.
- A removal is never taken out of a state. It is replaced only by a removal the device sets itself, or in a merge by the later one (section 4.2). It also stays when a change brings the record back (section 4.3).
- A record that an installation deleted while it counted gets its removal when the installation begins to stamp (section 2.4).

### 3.3 The state stamp

The state stamp is a stamp, a `long` of at least 1, that the device takes for the record. A device takes one on these occasions, and on no other:

1. after every change its user makes to the record on it: creating it, changing fields, deleting it, taking a deletion back (section 3.5);
2. after every merge in which it took at least one field state or the removal from the other state (section 4.4);
3. after a merge that brings it a record of which it held no state, also when the other state holds no field state and no removal (section 4.4);
4. when it sends the current state of the record again after `STALE` with a higher version (section 5.3). The state does not change then; the device takes a new state stamp for the same state.

The device takes the state stamp after the stamps of the change, and after it has seen the stamps of the other state. It is therefore above the stamp of every field state and of the removal in the device's state, and above every state stamp the device gave or saw for the record before. The one exception is a record that the installation deleted while it counted and whose state has not changed since: its counted version stands in the place of the state stamp (section 2.4), below the stamp of the removal it got when the installation began to stamp.

The state stamp belongs to the device. Two siblings that hold the same field states and the same removal of a record can hold different state stamps for it, since each took its own when it reached that state. A device never takes over the state stamp of a sibling as its own; it only counts it as seen (section 2.2).

For a record whose state has not changed since the installation began to stamp, the version it counted stands in the place of the state stamp (section 2.4).

### 3.4 Fields never stamped

A field that was last changed while the installation counted, or that has only the default of the device's schema (section 3.1), was never stamped. Its field state has the stamp 0 and, as `device`, the key of the device on which it stood unstamped: the installation that counted, or the device that put in the default. A sibling that takes such a field state keeps it with that stamp and that key. The device that holds such a field first encodes its value, under its own writer schema of that moment, when it first has to pass the field state on or to compare it by section 4.1, rule 3; from then on the field state holds those bytes and that schema, as section 3.1 says.

Every stamp is at least 1, so every stamped change of a field is later than a field state never stamped, and every removal is later than it.

### 3.5 What a change stamps

A device stamps what its user does to a record of the set. Each line is one change; the stamps are taken in the order given, each as the next stamp of section 2.2.

| The user                                  | Stamps taken | The device                                                                                                                                                                                                                                  |
| ----------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| creates a record                          | 2            | takes one stamp and gives it, with its own key, to every field of the record; then takes the state stamp                                                                                                                                    |
| changes one or several fields of a record | 2            | takes one stamp and gives it, with its own key, to each field whose value the change sets, with the new value; the other field states and the removal stay; then takes the state stamp                                                      |
| deletes a record                          | 2            | takes one stamp and puts a removal that stands, with that stamp and its own key, into the state, in the place of a removal the state holds; the field states stay as they are; then takes the state stamp                                   |
| takes back the deletion of a record       | 2            | takes one stamp and puts a removal that was taken back, with that stamp and its own key, into the state, in the place of the removal the state holds; it stamps no field, and the field states stay as they are; then takes the state stamp |

- A change of several fields that the user makes in one step, such as saving a form, is one change with one stamp for its fields. An app decides what one step is; two steps take two stamps each.
- A device SHOULD NOT stamp a field whose value a change leaves as it was.
- A record of a type without fields takes the same stamps; on creation the first is given to no field. Its deletion and the taking back work as for every record.
- A device deletes only a record that is there on it, and takes back only the deletion of a record that is deleted on it (section 4.3). It changes no field of a deleted record; it takes the deletion back first.
- Taking back changes no field: a field that a sibling changed in between keeps the sibling's value in the merged state. The removal that was taken back has a higher stamp than the removal it replaces, so it is the later of the two in every merge (section 4.2).
- A device that discarded the field states of a deleted record (section 4.3) cannot take the deletion back until a merge has brought it the field states again.

## 4. Merging two states

A device merges whenever it gets a state of a record of its set from a sibling: its own state and the other state become one. The merge has two parts. The first (sections 4.1 to 4.3) depends only on the two states and gives the same result on every device, whichever of the two states is its own. The second (section 4.4) is what the merging device does to its clock and its state stamp.

A device that holds no state of the record takes the other state: every field state and the removal come from the other state, and section 4.4 applies.

### 4.1 Field states

The merged state holds one field state for every field name that either state holds:

- for a name that only one state holds, the field state of that state;
- for a name that both hold, the later of the two field states.

Of two field states, the **later** is:

1. the one with the higher `stamp`;
2. with equal stamps, the one with the higher `device`. Device keys are compared as 32 unsigned bytes, from the first byte on: the first byte in which they differ decides, and the key with the higher byte there is the higher key;
3. with equal stamps and equal device keys, the one with the higher value. Values are compared by the bytes of `value` as the field states hold them (section 3.1), without decoding them, as unsigned bytes from the first byte on: the first byte in which they differ decides, and a value whose bytes are the beginning of the other's is the lower one. The last case can arise only when the field's type differs between the two writer schemas, since the encodings of one type are self-delimiting. If the bytes are equal as well, the one with the higher `schema` is the later one: the eight bytes of the fingerprint as the field states hold them, compared as unsigned bytes from the first byte on. If the two agree in that as well, they are the same field state, and the device keeps the one it holds.

Rule 3 makes both sides compute the same also where one device gave one stamp to two values, or wrote the same bytes under one stamp with two writer schemas, which a device that restored a backup can do while its clock stands behind its `highest` (section 2.4). In no other case does a device look at the values or at `schema` to decide.

A field state is taken whole: the bytes of its value, their schema, its stamp and its device key. A device MUST NOT mix the parts of two field states.

For each field name, the merge so says which side stands: the device's **own** state, when only it holds the name, when its field state is the later one, or when the two are the same field state; the **other** state, when only it holds the name or its field state is the later one.

### 4.2 The removal

- If neither state holds a removal, the merged state holds none.
- If one state holds a removal, the merged state holds it, whether it stands or was taken back.
- If both hold one, the merged state holds the later of the two. Of two removals, the later is the one with the higher `stamp`; with equal stamps, the one with the higher `device`, compared as in section 4.1; with equal stamps and equal device keys, the one that stands, over the one that was taken back. If the two agree in that as well, they are the same removal, and the device keeps its own.

A removal is taken whole: its stamp, its device key, and whether it stands. The device takes the removal from the other state when only the other state holds one, or when the other state's removal is the later one. In every other case its own side stands for the removal.

A deletion and its taking back are so decided like two changes of one field: the later one wins.

### 4.3 Deleted, and back

A record is **deleted** in a state exactly when the state holds a removal that stands and that is later than every field state the state holds: its stamp is higher than the field state's stamp, or the stamps are equal and its device key is the higher one (section 4.1, rules 1 and 2). In every other case the record is **there**:

| The state holds                                                                        | The record is |
| -------------------------------------------------------------------------------------- | ------------- |
| no removal                                                                             | there         |
| a removal that was taken back                                                          | there         |
| a removal that stands, and no field state                                              | deleted       |
| a removal that stands and is later than every field state                              | deleted       |
| a removal that stands, and at least one field state that the removal is not later than | there         |

The same rule decides between a deletion on one device and a change on another as between two changes of one field: the later one wins. A removal is not later than a field state with its own stamp and its own device key, so the record is there in that case; the values are not looked at here.

- **A change brings a record back.** A field state that a removal that stands is not later than, from a sibling that changed the field after the deletion or without knowing of it, makes the record there again in the merged state, with every field state the merged state holds. The removal stays in the state (section 3.2).
- **Taking back brings a record back.** A removal that was taken back never deletes, whatever the stamps of the field states. A record of a type without fields comes back in this way only.
- **A deletion after that.** A later removal that stands, and that is later than every field state of the merged state, deletes the record again.
- **A deleted record keeps its state.** A device SHOULD keep the field states of a deleted record, so that the record is whole when it comes back. It MAY discard them, values included, and keep only the removal and the state stamp; it MUST keep those as long as it is a device of the set, as a receiver keeps a tombstone ([records.md](records.md), section 5.3). A device that discarded them takes them again whenever it merges a state that holds them, with a new state stamp each time (section 4.4), and MAY discard them again while the record is deleted.
- **An incomplete record.** A device that discarded the field states of a deleted record, or never held them, and whose merge makes the record there, holds only the field states that the merge brought. Unless the other state held every field of the record, the device holds the record incompletely. It MUST NOT send an incomplete record to another app (section 5.1) and SHOULD NOT show it to its user as a record, until a merge with a sibling's whole state has completed it. How a device asks a sibling for the whole state is defined with the parts to come.

### 4.4 What the merging device does

After the merge of sections 4.1 to 4.3, the device:

1. counts every stamp of the other state as seen (section 2.2): the stamp of every field state, the stamp of the removal, and the state stamp;
2. keeps the merged state as its state of the record;
3. takes a new state stamp, as the next stamp of section 2.2, if it took at least one field state or the removal from the other state, that is, if the other side stands for at least one field name or for the removal, or if it held no state of the record before. If it held a state and took nothing, its state stamp stays as it is.

Of the stamps of step 1, only those of what the device takes and the other state's state stamp can raise its `highest`: a field state or a removal that it does not take has a stamp no higher than the one it holds in its place, which it gave or saw before. The other state's state stamp counts whether the device takes anything or not; it keeps the device's next state stamp of the record above the sibling's.

A merge takes at most one stamp. A device that held no state of the record keeps the other state as its own and takes a state stamp, also when the other state holds no field state and no removal, as for a record of a type without fields.

A device that can take no stamp (section 2.3) still does steps 1 and 2. If step 3 asks for a state stamp, it has none for the merged state and sends no record message of that record any more.

### 4.5 The order does not matter

The merge of field states and removals takes, for each field name and for the removal, the latest of all it has met, and rule 3 of section 4.1 and the last rule of section 4.2 decide every tie by the content alone. Its result therefore does not depend on the order in which states are merged, on how often a state is merged, or on which device merges: two devices that have merged the same states hold the same field states and the same removal, and so agree on whether the record is deleted. Merging a state a second time takes nothing and changes nothing.

The one exception is a device that discarded the field states of a deleted record (section 4.3): it holds fewer field states than its siblings, and takes them again from a state it merged before. It still holds the same removal, and the record is deleted on it as on its siblings, since every field state it discarded is one the removal is later than.

The state stamps are not part of that: they differ from device to device (section 3.3).

## 5. The version toward other apps

### 5.1 The state stamp is the version

Toward other apps, a device sends a record of its set as [records.md](records.md) and [protocol.md](protocol.md) say, whole and under one version:

- The version, `record.version` of the message ([envelope.md](envelope.md), section 2), is the device's state stamp of the record at the time it writes the message.
- The message is a `DATA` when the record is there (section 4.3), and a `DELETE` when it is deleted.
- A `DATA` carries the values of the field states the device holds, for the fields of the writer schema it offered. It carries no stamp and no device key: other apps get whole records, as before.
- A device MUST NOT send a `DATA` of a record for which it holds a stamped field state, one with a stamp of at least 1, whose field the writer schema it would write with lacks, if that field state was written with a later version of the type than the one the device writes with: the record it would send drops a value that a sibling on a later version set, and a receiver would lose it. It leaves sending that record to a sibling whose schema has the field, or sends it once it writes with such a schema itself. The device tells this by the version of the schema that the field state names in `schema` (section 3.1), compared with the `axt.version` of its own writer schema. A field that its own version of the type, or an earlier one, removed ([types.md](types.md), section 3.3) does not hold a record back: its field state was written with the device's own version or an earlier one. Nor does a field state never stamped (section 3.4).
- A device MUST NOT send a record it holds incompletely (section 4.3), and MUST NOT send a record for whose state it could take no state stamp (section 2.3).

Nothing changes for a receiver. A state stamp is a `long` of at least 1 that rises with every state of the record on the device, so the version rule of [records.md](records.md), section 5.2, applies as it stands, and a receiver need not know whether a version was counted or is a state stamp.

Two siblings in the same state can send it under two versions, each under its own state stamp (section 3.3). A receiver applies the higher one and reports the lower one, if it arrives later, as `STALE`. Both carry the same value for every stamped field, by the rule above; they can differ only in a field that one device's version of the type has and the other's lacks: one that was never stamped, which then holds a default, or one that the later version removed. Apart from that the receiver ends in the same state either way.

### 5.2 Why the version is not the highest field stamp

The highest stamp among the field states and the removal would rise as well, but it would name two different records with one version. Two devices change different fields of a record while apart, the one `start` with the stamp 110, the other `location` with the stamp 120, and each sends its state: the second under the version 120, with the old `start`. When the two have merged, the merged record holds both changes, and its highest field stamp is still 120, a version that already stands for another record. A receiver that has the version 120 would take the merged record for a duplicate and never show the new `start`. One id and version MUST stand for the same message ([records.md](records.md), section 3), so every state that a device reaches, by a change or by a merge that took something, gets a stamp of its own. Section 6.3 shows the case in full.

### 5.3 `STALE` with a higher version

A receiver reports `STALE` with its own version of the record when a message carries a lower one ([records.md](records.md), section 7). A device counts every receiver's version reported in this way as a stamp it has seen (section 2.2), so that every stamp it takes from then on is above it.

What else it does, one comparison decides: whether the receiver's version is above the **highest version the device knows of the record**. That is the higher of its own state stamp of the record and the highest state stamp of the record it saw from a sibling in a merge (section 4.4). A device need not remember the versions it gave before.

| The receiver's version is                                    | The device                                                                                        |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| not above the highest version the device knows of the record | does nothing more: an older message arrived late, or a sibling sent a state the device has merged |
| above it                                                     | acts as below                                                                                     |

A higher version is no fault as such: a sibling may have sent the receiver a state under a higher state stamp. The device may also have lost versions it gave ([protocol.md](protocol.md), section 10), or the version is one of a device that was removed since. The device then:

- stamps from then on, if it counted until now (section 2.4);
- keeps the receiver's version for the record as the **version to pass**, whether it is the only current device of its set or not. If a later `STALE` reports a higher one, it keeps that. It drops the version to pass as soon as its state stamp of the record is above it: after the resend below, or after a change or a merge that gave it a higher state stamp;
- if it is the only current device of its set, MUST take a new state stamp for the record at once (section 3.3) and send the record's current state under it, unless one of the two cases below holds. No sibling can bring it a newer state;
- if its set has other current devices, waits for them: a merge with a sibling that holds a newer state gives the device a state stamp above the receiver's version. Once it has, after the `STALE`, merged the state of the record with every other current device of its set, it looks at its state stamp of the record. If that is still below the version to pass, the device MUST take a new state stamp for the record and send the record's current state under it, unless one of the two cases below holds. Otherwise it sends its state as section 5.1 says. How it merges with each sibling is defined with the parts to come;
- waits for a sibling at most 14 days from the `STALE`, the time a relay holds a message ([transports.md](transports.md), section 5.5). After that, and for a sibling that is removed from the set, it goes on as if it had merged with that sibling.

Both sending rules hold unless the device can take no stamp (section 2.3), or section 5.1 forbids it to send the record: it holds the record incompletely, it holds a field state of a later version of the type that its writer schema lacks, or it could take no state stamp for the record's state. In those cases it sends nothing, and keeps the version to pass.

The new state stamp is above the receiver's version, since the device has seen that version, so the receiver applies the state. Without the last rule, a receiver would stay behind for good where the device that gave the higher version was removed, or lost that state, before any sibling merged it.

## 6. Examples

The examples of this section were produced with [conformance/tools/sync_examples.py](../conformance/tools/sync_examples.py). The script computes every stamp, every change and every merge below from the inputs stated here, by the rules of sections 2 to 5, and checks them against the numbers of this section. The vectors of the category `sync` hold the same cases ([conformance.md](conformance.md)); where an example and a vector differ, the vector holds.

### 6.1 Stamps

The next stamp for given inputs, by section 2.2. The clock of the first lines shows 2025-11-18 09:00:00.000 UTC, a `now_ms` of 1,763,456,400,000, and 1,763,456,400,000 × 65,536 is 115,569,878,630,400,000.

| Case                                                                     | `now_ms`          | `highest`                 | `r`    | `base`: `max(now_ms × 65536, highest + 1)` | Next stamp                |
| ------------------------------------------------------------------------ | ----------------- | ------------------------- | ------ | ------------------------------------------ | ------------------------- |
| 1. The first stamp of a device                                           | 1,763,456,400,000 | 0                         | 12,345 | 115,569,878,630,400,000                    | 115,569,878,630,412,345   |
| 2. A second stamp in the same millisecond: the device counts             | 1,763,456,400,000 | 115,569,878,630,412,345   | 7      | 115,569,878,630,412,346                    | 115,569,878,630,412,353   |
| 3. A millisecond later: the clock leads again                            | 1,763,456,400,001 | 115,569,878,630,412,353   | 30,000 | 115,569,878,630,465,536                    | 115,569,878,630,495,536   |
| 4. The device has seen a stamp of a sibling whose clock is an hour ahead | 1,763,456,400,001 | 115,570,114,560,020,000   | 100    | 115,570,114,560,020,001                    | 115,570,114,560,020,101   |
| 5. The clock was set back to 1970                                        | 0                 | 115,570,114,560,020,101   | 32,767 | 115,570,114,560,020,102                    | 115,570,114,560,052,869   |
| 6. A clock before 1970 and no stamp yet                                  | −5                | 0                         | 0      | 1                                          | 1                         |
| 7. `highest` is one below the clock's value                              | 1,763,456,400,000 | 115,569,878,630,399,999   | 0      | 115,569,878,630,400,000                    | 115,569,878,630,400,000   |
| 8. The last `base` from which a stamp can be taken                       | 1,763,456,400,000 | 9,223,372,036,854,743,039 | 50     | 9,223,372,036,854,743,040                  | 9,223,372,036,854,743,090 |
| 9. The same with the highest random part: the largest `long`             | 1,763,456,400,000 | 9,223,372,036,854,743,039 | 32,767 | 9,223,372,036,854,743,040                  | 9,223,372,036,854,775,807 |
| 10. One above: no stamp, also with the lowest random part                | 1,763,456,400,000 | 9,223,372,036,854,743,040 | 0      | 9,223,372,036,854,743,041                  | no stamp                  |
| 11. A clock so far ahead that the product is above the largest `long`    | 2^47              | 0                         | 0      | 9,223,372,036,854,775,808                  | no stamp                  |
| 12. `highest` is the largest `long`                                      | 1,763,456,400,000 | 9,223,372,036,854,775,807 | 0      | 9,223,372,036,854,775,808                  | no stamp                  |

In case 4 the sibling's stamp is (1,763,456,400,000 + 3,600,000) × 65,536 + 20,000. The largest `long`, 2^63 − 1, is 9,223,372,036,854,775,807; 2^63 − 32,768, the last `base` of cases 8 and 9, is 9,223,372,036,854,743,040; and 2^47 is 140,737,488,355,328. In cases 10 to 12, `base + 32767` is above 2^63 − 1, so there is no stamp for any `r`.

A change needs two stamps, and a device begins one only while `base + 65535` is at most 2^63 − 1 (section 2.3), a `base` of at most 9,223,372,036,854,710,272. The device of case 8 can so take one stamp, such as the state stamp of a merge, but MUST NOT begin a change.

### 6.2 The stamps of the following examples

The examples of sections 6.3 to 6.6 use small stamps, such as 100 and 110, so that they can be followed; every `long` of at least 1 is a valid stamp, and a device whose clock stands at 1970 gives such stamps. The numbers are chosen, not computed: each is above every stamp its device had given or seen, as section 2.2 requires, and the random part accounts for the gaps.

An owner runs cat-a-log on a phone and on a tablet, which are one device set. Their device keys are test keys, derived as the test keys of [keys.md](keys.md), section 7.1, from the labels `cat-a-log, phone, Ed25519` and `cat-a-log, tablet, Ed25519`, which [keys.md](keys.md) does not list. **These keys are for tests only and MUST NOT be used outside tests.** The tablet's device key is the higher of the two (section 4.1, rule 2). Both hold the appointment of [records.md](records.md), section 9, an `axt.example.v1.Appointment`; the examples show three of its fields, and the others never change. The phone created the record with the stamp 100 and took the state stamp 101; the tablet took the state from the phone in a merge and took the state stamp 105. Both therefore start from this state:

| Field      | Value            | Stamp | Device |
| ---------- | ---------------- | ----- | ------ |
| `title`    | "Vet"            | 100   | phone  |
| `start`    | 2025-11-18 10:00 | 100   | phone  |
| `location` | ""               | 100   | phone  |

No removal. State stamp: 101 on the phone, 105 on the tablet. The phone has given or seen the stamps up to 101, the tablet those up to 105: the tablet saw the phone's state stamp 101 in its merge, the phone has not seen the tablet's 105.

### 6.3 Two devices change different fields

While the devices are apart, the phone's user moves `start` to 10:30 and the tablet's user sets `location`. Then each device gets the other's state and merges.

| Step | What happens                                                       | Stamps taken                     | State stamp, phone | State stamp, tablet |
| ---- | ------------------------------------------------------------------ | -------------------------------- | ------------------ | ------------------- |
| 1    | The phone sets `start` to 10:30                                    | phone: 110 (field), 111 (state)  | 111                | 105                 |
| 2    | The tablet sets `location` to "Dr. Weber, Hauptstr. 5"             | tablet: 120 (field), 121 (state) | 111                | 121                 |
| 3    | The tablet merges the phone's state of step 1 and takes `start`    | tablet: 127 (state)              | 111                | 127                 |
| 4    | The phone merges the tablet's state of step 2 and takes `location` | phone: 130 (state)               | 130                | 127                 |
| 5    | Each merges the other's state of steps 3 and 4 and takes nothing   | none                             | 130                | 127                 |

The merge of step 4 on the phone, field by field:

| Field      | Own (phone)       | Other (tablet, step 2)                | Stands | Why                  |
| ---------- | ----------------- | ------------------------------------- | ------ | -------------------- |
| `title`    | "Vet", 100, phone | "Vet", 100, phone                     | own    | the same field state |
| `start`    | 10:30, 110, phone | 10:00, 100, phone                     | own    | 110 is above 100     |
| `location` | "", 100, phone    | "Dr. Weber, Hauptstr. 5", 120, tablet | other  | 120 is above 100     |

The phone took one field state, so it takes a new state stamp. It has seen the stamps 100, 120 and the tablet's state stamp 121, so the stamp is above 121: here 130. In step 3 the tablet takes `start` in the same way; it has given 121 and seen 111, and takes 127.

After step 4 both devices hold the same field states:

| Field      | Value                    | Stamp | Device |
| ---------- | ------------------------ | ----- | ------ |
| `title`    | "Vet"                    | 100   | phone  |
| `start`    | 2025-11-18 10:30         | 110   | phone  |
| `location` | "Dr. Weber, Hauptstr. 5" | 120   | tablet |

The state stamps differ, 130 on the phone and 127 on the tablet (section 3.3). In step 5 neither side takes anything, so both state stamps stay; each device has seen the other's, and its next stamp is above 130.

Toward another app, the devices have sent, or may send, four versions of the record, each a `DATA`:

| Version | Sent by | `start` | `location`               |
| ------- | ------- | ------- | ------------------------ |
| 111     | phone   | 10:30   | ""                       |
| 121     | tablet  | 10:00   | "Dr. Weber, Hauptstr. 5" |
| 127     | tablet  | 10:30   | "Dr. Weber, Hauptstr. 5" |
| 130     | phone   | 10:30   | "Dr. Weber, Hauptstr. 5" |

Each version stands for one record. A receiver that gets them in any order, some or all, ends with the one of the highest version it got ([records.md](records.md), section 5.2); once it has 127 or 130, it holds both changes. A tablet that sends 127 to a receiver that has 130 gets `STALE` with the receiver's version 130, a stamp it has seen already, and does nothing (section 5.3).

Were the version the highest field stamp, the versions would be 110, 120, 120 and 120: the tablet's state of step 2 and the merged state would share the version 120 (section 5.2).

### 6.4 Two devices change the same field

Starting again from the state of section 6.2, both users change `title` while the devices are apart, the phone to "Vet, Mimi" and the tablet to "Vet with Mimi". Each takes a stamp for the field and a state stamp; then each merges the other's state.

| Case                            | Phone: field stamp, state stamp | Tablet: field stamp, state stamp | Stands on both devices | Why                                              |
| ------------------------------- | ------------------------------- | -------------------------------- | ---------------------- | ------------------------------------------------ |
| 1. The tablet's change is later | 140, 141                        | 150, 151                         | the tablet's           | 150 is above 140                                 |
| 2. The phone's change is later  | 160, 161                        | 150, 151                         | the phone's            | 160 is above 150                                 |
| 3. Equal stamps                 | 150, 151                        | 150, 152                         | the tablet's           | the stamps are equal; the tablet's key is higher |

| Case | The device that takes `title` | It has given or seen | Its new state stamp | The other device     |
| ---- | ----------------------------- | -------------------- | ------------------- | -------------------- |
| 1    | the phone                     | up to 151            | 155                 | the tablet keeps 151 |
| 2    | the tablet                    | up to 161            | 165                 | the phone keeps 161  |
| 3    | the phone                     | up to 152            | 156                 | the tablet keeps 152 |

The device whose change stands takes nothing from the other's state and keeps its state stamp. The value that loses is gone on both devices. In case 3 the two state stamps of the changes are 151 and 152; had both devices drawn 151, one version would stand for two records, the one case in 32,768 per pair of section 2.2.

### 6.5 A deletion and a change

Starting again from the state of section 6.2, the phone's user deletes the appointment: the phone takes the stamp 150 for a removal that stands and the state stamp 151, and sends a `DELETE` under the version 151. The tablet, apart, changes `location` to "Praxis" and takes a state stamp. Then each device merges the other's state. The merged field states and the removal are the same on both devices:

| Case                                   | Tablet's `location`, field stamp | Tablet's state stamp | Removal            | The record is | Why                                                             |
| -------------------------------------- | -------------------------------- | -------------------- | ------------------ | ------------- | --------------------------------------------------------------- |
| 1. The change came before the deletion | 145, tablet                      | 146                  | 150, phone, stands | deleted       | the removal's 150 is above every field stamp: 100, 100 and 145  |
| 2. The change came after the deletion  | 160, tablet                      | 161                  | 150, phone, stands | there         | 150 is not above 160                                            |
| 3. Equal stamps                        | 150, tablet                      | 152                  | 150, phone, stands | there         | the stamps are equal, and the phone's key is not the higher one |

What each device takes in its merge, and the state stamp it takes for it, which is above every stamp it has given or seen:

| Case | The tablet takes | The tablet has given or seen | Tablet's new state stamp | The phone takes       | The phone has given or seen | Phone's new state stamp | Each then sends |
| ---- | ---------------- | ---------------------------- | ------------------------ | --------------------- | --------------------------- | ----------------------- | --------------- |
| 1    | the removal      | up to 151                    | 155                      | `location`, 145 > 100 | up to 151                   | 153                     | a `DELETE`      |
| 2    | the removal      | up to 161                    | 165                      | `location`, 160 > 100 | up to 161                   | 163                     | a `DATA`        |
| 3    | the removal      | up to 152                    | 156                      | `location`, 150 > 100 | up to 152                   | 154                     | a `DATA`        |

In case 1 the record is deleted on both devices. The phone took the tablet's `location` all the same, so its state changed and it has a new version, 153, for its `DELETE`. In cases 2 and 3 the record is there on both devices after the merge, with `title` "Vet", `start` 10:00 and `location` "Praxis", and the removal of the stamp 150 stays in both states, standing but not later than `location`. The phone, which had sent a `DELETE` under the version 151, sends a `DATA` under its new state stamp, which brings the record back at a receiver ([records.md](records.md), section 5.3).

Had the tablet deleted the record and the phone changed a field with the same stamp, the record would be deleted: the removal's key, the tablet's, is the higher one.

**Taking the deletion back.** After the merge of case 1, the phone's user takes the deletion back. The phone has given or seen the stamps up to 153. It takes the stamp 170 for a removal that was taken back and the state stamp 171, and stamps no field (section 3.5). The tablet, which has given or seen the stamps up to 155, merges that state: it takes the removal, since 170 is above 150, has then seen the stamps up to 171, and takes the state stamp 175.

| Part       | Before, on both devices | After, on both devices |
| ---------- | ----------------------- | ---------------------- |
| `title`    | "Vet", 100, phone       | "Vet", 100, phone      |
| `start`    | 10:00, 100, phone       | 10:00, 100, phone      |
| `location` | "Praxis", 145, tablet   | "Praxis", 145, tablet  |
| Removal    | 150, phone, stands      | 170, phone, taken back |
| The record | deleted                 | there                  |

The record is there on both devices, with the tablet's `location`: taking back changed no field. The phone sends a `DATA` under the version 171 and the tablet one under 175. A removal that stands with a stamp above 170, from either device, would delete the record again.

### 6.6 An installation that counted

cat-a-log ran on the phone alone and counted its versions. The appointment is at version 3, the highest version the phone has counted for any record, so its `highest` is 3; it has deleted no record, so it takes no stamp when it begins to stamp. The phone then adds the tablet (section 2.4), and at 09:00:00.000 UTC, the `now_ms` of section 6.1, its user sets `location`:

| Moment                         | `title`         | `start`         | `location`             | Version toward other apps |
| ------------------------------ | --------------- | --------------- | ---------------------- | ------------------------- |
| When the phone begins to stamp | "Vet", 0, phone | 10:30, 0, phone | "", 0, phone           | 3                         |
| After the change               | "Vet", 0, phone | 10:30, 0, phone | "Dr. Weber", S1, phone | S2                        |

The two stamps of the change, by section 2.2:

| Stamp               | `now_ms`          | `highest`               | `r`    | `base`                  | Stamp                   |
| ------------------- | ----------------- | ----------------------- | ------ | ----------------------- | ----------------------- |
| S1, the field stamp | 1,763,456,400,000 | 3                       | 12,345 | 115,569,878,630,400,000 | 115,569,878,630,412,345 |
| S2, the state stamp | 1,763,456,400,000 | 115,569,878,630,412,345 | 7      | 115,569,878,630,412,346 | 115,569,878,630,412,353 |

The version rises from 3 to 115,569,878,630,412,353, and a receiver applies it as any higher version. The tablet, which took the state of the first line from the phone, holds the same field states with the stamp 0 and the phone's key; any stamped change of a field, on either device, is later than them.

## References

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032): Ed25519
