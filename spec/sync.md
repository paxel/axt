# Sync between the devices of one owner

Status: sections 1 to 16 written, 0.1.0. Still to come, as further sections of this document: what the devices of a set do with the records they received from other apps ([axt-1025](https://github.com/paxel/axt/issues/27)). Until 0.1.0 is released, that part may still change the details this document leaves to it, and the schemas of `axt.Change` and `axt.Resync` may still change in place; their fingerprints (section 15) and the examples (section 16) are then produced again.

This document defines how the devices of one owner, which [keys.md](keys.md), section 5, makes one device set, change the same records: the stamp every change carries, the state a device keeps of a record, how two states of one record merge per field, when a record counts as deleted, and which version a device gives a record toward other apps. Sections 1 to 6 say what a device keeps and how it merges, whatever brings a state from one device to another. Sections 7 to 16 define the messages that bring it: `CHANGE`, which carries field states and the removal of one record from a device to a sibling, and `RESYNC`, with which a device asks a sibling for every record again; what a device sends to which sibling, how it is acknowledged and sent again, and what a restored, a removed and a new device do.

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
- **State stamp**: the stamp a device takes for a record on the occasions of section 3.3: whenever the state of the record changes on it, when it first takes the record, when it sends the record again after `STALE`, before it sends a sibling a second, different `CHANGE` of the record under one state stamp, before it sends the record in answer to a `RESYNC`, and before it first sends the record after a restore or a loss of its bookkeeping. It is the version of the record toward other apps (section 5).
- **Part** of a state: one of its field states, or its removal. Parts are what a `CHANGE` message carries and what a sibling acknowledges (section 10.1).
- **Field state of unknown age**: a field state with the stamp −1, which a device built from a file of its own set or holds, after it restored a backup, for a field never stamped. It loses to every field state with a stamp of 0 or more (section 4.6).
- **Later**: of two field states, of two removals, or of a removal and a field state, the one with the higher stamp, and with equal stamps the one with the higher device key (sections 4.1 to 4.3).

Where this document says "a device", it means a device that stamps (section 2.4), unless it says otherwise.

## 2. Stamps

### 2.1 The stamp

A stamp is a `long` of at least 1. It orders changes: of two changes, the one with the higher stamp is the later one. A stamp comes from a hybrid logical clock. While the wall clock of a device leads, a stamp shows the time of the change: it is the time in milliseconds times 65,536, plus a random part. When the wall clock lags, because a sibling's clock ran ahead or the clock was set back, the device goes on counting from the highest stamp it knows, so its stamps keep rising.

The values 0 and −1 are not stamps. In a field state, 0 stands for "never stamped" (section 3.4) and −1 for "of unknown age" (section 4.6); 0 also stands for `highest` (section 2.2) while a device knows no stamp. Neither is ever counted as a stamp seen.

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
- every receiver's version that an `ACK` reported to it with the outcome `STALE` for a record of its set, whether that version is above the versions the device knows of the record or not (section 5.3);
- every `receiver_version` that the `ACK` of a sibling reported to it for a `CHANGE`, with whatever outcome: the sibling's state stamp of the record (section 9.2).

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

A device that restored its data from a backup and has a sibling SHOULD merge with a sibling before its first change (section 4); it asks its siblings for every record with `RESYNC` (sections 11.3 and 12.1). Its `highest` is that of the backup, and while its clock stands behind that value it can draw a stamp again that it gave before the backup was restored, for another change (section 4.1, rule 3).

When an installation begins to stamp:

- Its records keep the versions it counted until their state changes. For such a record, the counted version stands in the place of the state stamp (section 3.3).
- The fields of such a record were never stamped (section 3.4).
- For each record it deleted while it counted, it takes one stamp, each as the next stamp of section 2.2, and puts a removal that stands, with that stamp and its own key, into the state of the record (section 3.2). The version it counted for the deletion stays in the place of the state stamp, as for its other records. An installation that must begin to stamp but can take no stamp for this (section 2.3) does not begin: it changes, creates, deletes and takes back no record, and sends no record message of the records it would have had to stamp, the deleted ones without a removal, as section 2.3 says for a device at the limit.
- Every version it counted is in its `highest` (section 2.2), so its first stamp is above all of them. A stamp taken from a clock is far above any count: for a clock in the year 2025, it is above 10^17.

## 3. The state of a record

For every record of its set, a device keeps the record's id, the full name of its type ([records.md](records.md), section 4.3), and its state: a field state for each field, at most one removal, and the state stamp. Beside the state, it keeps for the record the highest state stamp of the record that it has seen from a sibling, in a merge (section 4.4) or in the sibling's `ACK` for a `CHANGE` (section 9.2), and, while there is one, the version to pass (section 5.3).

### 3.1 Field states

The fields are the top-level fields of the record's writer schema, as in [records.md](records.md), section 6.1: a nested record, an array or a map is one value, with one stamp.

A field state is:

| Part     | Type and range         | Content                                                                                                                                                             |
| -------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`   | string                 | The name of the field, as the writer schema of the changing device has it                                                                                           |
| `value`  | bytes                  | The value the last change gave the field: the bytes the changing device wrote, in Avro binary encoding under the type the field has in that device's writer schema  |
| `schema` | 8 bytes                | The fingerprint ([envelope.md](envelope.md), section 5) of that writer schema, which also tells its version, the `axt.version` of [types.md](types.md), section 3.2 |
| `stamp`  | `long`, −1 to 2^63 − 1 | The stamp of that change; 0 for a field never stamped (section 3.4), −1 for a field state of unknown age (section 4.6)                                              |
| `device` | 32 bytes               | The device key of the device that made that change                                                                                                                  |

- A state holds at most one field state for a name. Two names are the same when they are the same sequence of Unicode code points; the aliases of a schema are not looked at.
- The bytes of `value` are kept and passed on unchanged, together with `schema`, by every device that holds the field state. No device encodes the value of another device's change again: Avro binary encoding of one value is not unique, since a map has no fixed order and arrays and maps can be split into blocks, and the comparison of section 4.1, rule 3, is on these bytes.
- For its own use, a device decodes the bytes with the schema that `schema` names, resolved against its own reader schema, as it decodes a record ([envelope.md](envelope.md), section 3). It keeps the text of that schema as long as it keeps a field state written with it.
- A device holds a field state for every field of its own writer schema of the type. A field of its schema for which it took no field state, such as one that its version of the type adds, has the default of the schema as its value and was never stamped (section 3.4).
- A device also holds every field state it took from a sibling for a field that its own schema does not have, and passes it on. It keeps the value as the bytes and the schema it came with; a field state travels in a `CHANGE` message (section 8), and section 8.5 says what a device does with a field it does not know.
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
4. when it sends the current state of the record again after `STALE` with a higher version (section 5.3). The state does not change then; the device takes a new state stamp for the same state;
5. before it sends a sibling a `CHANGE` of the record, if it has already sent that sibling a different `CHANGE` of the record under its current state stamp (section 10.2). The state does not change then either;
6. before it sends a sibling the first `CHANGE` of the record after it acted on a `RESYNC` of that sibling (section 11.2). The state does not change;
7. before it sends the first `CHANGE` of the record, to whichever sibling, after it restored a backup (section 12.1) or lost the bookkeeping of section 10.1. It does so also when a change or a merge has given the record a new state stamp since the restore or the loss. The state does not change.

The device takes the state stamp after the stamps of the change, and after it has seen the stamps of the other state. It is therefore above the stamp of every field state and of the removal in the device's state, and above every state stamp the device gave or saw for the record before. The one exception is a record that the installation deleted while it counted and whose state has not changed since: its counted version stands in the place of the state stamp (section 2.4), below the stamp of the removal it got when the installation began to stamp.

The state stamp belongs to the device. Two siblings that hold the same field states and the same removal of a record can hold different state stamps for it, since each took its own when it reached that state. A device never takes over the state stamp of a sibling as its own; it only counts it as seen (section 2.2).

For a record whose state has not changed since the installation began to stamp, the version it counted stands in the place of the state stamp (section 2.4).

### 3.4 Fields never stamped

A field that was last changed while the installation counted, or that has only the default of the device's schema (section 3.1), was never stamped. Its field state has the stamp 0 and, as `device`, the key of the device on which it stood unstamped: the installation that counted, or the device that put in the default. A sibling that takes such a field state keeps it with that stamp and that key. The device that holds such a field first encodes its value, under its own writer schema of that moment, when it first has to pass the field state on or to compare it by section 4.1, rule 3; from then on the field state holds those bytes and that schema, as section 3.1 says.

Every stamp is at least 1, so every stamped change of a field is later than a field state never stamped, and every removal is later than it. A field state never stamped is in turn later than a field state of unknown age, which has the stamp −1 (section 4.6).

Two field states never stamped of one field, with the same device key, are decided by their values (section 4.1, rule 3). A device that holds such a field state from a source that can be older than what its siblings hold, a file or a backup, therefore gives it the stamp −1 (section 4.6).

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

Rule 3 makes both sides compute the same also where one device gave one stamp to two values, or wrote the same bytes under one stamp with two writer schemas, which a device that restored a backup can do while its clock stands behind its `highest` (section 2.4). It also decides between two field states never stamped, with the stamp 0, and between two field states of unknown age, with the stamp −1 (section 4.6), that carry one device key and different values. In no other case does a device look at the values or at `schema` to decide.

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
- **A deleted record keeps its state.** A device SHOULD keep the field states of a deleted record, so that the record is whole when it comes back. It MAY discard them, values included, and keep only the removal and the state stamp, but MUST NOT discard a field state that is still due for a sibling (section 10.1); it MUST keep those as long as it is a device of the set, as a receiver keeps a tombstone ([records.md](records.md), section 5.3). A device that discarded them takes them again whenever it merges a state that holds them, with a new state stamp each time (section 4.4), and MAY discard them again while the record is deleted.
- **An incomplete record.** A device that discarded the field states of a deleted record, or never held them, and whose merge makes the record there, holds only the field states that the merge brought. Unless the other state held every field of the record, the device holds the record incompletely. It MUST NOT send an incomplete record to another app (section 5.1) and SHOULD NOT show it to its user as a record, until a merge with a sibling's whole state has completed it. A device that lacks a record, or holds only its removal, takes field states only from a whole state: it answers a `CHANGE` that is not whole with `RECORD_UNKNOWN`, and the sibling sends the record whole (section 8.3, step 10), so that no `CHANGE` leaves a record incomplete. A device that holds a record incompletely all the same asks its siblings with `RESYNC` (section 11.3).

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

### 4.6 Field states of unknown age

A field state can come from a source that is older than what the siblings hold: a file, or a backup. Had it the stamp 0 of a field never stamped, it would tie with a sibling's field state never stamped of the same device key, the bytes of the values would decide (section 4.1, rule 3), and an old value could win on every device. Such a field state therefore has the stamp −1: it is a **field state of unknown age**. A device gives the stamp −1 to:

- every field state that it builds from a `DATA` of a file of its own set (section 13.4), with the file's sender as `device`;
- every field state never stamped, with the stamp 0, that it holds when it restores a backup while its set has another current device (section 12.1): the stamp becomes −1 on that device, and the other parts of the field state stay. An installation that is the only current device of its set when it restores changes nothing: no sibling holds another value;
- every field state never stamped that it held when it restored a backup and still holds unchanged, at the moment it learns, from a chain ([keys.md](keys.md), sections 5.4 and 5.5), of a current device of its set that the backup did not hold (section 12.1). A backup made before a sibling joined knows no sibling, so the device restores it as the only device of its set; this rule gives those field states the stamp −1 when it meets the sibling again.

A field state of unknown age is a field state like any other, with the lowest stamp there is:

- **It merges by section 4.1.** It loses to every field state with a stamp of 0 or more. Of two field states with the stamp −1, the one with the higher device key is the later one, then the one with the higher value, then the one with the higher `schema` (section 4.1, rules 2 and 3). Every device so ends with the same field state, but the value that stands may be the older one: of two field states of unknown age, neither is known to be the newer.
- **It travels like any other.** It is a part of the state, is due for a sibling until it is delivered, and is sent in a `CHANGE` with its stamp −1 (sections 8.1 and 10). A device that takes it keeps it with that stamp and that device key.
- **Nothing ends it but a later field state** of that name: one that a merge brings, or a change of the device's user, which stamps the field (section 3.5).
- **It is no stamp seen.** A device never counts −1 as a stamp it has given or seen (section 2.2).
- **Only a field state has it.** The stamp of a removal and a state stamp are at least 1 (sections 3.2 and 3.3).
- Section 5.1 says when a field state of unknown age holds back a `DATA` to another app.

## 5. The version toward other apps

### 5.1 The state stamp is the version

Toward other apps, a device sends a record of its set as [records.md](records.md) and [protocol.md](protocol.md) say, whole and under one version:

- The version, `record.version` of the message ([envelope.md](envelope.md), section 2), is the device's state stamp of the record at the time it writes the message.
- The message is a `DATA` when the record is there (section 4.3), and a `DELETE` when it is deleted.
- A `DATA` carries the values of the field states the device holds, for the fields of the writer schema it offered. It carries no stamp and no device key: other apps get whole records, as before.
- A device MUST NOT send a `DATA` of a record for which it holds a stamped field state, one with a stamp of at least 1, whose field the writer schema it would write with lacks, if that field state was written with a later version of the type than the one the device writes with: the record it would send drops a value that a sibling on a later version set, and a receiver would lose it. It leaves sending that record to a sibling whose schema has the field, or sends it once it writes with such a schema itself. The device tells this by the version of the schema that the field state names in `schema` (section 3.1), compared with the `axt.version` of its own writer schema. A field that its own version of the type, or an earlier one, removed ([types.md](types.md), section 3.3) does not hold a record back: its field state was written with the device's own version or an earlier one. Nor does a field state never stamped (section 3.4).
- A device MUST NOT send a record it holds incompletely (section 4.3), and MUST NOT send a record for whose state it could take no state stamp (section 2.3).
- A device MUST NOT send a `DATA` of a record of which it holds a field state of unknown age, with the stamp −1 (section 4.6), while it has a `RESYNC` open toward a sibling (section 11.3) and has taken the acknowledgement of none of its open requests, for at most 14 days from the moment it opened the first of those requests, which is when it first sends that `RESYNC` or, toward a sibling it cannot reach yet, when it decides to ask. After the first acknowledgement of one of its open requests, or after those 14 days, it sends as this section says, also while other requests are still open: the hold ends when the wait of section 12.1 ends. If all its requests have closed and it opens one later, the hold and its 14 days begin anew with that request. An old value from a backup or a file so does not go to other apps under a new version while a sibling's answer is still expected. The acknowledgement says that the answer was sent: a `CHANGE` of it can still come later, and gives the record a new state stamp when the device takes something from it. A device that has no `RESYNC` open, such as one that only took records from a file and asked no sibling, is not held back.

Nothing changes for a receiver. A state stamp is a `long` of at least 1 that rises with every state of the record on the device, so the version rule of [records.md](records.md), section 5.2, applies as it stands, and a receiver need not know whether a version was counted or is a state stamp.

Two siblings in the same state can send it under two versions, each under its own state stamp (section 3.3). A receiver applies the higher one and reports the lower one, if it arrives later, as `STALE`. Both carry the same value for every stamped field, by the rule above; they can differ only in a field that one device's version of the type has and the other's lacks: one that was never stamped, which then holds a default, or one that the later version removed. Apart from that the receiver ends in the same state either way.

### 5.2 Why the version is not the highest field stamp

The highest stamp among the field states and the removal would rise as well, but it would name two different records with one version. Two devices change different fields of a record while apart, the one `start` with the stamp 110, the other `location` with the stamp 120, and each sends its state: the second under the version 120, with the old `start`. When the two have merged, the merged record holds both changes, and its highest field stamp is still 120, a version that already stands for another record. A receiver that has the version 120 would take the merged record for a duplicate and never show the new `start`. One id and version MUST stand for the same message ([records.md](records.md), section 3), so every state that a device reaches, by a change or by a merge that took something, gets a stamp of its own. Section 6.3 shows the case in full.

### 5.3 `STALE` with a higher version

A receiver reports `STALE` with its own version of the record when a message carries a lower one ([records.md](records.md), section 7). This section is about the `STALE` that another app reports for a record message; `STALE` in the `ACK` of a sibling for a `CHANGE` is another matter (section 9.2). A device counts every receiver's version reported in this way as a stamp it has seen (section 2.2), so that every stamp it takes from then on is above it.

What else it does, one comparison decides: whether the receiver's version is above the **highest version the device knows of the record**. That is the higher of its own state stamp of the record and the highest state stamp of the record it saw from a sibling, in a merge (section 4.4) or in the sibling's `ACK` for a `CHANGE` (section 9.2). A device need not remember the versions it gave before.

| The receiver's version is                                    | The device                                                                                        |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| not above the highest version the device knows of the record | does nothing more: an older message arrived late, or a sibling sent a state the device has merged |
| above it                                                     | acts as below                                                                                     |

A higher version is no fault as such: a sibling may have sent the receiver a state under a higher state stamp. The device may also have lost versions it gave ([protocol.md](protocol.md), section 10), or the version is one of a device that was removed since. The device then:

- stamps from then on, if it counted until now (section 2.4);
- keeps the receiver's version for the record as the **version to pass**, whether it is the only current device of its set or not. If a later `STALE` reports a higher one, it keeps that. It drops the version to pass as soon as its state stamp of the record is above it: after the resend below, or after a change or a merge that gave it a higher state stamp;
- if it is the only current device of its set, MUST take a new state stamp for the record at once (section 3.3) and send the record's current state under it, unless one of the two cases below holds. No sibling can bring it a newer state;
- if its set has other current devices, waits for them: a merge with a sibling that holds a newer state gives the device a state stamp above the receiver's version. Once it has, after the `STALE`, merged the state of the record with every other current device of its set, it looks at its state stamp of the record. If that is still below the version to pass, the device MUST take a new state stamp for the record and send the record's current state under it, unless one of the two cases below holds. Otherwise it sends its state as section 5.1 says. Section 10.4 says when it has merged with a sibling;
- waits for a sibling at most 14 days from the `STALE`, the time a relay holds a message ([transports.md](transports.md), section 5.5). After that, and for a sibling that is removed from the set, it goes on as if it had merged with that sibling.

Both sending rules hold unless the device can take no stamp (section 2.3), or section 5.1 forbids it to send the record: it holds the record incompletely, it holds a field state of a later version of the type that its writer schema lacks, it could take no state stamp for the record's state, or it holds a field state of unknown age of the record and the hold of section 5.1 has not ended. In those cases it sends nothing, and keeps the version to pass.

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

## 7. Siblings in an exchange

Sections 7 to 14 define how the states of sections 3 and 4 travel between the devices of a set. Two messages do it: `CHANGE`, which carries field states, the removal, or both, of one record (section 8), and `RESYNC`, with which a device asks a sibling for every record again (section 11). They travel between two siblings, in a live connection or through a relay, by the steps of [protocol.md](protocol.md) wherever this document does not say otherwise.

### 7.1 Who is a sibling

A device knows its own set as a receiver knows a sender: it applies the additions and removals of its set by [keys.md](keys.md), section 5.5, and so keeps the current keys and the removed keys of its set ([keys.md](keys.md), section 5.1). For a device, a **sibling** is a current key of its own set other than its own key.

- A message whose signature verifies and whose `sender` is a sibling is a message of a sibling. It is no first contact ([keys.md](keys.md), section 3.2): the device MUST NOT ask its user about the key, which the owner confirmed when the device was added ([keys.md](keys.md), section 5.2).
- A device keeps for each sibling what [keys.md](keys.md), section 3.3, keeps for each current key of a known sender: its encryption key, its relay and mailbox, and its kept manifest ([manifest.md](manifest.md), section 6).
- A key is a sibling until the device applies its removal (section 12.2).

What a device does with a `CHANGE` or a `RESYNC` whose signature verifies depends on its `sender`:

| The `sender` is                                         | The device                                                                                                                                                                                                                                                                           |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| a sibling                                               | processes the message (sections 8.3 and 11.2)                                                                                                                                                                                                                                        |
| the device's own key                                    | ignores it without a report                                                                                                                                                                                                                                                          |
| a removed key of the device's own set                   | rejects it without a report ([keys.md](keys.md), section 3.3)                                                                                                                                                                                                                        |
| a current key of another known sender                   | rejects it with the error `INVALID_MESSAGE` ([protocol.md](protocol.md), section 8.2): only the devices of the device's own set send it these kinds                                                                                                                                  |
| a removed key of another known sender, or a refused key | rejects it without a report ([keys.md](keys.md), sections 3.3 and 3.4)                                                                                                                                                                                                               |
| a key the device does not know                          | treats it as a message of an unknown key ([keys.md](keys.md), section 3.2) and MAY keep it. If an addition then makes the key a sibling ([keys.md](keys.md), section 5.5), it processes the message; if its user accepts the key as another app's, the row of a known sender applies |

In a live connection, a `CHANGE` or a `RESYNC` that arrives before the other device's valid `MANIFEST` is not processed ([protocol.md](protocol.md), section 3.1), and one whose `sender` is not the connection key closes the connection ([transports.md](transports.md), section 4.5).

### 7.2 Manifest, offer and accept

Two siblings exchange as two apps do: each sends its chain and its `MANIFEST`, a device offers schemas in an `OFFER`, the sibling answers with `ACCEPT`, the device sends `CHANGE` messages in the place of record messages, and the sibling acknowledges them in an `ACK`. Sibling sync carries every type, so these rules differ from [protocol.md](protocol.md), sections 4 to 6:

- **The manifest.** A device sends its `MANIFEST` to a sibling as to any app ([protocol.md](protocol.md), sections 3.1 and 15.1). Of a sibling's manifest a device uses `formats`, `encryption_key` and `relay`. Its `takes`, `any_type` and `sends` do not apply between siblings: no type is held back because it does not fit them, and the rules of [manifest.md](manifest.md), sections 5.2 to 5.4, and of [protocol.md](protocol.md), section 4.2, on offering only what fits do not apply.
- **What is offered.** A device offers to a sibling, in an `OFFER` of [protocol.md](protocol.md), section 4, the writer schema of every field state that a `CHANGE` it is about to send names in `schema` (section 8.1): its own writer schemas, and the schemas it kept with field states it took from other siblings (section 7.3). It offers schemas of every type: example types, types of an app's own namespace, and types that the sibling does not know. Each schema is one entry of `types`. An offer holds no full name twice ([protocol.md](protocol.md), section 4.2), so two schemas of one type, two versions of it, travel in two offers. `count` is the number of `CHANGE` messages the device is about to send that name the schema, or `0`.
- **Every type is accepted.** A device MUST answer every type of a valid offer from a sibling in an `ACCEPT`, without asking its user, and SHOULD do so within 5 seconds. It MUST NOT decline a type that a sibling offers, with no reason: not with `NOT_WANTED`; not with `DOES_NOT_FIT`, whatever its manifest says; and not with `DOES_NOT_RESOLVE`, also when it has no schema of the type, when the offered schema does not resolve against its own, and when the schema defines a time type other than as published or another named type in the namespace `axt`. The three rules of [protocol.md](protocol.md), section 5.2, that make a receiver decline do not apply to an offer of a sibling; section 8.5 says what a device does with values it cannot read. The validity rules of [protocol.md](protocol.md), section 4.2, hold for an offer between siblings as they stand, all of them: the `offer_id` is a UUID in text form, neither nil nor max; `types` has 1 to 256 entries; each `schema` is within the schema limits and is an Avro schema of a record; no full name and no fingerprint appears twice in one offer; each `count` is at least 0. An offer that is not valid is rejected as that section says, with `OFFER_INVALID` or `TOO_LARGE`. Only its rule on offering what fits the manifest does not apply.
- **A decline all the same.** A device that gets a `DECLINE` from a sibling takes it as [protocol.md](protocol.md), section 5.3, says: it sends no `CHANGE` that names the declined schema under that offer. It MAY offer the schema again in a later live connection, and through the relay once the holding time has passed.
- **An offer is replaced by fingerprint.** Between siblings, a later offer ends an earlier offer of the same device in the same channel only for a schema with the same fingerprint, not for another schema of the same full name: a record can hold field states written with several versions of its type, and a `CHANGE` can name several of them. Where [protocol.md](protocol.md), sections 4.3 and 5.3, speak of the current offer of a type and of the latest offer of a type, the devices of one set read "of a schema, by its fingerprint": a device keeps, for each sibling and channel, the current offer of each fingerprint, and takes the answer to its latest offer of each fingerprint. An offer between siblings never ends because a type does not fit a manifest. It ends, as in [protocol.md](protocol.md), section 4.3, with the live connection it was made in and when the key that signed it or the key in its `to` is removed.
- **Through a relay**, an accepted offer covers every `CHANGE` that names its schema until the offer ends, also one for a change made after the offer. A device makes no new offer for each change; the rule of [protocol.md](protocol.md), section 4.3, that a record that changes after the offer is offered again does not apply between siblings.
- **No record messages.** A device MUST NOT send a `DATA` or a `DELETE` to a sibling. An accepted offer between siblings allows `CHANGE` messages only; it is not an accepted offer of a type for a record message. A device that gets a `DATA` or a `DELETE` from a sibling therefore rejects it with `NOT_ACCEPTED`, at step 5 of [protocol.md](protocol.md), section 6.2, if the steps before it pass. The order is that of that section: a `DATA` whose body fingerprint is not that of the schema of a current offer of that sibling in the channel fails step 4 with `SCHEMA_UNKNOWN`; a `DATA` whose schema was offered, and every `DELETE`, fails step 5.

A device MUST NOT send a `CHANGE` to a sibling unless, for every fingerprint that an entry of its `fields` names in `schema`, it has made an offer in the channel that carries a schema with that fingerprint, the sibling has accepted that schema's type for that offer, and the offer has not ended. A `CHANGE` whose `fields` is empty needs no offer.

### 7.3 The schemas a device keeps

A device **holds** a schema when it has its full JSON text. It holds:

- its own writer schemas of the types of the records of its set;
- every schema that an offer of a sibling carried, for as long as that offer has not ended ([envelope.md](envelope.md), section 3);
- every schema with which a field state that it holds was written (section 3.1), also after the offer that brought the schema has ended. A device MUST keep the text of such a schema for as long as it holds the field state.

A device looks a schema up by its fingerprint among all schemas it holds, whichever sibling offered it and in whichever channel: the devices of a set are one sender ([keys.md](keys.md), section 2.4). Two texts with one fingerprint count as the same schema: a device that holds a text for a fingerprint keeps it when an offer brings another text with that fingerprint.

Before a device sends a field state that it took from one sibling on to another, it offers that sibling the schema the field state names, from the text it kept (section 7.2). So a schema reaches every device that a value written with it reaches.

## 8. The `CHANGE` message

### 8.1 Content

A `CHANGE` message carries field states, the removal, or both, of one record of the set from a device to one sibling:

- Its `sender` is the key of the device that sends it, and it is signed with that key like every message ([keys.md](keys.md), section 2.2), whichever devices made the changes it carries.
- Its `record` MUST be present; a `CHANGE` without `record` is no valid message of its kind and is rejected with `INVALID_MESSAGE`, as part of the validity of its envelope ([protocol.md](protocol.md), section 2). `record.id` is the id of the record. `record.version` is the highest stamp in the message: the highest of `state`, of `removal.stamp` if `removal` is not `null`, and of the `stamp` of every entry of `fields`.
- Its body MUST be one `axt.Change` in single-object encoding, with the schema [types/axt/Change.avsc](../types/axt/Change.avsc) and, in envelope format 1, the fingerprint of section 15.

| Field             | Avro type                                         | Content                                                                                                                 |
| ----------------- | ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `to`              | `fixed` of 32 bytes, `axt.ChangeTo`               | The device key of the sibling the message is for ([protocol.md](protocol.md), section 9.1)                              |
| `origin`          | `null` or `fixed` of 32 bytes, `axt.ChangeOrigin` | `null` for a record of the set. A key here is for the records a set received from another app                           |
| `type`            | `string`                                          | The full name of the record's type ([records.md](records.md), section 4.3)                                              |
| `state`           | `long`                                            | The sending device's state stamp of the record (section 3.3)                                                            |
| `whole`           | `boolean`                                         | Whether `fields` holds every field state the sending device holds of the record                                         |
| `removal`         | `null` or record `axt.ChangeRemoval`              | The removal of the record (section 3.2), or `null`                                                                      |
| `removal.stamp`   | `long`                                            | The removal's `stamp`                                                                                                   |
| `removal.device`  | `fixed` of 32 bytes, `axt.ChangeRemovalDevice`    | The removal's `device`                                                                                                  |
| `removal.stands`  | `boolean`                                         | The removal's `stands`                                                                                                  |
| `fields`          | array of record `axt.ChangeField`                 | The field states the message carries (section 3.1), in any order                                                        |
| `fields[].name`   | `string`                                          | The field state's `name`                                                                                                |
| `fields[].schema` | `fixed` of 8 bytes, `axt.ChangeFieldSchema`       | The field state's `schema`: the fingerprint of the writer schema the value was written with                             |
| `fields[].value`  | `null` or `bytes`                                 | The field state's `value`, the bytes as the device holds them. `null` is for a message whose `origin` is a key          |
| `fields[].stamp`  | `long`                                            | The field state's `stamp`: 0 for a field never stamped (section 3.4), −1 for a field state of unknown age (section 4.6) |
| `fields[].device` | `fixed` of 32 bytes, `axt.ChangeFieldDevice`      | The field state's `device`                                                                                              |

- **`origin` and a `null` value.** This document defines the `CHANGE` of a record of the set only. A device MUST set `origin` to `null` and MUST NOT write `null` in a `value`, until this document defines messages with a key in `origin`. Section 8.2 says what a device does with a message that has either.
- **`state`** is the state stamp the device holds of the record when it writes the message, or the version it counted that stands in its place (sections 2.4 and 3.3). A device that holds no state stamp of a record, because it could take none (section 2.3), sends no `CHANGE` of that record. A device whose state stamp names an earlier state, because it could take none for a later merge or change (section 2.3), sends the state stamp it holds.
- **`whole`** is `true` exactly when `fields` holds every field state that the device holds of the record and the device does not hold the record incompletely (section 4.3). It is so `true` for every message of a record of which the device holds no field state, such as a deleted record whose field states it discarded, unless it holds that record incompletely. Whether the message carries the removal does not count.
- **`removal`** is the removal the device holds, with its three parts as it holds them. `null` says that the device holds none or that the message does not carry it; it never takes a removal away (section 3.2).
- **`fields`.** Each entry is one field state as the device holds it, taken whole (section 4.1): the bytes of `value` and their `schema` unchanged, as section 3.1 requires, with the stamp and the device key of the change. For a field never stamped, the entry has the stamp 0 and the bytes of section 3.4; for a field state of unknown age, the stamp −1 (section 4.6). The order of the entries has no meaning.
- **The version.** A state stamp is above every stamp of the state it names (section 3.3), so `record.version` is `state` in all but two cases: for a record that was deleted while its installation counted and has not changed since, it is the stamp of the removal when the message carries it (section 3.3); and for a device at the limit of section 2.3, it can be the stamp of a field state or of the removal.

### 8.2 Validity and limits

The body of a `CHANGE` is valid when:

- `origin` is `null`;
- `type` is an Avro full name, names of the form `[A-Za-z_][A-Za-z0-9_]*` joined by dots, of at most 512 bytes;
- `state` is at least 1;
- `removal` is `null`, or its `stamp` is at least 1;
- `fields` has 0 to 4,096 entries;
- each `name` is 1 to 512 bytes of UTF-8, and no name appears twice; names are compared as sequences of Unicode code points (section 3.1);
- each `value` is not `null`;
- each `fields[].stamp` is at least −1;
- `whole` is `true`, or the message carries something: `fields` is not empty or `removal` is not `null`;
- `record.version` is the highest of `state`, of `removal.stamp` if `removal` is not `null`, and of every `fields[].stamp`.

A device MUST reject a `CHANGE` whose body is not valid with the error `INVALID_MESSAGE` ([protocol.md](protocol.md), section 8.2). That holds for a message with a key in `origin` and for one with a `null` value as well, until this document defines them.

- **No stamp is refused.** Every stamp up to the largest `long`, 2^63 − 1, is valid in `state`, in a removal and in a field state (section 2.3). The lowest value of a field state's `stamp` is −1; a device counts neither −1 nor 0 as a stamp seen.
- **Device keys are not checked.** `removal.device` and `fields[].device` are 32 bytes that the merge compares (section 4.1) and nothing else. A device MUST NOT reject a `CHANGE` because such a key is not a key of its set, is a removed key, or is no valid Ed25519 public key: a field state that a removed device wrote stays in the state of its record, and a `CHANGE` can carry the field state of a device whose addition the receiving device has not applied yet.
- **Size.** A `CHANGE` is a message of at most 16 MiB ([envelope.md](envelope.md), section 8); section 10.2 says what a device does with a record that does not fit.

### 8.3 Processing

A device processes a `CHANGE` in these steps. A step that fails ends the processing: the message has no outcome, the device changes nothing, and it reports the failure with the error code named, as [protocol.md](protocol.md), section 8.3, says. "Changes nothing" includes its clock and its bookkeeping: it counts no stamp of the message as seen (section 2.2) and marks nothing as delivered (section 10.1).

| Step | Check                                                                                                                                                                                                                                                                     | If it fails                                                                                                                                        |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | The message and its envelope are valid, and its signature verifies, as for every message ([protocol.md](protocol.md), section 8.2). A `CHANGE` without `record` is not valid                                                                                              | as [protocol.md](protocol.md), section 8.2, says; `INVALID_MESSAGE` without `record`                                                               |
| 2    | The `sender` is a sibling (section 7.1)                                                                                                                                                                                                                                   | as the table of section 7.1 says; the body is not read                                                                                             |
| 3    | The body is one `axt.Change` in single-object encoding, with no bytes left over, and its `to` is the device's own key                                                                                                                                                     | `INVALID_MESSAGE` for a body that is not; a message with another key in `to` is ignored without a report ([protocol.md](protocol.md), section 9.1) |
| 4    | `record.id` is a UUID in text form, neither the nil UUID nor the max UUID ([records.md](records.md), section 2)                                                                                                                                                           | `RECORD_ID_INVALID`                                                                                                                                |
| 5    | `record.version` is at least 1                                                                                                                                                                                                                                            | `VERSION_INVALID`                                                                                                                                  |
| 6    | The body is valid (section 8.2)                                                                                                                                                                                                                                           | `INVALID_MESSAGE`                                                                                                                                  |
| 7    | For every entry of `fields`, the device holds a schema whose fingerprint is the entry's `schema` (section 7.3)                                                                                                                                                            | `SCHEMA_UNKNOWN`                                                                                                                                   |
| 8    | For every entry of `fields`, that schema is the schema of a record whose full name is `type`, and it has a top-level field whose name is the entry's `name`                                                                                                               | `INVALID_MESSAGE`                                                                                                                                  |
| 9    | The device keeps no other full name than `type` for the id (section 3)                                                                                                                                                                                                    | `TYPE_CHANGED`                                                                                                                                     |
| 10   | `whole` is `true`; or the device holds a state of the record that holds at least one field state; or it holds a state of the record that holds no removal                                                                                                                 | `RECORD_UNKNOWN`                                                                                                                                   |
| 11   | For every entry of `fields`, `value` decodes, in Avro binary encoding, as one value of the type that the field `name` has in the entry's schema, with no bytes left over, with well-formed strings, and to a data depth of at most 32 ([types.md](types.md), section 5.7) | `UNDECODABLE`                                                                                                                                      |
| 12   | Every time value in the decoded values is valid ([time.md](time.md), section 8)                                                                                                                                                                                           | `VALUE_INVALID`                                                                                                                                    |
| 13   | The device merges the message and reaches an outcome (section 8.4)                                                                                                                                                                                                        | (no failure)                                                                                                                                       |

- **Steps 1 to 3.** A message without `record` is reported with `INVALID_MESSAGE` only to a sibling and to a current key of another known sender, as [protocol.md](protocol.md), section 8.3, allows; nothing goes to the device's own key, to a removed key or to a key the device does not know. A message whose `sender` is no sibling gets the result of its row of section 7.1 without its body being read. A body that does not decode as one `axt.Change` fails after that, at step 3, and is reported to the sibling with `INVALID_MESSAGE`; step 6 checks the content of a body that decodes.
- **Step 7.** The error's `fingerprint` is the `schema` of the first entry of `fields`, in the order of the message, for which the device holds no schema. `SCHEMA_UNKNOWN` is the rejection and the request for that schema, as for a `DATA` ([protocol.md](protocol.md), section 6.2).
- **Step 8.** The full name is compared with `type` as text, and the field name with `name` by code points; the aliases of a schema are not looked at.
- **Step 10** fails for a message that is not whole when the device holds no state of the record, and when the state it holds has a removal and no field state, as for a deleted record whose field states it discarded (section 4.3). A device takes a record that it lacks, or of which it holds only the removal, from a whole message alone.
- **Step 11.** The data depth counts the record as depth 1, as in [types.md](types.md), section 5.7: a value that is an array is at depth 2. The device decodes with the entry's schema alone. Whether that schema resolves against the device's own schema of the type is not checked (section 8.5).
- **Step 12.** The error's `field` is the path of the first value that fails, in the order of `fields` and within one value in the order of the encoding, by the field names of the entry's schema ([metadata.md](metadata.md), section 7.2); it begins with the entry's `name`. A device MUST NOT reject a `CHANGE` for a check of the attributes of [metadata.md](metadata.md), section 7.1: the device on which the change was made applied them, and a value that one sibling rejected would stay different on the devices of the set.
- **No version rule.** A `CHANGE` is not compared by its version with anything the device keeps: the version rule of [records.md](records.md), section 5.2, is for record messages. Every `CHANGE` that passes steps 1 to 12 is merged. Its id and version name the message for the `ACK` and for an `ERROR`.
- **No user.** A device MUST NOT ask its user before it merges a `CHANGE`.

### 8.4 The merge and its outcome

Processing a `CHANGE` is a merge by section 4. The **other state** is what the message stands for: its field states are the entries of `fields`; its removal is `removal`, and it holds none when `removal` is `null`; its state stamp is `state`.

- **A record the device lacks.** A device that holds no state of the record takes the other state as its own (section 4), and keeps `type` as the full name of the record's type. By step 10 the message is whole.
- **A message that is not whole.** The other state holds only some field states. The merge takes, for each name it holds, the later of the two field states, and leaves every field state of the device that the message does not name as it is (section 4.1). A `removal` of `null` leaves the device's removal as it is (section 4.2).
- **The clock and the state stamp.** The device does the steps of section 4.4: it counts the stamp of every entry of `fields`, the stamp of the removal and `state` as seen; it keeps the merged state; and it takes a new state stamp if it took at least one field state or the removal from the message, or held no state of the record before. If `state` is above the highest state stamp of the record that the device has seen from a sibling (section 3), it becomes that value.
- **A device that can take no stamp** merges all the same, as sections 2.3 and 4.4 say.
- **An incomplete record.** A device that holds a record incompletely (section 4.3) holds it completely once it has merged a whole `CHANGE` of it.
- **What is due again.** Every part of the device's state for which the message carried another, earlier one is due for that sibling again (section 10.1), whatever the outcome: `STALE`, or `APPLIED` when the device took other parts of the message.

The outcome follows from the merge alone:

| The merge                                                                                                                                                                                          | Outcome     |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| The device held no state of the record, or took at least one field state or the removal from the message: step 3 of section 4.4 asks for a new state stamp, whether the device can take one or not | `APPLIED`   |
| The device took nothing, and every field state and the removal of the message is the same as the one the device holds (section 4.1, rule 3, and section 4.2)                                       | `DUPLICATE` |
| The device took nothing, and at least one field state or the removal of the message is not the same as the one the device holds: the device holds a later one                                      | `STALE`     |

A whole message with no entry in `fields` and no removal, for a record of which the device holds a state, has the outcome `DUPLICATE`. A message that is processed a second time has the outcome `DUPLICATE`, or `STALE` if the state of the record has moved on in between (section 4.5).

### 8.5 Fields and types the device does not know

A device on an earlier version of a type, or without the type, keeps what it cannot read and passes it on:

- **A field its schema lacks.** A device that takes a field state whose `name` its own writer schema of the type does not have keeps it as it came: the bytes of its value, the fingerprint of its schema, its stamp and its device key (section 3.1). It keeps the text of that schema (section 7.3), sends the field state to its other siblings like every other part (section 10), and offers them the schema first. Section 5.1 says when such a field keeps the device from sending the record to another app.
- **A type it does not know.** A device that has no schema of its own for `type`, such as a type that a later version of its app added or a type of another namespace, keeps the whole record in the same way and passes it on. It need not show the record to its user.
- **A value it cannot read.** A device that holds a schema of its own for the type against which the entry's schema does not resolve ([envelope.md](envelope.md), section 6) keeps the field state and passes it on as well. What it shows for the field is up to the app.
- **Reading later.** When the device comes to have a schema with the field, such as after an update of its app, it reads the kept bytes with the kept schema, resolved against its own (section 3.1).

In none of these cases does the device encode the value again, change its bytes, or drop it.

## 9. Acknowledgement and errors

### 9.1 The `ACK` for a `CHANGE`

A device MUST acknowledge every `CHANGE` that it processed to an outcome (section 8.4), and only those, in an `ACK` message with the body `axt.Ack` of [protocol.md](protocol.md), section 7.1. It SHOULD send the `ACK` within 5 seconds of processing the message and MAY collect the outcomes of that time into one `ACK` ([protocol.md](protocol.md), section 7.2), of up to 4,096 entries ([protocol.md](protocol.md), section 7.1). An `ACK` holds no id and version twice, so a device that processed one `CHANGE` twice before it sent an `ACK`, such as a repeat from the relay, acknowledges the two in two `ACK` messages.

| Field                        | Content for a `CHANGE`                                                                                  |
| ---------------------------- | ------------------------------------------------------------------------------------------------------- |
| `to`                         | The key that signed the acknowledged `CHANGE` messages, a sibling's key                                 |
| `records[].id`               | `record.id` of the `CHANGE`                                                                             |
| `records[].version`          | `record.version` of the `CHANGE`                                                                        |
| `records[].outcome`          | `APPLIED`, `DUPLICATE` or `STALE` (section 8.4)                                                         |
| `records[].receiver_version` | The acknowledging device's state stamp of the record after it processed the `CHANGE`, for every outcome |
| `records[].kept_fields`      | Empty                                                                                                   |

An `ACK` whose `sender` is a sibling reports `CHANGE` messages and requests made with `RESYNC` (section 11.2) and nothing else, since siblings send each other no record messages (section 7.2); an `ACK` of any other sender reports record messages. An entry for a `RESYNC` has the id of the request, the `version` 1, the outcome `APPLIED` or `DUPLICATE`, the `receiver_version` 1 and no kept field. A device so tells by the `sender` of an `ACK` which rules apply to it. An `ACK` of a sibling is valid when:

- `records` has 1 to 4,096 entries;
- each `id` is a UUID in text form, neither nil nor max, and each `version` is at least 1;
- no id and version appears twice; ids are compared as 128-bit values ([envelope.md](envelope.md), section 7);
- each `outcome` is `APPLIED`, `DUPLICATE` or `STALE`;
- each `receiver_version` is at least 1; it need not be above, equal to or below its `version`;
- each `kept_fields` is empty.

A device MUST report an `ACK` of a sibling that is not valid with `INVALID_MESSAGE` and take none of its entries. The outcomes `MERGED`, `KEPT` and `WITHDRAWN` are never those of a `CHANGE`, and no outcome of a `CHANGE` is decided later ([protocol.md](protocol.md), section 7.3).

`receiver_version` is what `state` is in a `CHANGE` (section 8.1): the state stamp that the acknowledging device holds of the record when it has processed the message, the new one if the merge made it take one (section 8.4), or the version it counted that stands in its place (sections 2.4 and 3.3). A device that holds no state stamp of the record after processing the message, because it could take none (section 2.3), puts `record.version` of the `CHANGE` there. A device that took everything from a sibling sends that sibling nothing back (section 10.2); the `ACK` so tells the sibling the state stamp under which the device may send the merged state to other apps.

### 9.2 What the sender does with an outcome

A device takes the entries of a valid `ACK` of a sibling whose `to` is its own key ([protocol.md](protocol.md), section 9.1). An entry whose id is the id of a request that the device has open with that sibling, with the version 1, acknowledges that request (section 11.3). Every other entry is about a `CHANGE`: the device takes it if its id and version are those of a `CHANGE` to that sibling that the device still keeps (section 10.1), and ignores it without a report otherwise. It so ignores an outcome for a `CHANGE` that already has an outcome or a settling error, for one that arrives later than 15 days after the device last sent that message, for one that it sent before it acted on a `RESYNC` of that sibling (section 11.2), and for one that it sent before it restored a backup (section 12.1).

| Outcome     | The sibling                                               | The device                                                                                                                                   |
| ----------- | --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `APPLIED`   | took at least one part of the message, or took the record | marks the parts of the message as delivered (section 10.1)                                                                                   |
| `DUPLICATE` | holds every part of the message already                   | the same                                                                                                                                     |
| `STALE`     | holds, for at least one part of the message, a later one  | the same; the sibling has made its later part due for the device again (section 10.1), so it reaches the device in a `CHANGE` of the sibling |

- Every outcome settles the message: the sibling has merged it, and the device does not send it again.
- The first outcome for an id and version stands; a repeated entry and a later one with another outcome change nothing.
- **The sibling's state stamp.** For every entry of a `CHANGE` that it takes, with whatever outcome, the device counts `receiver_version` as a stamp it has seen (section 2.2), and, if it is above the highest state stamp of the record that the device has seen from a sibling (section 3), it becomes that value: exactly as the `state` of a `CHANGE` of the sibling does (section 8.4). The device takes nothing else from it.
- `STALE` in the `ACK` of a sibling is not the `STALE` of section 5.3 and of [records.md](records.md), section 7. The device MUST NOT act on it as section 5.3 says: it keeps no version to pass, waits for no one and sends nothing again.
- **One id and version, one message.** A device never sends a sibling two different `CHANGE` messages under one id and version (section 10.2). An outcome therefore names one `CHANGE`, and delivers the parts of that message and no others: an outcome of an earlier message that arrives late is not taken for a later one.

### 9.3 Errors

A `CHANGE` that fails a step of section 8.3 is reported with an `ERROR` ([protocol.md](protocol.md), section 8), whose `record` is the `record` of the `CHANGE`. A device matches an `ERROR` of a sibling to a `CHANGE` by that `record`: its id and version are those of a `CHANGE` to that sibling that the device still keeps (section 10.1). An `ERROR` whose `record` is `null`, or names no message that the device still keeps, is logged and changes nothing, whatever its code; one whose `record` is that of an open request is about a `RESYNC` (section 11.3). The device that sent the `CHANGE`:

| Code                                                      | The device then                                                                                                                                                                                                                                                                                                            |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SCHEMA_UNKNOWN`                                          | offers the sibling the schema whose fingerprint the error names again (section 7.2), also when an accepted offer of it stood, and, once it is accepted, sends the message again, or, if the state has changed, what is then due (section 10.2). If the error's `fingerprint` is `null`, it sends the message again at once |
| `RECORD_UNKNOWN`                                          | forgets what the sibling has of the record (section 10.1) and sends the record whole (section 10.2)                                                                                                                                                                                                                        |
| `RECORD_ID_INVALID`, `VERSION_INVALID`, `INVALID_MESSAGE` | logs it; it is a fault of its implementation. It does not send that message again                                                                                                                                                                                                                                          |
| `TYPE_CHANGED`                                            | logs it; the two devices keep the record under two types, which no message resolves. It does not send that message again                                                                                                                                                                                                   |
| `UNDECODABLE`, `VALUE_INVALID`                            | logs it, and MAY show its user the record and, for `VALUE_INVALID`, the field. It does not send that message again                                                                                                                                                                                                         |
| `FORMAT_UNSUPPORTED`                                      | sends the message again in the chosen format ([protocol.md](protocol.md), section 3.2); while there is one format, that is the same message                                                                                                                                                                                |
| `TOO_LARGE`, `SIGNATURE_INVALID`, and every other code    | logs it; it is a fault of its implementation. It does not send that message again                                                                                                                                                                                                                                          |

A message that a row with "does not send that message again" settles is not sent again as it is. Its parts stay due (section 10.1), and travel in the next `CHANGE` of the record that the device sends to that sibling, which it sends when its state stamp of the record has changed, on whatever occasion of section 3.3 (section 10.3). After `UNDECODABLE`, `VALUE_INVALID` and `INVALID_MESSAGE`, which are about the content of the message, the device MAY leave the parts of that message out of that next `CHANGE`, so that they do not block the other parts that are due; they stay due. An `ERROR` about a `CHANGE` for whose id and version the device already has an outcome is ignored ([protocol.md](protocol.md), section 8.3). Errors are reported to a sibling as to any app: through a relay only for a message whose signature verified ([protocol.md](protocol.md), section 8.3).

## 10. What a device sends to which sibling

### 10.1 Delivered and due

A device MUST keep, with its data and through every restart, for each sibling and each record of the set of which it holds a state:

- whether the record is **known** to the sibling;
- for the `CHANGE` of the record that it last sent to the sibling under its current state stamp of the record, if it sent one, which parts it held, identified as in the next item, and its `whole` (section 10.2);
- after a restore or a loss of this bookkeeping, for each record, whether it has sent a `CHANGE` of the record since (section 3.3, occasion 7);
- for every `CHANGE` that it sent to the sibling and that has neither an outcome nor an error that settles it (section 9.3): its id, its version and which parts it held, each field state by its name, its stamp, its device key, the SHA-256 of the bytes of its value and the fingerprint of its schema, and the removal by its stamp, its device key and whether it stands. It keeps this for 15 days after it last sent that message, the longest a relay holds a message ([transports.md](transports.md), section 5.5), and then drops it; an outcome or an error that arrives later than 15 days after the device last sent the message is ignored (section 9.2);
- which parts of its state are **delivered** to the sibling. A part is a field state, identified by all it holds, its name, the bytes of its value, their schema, its stamp and its device key, or the removal, identified by its stamp, its device key and whether it stands (sections 4.1 and 4.2).

Two events make a record known to a sibling and parts delivered to it:

1. **The sibling acknowledges.** An outcome of the sibling for a `CHANGE` that the device sent to it (section 9.2) makes the record known to the sibling and delivers every part that the message carried and that the device's state still holds exactly: a field state with that name, stamp, device key, value and schema, compared by the hash and the fingerprint the device kept, or the removal with that stamp, device key and standing. With one name, stamp and device key the value can differ, for the stamps 0 and −1 and after a restore (section 4.1, rule 3).
2. **The sibling sends.** When the device processes a `CHANGE` of that sibling to an outcome (section 8.4), the record is known to the sibling, and every part that the message carried is delivered to it, whether the device took the part or held the same one already. A part of the message for which the device holds a later one is not in the device's state, and nothing is kept for it.

Four events take that back:

- `RECORD_UNKNOWN` of the sibling for a `CHANGE` of a record (section 9.3): the record is no longer known to that sibling, and no part of it is delivered to it.
- A `RESYNC` of the sibling that the device acts on (section 11.2): no record is known to that sibling, no part is delivered to it, and the device keeps none of the `CHANGE` messages it sent to that sibling before.
- A `CHANGE` of the sibling that held an earlier part (section 8.4): whenever a `CHANGE` of the sibling that the device processes to an outcome held a field state or a removal that is earlier than the one the device holds for it, the device's later part is no longer delivered to that sibling, and so due for it again, whether the outcome is `STALE` or `APPLIED`. The sibling evidently does not hold it, or sent an older message.
- The removal of the sibling (section 12.2): the device discards all it kept for that key.

A part of the device's state that is not delivered to a sibling is **due** for that sibling, whichever device made the change and from whichever sibling the device took it. A part that the device's state no longer holds, because a later one took its place, is no longer kept as delivered or due. A device that has lost this bookkeeping, and a device that restored a backup (section 12.1), treats every record as not known to every sibling, and takes a new state stamp for each record before it sends its first `CHANGE` of that record afterwards (section 3.3, occasion 7); it then sends more than is needed, and loses nothing.

### 10.2 Whole or in part

A device sends to each sibling every part that is due for it, and every record that is not known to it. It sends a `CHANGE` when section 10.3 names a reason, and only then. For a sibling with which it has a channel (section 13) and for a record of which it holds a state, the `CHANGE` is:

| For that sibling, the record is     | The `CHANGE` carries                                                                                                             |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| not known                           | every field state the device holds of the record, and its removal if it holds one                                                |
| known, and at least one part is due | the parts that are due, and no others; it MAY leave out those of a message that an error about its content settled (section 9.3) |
| known, and no part is due           | nothing is sent                                                                                                                  |

- **Whole on the first transfer.** A record is not known to a sibling before its first transfer to it, after `RECORD_UNKNOWN`, after a `RESYNC`, and on a device that restored a backup or lost its bookkeeping (section 10.1). The message then holds every field state, delivered or not, so its `whole` is `true` (section 8.1), unless the device holds the record incompletely.
- **Only the changes after that.** For a known record, the message holds the field states that are due and, if the removal is due, the removal. Its `whole` is `true` only if these happen to be all field states the device holds.
- **Whichever device made the change.** A part that the device took from one sibling is due for every other sibling until that sibling has it. A change therefore reaches a third device also when the device that made it is gone.
- **Not back.** A part that the device took from a sibling is delivered to that sibling (section 10.1, event 2), so it is not sent back to it.
- **Deleted records.** A deleted record is sent like every other: its removal is a part. A device that discarded the field states of a deleted record (section 4.3) sends what it holds.
- **No state stamp.** A device sends no `CHANGE` of a record for which it holds no state stamp (section 8.1).
- **A record held incompletely.** A device that holds a record incompletely (section 4.3) sends its parts with `whole` `false`. After `RECORD_UNKNOWN` of a sibling for such a record, it sends that sibling nothing of the record until it holds the record completely, also not in answer to a `RESYNC` of that sibling (section 11.2).
- **An open request.** A device sends no `CHANGE` to a sibling with which it has a request open, apart from its answer to a request of that sibling (section 11.3).
- **One message at a time.** A device puts all parts of a record that it sends to a sibling at one time into one `CHANGE`.
- **One id and version, one message.** Before a device sends a sibling a `CHANGE` of a record, it looks at the `CHANGE` of that record that it last sent to that sibling under its current state stamp. If there is one and the new message differs from it, in `whole`, in `removal` or in the entries of `fields`, whatever their order, the device MUST first take a new state stamp for the record (section 3.3, occasion 5), as the next stamp of section 2.2, and sends the new message with it as `state`. The usual case is a record that goes whole after `RECORD_UNKNOWN` or a `RESYNC`, having gone in part before; another is a resend after a `CHANGE` of the sibling has delivered some of the parts (section 10.1, event 2). The state of the record does not change, nothing becomes due by it, and the device need not send the record to another app for it. Nor is the new state stamp a reason to send any other sibling a `CHANGE`: a part that is on its way to another sibling is not sent again because of it. A message that is the same as the one sent before, a resend, goes under the same state stamp. A device that can take no stamp (section 2.3) does not send the different message. One id and version so name one `CHANGE` for each sibling.
- **When.** A device sends a `CHANGE` of a record to a sibling only for one of the reasons of section 10.3. When there is one, it SHOULD send as soon as it has a channel to the sibling and the accepted offers that section 7.2 requires. It MAY send the messages in any order and need not wait for acknowledgements. A part that is due and on its way without an outcome is still due: it travels again in the next `CHANGE` of the record that a reason of section 10.3 brings, and is no reason of its own.
- **A record that does not fit.** A device MUST NOT send a `CHANGE` above 16 MiB. A record whose whole `CHANGE` would be above it is not sent to a sibling to which it is not known; its due parts are still sent to a sibling to which it is known, when their `CHANGE` fits. A device SHOULD refuse a change of its user that would make the whole `CHANGE` of a record larger than 16 MiB, and SHOULD tell its user about a record that it cannot send.

### 10.3 Resends

These rules stand beside those of [protocol.md](protocol.md), section 11, which are for record messages. A device sends a sibling a `CHANGE` of a record for these reasons, and for no other:

- **Something new is due.** Whenever a part of a record becomes due for a sibling, by a change of the device's user, by a merge in which the device took it from another sibling, or by a `CHANGE` of that sibling that held an earlier part (section 10.1), and whenever a record is not known to a sibling, as on its first channel to that sibling, the device sends a `CHANGE` by section 10.2, with every part that is then due, also those of an earlier `CHANGE` that has no outcome yet.
- **Without an acknowledgement, in a live connection.** A `CHANGE` with neither an outcome nor an error when its connection ends has not been delivered. Its parts are still due, and the device sends what is due in a later connection, under offers accepted there, or through the relay.
- **Without an acknowledgement, through a relay.** Once the holding time of 14 days ([transports.md](transports.md), section 5.5) has passed since the device last sent a sibling a `CHANGE` of a record through the relay, with neither an outcome nor an error that settles it, and not before, it sends that sibling a `CHANGE` of the record again by section 10.2: the same message, if neither its state nor what is due has changed, and otherwise a message under a new state stamp (section 10.2).
- **For a schema.** After `SCHEMA_UNKNOWN`, once the schema is accepted again (section 9.3).
- **For the whole record.** After `RECORD_UNKNOWN`, at once (section 9.3).
- **After another error.** After an error that settles a message (section 9.3), the device sends the record's due parts to that sibling again when its state stamp of the record has changed, on whatever occasion of section 3.3, also one that another sibling caused (section 10.2), and not before.
- **On request.** After a `RESYNC` that the device acts on, every record (section 11.2). Unlike a receiver of record messages ([protocol.md](protocol.md), section 11), a sibling can ask.
- **After its own request.** When a sibling acknowledges the device's `RESYNC`, the device sends that sibling what is then due and what is not known to it (section 11.3).

Every resend is safe: a `CHANGE` that is merged twice changes nothing the second time (section 4.5).

### 10.4 Merged with a sibling

Section 5.3 has a device wait, after `STALE` with a higher version from another app, until it has merged the state of the record with every other current device of its set. A device has **merged the state of a record with a sibling** when, since it took that `STALE`, one of these has happened:

- it has processed a `CHANGE` of that record from that sibling to an outcome (section 8.4);
- it has taken an outcome of that sibling for a `CHANGE` of that record (section 9.2), whenever it sent that `CHANGE`.

A device that has nothing of the record due for a sibling sends that sibling no `CHANGE` of it and so gets no outcome; for that sibling the wait ends with a `CHANGE` of the record from it, with its removal (section 12.2), or after the 14 days of section 5.3.

## 11. The `RESYNC` message

### 11.1 Content

With a `RESYNC` message a device asks one sibling to send it every record of the set again. The request is confirmed, and its answer has an end:

- Its `sender` is the key of the device that asks, and it is signed with that key like every message.
- Its `record` MUST be present. It names the request, not a record. `record.id` is the id of the request: a UUID of version 4 or version 7 that the device generates for the request as it generates the id of a record ([records.md](records.md), section 2), neither the nil UUID nor the max UUID. A device MUST NOT use the id of a record as the id of a request, and MUST NOT use the id of a request for a second request; a repeat of a request (section 11.3) carries the id of that request. `record.version` is 1.
- Its body MUST be one `axt.Resync` in single-object encoding, with the schema [types/axt/Resync.avsc](../types/axt/Resync.avsc) and, in envelope format 1, the fingerprint of section 15.

| Field | Avro type                           | Content                                                                               |
| ----- | ----------------------------------- | ------------------------------------------------------------------------------------- |
| `to`  | `fixed` of 32 bytes, `axt.ResyncTo` | The device key of the sibling that is asked ([protocol.md](protocol.md), section 9.1) |

A device checks a `RESYNC` in these steps. A step that fails ends the processing: the device changes nothing and reports the failure with the error code named, as [protocol.md](protocol.md), section 8.3, says. As for a `CHANGE` (section 8.3), a `RESYNC` without `record` is reported only to a sibling and to a current key of another known sender, and to no other key.

| Step | Check                                                                                                                                                                        | If it fails                                                                                                                                        |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | The message and its envelope are valid, and its signature verifies, as for every message ([protocol.md](protocol.md), section 8.2). A `RESYNC` without `record` is not valid | as [protocol.md](protocol.md), section 8.2, says; `INVALID_MESSAGE` without `record`                                                               |
| 2    | The `sender` is a sibling (section 7.1)                                                                                                                                      | as the table of section 7.1 says; the body is not read                                                                                             |
| 3    | The body is one `axt.Resync` in single-object encoding, with no bytes left over, and its `to` is the device's own key                                                        | `INVALID_MESSAGE` for a body that is not; a message with another key in `to` is ignored without a report ([protocol.md](protocol.md), section 9.1) |
| 4    | `record.id` is a UUID in text form, neither the nil UUID nor the max UUID                                                                                                    | `RECORD_ID_INVALID`                                                                                                                                |
| 5    | `record.version` is at least 1                                                                                                                                               | `VERSION_INVALID`                                                                                                                                  |
| 6    | `record.version` is 1                                                                                                                                                        | `INVALID_MESSAGE`                                                                                                                                  |
| 7    | The device acts on the request, or acknowledges a repeat (section 11.2)                                                                                                      | (no failure)                                                                                                                                       |

### 11.2 What the sibling does

A device keeps, for each sibling and for as long as that key is a sibling, the ids of the requests of that sibling that it has acted on. Ids are compared as 128-bit values ([envelope.md](envelope.md), section 7).

**A request it has not acted on.** A device that gets a `RESYNC` of a sibling whose id is not among them acts on it. It keeps the id, and:

1. forgets what it kept for that sibling by section 10.1: from then on no record is known to that sibling, no part is delivered to it, and the device keeps none of the `CHANGE` messages it sent to that sibling before;
2. from then on ignores every outcome and every error of that sibling for a `CHANGE` that it sent to that sibling before it acted on the request. Such an outcome delivers nothing and makes no record known, whenever it arrives;
3. sends that sibling a `CHANGE` of every record of the set of which it holds a state, the deleted ones included, by section 10.2. Each is not known to the sibling, so each travels with every field state the device holds. Before it sends the first `CHANGE` of a record after it acted on the request, it takes a new state stamp for that record (section 3.3, occasion 6), so that no message of the answer goes under an id and version that the device used toward that sibling before;
4. acknowledges the request, after the last `CHANGE` of step 3: with an entry in an `ACK` to the asking device ([protocol.md](protocol.md), section 7.1) whose `id` is the id of the request, whose `version` is 1, whose `outcome` is `APPLIED`, whose `receiver_version` is 1 and whose `kept_fields` is empty.

- **The answer and its end.** The answer to a request is the `CHANGE` messages of step 3, one of each record of which the device held a state when it acted on the request. The `ACK` of step 4 is the end of the answer: it says that the answer was sent, not that it was received. The device sends it in the channel in which it sent the answer, after the last `CHANGE`. In a live connection the messages before it have then been sent on the same connection, and through the relay a mailbox is listed in the order of the puts ([transports.md](transports.md), section 5.4), so a device that fetches its messages in that order meets the `CHANGE` messages of the answer before the `ACK`. A `CHANGE` of the answer can all the same come later than the acknowledgement: one that the asking device rejected and that is sent again (section 9.3), and one that the relay no longer held (section 10.3). It is merged like any other.
- **A channel that ends first.** If a live connection ends before the device has sent the acknowledgement, the device goes on in the next channel it has to that sibling, a later connection or the relay: it sends there every `CHANGE` of the answer that it has not sent yet, sends again those that have no outcome (section 10.3), and then sends the acknowledgement.
- **A record that cannot be sent.** A record of which section 10.2 lets the device send that sibling nothing, such as one for which it can take no state stamp (section 2.3) or one whose whole `CHANGE` does not fit, is not part of the answer and does not hold up the acknowledgement. A record that the device holds incompletely and for which that sibling has reported `RECORD_UNKNOWN` is still not sent after a `RESYNC`, until the device holds it completely (section 10.2).
- **No record.** A device that holds no state of any record sends only the acknowledgement.
- **Offers.** The offers that the two devices have made to each other stay as they are. The schemas travel again where section 7.2 requires an offer.
- **Nothing else changes.** The states of the device's records do not change, and neither does what the asking device keeps for it.

**A request it has acted on.** A `RESYNC` whose id is among those the device has acted on for that sibling is not acted on again. The device has sent the acknowledgement of a request when it has sent the `ACK` message that holds the entry of step 4. A repeat that arrives after that is acknowledged with an entry like that of step 4 whose `outcome` is `DUPLICATE`. A repeat that arrives before that changes nothing and gets no entry of its own; the acknowledgement of step 4 follows when the answer is sent.

**A second request.** A `RESYNC` of that sibling with another id, which the device has not acted on, is acted on like the first, also while the device is still sending the answer to an earlier request: steps 1 to 3 apply again, so the answer starts anew, also for the records it had already sent. The device acknowledges both requests, each with an entry of step 4, when that answer has been sent.

### 11.3 When a device asks

A device sends a `RESYNC` to each of its siblings, each with that sibling's key in `to` and with an id of its own:

- **After a restore.** A device that restored its data from a backup, or that for another reason cannot rule out that it holds an older state than it held before ([protocol.md](protocol.md), section 10), MUST send a `RESYNC` to every sibling (section 12.1).
- **After a long absence.** A device that has not listed its mailbox for longer than the holding time of 14 days ([transports.md](transports.md), section 5.5) SHOULD send a `RESYNC` to each sibling it exchanges with through the relay. The siblings would send what has no outcome again on their own (section 10.3), but only after the holding time.
- **For an incomplete record.** A device that holds a record incompletely (section 4.3) SHOULD send a `RESYNC`.
- **Otherwise.** A device MAY send a `RESYNC` whenever it has reason to think that it lacks states its siblings hold, for example after it took records from a file of its own set (section 13.4).

A request is **open** from the moment the device decides to ask until it takes the acknowledgement of that request: an entry of a valid `ACK` of that sibling (section 9.1) whose `id` is the id of the request and whose `version` is 1, with the outcome `APPLIED` or `DUPLICATE`. While a request to a sibling is open, the device:

- MUST send the `RESYNC`, the same request under the same id, at the start of each live connection with that sibling, after the sibling's valid `MANIFEST` ([protocol.md](protocol.md), section 3.1) and before any other message but its chain, its `MANIFEST`, answers and acknowledgements;
- MUST send it through the relay, to a sibling whose encryption key and relay it has (section 13.2), at once, and again each time the holding time of 14 days has passed since it last sent it there, not before;
- MUST NOT send that sibling a `CHANGE`, with one exception: the `CHANGE` messages of its answer to a request of that sibling (section 11.2), which it sends, and acknowledges that request, although its own request is open. Two devices that have requests open toward each other so each get the other's answer. It goes on answering that sibling's offers and acknowledging that sibling's `CHANGE` messages (sections 7.2 and 9.1), and goes on sending its other siblings what is due for them;
- makes no second request to that sibling. A new reason to ask is met by the open request.

How a request ends, and what does not end it:

- **The acknowledgement.** When the device takes the acknowledgement, the request is closed. The acknowledgement says that the sibling has sent its answer, not that every message of it has arrived: a `CHANGE` of the answer can still come later, after a resend (section 11.2), and is then merged like any other. From then on the device sends that sibling what is due for it (section 10.2). The `receiver_version` of the entry carries nothing.
- **A sibling that is removed.** A request to a sibling ends when the device applies the removal of that sibling (section 12.2).
- **An error.** An `ERROR` of the sibling is about a `RESYNC` when its `record` is the `record` of that request. After `FORMAT_UNSUPPORTED`, the device sends the request again at once, in the chosen format ([protocol.md](protocol.md), section 3.2), which is the same message while there is one format. After every other code it logs the error, which is a fault of its implementation; the request stays open, and the device sends it again at the next occasion named above, the start of a live connection or the end of the holding time, not at once.
- **What the asking device keeps.** A `RESYNC` changes nothing on the device that sends it, apart from what section 12.1 says of a restored device.

## 12. A restored, a removed and a new device

### 12.1 A device that restored a backup

A device that restored its data from a backup holds an older state of the records and an older `highest`. It has no connection and no offer: every offer it made or got before, in whatever channel, has ended for it, and it offers anew. It:

- gives stamps from then on (section 2.4; [protocol.md](protocol.md), section 10);
- discards the bookkeeping of the backup (section 10.1): it treats every record as not known to every sibling and no part as delivered, and keeps none of the `CHANGE` messages it sent before. An outcome or an error of a sibling for a `CHANGE` that it sent before it restored the backup is ignored (section 9.2). What the backup holds as delivered may have been replaced on the sibling by a change that the device itself made after the backup and has lost;
- gives every field state never stamped that it holds, with the stamp 0, the stamp −1, if its set has another current device (section 4.6);
- remembers that it restored, and which field states never stamped it held then, each until a change of its user stamps it or a field state of a sibling replaces it. When it later learns, from a chain ([keys.md](keys.md), sections 5.4 and 5.5), of a current device of its set that its backup did not hold, it acts toward that device as this section says for a restore: at that moment those of the field states it remembers that it still holds unchanged, with the stamp 0, get the stamp −1 (section 4.6), and it opens a request toward that device and sends it a `RESYNC` (section 11.3). A device whose backup was made before the sibling joined holds no sibling when it restores; without this rule its old values could win by their bytes, and the records that the sibling holds as delivered would not come back;
- keeps the ids of the requests of its siblings that it acted on, as far as the backup holds them and none that it learned after the backup was made (section 11.2), so that it acts again on a repeat of a request that it acted on since; forgets the requests that it had open itself, and opens a new request to every sibling, each with a new id, and sends each a `RESYNC` (section 11.3). It sends a sibling no `CHANGE` before that sibling has acknowledged the request, apart from its answer to a request of that sibling (section 11.3);
- takes a new state stamp for a record before it sends the first `CHANGE` of that record after the restore, to whichever sibling, also when a change or a merge has given the record a new state stamp since (section 3.3, occasion 7), so that no message goes under an id and version it used before the restore. A device that can take no stamp (section 2.3) sends no `CHANGE` of that record;
- SHOULD NOT let its user change a record before it has merged with a sibling (section 2.4). That wait ends when it takes the acknowledgement of its `RESYNC` from one sibling (section 11.3), or 14 days after it opened the first of its open requests, that is, first sent a `RESYNC` or, with no sibling in reach, decided to ask, whichever comes first; if all its requests have closed and it opens one later, the wait begins anew with that request. The acknowledgement says that the answer was sent: a `CHANGE` of it can still come later, after a resend, and is then merged like any other, with the user's change in between decided by the stamps;
- does not send a `DATA` of a record of which it holds a field state of unknown age to another app until that wait has ended: until the first acknowledgement of one of its open requests, for at most 14 days (section 5.1).

Each sibling sends it every record whole (section 11.2), with every part the sibling holds, whichever device made the change. The merge brings each field state and the removal of the restored device to the later of the two (section 4); a field state of unknown age loses to every field state of that name that a sibling holds with a stamp of 0 or more (section 4.6). The device's own earlier changes come back as far as they had reached a sibling. A change that it made after the backup and that reached no sibling before the restore is lost on the devices of the set ([protocol.md](protocol.md), section 10). After the acknowledgement, the restored device sends that sibling every record that is then not known to it, and every part that is then due (section 10.2).

An installation that restores a signing key together with its data ([keys.md](keys.md), section 5.8) is a restored device in this sense.

### 12.2 A removed device

When a device applies the removal of a sibling ([keys.md](keys.md), section 5.5), that key is no sibling any more. The device:

- discards what it kept for that key by section 10.1, and every `CHANGE` it had not sent to it yet;
- sends that key no further message, and ends the offers it made to it and had from it ([keys.md](keys.md), section 5.5; [protocol.md](protocol.md), section 4.3);
- rejects every message signed with that key without a report ([keys.md](keys.md), section 3.3): a `CHANGE`, a `RESYNC`, an `ACK` and an `ERROR` of the removed device, also one that the device sent before its removal and that arrives after it;
- counts that key as merged with for the wait of section 5.3.

The field states and removals that the removed device made stay in the states of the records, with its key as their `device`. They merge and are passed on as before, and a `CHANGE` of a sibling that carries one is processed like every other (section 8.2). What the removed device had changed and sent to no sibling before its removal is lost on the devices of the set.

A device that gets a valid removal of its own key signs no further message ([keys.md](keys.md), section 5.3): it sends no `CHANGE`, no `RESYNC` and no `ACK` any more.

### 12.3 A new device

No sibling has kept anything for the key of a device that joins a set ([keys.md](keys.md), section 5.2), and the new device has kept nothing for any sibling. Every record is therefore not known in either direction: each sibling that has a channel to the new device sends it every record whole (section 10.2), and the new device sends each sibling every record it holds. It needs no `RESYNC`. The first channel is the connection in which it joined: after the answer to its `DEVICE_JOIN`, both devices send their chain and their `MANIFEST` ([protocol.md](protocol.md), section 3.3), each offers its schemas, and each accepts the other's and takes the records.

- **An installation with records of its own.** An installation that joins a set may hold records ([keys.md](keys.md), section 5.1). They become records of the set. The installation begins to stamp when it holds the `DEVICE_ADD` of its own key (section 2.4): its records keep the versions it counted in the place of the state stamp, and their fields were never stamped (section 3.4). They travel to its siblings as section 10 says, like every record of the set.
- **An id on both sides.** A record id that the new device and a sibling both hold is merged like any record of the set (section 4). Ids are random ([records.md](records.md), section 2), so this is the same record only where one side took it from the other, such as from a file (section 13.4).
- **A device that takes the place of an old one** ([keys.md](keys.md), section 5.7) gets the records of the set in this way. The old device sees when it is done: every record of which it holds a state is known to the new device, and every part it holds is delivered to it (section 10.1). The owner SHOULD remove the old device only then, and the old device SHOULD show its user whether that is so: a part that only the old device holds is lost with its removal (section 12.2).

## 13. Transports

A `CHANGE` and a `RESYNC` travel in a live connection on the local network and through a relay. They never travel in a file.

### 13.1 Local network

Two siblings open a live connection as two apps do ([transports.md](transports.md), section 4). The connection key is a sibling's key (section 7.1), so the device asks no one.

- The first messages are those of [protocol.md](protocol.md), section 3.1: the chain, then the `MANIFEST`. A `RESYNC` of an open request (section 11.3), the offers and the `CHANGE` messages follow the sibling's valid `MANIFEST`.
- The kept manifests of the other devices of the set are passed on in the connection as section 13.2 says. Such a `MANIFEST` has another `sender` than the connection key and MAY come at any time ([transports.md](transports.md), section 4.5).
- Every `CHANGE` in the connection has the connection key as its `sender` ([transports.md](transports.md), section 4.5). A device signs the `CHANGE` messages it sends itself, also for parts that another device made; it never passes on a `CHANGE` of another device as the message it got.
- The offers of the connection end with it (section 7.2). The bookkeeping of section 10.1 and the schemas of section 7.3 do not: a later connection begins with manifests and offers, and then carries what is due.

### 13.2 Relay

Through a relay ([transports.md](transports.md), section 5), a device seals each message for the sibling's encryption key and puts it into the sibling's mailbox ([keys.md](keys.md), section 4), as for any app, with the differences of [protocol.md](protocol.md), section 15.1.

- A device exchanges with a sibling through the relay once it has that sibling's `MANIFEST` with an encryption key and a relay. It gets the `MANIFEST` from the sibling itself, in a live connection or through the relay ([protocol.md](protocol.md), section 15.1), or passed on by another device of the set.
- **Passing on manifests.** A device MUST pass on to each sibling the kept `MANIFEST` ([manifest.md](manifest.md), section 6) of every other current device of its set, as the message it got: a `MANIFEST` has no addressee and keeps its signature ([protocol.md](protocol.md), section 2). It does so whenever it holds one that this sibling has not got from it, and again when the kept manifest of that device changes; it keeps, for each sibling, the revision of each manifest it passed on, and, with each kept `MANIFEST` of a sibling, which device it got it from, so that it does not pass it back. It passes them on in a live connection, after its own `MANIFEST`, and through the relay to a sibling whose encryption key and relay it has. It does not pass a `MANIFEST` on to the device it is of, nor back to the sibling it got it from.
- **Taking a passed-on manifest, in a live connection.** A `MANIFEST` whose `sender` is another key than the connection key is a passed-on one. The device verifies its signature and takes it only if its `sender` is a current key of the device's own set other than its own key. It then takes it as the manifest of that sibling by the revision rule for a manifest received outside a live connection: it replaces the kept manifest only if its revision is higher ([manifest.md](manifest.md), section 6). A `MANIFEST` whose `sender` is the connection key is not passed on: it is the sibling's own, and applies as [manifest.md](manifest.md), section 6, says for a manifest received in a live connection, whatever its revision. One with a lower revision than the kept one so replaces it and is passed on again, since the kept manifest has changed; one with the same revision as the kept one changes nothing. Only a passed-on `MANIFEST`, and every `MANIFEST` that comes through the relay, replaces the kept manifest only if its revision is higher. A passed-on `MANIFEST` is checked for validity as [manifest.md](manifest.md), section 4, says; one whose body does not decode as a manifest, or that is not valid, is ignored without a report. With any other `sender`, the device's own key included, such a `MANIFEST` is ignored without a report, and does not close the connection ([transports.md](transports.md), section 4.5). It is never the `MANIFEST` of the other device that [protocol.md](protocol.md), section 3.1, waits for.
- **Through the relay**, nothing shows which device put a message, and nothing needs to: a `MANIFEST` whose signature verifies and whose `sender` is a sibling is taken by the revision rule of [manifest.md](manifest.md), section 6, whoever put it; a `MANIFEST` of any other key is handled as [manifest.md](manifest.md) and [keys.md](keys.md), section 3.2, say for every app.
- So two devices of a set that never met exchange through the relay as soon as one device that knows both has passed their manifests on, also when that device is removed afterwards, as the old device of a move is ([keys.md](keys.md), section 5.7).
- The relay may deliver late, out of order and more than once. The merge does not depend on the order or on repeats (section 4.5). A `CHANGE` that arrives before the offer of a schema it names is rejected with `SCHEMA_UNKNOWN`, unless the device holds that schema already (section 7.3).
- A message that waits in the mailbox of a removed device gets no outcome, and nothing is sent to that device any more (section 12.2).

### 13.3 File

A file MUST NOT hold a `CHANGE` or a `RESYNC`. Each is for one device, whose key its body names, and belongs to the bookkeeping between two devices, which needs a way back. A reader that finds a `CHANGE` or a `RESYNC` in a file MUST reject the whole file ([transports.md](transports.md), section 2.2), whoever the file's sender is.

### 13.4 A file of the device's own set

A file stays what it is: whole records as `DATA` and `DELETE` messages, without stamps. A device can read a file whose sender is its own set, that is, whose `axt.sender` is its own key or a sibling, as it is or by the chain at the start of the file ([keys.md](keys.md), section 5.5), for example to take its first records before sibling sync has brought them. It checks such a file as [transports.md](transports.md), section 2.2, says, and asks its user about no key. It MUST NOT keep the records of such a file as records it received from a sender: they are records of its own set. It MAY take them, and if it does:

- **A `DATA` of a record of which it holds no state**, that passes the steps 2, 3, 8 and 9 of [protocol.md](protocol.md), section 6.2: the device merges, by section 4, a state that it builds from the message. The fingerprint of the body is that of one of the schemas of the file's `axt.schemas`, or the file is rejected ([envelope.md](envelope.md), section 4.3); the device decodes the body with that writer schema alone. The state has one field state for each top-level field of that schema: its `name` is the field's name; its `value` is the bytes of that field in the body, which in Avro binary encoding holds the fields of the record one after the other; its `schema` is the fingerprint of the body; its `stamp` is −1, that of a field state of unknown age (section 4.6); its `device` is the key in `axt.sender`, which in a valid file is also the `sender` of the `DATA`. The state has no removal, and its state stamp is `record.version` of the message. The device so keeps the record, counts the version as a stamp it has seen and as a state stamp of the record that it has seen from a sibling (section 3), takes a state stamp of its own (section 4.4), and keeps the full name of the body's schema as the record's type. Whether the type fits the device's manifest is not looked at.
- **A `DATA` of a record of which it holds a state** is not applied.
- **A `DELETE`** is not applied: it carries no removal, and a removal has a stamp of at least 1 (section 4.6). The deletion reaches the device in a `CHANGE`.

The record is then not known to any sibling on the device, and travels to each by section 10.2, with its field states of unknown age; the record is not known to the device on any sibling either, so each sibling that holds it sends it whole. Every field state that a sibling holds of such a field with a stamp of 0 or more is later than the one of the file (section 4.6), on every device and in whatever order the messages arrive, so sibling sync brings such a device to the state of its siblings, and an old value of a file wins over no field state with a stamp of 0 or more; among field states of unknown age, the device key and then the value decide. Two files of two siblings so give field states of unknown age with two device keys, and the one with the higher key stands, whatever the age of the two files. A device that took records from a file MAY send a `RESYNC`, as any device may (section 11.3); it need not. While it has no `RESYNC` open, it is not held back from sending the record to another app (section 5.1).

## 14. Limits

| What                                                                                           | Limit                                                                               |
| ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| One `CHANGE` or `RESYNC` message, including its single-object header                           | 16 MiB (16,777,216 bytes) ([envelope.md](envelope.md), section 8)                   |
| Entries of `fields` in one `CHANGE`                                                            | 4,096                                                                               |
| `type` in a `CHANGE`                                                                           | 512 bytes                                                                           |
| One `name` in `fields`                                                                         | 1 to 512 bytes                                                                      |
| A stamp in `state`, in a removal or in a field state                                           | Up to 2^63 − 1; none is refused (section 2.3)                                       |
| Entries of one `ACK`                                                                           | 4,096 ([protocol.md](protocol.md), section 7.1)                                     |
| The `ACK` after processing a `CHANGE`                                                          | Within 5 seconds (section 9.1)                                                      |
| The `ACCEPT` for an offer of a sibling                                                         | Within 5 seconds (section 7.2)                                                      |
| A resend of a `CHANGE`, and a repeat of a `RESYNC`, through a relay                            | After the holding time of 14 days, not before (sections 10.3 and 11.3)              |
| How long a device keeps a `CHANGE` it sent, for its outcome                                    | 15 days after it last sent it (section 10.1)                                        |
| A `DATA` of a record with a field state of unknown age, while a `RESYNC` of the device is open | Held back for at most 14 days from the first sending of that `RESYNC` (section 5.1) |
| The wait of a restored device before its user changes a record                                 | Until the acknowledgement of its `RESYNC`, at most 14 days (section 12.1)           |
| The wait for a sibling after `STALE` from another app                                          | At most 14 days (section 5.3)                                                       |

The lengths are in bytes of UTF-8. A device MUST NOT produce a `CHANGE` above these limits, and MUST NOT reject one for its size, its number of fields or the length of a name while it is within them. The limit of 4,096 fields is far above what a type has; it bounds what a device has to hold for one message, as the 4,096 entries of an `ACK` do.

## 15. Schema and fingerprint

The schemas of the bodies of `CHANGE` and `RESYNC` are [types/axt/Change.avsc](../types/axt/Change.avsc) and [types/axt/Resync.avsc](../types/axt/Resync.avsc). Each follows the rules that [types.md](types.md), section 5, sets for every example type, where they apply to a schema of the specification, as [manifest.md](manifest.md), section 9, says of the manifest: its nested types are defined in place, with names that begin with the schema's name, and it carries no `axt.version`, since it changes only with the envelope format. The first field of each is `to`. The two fields that may be absent, `origin` and `removal`, and `fields[].value` are unions with `null` first and the default `null` ([types.md](types.md), section 5.3).

Their Parsing Canonical Forms:

```json
{"name":"axt.Change","type":"record","fields":[{"name":"to","type":{"name":"axt.ChangeTo","type":"fixed","size":32}},{"name":"origin","type":["null",{"name":"axt.ChangeOrigin","type":"fixed","size":32}]},{"name":"type","type":"string"},{"name":"state","type":"long"},{"name":"whole","type":"boolean"},{"name":"removal","type":["null",{"name":"axt.ChangeRemoval","type":"record","fields":[{"name":"stamp","type":"long"},{"name":"device","type":{"name":"axt.ChangeRemovalDevice","type":"fixed","size":32}},{"name":"stands","type":"boolean"}]}]},{"name":"fields","type":{"type":"array","items":{"name":"axt.ChangeField","type":"record","fields":[{"name":"name","type":"string"},{"name":"schema","type":{"name":"axt.ChangeFieldSchema","type":"fixed","size":8}},{"name":"value","type":["null","bytes"]},{"name":"stamp","type":"long"},{"name":"device","type":{"name":"axt.ChangeFieldDevice","type":"fixed","size":32}}]}}}]}
```

```json
{"name":"axt.Resync","type":"record","fields":[{"name":"to","type":{"name":"axt.ResyncTo","type":"fixed","size":32}}]}
```

| Schema       | Envelope format | CRC-64-AVRO          | As bytes                  |
| ------------ | --------------- | -------------------- | ------------------------- |
| `axt.Change` | 1               | `0xd3849acafc9d62e8` | `e8 62 9d fc ca 9a 84 d3` |
| `axt.Resync` | 1               | `0xe8762bd9d559fdf1` | `f1 fd 59 d5 d9 2b 76 e8` |

The fingerprints of this section and the keys, values, messages, lengths and hashes of section 16 were produced with [conformance/tools/sync_examples.py](../conformance/tools/sync_examples.py), which builds each message field by field and checks it against fastavro, the Apache avro package and three implementations of Ed25519. The test vectors of [conformance.md](conformance.md) take precedence over these values.

## 16. Examples of the messages

### 16.1 Devices and values

The phone and the tablet of section 6.2 are the two devices; their device keys are the test keys of that section, and the tablet's key is the higher one. **These keys are for tests only and MUST NOT be used outside tests.**

| Label                        | Key        | Hexadecimal                                                        |
| ---------------------------- | ---------- | ------------------------------------------------------------------ |
| `cat-a-log, phone, Ed25519`  | public key | `c338de9e8bc4ca4a886f9daefc0a4f476bd7c5fccf0d0a430574d0fdb8508ce0` |
| `cat-a-log, tablet, Ed25519` | public key | `ee08eaa3d8aa507343bc02924fe98d02f9e4471627ace61554f1b49635f24ab2` |

The record is the appointment of section 6.2, with the id `3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80` of [records.md](records.md), section 9, and the type `axt.example.v1.Appointment`. Both devices write with the schema [Appointment.1.avsc](../types/axt/example/v1/Appointment.1.avsc), whose fingerprint is `0x1af207f82b6430cd` (as bytes: `cd 30 64 2b f8 07 f2 1a`), and each has offered it to the other and has it accepted. The record has seven fields. As in section 6.2, the stamps are small numbers that are chosen, not computed, each above every stamp its device had given or seen.

The phone created the record with the stamp 100 and took the state stamp 101; the tablet took it from the phone in a whole `CHANGE`, acknowledged it and took the state stamp 105. Both hold this state, and every part of it is delivered in both directions:

| Field       | Value                                                                                                                     | Stamp | Device |
| ----------- | ------------------------------------------------------------------------------------------------------------------------- | ----- | ------ |
| `title`     | "Vet"                                                                                                                     | 100   | phone  |
| `start`     | 2025-11-18 10:00:00.000 in `Europe/Berlin`, with the offset 3600 and the instant 1,763,456,400,000 (2025-11-18T09:00:00Z) | 100   | phone  |
| `end`       | `null`                                                                                                                    | 100   | phone  |
| `all_day`   | `false`                                                                                                                   | 100   | phone  |
| `location`  | ""                                                                                                                        | 100   | phone  |
| `notes`     | ""                                                                                                                        | 100   | phone  |
| `reminders` | an empty array                                                                                                            | 100   | phone  |

No removal. State stamp: 101 on the phone, 105 on the tablet. The value of each field is the Avro binary encoding of the value shown, under the type the field has in the schema.

### 16.2 A `CHANGE` with two changed field states

The phone's user moves `start` to 10:30 and sets `location` to "Dr. Weber, Hauptstr. 5" in one step. The phone takes the stamp 110 for the two fields and the state stamp 111 (section 3.5). The record is known to the tablet, and two parts are due for it, so the phone sends one `CHANGE` with these two field states (section 10.2).

| Part of the message | Value                                                                                                                                                     |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `format`            | 1                                                                                                                                                         |
| `kind`              | `CHANGE`                                                                                                                                                  |
| `sender`            | the phone's key                                                                                                                                           |
| `record.id`         | `3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80`                                                                                                                    |
| `record.version`    | 111, the highest of 111, 110 and 110                                                                                                                      |
| `to`                | the tablet's key                                                                                                                                          |
| `origin`            | `null`                                                                                                                                                    |
| `type`              | `axt.example.v1.Appointment`                                                                                                                              |
| `state`             | 111                                                                                                                                                       |
| `whole`             | `false`                                                                                                                                                   |
| `removal`           | `null`                                                                                                                                                    |
| `fields`            | two entries, in this order: `start`, then `location`                                                                                                      |
| `signature`         | the phone's signature: `8ebace8259a6ab896b97682f8d86bd1d32a62c22dd9393708c1ebb3a39e0db256267e8d9a90b83efe0c5ded9bd6f02cc044bc62056f595df878d7e6f3bd20306` |

| `name`     | `schema`                         | `value`                                                                                                                                                                                                                                   | `stamp` | `device` |
| ---------- | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | -------- |
| `start`    | the fingerprint of Appointment.1 | 2025-11-18 10:30:00.000 in `Europe/Berlin`, with the offset 3600 and the instant 1,763,458,200,000 (2025-11-18T09:30:00Z); as bytes: `d2 1f 16 24 14 3c 00 00 02 1a 45 75 72 6f 70 65 2f 42 65 72 6c 69 6e 02 a0 38 02 80 c7 e5 e4 d2 66` | 110     | phone    |
| `location` | the fingerprint of Appointment.1 | "Dr. Weber, Hauptstr. 5"; as bytes: `2c 44 72 2e 20 57 65 62 65 72 2c 20 48 61 75 70 74 73 74 72 2e 20 35`                                                                                                                                | 110     | phone    |

The message: 385 bytes, SHA-256 `a670440adf7b41107be1b20b57440926e3ccebf4c3497a04cbd856ff7d7677e5`. Its bytes, with offsets in hexadecimal; the signature covers the prefix `AXT-v1 message` with its zero byte and the bytes from offset `000a` to the signature ([keys.md](keys.md), section 2.2):

```text
0000  c3 01                    single-object marker
0002  16 30 6f 71 b9 ce 9e a8  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  16                       kind: enum index 11, CHANGE
000c  c3 38 de 9e 8b c4 ca 4a  sender: fixed(32), the phone's test key
      88 6f 9d ae fc 0a 4f 47
      6b d7 c5 fc cf 0d 0a 43
      05 74 d0 fd b8 50 8c e0
002c  02                       record: union index 1, axt.RecordRef
002d  48                       record.id: string length 36
002e  33 66 32 63 38 61 35 65  "3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80"
      2d 39 62 31 64 2d 34 63
      37 65 2d 38 61 36 66 2d
      32 64 34 62 35 63 36 65
      37 66 38 30
0052  de 01                    record.version: long 111
0054  d6 03                    body: bytes length 235
0056  c3 01                    body: single-object marker
0058  e8 62 9d fc ca 9a 84 d3  body: fingerprint of axt.Change, format 1
0060  ee 08 ea a3 d8 aa 50 73  body: to: fixed(32), the tablet's test key
      43 bc 02 92 4f e9 8d 02
      f9 e4 47 16 27 ac e6 15
      54 f1 b4 96 35 f2 4a b2
0080  00                       body: origin: union index 0, null
0081  34                       body: type: string length 26
0082  61 78 74 2e 65 78 61 6d  body: "axt.example.v1.Appointment"
      70 6c 65 2e 76 31 2e 41
      70 70 6f 69 6e 74 6d 65
      6e 74
009c  de 01                    body: state: long 111
009e  00                       body: whole: boolean false
009f  00                       body: removal: union index 0, null
00a0  04                       body: fields: array block of 2 items
00a1  0a                       body: fields[0].name: string length 5
00a2  73 74 61 72 74           body: "start"
00a7  cd 30 64 2b f8 07 f2 1a  body: fields[0].schema: fixed(8), fingerprint of axt.example.v1.Appointment, version 1
00af  02                       body: fields[0].value: union index 1, bytes
00b0  42                       body: fields[0].value: bytes length 33
00b1  d2 1f 16 24 14 3c 00 00  body: the value: an axt.DateTime, 2025-11-18 10:30:00.000 in Europe/Berlin
      02 1a 45 75 72 6f 70 65
      2f 42 65 72 6c 69 6e 02
      a0 38 02 80 c7 e5 e4 d2
      66
00d2  dc 01                    body: fields[0].stamp: long 110
00d4  c3 38 de 9e 8b c4 ca 4a  body: fields[0].device: fixed(32), the phone's test key
      88 6f 9d ae fc 0a 4f 47
      6b d7 c5 fc cf 0d 0a 43
      05 74 d0 fd b8 50 8c e0
00f4  10                       body: fields[1].name: string length 8
00f5  6c 6f 63 61 74 69 6f 6e  body: "location"
00fd  cd 30 64 2b f8 07 f2 1a  body: fields[1].schema: fixed(8), fingerprint of axt.example.v1.Appointment, version 1
0105  02                       body: fields[1].value: union index 1, bytes
0106  2e                       body: fields[1].value: bytes length 23
0107  2c 44 72 2e 20 57 65 62  body: the value: "Dr. Weber, Hauptstr. 5" as an Avro string
      65 72 2c 20 48 61 75 70
      74 73 74 72 2e 20 35
011e  dc 01                    body: fields[1].stamp: long 110
0120  c3 38 de 9e 8b c4 ca 4a  body: fields[1].device: fixed(32), the phone's test key
      88 6f 9d ae fc 0a 4f 47
      6b d7 c5 fc cf 0d 0a 43
      05 74 d0 fd b8 50 8c e0
0140  00                       body: fields: end of the array
0141  8e ba ce 82 59 a6 ab 89  signature: fixed(64)
      6b 97 68 2f 8d 86 bd 1d
      32 a6 2c 22 dd 93 93 70
      8c 1e bb 3a 39 e0 db 25
      62 67 e8 d9 a9 0b 83 ef
      e0 c5 de d9 bd 6f 02 cc
      04 4b c6 20 56 f5 95 df
      87 8d 7e 6f 3b d2 03 06
0181  end
```

The tablet processes it by section 8.3. It holds the record, so step 10 passes. The merge, for the two names the message holds:

| Field      | Own (tablet)      | Other (the message)                  | Stands | Why              |
| ---------- | ----------------- | ------------------------------------ | ------ | ---------------- |
| `start`    | 10:00, 100, phone | 10:30, 110, phone                    | other  | 110 is above 100 |
| `location` | "", 100, phone    | "Dr. Weber, Hauptstr. 5", 110, phone | other  | 110 is above 100 |

The tablet took two field states, so the outcome is `APPLIED`. It had given or seen the stamps up to 105; it counts 110 and 111 as seen and takes a new state stamp above 111: here 115. The two parts are delivered to the phone, from which they came, so nothing is due for the phone. The tablet's `ACK` to the phone carries one entry:

| Field              | Value                                  |
| ------------------ | -------------------------------------- |
| `to`               | the phone's key                        |
| `id`               | `3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80` |
| `version`          | 111                                    |
| `outcome`          | `APPLIED`                              |
| `receiver_version` | 115, the tablet's new state stamp      |
| `kept_fields`      | empty                                  |

The `ACK`: 198 bytes, SHA-256 `65fd9649e305db3f519d411200bec4a7707f42d554920fabebad2c287231d0d7`. When the phone takes it, the two parts are delivered to the tablet, and the phone counts 115 as a stamp it has seen and as the highest state stamp of the record it has seen from a sibling (section 9.2). Both devices hold the same seven field states; the state stamps are 111 on the phone and 115 on the tablet. Should another app answer a `DATA` of the phone under the version 111 with `STALE` and the version 115, the phone knows that version and does nothing more (section 5.3).

### 16.3 A `RESYNC`

The phone restores a backup that was made before the change of section 16.2. It holds the state of section 16.1 again, with the state stamp 101, and has given or seen the stamps up to 101. Each of its field states has the stamp 100, so none becomes a field state of unknown age (section 4.6). It discards the bookkeeping of the backup, opens a request to the tablet with the id `7c1d9e42-5a3b-4f6c-8d2e-1b0a9c8f7e6d`, a UUID of version 4 chosen for this example, and sends the tablet a `RESYNC` before any `CHANGE` (sections 11.3 and 12.1):

| Part of the message | Value                                                                                                                                                     |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `format`            | 1                                                                                                                                                         |
| `kind`              | `RESYNC`                                                                                                                                                  |
| `sender`            | the phone's key                                                                                                                                           |
| `record.id`         | `7c1d9e42-5a3b-4f6c-8d2e-1b0a9c8f7e6d`, the id of the request                                                                                             |
| `record.version`    | 1                                                                                                                                                         |
| `to`                | the tablet's key                                                                                                                                          |
| `signature`         | the phone's signature: `e20d45349bb0ef2e789025187c27a56e312e6d6e703ee1b8cd4b43f64307dda8ab111f379f43492e8b0b53d697551a5e72f16b2f4f1e2b850412809e89b0c10d` |

The message: 190 bytes, SHA-256 `e5d8e0b5896571fb1228062365802a0690a0f1f21778d478de8621f48d49ae16`. Its bytes, with offsets in hexadecimal; the signature covers the prefix `AXT-v1 message` with its zero byte and the bytes from offset `000a` to the signature ([keys.md](keys.md), section 2.2):

```text
0000  c3 01                    single-object marker
0002  16 30 6f 71 b9 ce 9e a8  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  18                       kind: enum index 12, RESYNC
000c  c3 38 de 9e 8b c4 ca 4a  sender: fixed(32), the phone's test key
      88 6f 9d ae fc 0a 4f 47
      6b d7 c5 fc cf 0d 0a 43
      05 74 d0 fd b8 50 8c e0
002c  02                       record: union index 1, axt.RecordRef
002d  48                       record.id: string length 36
002e  37 63 31 64 39 65 34 32  "7c1d9e42-5a3b-4f6c-8d2e-1b0a9c8f7e6d"
      2d 35 61 33 62 2d 34 66
      36 63 2d 38 64 32 65 2d
      31 62 30 61 39 63 38 66
      37 65 36 64
0052  02                       record.version: long 1
0053  54                       body: bytes length 42
0054  c3 01                    body: single-object marker
0056  f1 fd 59 d5 d9 2b 76 e8  body: fingerprint of axt.Resync, format 1
005e  ee 08 ea a3 d8 aa 50 73  body: to: fixed(32), the tablet's test key
      43 bc 02 92 4f e9 8d 02
      f9 e4 47 16 27 ac e6 15
      54 f1 b4 96 35 f2 4a b2
007e  e2 0d 45 34 9b b0 ef 2e  signature: fixed(64)
      78 90 25 18 7c 27 a5 6e
      31 2e 6d 6e 70 3e e1 b8
      cd 4b 43 f6 43 07 dd a8
      ab 11 1f 37 9f 43 49 2e
      8b 0b 53 d6 97 55 1a 5e
      72 f1 6b 2f 4f 1e 2b 85
      04 12 80 9e 89 b0 c1 0d
00be  end
```

The tablet has not acted on a request with that id. It keeps the id and forgets what it kept for the phone: the appointment is no longer known to the phone, none of its parts is delivered to it, and an outcome of the phone for the `CHANGE` messages that the tablet sent it before is ignored from now on. It sends the phone every record of which it holds a state, each whole and under a new state stamp, and then acknowledges the request (section 11.2).

### 16.4 A whole `CHANGE`, and the end of the answer

The tablet has given or seen the stamps up to 115. Before it sends the appointment in answer to the `RESYNC` of section 16.3, it takes a new state stamp for it, above 115: here 117 (section 3.3, occasion 6). Its `CHANGE` carries every field state it holds:

| Part of the message | Value                                                                                                                                                      |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `format`            | 1                                                                                                                                                          |
| `kind`              | `CHANGE`                                                                                                                                                   |
| `sender`            | the tablet's key                                                                                                                                           |
| `record.id`         | `3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80`                                                                                                                     |
| `record.version`    | 117, the highest of 117, 100 and 110                                                                                                                       |
| `to`                | the phone's key                                                                                                                                            |
| `origin`            | `null`                                                                                                                                                     |
| `type`              | `axt.example.v1.Appointment`                                                                                                                               |
| `state`             | 117                                                                                                                                                        |
| `whole`             | `true`                                                                                                                                                     |
| `removal`           | `null`                                                                                                                                                     |
| `fields`            | seven entries, in the order of the schema's fields                                                                                                         |
| `signature`         | the tablet's signature: `9ab0779d184c6b409b3fe4badded825b1e0ccbc18bb5e38f731a34f73083b07046176b748f7cb138ca1877c83ccf006ea033563562a5a186e231eb3db2274803` |

| `name`      | `schema`                         | `value`                                                   | `stamp` | `device` |
| ----------- | -------------------------------- | --------------------------------------------------------- | ------- | -------- |
| `title`     | the fingerprint of Appointment.1 | "Vet"; as bytes: `06 56 65 74`                            | 100     | phone    |
| `start`     | the fingerprint of Appointment.1 | 2025-11-18 10:30, the value and the bytes of section 16.2 | 110     | phone    |
| `end`       | the fingerprint of Appointment.1 | `null`; as bytes: `00`                                    | 100     | phone    |
| `all_day`   | the fingerprint of Appointment.1 | `false`; as bytes: `00`                                   | 100     | phone    |
| `location`  | the fingerprint of Appointment.1 | "Dr. Weber, Hauptstr. 5", the bytes of section 16.2       | 110     | phone    |
| `notes`     | the fingerprint of Appointment.1 | ""; as bytes: `00`                                        | 100     | phone    |
| `reminders` | the fingerprint of Appointment.1 | an empty array; as bytes: `00`                            | 100     | phone    |

The message: 647 bytes, SHA-256 `1c33361873354e9b7c22f6f5569431c99fb51e60fa56d3e6ecc1ac117bd00e3f`. Its bytes, with offsets in hexadecimal; the signature covers the prefix `AXT-v1 message` with its zero byte and the bytes from offset `000a` to the signature ([keys.md](keys.md), section 2.2):

```text
0000  c3 01                    single-object marker
0002  16 30 6f 71 b9 ce 9e a8  fingerprint of axt.Envelope, format 1
000a  02                       format: int 1
000b  16                       kind: enum index 11, CHANGE
000c  ee 08 ea a3 d8 aa 50 73  sender: fixed(32), the tablet's test key
      43 bc 02 92 4f e9 8d 02
      f9 e4 47 16 27 ac e6 15
      54 f1 b4 96 35 f2 4a b2
002c  02                       record: union index 1, axt.RecordRef
002d  48                       record.id: string length 36
002e  33 66 32 63 38 61 35 65  "3f2c8a5e-9b1d-4c7e-8a6f-2d4b5c6e7f80"
      2d 39 62 31 64 2d 34 63
      37 65 2d 38 61 36 66 2d
      32 64 34 62 35 63 36 65
      37 66 38 30
0052  ea 01                    record.version: long 117
0054  e2 07                    body: bytes length 497
0056  c3 01                    body: single-object marker
0058  e8 62 9d fc ca 9a 84 d3  body: fingerprint of axt.Change, format 1
0060  c3 38 de 9e 8b c4 ca 4a  body: to: fixed(32), the phone's test key
      88 6f 9d ae fc 0a 4f 47
      6b d7 c5 fc cf 0d 0a 43
      05 74 d0 fd b8 50 8c e0
0080  00                       body: origin: union index 0, null
0081  34                       body: type: string length 26
0082  61 78 74 2e 65 78 61 6d  body: "axt.example.v1.Appointment"
      70 6c 65 2e 76 31 2e 41
      70 70 6f 69 6e 74 6d 65
      6e 74
009c  ea 01                    body: state: long 117
009e  01                       body: whole: boolean true
009f  00                       body: removal: union index 0, null
00a0  0e                       body: fields: array block of 7 items
00a1  0a                       body: fields[0].name: string length 5
00a2  74 69 74 6c 65           body: "title"
00a7  cd 30 64 2b f8 07 f2 1a  body: fields[0].schema: fixed(8), fingerprint of axt.example.v1.Appointment, version 1
00af  02                       body: fields[0].value: union index 1, bytes
00b0  08                       body: fields[0].value: bytes length 4
00b1  06 56 65 74              body: the value: "Vet" as an Avro string
00b5  c8 01                    body: fields[0].stamp: long 100
00b7  c3 38 de 9e 8b c4 ca 4a  body: fields[0].device: fixed(32), the phone's test key
      88 6f 9d ae fc 0a 4f 47
      6b d7 c5 fc cf 0d 0a 43
      05 74 d0 fd b8 50 8c e0
00d7  0a                       body: fields[1].name: string length 5
00d8  73 74 61 72 74           body: "start"
00dd  cd 30 64 2b f8 07 f2 1a  body: fields[1].schema: fixed(8), fingerprint of axt.example.v1.Appointment, version 1
00e5  02                       body: fields[1].value: union index 1, bytes
00e6  42                       body: fields[1].value: bytes length 33
00e7  d2 1f 16 24 14 3c 00 00  body: the value: an axt.DateTime, 2025-11-18 10:30:00.000 in Europe/Berlin
      02 1a 45 75 72 6f 70 65
      2f 42 65 72 6c 69 6e 02
      a0 38 02 80 c7 e5 e4 d2
      66
0108  dc 01                    body: fields[1].stamp: long 110
010a  c3 38 de 9e 8b c4 ca 4a  body: fields[1].device: fixed(32), the phone's test key
      88 6f 9d ae fc 0a 4f 47
      6b d7 c5 fc cf 0d 0a 43
      05 74 d0 fd b8 50 8c e0
012a  06                       body: fields[2].name: string length 3
012b  65 6e 64                 body: "end"
012e  cd 30 64 2b f8 07 f2 1a  body: fields[2].schema: fixed(8), fingerprint of axt.example.v1.Appointment, version 1
0136  02                       body: fields[2].value: union index 1, bytes
0137  02                       body: fields[2].value: bytes length 1
0138  00                       body: the value: union index 0, null
0139  c8 01                    body: fields[2].stamp: long 100
013b  c3 38 de 9e 8b c4 ca 4a  body: fields[2].device: fixed(32), the phone's test key
      88 6f 9d ae fc 0a 4f 47
      6b d7 c5 fc cf 0d 0a 43
      05 74 d0 fd b8 50 8c e0
015b  0e                       body: fields[3].name: string length 7
015c  61 6c 6c 5f 64 61 79     body: "all_day"
0163  cd 30 64 2b f8 07 f2 1a  body: fields[3].schema: fixed(8), fingerprint of axt.example.v1.Appointment, version 1
016b  02                       body: fields[3].value: union index 1, bytes
016c  02                       body: fields[3].value: bytes length 1
016d  00                       body: the value: boolean false
016e  c8 01                    body: fields[3].stamp: long 100
0170  c3 38 de 9e 8b c4 ca 4a  body: fields[3].device: fixed(32), the phone's test key
      88 6f 9d ae fc 0a 4f 47
      6b d7 c5 fc cf 0d 0a 43
      05 74 d0 fd b8 50 8c e0
0190  10                       body: fields[4].name: string length 8
0191  6c 6f 63 61 74 69 6f 6e  body: "location"
0199  cd 30 64 2b f8 07 f2 1a  body: fields[4].schema: fixed(8), fingerprint of axt.example.v1.Appointment, version 1
01a1  02                       body: fields[4].value: union index 1, bytes
01a2  2e                       body: fields[4].value: bytes length 23
01a3  2c 44 72 2e 20 57 65 62  body: the value: "Dr. Weber, Hauptstr. 5" as an Avro string
      65 72 2c 20 48 61 75 70
      74 73 74 72 2e 20 35
01ba  dc 01                    body: fields[4].stamp: long 110
01bc  c3 38 de 9e 8b c4 ca 4a  body: fields[4].device: fixed(32), the phone's test key
      88 6f 9d ae fc 0a 4f 47
      6b d7 c5 fc cf 0d 0a 43
      05 74 d0 fd b8 50 8c e0
01dc  0a                       body: fields[5].name: string length 5
01dd  6e 6f 74 65 73           body: "notes"
01e2  cd 30 64 2b f8 07 f2 1a  body: fields[5].schema: fixed(8), fingerprint of axt.example.v1.Appointment, version 1
01ea  02                       body: fields[5].value: union index 1, bytes
01eb  02                       body: fields[5].value: bytes length 1
01ec  00                       body: the value: a string of length 0
01ed  c8 01                    body: fields[5].stamp: long 100
01ef  c3 38 de 9e 8b c4 ca 4a  body: fields[5].device: fixed(32), the phone's test key
      88 6f 9d ae fc 0a 4f 47
      6b d7 c5 fc cf 0d 0a 43
      05 74 d0 fd b8 50 8c e0
020f  12                       body: fields[6].name: string length 9
0210  72 65 6d 69 6e 64 65 72  body: "reminders"
      73
0219  cd 30 64 2b f8 07 f2 1a  body: fields[6].schema: fixed(8), fingerprint of axt.example.v1.Appointment, version 1
0221  02                       body: fields[6].value: union index 1, bytes
0222  02                       body: fields[6].value: bytes length 1
0223  00                       body: the value: an array without items
0224  c8 01                    body: fields[6].stamp: long 100
0226  c3 38 de 9e 8b c4 ca 4a  body: fields[6].device: fixed(32), the phone's test key
      88 6f 9d ae fc 0a 4f 47
      6b d7 c5 fc cf 0d 0a 43
      05 74 d0 fd b8 50 8c e0
0246  00                       body: fields: end of the array
0247  9a b0 77 9d 18 4c 6b 40  signature: fixed(64)
      9b 3f e4 ba dd ed 82 5b
      1e 0c cb c1 8b b5 e3 8f
      73 1a 34 f7 30 83 b0 70
      46 17 6b 74 8f 7c b1 38
      ca 18 77 c8 3c cf 00 6e
      a0 33 56 35 62 a5 a1 86
      e2 31 eb 3d b2 27 48 03
0287  end
```

The tablet signs the message, although the phone made every change in it (section 13.1). The phone processes it and merges:

| Field       | Own (phone, restored) | Other (the message)                  | Stands | Why                  |
| ----------- | --------------------- | ------------------------------------ | ------ | -------------------- |
| `title`     | "Vet", 100, phone     | "Vet", 100, phone                    | own    | the same field state |
| `start`     | 10:00, 100, phone     | 10:30, 110, phone                    | other  | 110 is above 100     |
| `end`       | `null`, 100, phone    | `null`, 100, phone                   | own    | the same field state |
| `all_day`   | `false`, 100, phone   | `false`, 100, phone                  | own    | the same field state |
| `location`  | "", 100, phone        | "Dr. Weber, Hauptstr. 5", 110, phone | other  | 110 is above 100     |
| `notes`     | "", 100, phone        | "", 100, phone                       | own    | the same field state |
| `reminders` | empty, 100, phone     | empty, 100, phone                    | own    | the same field state |

The phone took two field states, so the outcome is `APPLIED`: the change it had lost with the restore is back. It had given or seen the stamps up to 101; it counts 100, 110 and 117 as seen and takes a new state stamp above 117: here 118. Its `ACK` to the tablet carries the id, the version 117, `APPLIED`, the `receiver_version` 118, its new state stamp, and no kept field: 198 bytes, SHA-256 `e2e067426df1ebbe2315f47ece97042da721c4981cb512642f6d6c6f251578b8`. On the phone, the record is known to the tablet, and all seven parts of the message are delivered to it, the two it took and the five it held already. When the tablet takes the `ACK`, the record is known to the phone again, its seven parts are delivered to it, and the tablet counts 118 as seen.

The appointment is the only record the tablet holds, so its answer is complete with that `CHANGE`. After it, the tablet acknowledges the request, in an `ACK` to the phone with one entry:

| Field              | Value                                                         |
| ------------------ | ------------------------------------------------------------- |
| `to`               | the phone's key                                               |
| `id`               | `7c1d9e42-5a3b-4f6c-8d2e-1b0a9c8f7e6d`, the id of the request |
| `version`          | 1                                                             |
| `outcome`          | `APPLIED`                                                     |
| `receiver_version` | 1                                                             |
| `kept_fields`      | empty                                                         |

That `ACK`: 196 bytes, SHA-256 `d6283680f586f43c358f0f2d3a5aceb18f19d6f1373c8549f008fb0d7d9e8317`. When the phone takes it, its request is closed: the tablet has sent its answer, the phone may let its user change records again, and sends the tablet what is due for it, which here is nothing (sections 11.3 and 12.1). Had the phone sent the same `RESYNC` once more, the tablet would not have acted on it again and would have answered with the same entry and the outcome `DUPLICATE`.

Had the tablet's message carried only `start` and `location`, with `whole` `false`, the phone would have merged it in the same way, since it holds the record. A device without the record, such as a phone that restored a backup made before the appointment existed, would have answered such a message with `RECORD_UNKNOWN`, and the tablet would have sent a whole message.

## References

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): key words for requirement levels
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032): Ed25519
