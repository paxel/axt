# Example types

This directory holds the example types as Avro schemas: common types such as Note, Task, Appointment and Person, so that apps can exchange records without agreeing on a format first. Every field carries documentation, so a receiver that does not know a type can still show its fields by name and description.

The example types may be evolved or replaced at any time, at the cost of compatibility. Types that belong to a single app live under that app's own namespace and are not kept here.

The rules for the types are in [spec/types.md](../spec/types.md); the schemas are added in [axt-1002](https://github.com/paxel/axt/issues/3).

The schemas of the specification itself, such as the envelope every message is wrapped in, live in [axt/](axt/) under the Avro namespace `axt`, which is reserved for them. They are not example types and change only with the specification; the envelope is defined in [spec/envelope.md](../spec/envelope.md).

Licence: CC0 1.0, see [LICENSING.md](../LICENSING.md).
