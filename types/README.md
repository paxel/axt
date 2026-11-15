# Example types

This directory holds the example types as Avro schemas: common types such as Note, Task, Appointment and Person, so that apps can exchange records without agreeing on a format first. Every field carries documentation, so a receiver that does not know a type can still show its fields by name and description.

The example types may be evolved or replaced at any time, at the cost of compatibility. Types that belong to a single app live under that app's own namespace and are not kept here.

The rules for the types are in [spec/types.md](../spec/types.md).

## Layout

The path of a schema mirrors its namespace, and its file name is the type's name and its version (the `axt.version` attribute). A published version is never changed; a new version is a new file.

| Path                               | Content                                                                                                                                                                                                             |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [axt/](axt/)                       | The schemas of the specification itself, under the Avro namespace `axt`, such as the envelope defined in [spec/envelope.md](../spec/envelope.md). They are not example types and change only with the specification |
| [axt/example/v1/](axt/example/v1/) | The example types in major version 1, under the namespace `axt.example.v1`, such as `Note.1.avsc` for version 1 of `axt.example.v1.Note`                                                                            |

The namespace `axt` and every namespace beginning with `axt.` are reserved for this repository.

## The example types

| Type                                             | What it holds                                                        |
| ------------------------------------------------ | -------------------------------------------------------------------- |
| [Note](axt/example/v1/Note.1.avsc)               | A text with a title, a format (plain or Markdown) and tags           |
| [Task](axt/example/v1/Task.1.avsc)               | Something to do, with a due date, a repeat rule, done and a priority |
| [Appointment](axt/example/v1/Appointment.1.avsc) | An event with start, end, time zone, place and reminders             |
| [Person](axt/example/v1/Person.1.avsc)           | A contact with name parts, birthday, phones, emails and addresses    |
| [Car](axt/example/v1/Car.1.avsc)                 | A car with make, model, year, plate, VIN and odometer reading        |
| [Pet](axt/example/v1/Pet.1.avsc)                 | An animal with name, species, breed, sex, birthday and microchip     |
| [Measurement](axt/example/v1/Measurement.1.avsc) | One value or count at a point in time, with its unit                 |
| [Document](axt/example/v1/Document.1.avsc)       | A file with a title, a media type and a date                         |

[conformance/tools/example_types.py](../conformance/tools/example_types.py) checks every schema against the rules and prints its fingerprint.

Licence: CC0 1.0, see [LICENSING.md](../LICENSING.md).
