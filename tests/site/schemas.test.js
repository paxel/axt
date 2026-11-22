// SPDX-License-Identifier: Apache-2.0 OR MIT
// Tests for scripts/site/schemas.js: fingerprints, and the reference pages generated from the
// schemas, the example types, CONTEXT.md and the enums of Error.avsc and Ack.avsc.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  brickHtml,
  canonicalForm,
  crc64avro,
  describedTypes,
  docMarkdown,
  fingerprintText,
  fullName,
  glossaryHtml,
  limitValue,
  readSchemas,
  referencePages,
  symbolMeanings,
  textsHtml,
} from "../../scripts/site/schemas.js";
import { readDocument } from "../../scripts/site/markdown.js";
import { buildNav } from "../../scripts/build-site.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

/**
 * A context for converting doc texts on a generated page.
 * @param {boolean} [strict]
 */
function convert(strict = true) {
  const docs = new Map([
    ["records.md", readDocument("records.md", "# Records\n\n## 7. Outcomes\n")],
    ["README.md", readDocument("README.md", "# Index\n")],
  ]);
  /** @type {string[]} */
  const warnings = [];
  return {
    doc: readDocument("glossary.md", "# glossary\n"),
    docs,
    repoUrl: "https://github.com/paxel/axt",
    ref: "summer",
    strict,
    warnings,
  };
}

void test("the Parsing Canonical Form keeps only what it must, in its order, with full names", () => {
  assert.equal(canonicalForm("int"), '"int"');
  assert.equal(canonicalForm({ type: "long", logicalType: "timestamp-millis" }), '"long"');
  assert.equal(
    canonicalForm({
      doc: "dropped",
      fields: [
        { name: "a", type: { type: "fixed", size: 8, name: "F" }, default: "x", doc: "d" },
        { name: "b", type: "F" },
        { name: "c", type: ["null", { type: "enum", name: "x.E", symbols: ["A"], default: "A" }] },
        { name: "d", type: { type: "array", items: "x.E" } },
        { name: "e", type: { type: "map", values: { type: "string", logicalType: "uuid" } } },
        {
          name: "f",
          type: { type: "record", name: "Inner", fields: [{ name: "g", type: "Inner2" }] },
        },
      ],
      name: "R",
      namespace: "ns",
      type: "record",
      "axt.version": 1,
    }),
    '{"name":"ns.R","type":"record","fields":[{"name":"a","type":{"name":"ns.F","type":"fixed","size":8}},' +
      '{"name":"b","type":"ns.F"},{"name":"c","type":["null",{"name":"x.E","type":"enum","symbols":["A"]}]},' +
      '{"name":"d","type":{"type":"array","items":"x.E"}},{"name":"e","type":{"type":"map","values":"string"}},' +
      '{"name":"f","type":{"name":"ns.Inner","type":"record","fields":[{"name":"g","type":"ns.Inner2"}]}}]}',
  );
  assert.throws(() => canonicalForm(7), /not a schema/);
  assert.equal(fullName("a.B", "x", "y"), "a.B");
  assert.equal(fullName("B", "x", "y"), "x.B");
  assert.equal(fullName("B", undefined, "y"), "y.B");
  assert.equal(fullName("B", undefined, ""), "B");
});

void test("CRC-64-AVRO: the empty text, and the fingerprints the specification states", () => {
  assert.equal(crc64avro(""), 0xc15d213aa4d7a795n);
  assert.deepEqual(fingerprintText(0xa89eceb9716f3016n), {
    hex: "0xa89eceb9716f3016",
    bytes: "16 30 6f 71 b9 ce 9e a8",
  });
  assert.equal(fingerprintText(0x1n).hex, "0x0000000000000001");
  // Every fingerprint a table of spec/ states for a schema of types/ is the one computed here.
  // Several versions of a type share its full name, so a name may have several fingerprints.
  /** @type {Map<string, Set<string>>} */
  const stated = new Map();
  const specDir = path.join(REPO_ROOT, "spec");
  for (const file of fs.readdirSync(specDir)) {
    const text = fs.readFileSync(path.join(specDir, file), "utf8");
    for (const m of text.matchAll(/^\| `(axt\.[A-Za-z0-9.]+)`[^\n]*?`(0x[0-9a-f]{16})`/gm)) {
      const name = m[1] ?? "";
      stated.set(name, (stated.get(name) ?? new Set()).add(m[2] ?? ""));
    }
  }
  const schemas = [
    ...readSchemas(REPO_ROOT, "types/axt"),
    ...readSchemas(REPO_ROOT, "types/axt/example/v1"),
  ];
  const statedCount = [...stated.values()].reduce((n, s) => n + s.size, 0);
  assert.ok(statedCount >= 29, `the tables state ${String(statedCount)} fingerprints`);
  /** @type {Set<string>} */
  const matched = new Set();
  for (const schema of schemas) {
    const want = stated.get(schema.name);
    if (!want) continue;
    const hex = fingerprintText(schema.fingerprint).hex;
    assert.ok(want.has(hex), `${schema.file}: ${hex} is not among ${[...want].join(", ")}`);
    matched.add(`${schema.name} ${hex}`);
  }
  assert.equal(matched.size, statedCount, "every stated fingerprint belongs to a schema");
});

void test("doc texts: their Markdown characters escaped, their mentions of spec/ linked", () => {
  assert.equal(
    docMarkdown("A *b* [c] `d`, as spec/records.md, section 7, defines."),
    "A \\*b\\* \\[c\\] \\`d\\`, as [spec/records.md](records.md), section 7, defines.",
  );
});

void test("the meaning of each enum symbol comes from the enum's doc", () => {
  const { intro, meanings, outro } = symbolMeanings(
    "What happened. APPLIED: took it. KEPT: took nothing. The default is for resolution only.",
    ["APPLIED", "KEPT", "MISSING"],
  );
  assert.equal(intro, "What happened.");
  assert.deepEqual(
    [...meanings],
    [
      ["APPLIED", "took it."],
      ["KEPT", "took nothing."],
    ],
  );
  assert.equal(outro, "The default is for resolution only.");
  assert.equal(symbolMeanings("Plain.", ["A"]).intro, "Plain.");
});

void test("the glossary of CONTEXT.md is a definition list with links into the site", () => {
  const html = glossaryHtml(
    "# Context\n\nThe vocabulary, see [spec/](spec/README.md) and [relay](relay/README.md).\n\n" +
      "**Record**: one datum,\nwith its id.\n\n**Sender's layer** and **owner's layer**: what a device holds.\n",
    convert(),
  );
  assert.match(
    html,
    /<p>The vocabulary, see <a href="index\.html">spec\/<\/a> and <a href="https:\/\/github\.com\/paxel\/axt\/blob\/summer\/relay\/README\.md">relay<\/a>\.<\/p>/,
  );
  assert.match(
    html,
    /<dt id="term-record"><strong>Record<\/strong><\/dt>\n<dd>one datum, with its id\.<\/dd>/,
  );
  assert.match(
    html,
    /<dt id="term-sender-s-layer"><strong>Sender's layer<\/strong> and <strong>owner's layer<\/strong><\/dt>/,
  );
});

/** @type {string} */
let tmp;

/**
 * @param {string} rel
 * @param {unknown} json
 */
function writeJson(rel, json) {
  const full = path.join(tmp, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, JSON.stringify(json));
}

before(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "axt-site-schemas-"));
  writeJson("types/axt/Ack.avsc", {
    type: "record",
    name: "Ack",
    namespace: "axt",
    doc: "The body of an ACK. Defined in spec/records.md.",
    fields: [
      { name: "to", type: { type: "fixed", name: "AckTo", size: 32, doc: "A key." }, doc: "Whom." },
      {
        name: "outcome",
        type: {
          type: "enum",
          name: "AckOutcome",
          doc: "As spec/records.md, section 7, defines. APPLIED: took it. KEPT: took nothing.",
          symbols: ["APPLIED", "KEPT"],
          default: "KEPT",
        },
        doc: "What happened.",
      },
      { name: "kept", type: { type: "array", items: "string" }, default: [], doc: "Kept fields." },
    ],
  });
  writeJson("types/axt/Error.avsc", {
    type: "record",
    name: "Error",
    namespace: "axt",
    doc: "The body of an ERROR.",
    fields: [
      {
        name: "code",
        type: { type: "enum", name: "ErrorCode", doc: "Why. BAD: bad.", symbols: ["BAD"] },
        doc: "The code.",
      },
      { name: "field", type: ["null", "string"], default: null, doc: "A field." },
    ],
  });
  writeJson("types/axt/Date.avsc", {
    type: "record",
    name: "Date",
    namespace: "axt",
    doc: "A date.",
    fields: [{ name: "year", type: "int", doc: "The year." }],
  });
  writeJson("types/axt/example/v1/Pet.1.avsc", {
    type: "record",
    name: "Pet",
    namespace: "axt.example.v1",
    doc: "A pet.",
    "axt.version": 1,
    "axt.title": "name",
    "axt.label": "Pet",
    "axt.label_translations": { de: "Haustier" },
    "axt.help": "An animal.",
    "axt.help_translations": { de: "Ein Tier." },
    "axt.emoji": "🐾",
    fields: [
      {
        name: "name",
        type: "string",
        default: "",
        doc: "The name.",
        "axt.label": "Name",
        "axt.label_translations": { de: "Name" },
        "axt.help": "Its name.",
        "axt.help_translations": { de: "Sein Name." },
        "axt.emoji": "🏷️",
        "axt.preferred_length": 40,
      },
      {
        name: "born",
        type: [
          "null",
          {
            type: "record",
            name: "Date",
            namespace: "axt",
            fields: [{ name: "year", type: "int" }],
          },
        ],
        default: null,
        doc: "When.",
      },
      { name: "again", type: ["null", "axt.Date"], default: null, doc: "Again." },
    ],
  });
  writeJson("types/axt/Field.avsc", {
    type: "record",
    name: "Field",
    namespace: "axt",
    doc: "A typed field.",
    fields: [
      { name: "name", type: "string", doc: "Its name (spec/records.md, section 7)." },
      {
        name: "kind",
        doc: "The brick.",
        type: [
          {
            type: "record",
            name: "StringField",
            doc: "Plain text.",
            fields: [
              { name: "max_length", type: ["null", "int"], default: null, doc: "The most." },
              { name: "items", type: ["null", "Field"], default: null, doc: "Itself." },
            ],
          },
          { type: "record", name: "EmailField", doc: "The format email of a text.", fields: [] },
        ],
      },
    ],
  });
  writeJson("types/axt/example/v1/Cat.1.avsc", {
    type: "record",
    name: "Cat",
    namespace: "axt.example.v1",
    doc: "A cat.",
    "axt.version": 1,
    fields: [
      { name: "name", type: "string", default: "", doc: "The name." },
      {
        name: "coat",
        type: {
          type: "enum",
          name: "CatCoat",
          doc: "The coat. UNKNOWN: not known. TABBY: striped.",
          symbols: ["UNKNOWN", "TABBY"],
          default: "UNKNOWN",
        },
        default: "UNKNOWN",
        doc: "The coat.",
      },
      { name: "tags", type: { type: "array", items: "string" }, default: [], doc: "Tags." },
      { name: "extra", type: "string", default: "", doc: "Not described." },
    ],
  });
  /**
   * @param {string} label
   * @param {string} emoji
   */
  const texts = (label, emoji) => ({
    label,
    label_translations: {},
    help: "",
    help_translations: {},
    emoji,
  });
  /**
   * @param {string} name
   * @param {Record<string, unknown>} kind
   * @param {Record<string, unknown>} [common]
   */
  const typed = (name, kind, common = {}) => ({
    name,
    doc: `The ${name}.`,
    texts: texts(name, ""),
    required: false,
    order: null,
    group: "",
    sensitive: false,
    advanced: false,
    kind,
    ...common,
  });
  writeJson("types/axt/example/v1/Cat.1.json", {
    ...typed("cat", {
      "axt.ObjectField": {
        name: "axt.example.v1.Cat",
        fields: [
          typed(
            "name",
            { "axt.StringField": { default: "", max_length: 40, pattern: null, placeholder: "" } },
            { required: true, order: 0, texts: { ...texts("Name", "🏷️"), help: "Its name." } },
          ),
          typed("coat", {
            "axt.EnumField": {
              name: "CatCoat",
              symbols: [
                { symbol: "UNKNOWN", texts: texts("Unknown", "") },
                { symbol: "TABBY", texts: texts("Tabby", "🐅") },
              ],
              fallback: "UNKNOWN",
              default: null,
            },
          }),
          typed("tags", {
            "axt.ListField": { items: typed("tags", { "axt.StringField": { max_length: 32 } }) },
          }),
        ],
        groups: [],
        version: 1,
        title: "name",
      },
    }),
    texts: { ...texts("Cat", "🐈"), label_translations: { de: "Katze" }, help: "A cat." },
  });
  writeJson("types/axt/limits.json", {
    limits: {
      "envelope.message": {
        value: 16777216,
        unit: "bytes",
        what: "One message",
        section: "records.md, section 7",
      },
      "x.wait": { value: 1209600, unit: "seconds", what: "A wait", section: "elsewhere" },
    },
  });
  writeJson("spec/relay-api.json", { openapi: "3.1.0" });
  fs.writeFileSync(path.join(tmp, "CONTEXT.md"), "# Context\n\n**Record**: one datum.\n");
});

after(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

void test("reference pages: overviews, one page per schema out of the sidebar, glossary, errors", () => {
  const ctx = convert();
  const pages = referencePages({ repoRoot: tmp, ...ctx, order: 100 });
  assert.deepEqual(
    pages.map((p) => [p.url, p.order, p.nav ?? true]),
    [
      ["spec/schemas.html", 100, true],
      ["spec/example-types.html", 101, true],
      ["spec/axt.Ack.html", 110, false],
      ["spec/axt.Date.html", 111, false],
      ["spec/axt.Error.html", 112, false],
      ["spec/axt.Field.html", 113, false],
      ["spec/axt.example.v1.Cat.1.html", 200, false],
      ["spec/axt.example.v1.Pet.1.html", 201, false],
      ["spec/bricks.html", 104, true],
      ["spec/limits.html", 105, true],
      ["spec/glossary.html", 102, true],
      ["spec/errors.html", 103, true],
    ],
  );
  assert.deepEqual(ctx.warnings, []);
  const byUrl = (/** @type {string} */ url) => pages.find((p) => p.url === url)?.body ?? "";
  assert.match(
    byUrl("spec/schemas.html"),
    /<a href="axt\.Ack\.html"><code>axt\.Ack<\/code><\/a><\/td><td>The body of an ACK\.<\/td><td><code>0x[0-9a-f]{16}<\/code>/,
  );
  const ack = byUrl("spec/axt.Ack.html");
  assert.match(ack, /Defined in <a href="records\.html">spec\/records\.md<\/a>\./);
  assert.match(
    ack,
    /<h2 id="type-axt-AckTo">fixed <code>axt\.AckTo<\/code><\/h2>\n<p>A key\.<\/p>\n<p>Size: 32 bytes\.<\/p>/,
  );
  assert.match(ack, /<td><a href="#type-axt-AckOutcome"><code>axt\.AckOutcome<\/code><\/a><\/td>/);
  assert.match(
    ack,
    /As <a href="records\.html">spec\/records\.md<\/a>, section <a href="records\.html#section-7">7<\/a>, defines\./,
  );
  assert.match(ack, /<tr><td><code>KEPT<\/code><\/td><td>took nothing\.<\/td><\/tr>/);
  assert.match(ack, /Default symbol: <code>KEPT<\/code>\./);
  assert.match(ack, /<td>array of <code>string<\/code><\/td><td><code>\[\]<\/code><\/td>/);
  assert.match(
    ack,
    /<h2 id="canonical-form">Parsing Canonical Form<\/h2>\n<pre><code class="language-json">\{&quot;name&quot;:&quot;axt\.Ack&quot;/,
  );
  assert.match(
    ack,
    /<a href="https:\/\/github\.com\/paxel\/axt\/blob\/summer\/types\/axt\/Ack\.avsc">types\/axt\/Ack\.avsc<\/a>/,
  );
  assert.match(byUrl("spec/axt.Error.html"), /<code>null<\/code> or <code>string<\/code>/);
  const pet = byUrl("spec/axt.example.v1.Pet.1.html");
  assert.match(
    pet,
    /<p class="lede">🐾 <strong>Pet<\/strong> <span class="translation"><code>de<\/code> Haustier<\/span>: An animal\.<\/p>/,
  );
  assert.match(pet, /<dt>Version<\/dt><dd><code>axt\.version<\/code> 1<\/dd>/);
  assert.match(pet, /<dt>Title field<\/dt><dd><code>name<\/code><\/dd>/);
  assert.match(
    pet,
    /<td>🏷️ Name<br><span class="translation"><code>de<\/code> Name<\/span><br><em>Its name\.<\/em><br><span class="translation"><code>de<\/code> Sein Name\.<\/span><\/td>/,
  );
  assert.match(pet, /<td><code>axt\.preferred_length: 40<\/code><\/td>/);
  assert.match(
    pet,
    /<code>null<\/code> or <a href="axt\.Date\.html"><code>axt\.Date<\/code><\/a>/,
    "a published type links to its page",
  );
  assert.doesNotMatch(pet, /id="type-axt-Date"/, "and gets no section of its own here");
  assert.match(
    byUrl("spec/axt.Date.html"),
    /<h2 id="type-axt-Date">record <code>axt\.Date<\/code><\/h2>/,
  );
  assert.match(byUrl("spec/example-types.html"), /<td>🐾 Pet<\/td>/);
  assert.match(byUrl("spec/example-types.html"), /<td>🐈 Cat<\/td>/);
  const schemas = byUrl("spec/schemas.html");
  assert.match(
    schemas,
    /<li><a href="https:\/\/github\.com\/paxel\/axt\/blob\/summer\/spec\/relay-api\.json"><code>spec\/relay-api\.json<\/code><\/a>: The interface/,
  );
  assert.match(
    schemas,
    /<code>types\/axt\/limits\.json<\/code><\/a>: The limits, also as the page <a href="limits\.html">/,
  );
  assert.doesNotMatch(schemas, /adapter\.schema\.json/, "a file the tree lacks is not linked");
  // An example type with a description: its texts and bricks come from the description.
  const cat = byUrl("spec/axt.example.v1.Cat.1.html");
  assert.match(
    cat,
    /<p class="lede">🐈 <strong>Cat<\/strong> <span class="translation"><code>de<\/code> Katze<\/span>: A cat\.<\/p>/,
  );
  assert.match(cat, /<dt>Version<\/dt><dd><code>version<\/code> 1<\/dd>/);
  assert.match(cat, /<dt>Title field<\/dt><dd><code>name<\/code><\/dd>/);
  assert.match(
    cat,
    /<dt>Description<\/dt><dd><a href="https:\/\/github\.com\/paxel\/axt\/blob\/summer\/types\/axt\/example\/v1\/Cat\.1\.json">/,
  );
  assert.match(cat, /<dt>Derived schema<\/dt>/);
  assert.match(cat, /<th>Brick, checks and hints<\/th>/);
  assert.match(
    cat,
    /<td>🏷️ Name<br><em>Its name\.<\/em><\/td>.*<td><a href="bricks\.html#axt\.StringField"><code>axt\.StringField<\/code><\/a><br><code>required<\/code><br><code>order: 0<\/code><br><code>max_length: 40<\/code><\/td>/,
  );
  assert.match(cat, /<tr><td><code>TABBY<\/code><\/td><td>🐅 Tabby<\/td><td>striped\.<\/td><\/tr>/);
  assert.match(
    cat,
    /<code>axt\.ListField<\/code><\/a><br>items: <a href="bricks\.html#axt\.StringField"><code>axt\.StringField<\/code><\/a><br><code>max_length: 32<\/code>/,
  );
  assert.match(
    cat,
    /<code>extra<\/code><\/td><td><\/td>.*<td><\/td><\/tr>/,
    "a field the description lacks has no texts and no brick",
  );
  const bricks = byUrl("spec/bricks.html");
  assert.match(bricks, /<h2 id="common-part">/);
  assert.match(
    bricks,
    /<tr><td><code>name<\/code><\/td><td><code>string<\/code><\/td><td><\/td><td>Its name \(<a href="records\.html">spec\/records\.md<\/a>/,
  );
  assert.doesNotMatch(bricks, /<td><code>kind<\/code>/, "the union of the bricks is no member");
  assert.match(
    bricks,
    /<tr><td><a href="#axt\.StringField"><code>axt\.StringField<\/code><\/a><\/td><td>Plain text\.<\/td><td><code>max_length<\/code><\/td><\/tr>/,
  );
  assert.match(bricks, /<td><code>format<\/code> \(<code>email<\/code>\)<\/td>/);
  assert.match(
    bricks,
    /<h2 id="axt\.EmailField"><code>axt\.EmailField<\/code><\/h2>\n<p>The format email of a text\.<\/p>\n<p>It has no members\.<\/p>/,
  );
  assert.match(
    bricks,
    /<code>null<\/code> or <a href="axt\.Field\.html#type-axt-Field"><code>axt\.Field<\/code><\/a>/,
    "a type of axt.Field links into its page",
  );
  const limits = byUrl("spec/limits.html");
  assert.match(
    limits,
    /<tr id="envelope\.message"><td><code>envelope\.message<\/code><\/td><td>16,777,216 \(16 MiB\)<\/td><td>bytes<\/td><td>One message<\/td><td><a href="records\.html">records\.md<\/a>, section <a href="records\.html#section-7">7<\/a><\/td><\/tr>/,
  );
  assert.match(
    limits,
    /<td>1,209,600 \(14 days\)<\/td><td>seconds<\/td><td>A wait<\/td><td>elsewhere<\/td>/,
  );
  assert.match(byUrl("spec/glossary.html"), /<dt id="term-record">/);
  const errors = byUrl("spec/errors.html");
  assert.match(errors, /<h2 id="error-codes">enum <code>axt\.ErrorCode<\/code><\/h2>/);
  assert.match(errors, /<h2 id="outcomes">enum <code>axt\.AckOutcome<\/code><\/h2>/);
  assert.match(errors, /<tr><td><code>BAD<\/code><\/td><td>bad\.<\/td><\/tr>/);
  // The sidebar lists the overviews, not each schema.
  const nav = buildNav(pages);
  assert.deepEqual(
    nav.find((t) => t.id === "spec")?.pages.map((p) => p.url),
    [
      "spec/schemas.html",
      "spec/example-types.html",
      "spec/glossary.html",
      "spec/errors.html",
      "spec/bricks.html",
      "spec/limits.html",
    ],
  );
  assert.deepEqual(
    referencePages({ repoRoot: path.join(tmp, "none"), ...convert(), order: 1 }),
    [],
  );
});

void test("limits: a value with the larger unit it is a whole number of", () => {
  assert.equal(limitValue(1, "bytes"), "1");
  assert.equal(limitValue(1024, "bytes"), "1,024 (1 KiB)");
  assert.equal(limitValue(3600, "seconds"), "3,600 (1 hour)");
  assert.equal(limitValue(90, "seconds"), "90");
  assert.equal(limitValue(1000, "entries"), "1,000");
});

void test("descriptions: what is not a typed field yields nothing", () => {
  assert.equal(describedTypes({}).size, 0);
  assert.equal(describedTypes({ kind: { "axt.ObjectField": 1 } }).size, 0);
  assert.equal(brickHtml({ kind: {} }), "");
  assert.equal(textsHtml(null), "");
  assert.equal(textsHtml({ label: "A", emoji: "", help: 3 }), "A");
});

void test("a description that is not an object fails its folder", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "axt-site-description-"));
  try {
    fs.writeFileSync(
      path.join(dir, "A.1.avsc"),
      JSON.stringify({ type: "record", name: "A", fields: [] }),
    );
    fs.writeFileSync(path.join(dir, "A.1.json"), "[]");
    assert.throws(() => readSchemas(dir, "."), /A\.1\.json: not a description/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
