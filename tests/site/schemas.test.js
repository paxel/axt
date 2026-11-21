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
  canonicalForm,
  crc64avro,
  docMarkdown,
  fingerprintText,
  fullName,
  glossaryHtml,
  readSchemas,
  referencePages,
  symbolMeanings,
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
  /** @type {Map<string, string>} */
  const stated = new Map();
  const specDir = path.join(REPO_ROOT, "spec");
  for (const file of fs.readdirSync(specDir)) {
    const text = fs.readFileSync(path.join(specDir, file), "utf8");
    for (const m of text.matchAll(/^\| `(axt\.[A-Za-z0-9.]+)`[^\n]*?`(0x[0-9a-f]{16})`/gm)) {
      stated.set(m[1] ?? "", m[2] ?? "");
    }
  }
  const schemas = [
    ...readSchemas(REPO_ROOT, "types/axt"),
    ...readSchemas(REPO_ROOT, "types/axt/example/v1"),
  ];
  assert.ok(stated.size >= 29, `the tables state ${String(stated.size)} fingerprints`);
  for (const schema of schemas) {
    const want = stated.get(schema.name);
    if (want) assert.equal(fingerprintText(schema.fingerprint).hex, want, schema.name);
  }
  assert.ok(
    schemas.filter((s) => stated.has(s.name)).length === stated.size,
    "every stated fingerprint belongs to a schema",
  );
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
      ["spec/axt.example.v1.Pet.1.html", 200, false],
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
  assert.match(byUrl("spec/glossary.html"), /<dt id="term-record">/);
  const errors = byUrl("spec/errors.html");
  assert.match(errors, /<h2 id="error-codes">enum <code>axt\.ErrorCode<\/code><\/h2>/);
  assert.match(errors, /<h2 id="outcomes">enum <code>axt\.AckOutcome<\/code><\/h2>/);
  assert.match(errors, /<tr><td><code>BAD<\/code><\/td><td>bad\.<\/td><\/tr>/);
  // The sidebar lists the overviews, not each schema.
  const nav = buildNav(pages);
  assert.deepEqual(
    nav.find((t) => t.id === "spec")?.pages.map((p) => p.url),
    ["spec/schemas.html", "spec/example-types.html", "spec/glossary.html", "spec/errors.html"],
  );
  assert.deepEqual(
    referencePages({ repoRoot: path.join(tmp, "none"), ...convert(), order: 1 }),
    [],
  );
});
