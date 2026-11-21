// SPDX-License-Identifier: Apache-2.0 OR MIT
// Tests for scripts/site/markdown.js: the Markdown of spec/ as pages of the Specification track.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  convertDocument,
  inline,
  readDocument,
  readIndex,
  sectionId,
  sectionNumbers,
  specPages,
  splitRow,
} from "../../scripts/site/markdown.js";
import { collectPages } from "../../scripts/build-site.js";

const KEYS = `# Keys

## 5. Devices

### 5.3 Adding a device

Text.

## 6. Tests
`;

const SYNC = `# Sync

## 2. Stamps

## 21. Received

### 21.1 Kept

## 22. Merge

### 22.1 Fields
`;

/**
 * A context for converting `source` as spec/page.md beside keys.md and sync.md.
 * @param {string} source
 * @param {boolean} [strict]
 */
function context(source, strict = true) {
  const doc = readDocument(
    "page.md",
    `# Page\n\n## 1. One\n\n## 2. Two\n\n### 2.1 Sub\n\n## 3. Three\n\n${source}`,
  );
  const docs = new Map([
    ["page.md", doc],
    ["keys.md", readDocument("keys.md", KEYS)],
    ["sync.md", readDocument("sync.md", SYNC)],
    ["README.md", readDocument("README.md", "# Index\n")],
  ]);
  /** @type {string[]} */
  const warnings = [];
  return { doc, docs, repoUrl: "https://github.com/paxel/axt", ref: "v9.9.9", strict, warnings };
}

/**
 * The HTML of one line of inline Markdown of spec/page.md.
 * @param {string} text
 */
const line = (text) => inline(text, context(""));

void test("numbered headings get ids from their numbers; the first heading is the title", () => {
  assert.equal(sectionId("5.3"), "section-5-3");
  assert.deepEqual([...sectionNumbers(KEYS)], ["5", "5.3", "6"]);
  assert.deepEqual(
    [...sectionNumbers("```text\n## 9. Not a heading\n```\n## 1. Real\n")],
    ["1"],
    "a heading inside a code block is none",
  );
  const doc = readDocument("keys.md", "# Keys, `signatures`\n");
  assert.equal(doc.title, "Keys, signatures");
  assert.equal(readDocument("README.md", "# X\n").name, "index");
  assert.throws(() => readDocument("x.md", "no heading"), /spec\/x\.md: no heading/);
  const html = convertDocument(context("## References\n"));
  assert.doesNotMatch(html, /<h1>/);
  assert.match(html, /<h2 id="section-1">1\. One<\/h2>/);
  assert.match(html, /<h3 id="section-2-1">2\.1 Sub<\/h3>/);
  assert.match(
    html,
    /<h2>References<\/h2>/,
    "an unnumbered heading gets its id from the page build",
  );
});

void test("inline Markdown: code spans, bold, links, escapes, and HTML in the text escaped", () => {
  assert.equal(line("a `<b>` and ``x ` y``"), "a <code>&lt;b&gt;</code> and <code>x ` y</code>");
  assert.equal(line("**Bold `c`** text"), "<strong>Bold <code>c</code></strong> text");
  assert.equal(
    line("write `\\^` as \\* <tag> & co"),
    "write <code>\\^</code> as * &lt;tag&gt; &amp; co",
  );
  assert.equal(line("[`keys.md`](keys.md)"), '<a href="keys.html"><code>keys.md</code></a>');
  assert.equal(line("[index](README.md)"), '<a href="index.html">index</a>');
  assert.equal(line("[x](https://example.org/a)"), '<a href="https://example.org/a">x</a>');
  assert.equal(line("[top](#section-1)"), '<a href="#section-1">top</a>');
  assert.equal(
    line("[Envelope.avsc](../types/axt/Envelope.avsc) and [types](../types/axt/)"),
    '<a href="https://github.com/paxel/axt/blob/v9.9.9/types/axt/Envelope.avsc">Envelope.avsc</a> and ' +
      '<a href="https://github.com/paxel/axt/tree/v9.9.9/types/axt/">types</a>',
  );
  assert.throws(() => line("[x](../../etc/passwd)"), /leaves the repository/);
  assert.equal(line("an [unclosed link"), "an [unclosed link");
});

void test("a reference right after a link goes to that document; a bare one to the page itself", () => {
  assert.equal(
    line("([keys.md](keys.md), section 5.3)"),
    '(<a href="keys.html">keys.md</a>, section <a href="keys.html#section-5-3">5.3</a>)',
  );
  assert.equal(line("as section 2.1 says."), 'as section <a href="#section-2-1">2.1</a> says.');
  assert.equal(line("Section 3, then"), 'Section <a href="#section-3">3</a>, then');
  assert.equal(
    line("sections 1, 2 and 3 or sections 1 to 3"),
    'sections <a href="#section-1">1</a>, <a href="#section-2">2</a> and <a href="#section-3">3</a> or ' +
      'sections <a href="#section-1">1</a> to <a href="#section-3">3</a>',
  );
  assert.equal(
    line("section 1, 2 bytes"),
    'section <a href="#section-1">1</a>, 2 bytes',
    "a singular section takes one number",
  );
});

void test("there, parentheses and semicolons decide which document a reference names", () => {
  assert.equal(
    line("[sync.md](sync.md) merges (sections 21.1 and 22.1 there)"),
    '<a href="sync.html">sync.md</a> merges (sections <a href="sync.html#section-21-1">21.1</a> and ' +
      '<a href="sync.html#section-22-1">22.1</a> there)',
  );
  assert.equal(
    line("[keys.md](keys.md) and [sync.md](sync.md): (section 5.3 there)"),
    '<a href="keys.html">keys.md</a> and <a href="sync.html">sync.md</a>: (section ' +
      '<a href="keys.html#section-5-3">5.3</a> there)',
    "there is the document linked last that has the section",
  );
  assert.equal(
    line(
      "([sync.md](sync.md), sections 2, and for a received record sections 21.1 and 22.1) and section 1",
    ),
    '(<a href="sync.html">sync.md</a>, sections <a href="sync.html#section-2">2</a>, and for a received ' +
      'record sections <a href="sync.html#section-21-1">21.1</a> and <a href="sync.html#section-22-1">22.1</a>) ' +
      'and section <a href="#section-1">1</a>',
  );
  assert.equal(
    line("([keys.md](keys.md), section 5; section 2)"),
    '(<a href="keys.html">keys.md</a>, section <a href="keys.html#section-5">5</a>; section ' +
      '<a href="#section-2">2</a>)',
  );
  assert.equal(
    line("of [keys.md](keys.md), section 6, and the 3 of section 5.3"),
    'of <a href="keys.html">keys.md</a>, section <a href="keys.html#section-6">6</a>, and the 3 of section ' +
      '<a href="keys.html#section-5-3">5.3</a>',
    "a bare reference the page lacks continues the document linked before",
  );
});

void test("references to other standards stay text", () => {
  assert.equal(
    line("[RFC 8032, section 5.1.5](https://x.org)"),
    '<a href="https://x.org">RFC 8032, section 5.1.5</a>',
  );
  assert.equal(line("RFC 5646, section 2.1"), "RFC 5646, section 2.1");
  assert.equal(
    line("the vectors of RFC 8032 (section 7.1)"),
    "the vectors of RFC 8032 (section 7.1)",
  );
  assert.equal(
    line("[RFC 3986](https://x.org), section 3"),
    '<a href="https://x.org">RFC 3986</a>, section 3',
  );
  assert.equal(line("a name of its section 4"), "a name of its section 4");
});

void test("a reference to a missing section fails, or is reported when the build tolerates it", () => {
  assert.throws(
    () => inline("see section 9", context("")),
    /"section 9" in spec\/page\.md names no section of spec\/page\.md/,
  );
  assert.throws(
    () => inline("[keys.md](keys.md), section 7", context("")),
    /no section of spec\/keys\.md/,
  );
  const ctx = context("", false);
  assert.equal(
    inline("see sections 1 and 9", ctx),
    'see sections <a href="#section-1">1</a> and 9',
  );
  assert.deepEqual(ctx.warnings, ['"sections 9" in spec/page.md names no section of spec/page.md']);
});

void test("lists: nested, ordered with a start, loose with continued paragraphs", () => {
  const html = convertDocument(
    context(
      "- one\n- two\n  - two a\n  - two b\n- three\n\n3. third\n4. fourth\n   - inner\n5. fifth\n",
    ),
  );
  assert.match(html, /<ul>\n<li>one<\/li>\n<li>two<ul>|<li>two\n<ul>/);
  assert.match(html, /<li>two a<\/li>\n<li>two b<\/li>/);
  assert.match(html, /<ol start="3">\n<li>third<\/li>/);
  assert.match(html, /<li>fourth\n<ul>\n<li>inner<\/li>\n<\/ul><\/li>\n<li>fifth<\/li>\n<\/ol>/);
  const loose = convertDocument(
    context("1. first\n   more of it\n\n   A second paragraph.\n2. second\n\nAfter.\n"),
  );
  assert.match(
    loose,
    /<li><p>first more of it<\/p>\n<p>A second paragraph\.<\/p><\/li>\n<li><p>second<\/p><\/li>/,
  );
  assert.match(loose, /<\/ol>\n<p>After\.<\/p>/);
  const mixed = convertDocument(context("- a\n1. b\n"));
  assert.match(
    mixed,
    /<ul>\n<li>a<\/li>\n<\/ul>\n<ol>\n<li>b<\/li>\n<\/ol>/,
    "another marker ends the list",
  );
});

void test("tables, code blocks, rules and paragraphs", () => {
  assert.deepEqual(splitRow("| `a|b` | c \\| d |"), ["`a|b`", "c \\| d"]);
  const html = convertDocument(
    context(
      '| Name | Value |\n| ---- | ----- |\n| `x` | section 1 |\n\n```json\n{"a": "<b>"}\n```\n\n```\nplain\n```\n\n---\n\nOne line\nand the next.\n',
    ),
  );
  assert.match(html, /<table>\n<thead><tr><th>Name<\/th><th>Value<\/th><\/tr><\/thead>/);
  assert.match(
    html,
    /<tr><td><code>x<\/code><\/td><td>section <a href="#section-1">1<\/a><\/td><\/tr>/,
  );
  assert.match(
    html,
    /<pre><code class="language-json">\{&quot;a&quot;: &quot;&lt;b&gt;&quot;\}<\/code><\/pre>/,
  );
  assert.match(html, /<pre><code>plain<\/code><\/pre>/);
  assert.match(html, /<hr>/);
  assert.match(html, /<p>One line and the next\.<\/p>/);
  assert.throws(
    () => convertDocument(context("```text\nopen\n")),
    /spec\/page\.md:\d+: unclosed code block/,
  );
  assert.match(convertDocument(context("| not a table\n")), /<p>\| not a table<\/p>/);
});

/** @type {string} */
let tmp;

before(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "axt-site-spec-"));
  const spec = path.join(tmp, "spec");
  fs.mkdirSync(spec);
  fs.writeFileSync(
    path.join(spec, "README.md"),
    "# AXT specification\n\n| Document | Purpose |\n| --- | --- |\n| [Keys](keys.md) | Signatures, `keys` |\n| [Sync](sync.md) | Stamps |\n",
  );
  fs.writeFileSync(path.join(spec, "keys.md"), `${KEYS}\nSee [sync.md](sync.md), section 21.1.\n`);
  fs.writeFileSync(path.join(spec, "sync.md"), SYNC);
  fs.writeFileSync(path.join(spec, "extra.md"), "# Extra\n");
});

after(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

void test("the index gives the order and the summaries of the Specification track", () => {
  const index = readDocument(
    "README.md",
    "# I\n\n| D | P |\n| --- | --- |\n| [B](b.md) | Bee |\n| [A](a.md) | `Ay` |\n| [B](b.md) | again |\n",
  );
  assert.deepEqual(
    [...readIndex(index)],
    [
      ["b.md", { order: 1, purpose: "Bee" }],
      ["a.md", { order: 2, purpose: "Ay" }],
    ],
  );
  const { pages, warnings } = specPages(path.join(tmp, "spec"), {
    repoUrl: "https://github.com/paxel/axt",
    ref: "summer",
    strict: true,
  });
  assert.deepEqual(warnings, []);
  assert.deepEqual(
    pages.map((p) => [p.url, p.title, p.order, p.summary, p.track]),
    [
      ["spec/index.html", "Specification", 0, "The documents of the AXT specification.", "spec"],
      ["spec/extra.html", "Extra", 3, "", "spec"],
      ["spec/keys.html", "Keys", 1, "Signatures, keys", "spec"],
      ["spec/sync.html", "Sync", 2, "Stamps", "spec"],
    ],
  );
  assert.match(
    pages.find((p) => p.url === "spec/keys.html")?.body ?? "",
    /<a href="sync\.html#section-21-1">21\.1<\/a>/,
  );
});

void test("collectPages adds the spec pages beside the site's, and a landing page for a spec-only release", () => {
  const site = path.join(tmp, "site");
  fs.mkdirSync(site, { recursive: true });
  fs.writeFileSync(path.join(site, "index.html"), '<!-- page: title="Home" -->\n<p>Home</p>');
  const pages = collectPages({ srcDir: site });
  assert.deepEqual(
    pages.map((p) => p.url),
    ["index.html", "spec/index.html", "spec/keys.html", "spec/sync.html", "spec/extra.html"],
  );
  const specOnly = collectPages({
    srcDir: path.join(tmp, "nosite"),
    specDir: path.join(tmp, "spec"),
  });
  const landing = specOnly.find((p) => p.url === "index.html");
  assert.ok(landing);
  assert.match(landing.body, /The specification of AXT as it was released/);
  fs.mkdirSync(path.join(site, "spec"));
  fs.writeFileSync(
    path.join(site, "spec/keys.html"),
    '<!-- page: title="Keys" track="spec" -->\n<p>x</p>',
  );
  assert.throws(
    () => collectPages({ srcDir: site }),
    /spec\/keys\.html: written in .* and converted from/,
  );
  assert.throws(
    () => collectPages({ srcDir: path.join(tmp, "nosite"), specDir: path.join(tmp, "nospec") }),
    /no index\.html/,
  );
});
