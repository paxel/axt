// SPDX-License-Identifier: Apache-2.0 OR MIT
// Reference pages of the Specification track, generated from the sources so they cannot drift
// from them: one page per schema of types/axt/, one per example type of types/axt/example/v1/,
// the glossary of CONTEXT.md, and the error codes and outcomes of the enums of Error.avsc and
// Ack.avsc. Fingerprints are computed here, without a dependency: the CRC-64-AVRO of the
// Parsing Canonical Form, as the Avro 1.12 specification defines both.

import fs from "node:fs";
import path from "node:path";
import { escapeHtml } from "./html.js";
import { inline, newBlock, readDocument } from "./markdown.js";

/** @typedef {import("./markdown.js").SpecDocument} SpecDocument */
/** @typedef {import("./markdown.js").ConvertContext} ConvertContext */

/**
 * A page this module generates; `nav: false` keeps it out of the sidebar, which lists the
 * overview pages only.
 * @typedef {{ title: string, track: string, order: number, summary: string, url: string, body: string, nav?: boolean }} GeneratedPage
 */

/** @typedef {Record<string, unknown>} JsonObject */

const PRIMITIVES = new Set([
  "null",
  "boolean",
  "int",
  "long",
  "float",
  "double",
  "bytes",
  "string",
]);

/** The attributes the Parsing Canonical Form keeps, in its order. */
const CANONICAL_KEYS = ["name", "type", "fields", "symbols", "items", "values", "size"];

/**
 * An attribute's value as text: a string as it is, anything else as JSON, nothing as "".
 * @param {unknown} value
 * @returns {string}
 */
function str(value) {
  if (typeof value === "string") return value;
  return value === undefined ? "" : JSON.stringify(value);
}

/**
 * @param {unknown} value
 * @returns {value is JsonObject}
 */
function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The full name of a named type: a dotted name stays; otherwise its namespace, or the
 * enclosing one, comes before it.
 * @param {string} name
 * @param {unknown} namespace
 * @param {string} enclosing
 * @returns {string}
 */
export function fullName(name, namespace, enclosing) {
  if (name.includes(".")) return name;
  const space = typeof namespace === "string" ? namespace : enclosing;
  return space ? `${space}.${name}` : name;
}

/**
 * The namespace a full name sets for the types inside it.
 * @param {string} full
 * @returns {string}
 */
function namespaceOf(full) {
  const dot = full.lastIndexOf(".");
  return dot < 0 ? "" : full.slice(0, dot);
}

/**
 * The Parsing Canonical Form of a schema (Avro 1.12, "Parsing Canonical Form for Schemas").
 * @param {unknown} schema
 * @returns {string}
 */
export function canonicalForm(schema) {
  /** @type {Set<string>} */
  const defined = new Set();
  /**
   * @param {unknown} s
   * @param {string} space
   * @returns {string}
   */
  const form = (s, space) => {
    if (typeof s === "string") {
      if (PRIMITIVES.has(s)) return JSON.stringify(s);
      return JSON.stringify(fullName(s, undefined, space));
    }
    if (Array.isArray(s)) return `[${s.map((b) => form(b, space)).join(",")}]`;
    if (!isObject(s)) throw new Error(`not a schema: ${JSON.stringify(s)}`);
    const type = s.type;
    if (typeof type === "string" && PRIMITIVES.has(type)) return JSON.stringify(type);
    if (typeof type !== "string") return form(type, space);
    /** @type {string[]} */
    const parts = [];
    let inner = space;
    if (type === "record" || type === "enum" || type === "fixed") {
      const full = fullName(String(s.name), s.namespace, space);
      if (defined.has(full)) return JSON.stringify(full);
      defined.add(full);
      inner = namespaceOf(full);
      parts.push(`"name":${JSON.stringify(full)}`);
    }
    for (const key of CANONICAL_KEYS) {
      if (key === "name" || !(key in s)) continue;
      const value = s[key];
      if (key === "type") parts.push(`"type":${JSON.stringify(type)}`);
      else if (key === "fields") {
        const fields = /** @type {JsonObject[]} */ (value);
        const each = fields.map(
          (f) => `{"name":${JSON.stringify(String(f.name))},"type":${form(f.type, inner)}}`,
        );
        parts.push(`"fields":[${each.join(",")}]`);
      } else if (key === "symbols") parts.push(`"symbols":${JSON.stringify(value)}`);
      else if (key === "items" || key === "values") parts.push(`"${key}":${form(value, inner)}`);
      else parts.push(`"size":${String(Number(value))}`);
    }
    return `{${parts.join(",")}}`;
  };
  return form(schema, "");
}

const CRC64_EMPTY = 0xc15d213aa4d7a795n;
const MASK64 = (1n << 64n) - 1n;

/** @type {bigint[]} */
const CRC64_TABLE = Array.from({ length: 256 }, (_, i) => {
  let fp = BigInt(i);
  for (let j = 0; j < 8; j++) fp = (fp >> 1n) ^ (CRC64_EMPTY & -(fp & 1n));
  return fp & MASK64;
});

/**
 * The CRC-64-AVRO fingerprint of a text, as an unsigned 64-bit number.
 * @param {string} text
 * @returns {bigint}
 */
export function crc64avro(text) {
  let fp = CRC64_EMPTY;
  for (const byte of Buffer.from(text, "utf8")) {
    fp = (fp >> 8n) ^ /** @type {bigint} */ (CRC64_TABLE[Number((fp ^ BigInt(byte)) & 0xffn)]);
  }
  return fp & MASK64;
}

/**
 * A fingerprint as the specification writes it: `0x…` and its 8 bytes in little-endian order.
 * @param {bigint} fp
 * @returns {{ hex: string, bytes: string }}
 */
export function fingerprintText(fp) {
  const hex = `0x${fp.toString(16).padStart(16, "0")}`;
  const bytes = Array.from({ length: 8 }, (_, i) =>
    ((fp >> BigInt(8 * i)) & 0xffn).toString(16).padStart(2, "0"),
  ).join(" ");
  return { hex, bytes };
}

// ---------------------------------------------------------------------------
// Reading the schemas

/**
 * One schema file and the named types it defines, in the order they appear.
 * @typedef {object} SchemaFile
 * @property {string} file its path in the repository, such as "types/axt/Ack.avsc"
 * @property {JsonObject} schema
 * @property {string} name its full name
 * @property {string} url its reference page
 * @property {string} canonical
 * @property {bigint} fingerprint
 * @property {{ full: string, schema: JsonObject }[]} named
 */

/**
 * @param {string} file
 * @param {JsonObject} schema
 * @returns {SchemaFile}
 */
export function readSchema(file, schema) {
  const name = fullName(String(schema.name), schema.namespace, "");
  /** @type {{ full: string, schema: JsonObject }[]} */
  const named = [];
  /**
   * @param {unknown} s
   * @param {string} space
   */
  const walk = (s, space) => {
    if (Array.isArray(s)) {
      for (const branch of s) walk(branch, space);
      return;
    }
    if (!isObject(s)) return;
    const type = s.type;
    if (typeof type !== "string") {
      walk(type, space);
      return;
    }
    let inner = space;
    if (type === "record" || type === "enum" || type === "fixed") {
      const full = fullName(String(s.name), s.namespace, space);
      if (!named.some((n) => n.full === full)) named.push({ full, schema: s });
      inner = namespaceOf(full);
    }
    for (const f of Array.isArray(s.fields) ? /** @type {JsonObject[]} */ (s.fields) : []) {
      walk(f.type, inner);
    }
    walk(s.items, inner);
    walk(s.values, inner);
  };
  walk(schema, "");
  const version =
    typeof schema["axt.version"] === "number" ? `.${String(schema["axt.version"])}` : "";
  const canonical = canonicalForm(schema);
  return {
    file,
    schema,
    name,
    url: `spec/${name}${version}.html`,
    canonical,
    fingerprint: crc64avro(canonical),
    named,
  };
}

/**
 * The .avsc files of one folder, sorted by name.
 * @param {string} repoRoot
 * @param {string} dir relative to repoRoot
 * @returns {SchemaFile[]}
 */
export function readSchemas(repoRoot, dir) {
  const full = path.join(repoRoot, dir);
  if (!fs.existsSync(full)) return [];
  return fs
    .readdirSync(full)
    .filter((f) => f.endsWith(".avsc"))
    .sort()
    .map((f) => {
      const file = `${dir}/${f}`;
      const schema = /** @type {unknown} */ (
        JSON.parse(fs.readFileSync(path.join(full, f), "utf8"))
      );
      if (!isObject(schema)) throw new Error(`${file}: not a named schema`);
      return readSchema(file, schema);
    });
}

// ---------------------------------------------------------------------------
// Rendering

/**
 * The text of a doc attribute as Markdown: its own Markdown characters escaped, and every
 * mention of a document of the specification ("spec/records.md, section 7") made a link, so
 * that its section references are linked as in the specification.
 * @param {string} text
 * @returns {string}
 */
export function docMarkdown(text) {
  return text
    .replace(/[\\`*[\]]/g, (ch) => `\\${ch}`)
    .replace(
      /\bspec\/([a-z0-9-]+)\.md\b/g,
      (_, name) => `[spec/${String(name)}.md](${String(name)}.md)`,
    );
}

/**
 * @typedef {object} RenderContext
 * @property {ConvertContext} convert
 * @property {Map<string, SchemaFile>} pages every schema with a page, by full name
 * @property {SchemaFile} current the schema of the page being rendered
 */

/**
 * A doc attribute as HTML.
 * @param {unknown} doc
 * @param {RenderContext} ctx
 * @returns {string}
 */
function docHtml(doc, ctx) {
  return typeof doc === "string" ? inline(docMarkdown(doc), ctx.convert, newBlock()) : "";
}

/**
 * The id of the section of a named type on its page.
 * @param {string} full
 * @returns {string}
 */
export function typeId(full) {
  return `type-${full.replaceAll(".", "-")}`;
}

/**
 * Where a named type is described: its own section on this page, or the page of the schema
 * that publishes it.
 * @param {string} full
 * @param {RenderContext} ctx
 * @returns {string}
 */
function typeHref(full, ctx) {
  const published = ctx.pages.get(full);
  if (published && published !== ctx.current) return path.posix.basename(published.url);
  return `#${typeId(full)}`;
}

/**
 * The type of a field, as a short line of HTML.
 * @param {unknown} t
 * @param {string} space
 * @param {RenderContext} ctx
 * @returns {string}
 */
export function typeHtml(t, space, ctx) {
  if (typeof t === "string") {
    if (PRIMITIVES.has(t)) return `<code>${t}</code>`;
    const full = fullName(t, undefined, space);
    return `<a href="${typeHref(full, ctx)}"><code>${escapeHtml(full)}</code></a>`;
  }
  if (Array.isArray(t)) return t.map((b) => typeHtml(b, space, ctx)).join(" or ");
  if (!isObject(t)) return "";
  const type = t.type;
  if (typeof type !== "string") return typeHtml(type, space, ctx);
  const logical = typeof t.logicalType === "string" ? ` (${escapeHtml(t.logicalType)})` : "";
  if (PRIMITIVES.has(type)) return `<code>${type}</code>${logical}`;
  if (type === "array") return `array of ${typeHtml(t.items, space, ctx)}`;
  if (type === "map") return `map of ${typeHtml(t.values, space, ctx)}`;
  const full = fullName(String(t.name), t.namespace, space);
  return `<a href="${typeHref(full, ctx)}"><code>${escapeHtml(full)}</code></a>`;
}

/**
 * A default value as JSON.
 * @param {JsonObject} field
 * @returns {string}
 */
function defaultHtml(field) {
  return "default" in field ? `<code>${escapeHtml(JSON.stringify(field.default))}</code>` : "";
}

/**
 * The meaning of each symbol of an enum, from its doc: "APPLIED: took the record. MERGED: …".
 * The text before the first symbol, and after the sentence of the last, is the enum's own.
 * @param {string} doc
 * @param {string[]} symbols
 * @returns {{ intro: string, meanings: Map<string, string>, outro: string }}
 */
export function symbolMeanings(doc, symbols) {
  /** @type {{ symbol: string, at: number, start: number }[]} */
  const marks = [];
  for (const symbol of symbols) {
    const m = new RegExp(String.raw`(?:^|\s)${symbol}: `).exec(doc);
    if (m)
      marks.push({
        symbol,
        at: m.index + (m[0].startsWith(symbol) ? 0 : 1),
        start: m.index + m[0].length,
      });
  }
  marks.sort((a, b) => a.at - b.at);
  /** @type {Map<string, string>} */
  const meanings = new Map();
  let outro = "";
  for (const [i, mark] of marks.entries()) {
    const next = marks[i + 1];
    let text = doc.slice(mark.start, next ? next.at : doc.length).trim();
    if (!next) {
      const end = /\.\s+(?=[A-Z])/.exec(text);
      if (end) {
        outro = text.slice(end.index + 1).trim();
        text = text.slice(0, end.index + 1);
      }
    }
    meanings.set(mark.symbol, text);
  }
  const first = marks[0];
  return { intro: (first ? doc.slice(0, first.at) : doc).trim(), meanings, outro };
}

/** The attributes of an example type shown as its own columns or lines, not as checks. */
const SHOWN = new Set([
  "name",
  "type",
  "doc",
  "default",
  "axt.label",
  "axt.label_translations",
  "axt.help",
  "axt.help_translations",
  "axt.emoji",
]);

/**
 * A translations object as "de: Haustier".
 * @param {unknown} translations
 * @returns {string}
 */
function translationsHtml(translations) {
  if (!isObject(translations)) return "";
  return Object.entries(translations)
    .map(
      ([lang, text]) =>
        `<span class="translation"><code>${escapeHtml(lang)}</code> ${escapeHtml(String(text))}</span>`,
    )
    .join(" ");
}

/**
 * The checks and display attributes of a field beyond its label, help and emoji.
 * @param {JsonObject} field
 * @returns {string}
 */
function checksHtml(field) {
  return Object.entries(field)
    .filter(([key]) => key.startsWith("axt.") && !SHOWN.has(key))
    .map(([key, value]) => `<code>${escapeHtml(key)}: ${escapeHtml(JSON.stringify(value))}</code>`)
    .join("<br>");
}

/**
 * The section of one named type on its page.
 * @param {{ full: string, schema: JsonObject }} named
 * @param {RenderContext} ctx
 * @param {boolean} example the page of an example type, with labels, help and checks
 * @returns {string}
 */
function namedSection(named, ctx, example) {
  const s = named.schema;
  const type = String(s.type);
  const space = namespaceOf(named.full);
  let html = `<h2 id="${typeId(named.full)}">${escapeHtml(type)} <code>${escapeHtml(named.full)}</code></h2>\n`;
  if (type === "enum") {
    const symbols = /** @type {string[]} */ (s.symbols);
    const { intro, meanings, outro } = symbolMeanings(
      typeof s.doc === "string" ? s.doc : "",
      symbols,
    );
    if (intro) html += `<p>${docHtml(intro, ctx)}</p>\n`;
    html += "<table>\n<thead><tr><th>Symbol</th><th>Meaning</th></tr></thead>\n<tbody>\n";
    html += symbols
      .map(
        (sym) =>
          `<tr><td><code>${escapeHtml(sym)}</code></td><td>${docHtml(meanings.get(sym) ?? "", ctx)}</td></tr>`,
      )
      .join("\n");
    html += "\n</tbody>\n</table>\n";
    if (outro) html += `<p>${docHtml(outro, ctx)}</p>\n`;
    if ("default" in s)
      html += `<p>Default symbol: <code>${escapeHtml(String(s.default))}</code>.</p>\n`;
    return html;
  }
  if (s.doc !== undefined) html += `<p>${docHtml(s.doc, ctx)}</p>\n`;
  if (type === "fixed") return `${html}<p>Size: ${escapeHtml(String(s.size))} bytes.</p>\n`;
  const fields = Array.isArray(s.fields) ? /** @type {JsonObject[]} */ (s.fields) : [];
  const head = example
    ? "<th>Field</th><th>Label</th><th>Type</th><th>Default</th><th>Description</th><th>Checks</th>"
    : "<th>Field</th><th>Type</th><th>Default</th><th>Description</th>";
  const rows = fields.map((f) => {
    const name = `<td id="${typeId(named.full)}-${escapeHtml(String(f.name))}"><code>${escapeHtml(String(f.name))}</code></td>`;
    const common = `<td>${typeHtml(f.type, space, ctx)}</td><td>${defaultHtml(f)}</td><td>${docHtml(f.doc, ctx)}</td>`;
    if (!example) return `<tr>${name}${common}</tr>`;
    const emoji = typeof f["axt.emoji"] === "string" ? `${escapeHtml(f["axt.emoji"])} ` : "";
    const label =
      `${emoji}${escapeHtml(str(f["axt.label"]))}` +
      (f["axt.label_translations"] ? `<br>${translationsHtml(f["axt.label_translations"])}` : "");
    const help = f["axt.help"]
      ? `<br><em>${escapeHtml(str(f["axt.help"]))}</em>` +
        (f["axt.help_translations"] ? `<br>${translationsHtml(f["axt.help_translations"])}` : "")
      : "";
    return `<tr>${name}<td>${label}${help}</td>${common}<td>${checksHtml(f)}</td></tr>`;
  });
  return `${html}<table>\n<thead><tr>${head}</tr></thead>\n<tbody>\n${rows.join("\n")}\n</tbody>\n</table>\n`;
}

/**
 * The reference page of one schema.
 * @param {SchemaFile} schema
 * @param {Map<string, SchemaFile>} pages
 * @param {ConvertContext} convert
 * @param {boolean} example
 * @param {number} order
 * @returns {GeneratedPage}
 */
function schemaPage(schema, pages, convert, example, order) {
  const ctx = { convert, pages, current: schema };
  const { hex, bytes } = fingerprintText(schema.fingerprint);
  const s = schema.schema;
  const source = `${convert.repoUrl}/blob/${convert.ref}/${schema.file}`;
  let body = "";
  if (example) {
    const emoji = typeof s["axt.emoji"] === "string" ? `${escapeHtml(s["axt.emoji"])} ` : "";
    body += `<p class="lede">${emoji}<strong>${escapeHtml(str(s["axt.label"]))}</strong>`;
    if (s["axt.label_translations"]) body += ` ${translationsHtml(s["axt.label_translations"])}`;
    body += `: ${escapeHtml(str(s["axt.help"]))}</p>\n`;
    if (s["axt.help_translations"])
      body += `<p>${translationsHtml(s["axt.help_translations"])}</p>\n`;
  }
  body += `<p${example ? "" : ' class="lede"'}>${docHtml(s.doc, ctx)}</p>\n<dl class="facts">\n`;
  if (example) {
    body += `<dt>Version</dt><dd><code>axt.version</code> ${escapeHtml(String(s["axt.version"]))}</dd>\n`;
    if (typeof s["axt.title"] === "string") {
      body += `<dt>Title field</dt><dd><code>${escapeHtml(s["axt.title"])}</code></dd>\n`;
    }
  }
  body +=
    `<dt>Fingerprint</dt><dd>CRC-64-AVRO <code>${hex}</code>, as bytes <code>${bytes}</code></dd>\n` +
    `<dt>Schema</dt><dd><a href="${escapeHtml(source)}">${escapeHtml(schema.file)}</a></dd>\n</dl>\n`;
  const own = schema.named.filter((n) => n.full === schema.name || !pages.has(n.full));
  for (const named of own) body += namedSection(named, ctx, example);
  body += `<h2 id="canonical-form">Parsing Canonical Form</h2>\n<pre><code class="language-json">${escapeHtml(schema.canonical)}</code></pre>\n`;
  const docText = typeof s.doc === "string" ? s.doc : "";
  return {
    title: schema.name,
    track: "spec",
    order,
    summary: (/^[^.]*\./.exec(docText)?.[0] ?? docText).slice(0, 200),
    url: schema.url,
    body,
    nav: false,
  };
}

/**
 * An overview of schema pages, as a table.
 * @param {SchemaFile[]} schemas
 * @param {boolean} example
 * @returns {string}
 */
function overviewTable(schemas, example) {
  const rows = schemas.map((schema) => {
    const s = schema.schema;
    const doc = typeof s.doc === "string" ? (/^[^.]*\./.exec(s.doc)?.[0] ?? s.doc) : "";
    const label = example
      ? `<td>${escapeHtml(str(s["axt.emoji"]))} ${escapeHtml(str(s["axt.label"]))}</td>`
      : "";
    return (
      `<tr><td><a href="${path.posix.basename(schema.url)}"><code>${escapeHtml(schema.name)}</code></a></td>` +
      `${label}<td>${escapeHtml(doc)}</td><td><code>${fingerprintText(schema.fingerprint).hex}</code></td></tr>`
    );
  });
  const head = example
    ? "<th>Type</th><th>Label</th><th>What it is</th><th>CRC-64-AVRO</th>"
    : "<th>Schema</th><th>What it is</th><th>CRC-64-AVRO</th>";
  return `<table>\n<thead><tr>${head}</tr></thead>\n<tbody>\n${rows.join("\n")}\n</tbody>\n</table>`;
}

/**
 * The glossary of CONTEXT.md: each "**Term**: meaning" paragraph a term of a definition list.
 * @param {string} source
 * @param {ConvertContext} convert
 * @returns {string}
 */
export function glossaryHtml(source, convert) {
  /** @type {string[]} */
  const items = [];
  /** @type {string[]} */
  const intro = [];
  for (const paragraph of source.split(/\n\s*\n/)) {
    const text = paragraph.replace(/\s*\n\s*/g, " ").trim();
    if (!text || text.startsWith("# ")) continue;
    // CONTEXT.md is at the repository's root, the glossary page in spec/.
    const md = text.replace(/\]\((?!https?:|#)([^)]+)\)/g, (_, url) => {
      const target = String(url);
      return `](${target.startsWith("spec/") ? target.slice(5) : `../${target}`})`;
    });
    const term = /^((?:\*\*[^*]+\*\*(?: and | or |, )?)+):\s+([\s\S]*)$/.exec(md);
    if (!term) {
      intro.push(`<p>${inline(md, convert, newBlock())}</p>`);
      continue;
    }
    const names = [...(term[1] ?? "").matchAll(/\*\*([^*]+)\*\*/g)].map((m) => m[1] ?? "");
    const id = `term-${(names[0] ?? "").toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
    items.push(
      `<dt id="${id}">${inline(term[1] ?? "", convert, newBlock())}</dt>\n<dd>${inline(term[2] ?? "", convert, newBlock())}</dd>`,
    );
  }
  return `${intro.join("\n")}\n<dl class="glossary">\n${items.join("\n")}\n</dl>`;
}

/**
 * Every reference page of the Specification track.
 * @param {object} options
 * @param {string} options.repoRoot the tree the sources come from
 * @param {Map<string, SpecDocument>} options.docs the documents of spec/, for links into them
 * @param {string} options.repoUrl
 * @param {string} options.ref
 * @param {boolean} options.strict
 * @param {string[]} options.warnings
 * @param {number} options.order the order of the first page, after the documents
 * @returns {GeneratedPage[]}
 */
export function referencePages({ repoRoot, docs, repoUrl, ref, strict, warnings, order }) {
  const spec = readSchemas(repoRoot, "types/axt");
  const examples = readSchemas(repoRoot, "types/axt/example/v1");
  if (!spec.length && !examples.length) return [];
  /** @type {Map<string, SchemaFile>} */
  const pages = new Map([...spec, ...examples].map((s) => [s.name, s]));
  /**
   * @param {string} name
   * @returns {ConvertContext}
   */
  const convert = (name) => ({
    doc: readDocument(`${name}.md`, `# ${name}\n`),
    docs,
    repoUrl,
    ref,
    strict,
    warnings,
  });
  /** @type {GeneratedPage[]} */
  const out = [
    {
      title: "Schemas",
      track: "spec",
      order,
      summary:
        "Every schema of the specification, with its fields, its fingerprint and its documents.",
      url: "spec/schemas.html",
      body:
        '<p class="lede">The schemas of the specification under <code>types/axt/</code>, generated ' +
        "from the files, with their fields, defaults, docs and fingerprints.</p>\n" +
        overviewTable(spec, false),
    },
    {
      title: "Example types",
      track: "spec",
      order: order + 1,
      summary: "The example types, with their labels, help, emoji, checks and fingerprints.",
      url: "spec/example-types.html",
      body:
        '<p class="lede">The example types under <code>types/axt/example/v1/</code>, which work ' +
        "between apps without prior agreement, with the labels and checks they carry.</p>\n" +
        overviewTable(examples, true),
    },
  ];
  for (const [i, schema] of spec.entries()) {
    out.push(
      schemaPage(
        schema,
        pages,
        convert(path.posix.basename(schema.url, ".html")),
        false,
        order + 10 + i,
      ),
    );
  }
  for (const [i, schema] of examples.entries()) {
    out.push(
      schemaPage(
        schema,
        pages,
        convert(path.posix.basename(schema.url, ".html")),
        true,
        order + 100 + i,
      ),
    );
  }
  const context = path.join(repoRoot, "CONTEXT.md");
  if (fs.existsSync(context)) {
    out.push({
      title: "Glossary",
      track: "spec",
      order: order + 2,
      summary: "The terms of AXT, from CONTEXT.md.",
      url: "spec/glossary.html",
      body: glossaryHtml(fs.readFileSync(context, "utf8"), convert("glossary")),
    });
  }
  const error = pages.get("axt.Error");
  const ack = pages.get("axt.Ack");
  if (error && ack) {
    const ctx = (/** @type {SchemaFile} */ current) => ({
      convert: convert("errors"),
      pages,
      current,
    });
    const enumOf = (/** @type {SchemaFile} */ s, /** @type {string} */ name) =>
      s.named.find((n) => n.full === name);
    const code = enumOf(error, "axt.ErrorCode");
    const outcome = enumOf(ack, "axt.AckOutcome");
    let body =
      '<p class="lede">The codes of an <code>ERROR</code> and the outcomes of an <code>ACK</code>, ' +
      `from the enums of <a href="${path.posix.basename(error.url)}">axt.Error</a> and ` +
      `<a href="${path.posix.basename(ack.url)}">axt.Ack</a>.</p>\n`;
    if (code)
      body += namedSection(code, ctx(error), false).replace(
        /<h2 id="[^"]*">/,
        '<h2 id="error-codes">',
      );
    if (outcome)
      body += namedSection(outcome, ctx(ack), false).replace(
        /<h2 id="[^"]*">/,
        '<h2 id="outcomes">',
      );
    out.push({
      title: "Errors and outcomes",
      track: "spec",
      order: order + 3,
      summary: "The error codes of an ERROR and the outcomes of an ACK.",
      url: "spec/errors.html",
      body,
    });
  }
  return out;
}
