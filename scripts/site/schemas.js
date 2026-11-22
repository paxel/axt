// SPDX-License-Identifier: Apache-2.0 OR MIT
// Reference pages of the Specification track, generated from the sources so they cannot drift
// from them: one page per schema of types/axt/, one per example type of types/axt/example/v1/
// with the texts and checks of its description, the bricks of Field.avsc, the limits of
// limits.json, the glossary of CONTEXT.md, and the error codes and outcomes of the enums of
// Error.avsc and Ack.avsc. Fingerprints are computed here, without a dependency: the CRC-64-AVRO of the
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
 * @property {JsonObject} [description] the description beside it, for an example type
 * @property {string} [descriptionFile] its path in the repository
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
      const read = readSchema(file, schema);
      const json = f.replace(/\.avsc$/, ".json");
      if (fs.existsSync(path.join(full, json))) {
        const description = /** @type {unknown} */ (
          JSON.parse(fs.readFileSync(path.join(full, json), "utf8"))
        );
        if (!isObject(description)) throw new Error(`${dir}/${json}: not a description`);
        read.description = description;
        read.descriptionFile = `${dir}/${json}`;
      }
      return read;
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
 * @property {string} [base] the page that holds the sections of the current schema's named
 *   types, when the page being rendered is another one
 * @property {Map<string, Described>} [described] the typed fields of the current schema's
 *   objects and enums, from its description
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
  return `${ctx.base ?? ""}#${typeId(full)}`;
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
 * The checks and display attributes of a field beyond its label, help and emoji, in a release
 * whose example types carry them as attributes of the schema.
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
 * The texts of a schema or a field of a release whose example types carry them as attributes,
 * in the form of the texts of a typed field.
 * @param {JsonObject} s
 * @returns {JsonObject}
 */
function attributeTexts(s) {
  return {
    label: s["axt.label"],
    label_translations: s["axt.label_translations"],
    help: s["axt.help"],
    help_translations: s["axt.help_translations"],
    emoji: s["axt.emoji"],
  };
}

/**
 * The texts of a typed field, an enum symbol or a group: its emoji and label, their
 * translations, and its help text with its translations.
 * @param {unknown} texts
 * @returns {string}
 */
export function textsHtml(texts) {
  if (!isObject(texts)) return "";
  const emoji = typeof texts.emoji === "string" && texts.emoji ? `${escapeHtml(texts.emoji)} ` : "";
  let html = `${emoji}${escapeHtml(str(texts.label))}`;
  const labels = translationsHtml(texts.label_translations);
  if (labels) html += `<br>${labels}`;
  if (typeof texts.help === "string" && texts.help) {
    html += `<br><em>${escapeHtml(texts.help)}</em>`;
    const helps = translationsHtml(texts.help_translations);
    if (helps) html += `<br>${helps}`;
  }
  return html;
}

// ---------------------------------------------------------------------------
// Descriptions: the typed fields of spec/fields.md, from which an example type's schema is derived

/**
 * One object or enum of a description: the typed field that describes it, and its brick.
 * @typedef {{ field: JsonObject, brick: JsonObject }} Described
 */

/**
 * The brick of a typed field: the one branch of its union `kind`, by its full name.
 * @param {unknown} field
 * @returns {{ name: string, value: JsonObject } | undefined}
 */
export function brickOf(field) {
  if (!isObject(field) || !isObject(field.kind)) return undefined;
  const [entry] = Object.entries(field.kind);
  if (!entry || !isObject(entry[1])) return undefined;
  return { name: entry[0], value: entry[1] };
}

/**
 * @param {unknown} value
 * @returns {JsonObject[]}
 */
function objects(value) {
  return Array.isArray(value) ? value.filter(isObject) : [];
}

/**
 * The objects and enums of a description by their full names; a nested one takes the namespace
 * of the root (spec/fields.md, section 9.1).
 * @param {JsonObject} root
 * @returns {Map<string, Described>}
 */
export function describedTypes(root) {
  /** @type {Map<string, Described>} */
  const out = new Map();
  const space = namespaceOf(str(brickOf(root)?.value.name));
  /** @param {unknown} field */
  const walk = (field) => {
    const brick = brickOf(field);
    if (!brick || !isObject(field)) return;
    const v = brick.value;
    if (brick.name === "axt.ObjectField" || brick.name === "axt.EnumField") {
      const full = fullName(str(v.name), undefined, space);
      if (!out.has(full)) out.set(full, { field, brick: v });
    }
    for (const f of objects(v.fields)) walk(f);
    walk(v.items);
    walk(v.values);
  };
  walk(root);
  return out;
}

/** The members of a brick that give the type its shape, shown elsewhere on the page. */
const SHAPE = new Set([
  "default",
  "name",
  "fields",
  "groups",
  "version",
  "title",
  "symbols",
  "fallback",
  "items",
  "values",
]);

/**
 * Whether a member's value says something: not null, empty or false.
 * @param {unknown} value
 * @returns {boolean}
 */
function isSet(value) {
  if (value === null || value === undefined || value === "" || value === false) return false;
  if (Array.isArray(value)) return value.length > 0;
  return !isObject(value) || Object.keys(value).length > 0;
}

/**
 * @param {string} key
 * @param {unknown} value
 * @returns {string}
 */
function memberHtml(key, value) {
  return value === true
    ? `<code>${escapeHtml(key)}</code>`
    : `<code>${escapeHtml(key)}: ${escapeHtml(JSON.stringify(value))}</code>`;
}

/**
 * The brick of a typed field, linked to the Bricks page, with what the field sets beyond its
 * shape: `required`, its place and how it is shown, the checks and hints of its brick, and for
 * a list or a map the same of its items or values.
 * @param {JsonObject} field
 * @returns {string}
 */
export function brickHtml(field) {
  const brick = brickOf(field);
  if (!brick) return "";
  const parts = [
    `<a href="bricks.html#${escapeHtml(brick.name)}"><code>${escapeHtml(brick.name)}</code></a>`,
  ];
  for (const key of ["required", "order", "group", "sensitive", "advanced"]) {
    if (isSet(field[key])) parts.push(memberHtml(key, field[key]));
  }
  for (const [key, value] of Object.entries(brick.value)) {
    if (!SHAPE.has(key) && isSet(value)) parts.push(memberHtml(key, value));
  }
  for (const key of ["items", "values"]) {
    const inner = brick.value[key];
    if (isObject(inner)) parts.push(`${key}: ${brickHtml(inner)}`);
  }
  return parts.join("<br>");
}

/**
 * The texts of an example type: of its description, or of its attributes in a release before
 * the bricks.
 * @param {SchemaFile} schema
 * @returns {unknown}
 */
function rootTexts(schema) {
  return schema.description ? schema.description.texts : attributeTexts(schema.schema);
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
    const described = ctx.described?.get(named.full);
    const texts = new Map(
      objects(described?.brick.symbols).map((sym) => [str(sym.symbol), sym.texts]),
    );
    html += `<table>\n<thead><tr><th>Symbol</th>${described ? "<th>Label</th>" : ""}<th>Meaning</th></tr></thead>\n<tbody>\n`;
    html += symbols
      .map(
        (sym) =>
          `<tr><td><code>${escapeHtml(sym)}</code></td>` +
          (described ? `<td>${textsHtml(texts.get(sym))}</td>` : "") +
          `<td>${docHtml(meanings.get(sym) ?? "", ctx)}</td></tr>`,
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
  const described = ctx.described?.get(named.full);
  const checks = described ? "Brick, checks and hints" : "Checks";
  const head = example
    ? `<th>Field</th><th>Label</th><th>Type</th><th>Default</th><th>Description</th><th>${checks}</th>`
    : "<th>Field</th><th>Type</th><th>Default</th><th>Description</th>";
  const rows = fields.map((f) => {
    const name = `<td id="${typeId(named.full)}-${escapeHtml(String(f.name))}"><code>${escapeHtml(String(f.name))}</code></td>`;
    const common = `<td>${typeHtml(f.type, space, ctx)}</td><td>${defaultHtml(f)}</td><td>${docHtml(f.doc, ctx)}</td>`;
    if (!example) return `<tr>${name}${common}</tr>`;
    if (!ctx.described)
      return `<tr>${name}<td>${textsHtml(attributeTexts(f))}</td>${common}<td>${checksHtml(f)}</td></tr>`;
    const typed = objects(described?.brick.fields).find((c) => c.name === f.name);
    return `<tr>${name}<td>${typed ? textsHtml(typed.texts) : ""}</td>${common}<td>${typed ? brickHtml(typed) : ""}</td></tr>`;
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
  /** @type {RenderContext} */
  const ctx = { convert, pages, current: schema };
  if (schema.description) ctx.described = describedTypes(schema.description);
  const { hex, bytes } = fingerprintText(schema.fingerprint);
  const s = schema.schema;
  const blob = (/** @type {string} */ file) => `${convert.repoUrl}/blob/${convert.ref}/${file}`;
  const root = schema.description ? brickOf(schema.description)?.value : undefined;
  let body = "";
  if (example) {
    const texts = /** @type {JsonObject} */ (rootTexts(schema) ?? {});
    const emoji =
      typeof texts.emoji === "string" && texts.emoji ? `${escapeHtml(texts.emoji)} ` : "";
    body += `<p class="lede">${emoji}<strong>${escapeHtml(str(texts.label))}</strong>`;
    const labels = translationsHtml(texts.label_translations);
    if (labels) body += ` ${labels}`;
    body += `: ${escapeHtml(str(texts.help))}</p>\n`;
    const helps = translationsHtml(texts.help_translations);
    if (helps) body += `<p>${helps}</p>\n`;
  }
  body += `<p${example ? "" : ' class="lede"'}>${docHtml(s.doc, ctx)}</p>\n<dl class="facts">\n`;
  if (example) {
    const version = root ? root.version : s["axt.version"];
    body += `<dt>Version</dt><dd><code>${root ? "version" : "axt.version"}</code> ${escapeHtml(str(version))}</dd>\n`;
    const title = root ? root.title : s["axt.title"];
    if (typeof title === "string" && title) {
      body += `<dt>Title field</dt><dd><code>${escapeHtml(title)}</code></dd>\n`;
    }
  }
  body += `<dt>Fingerprint</dt><dd>CRC-64-AVRO <code>${hex}</code>, as bytes <code>${bytes}</code></dd>\n`;
  if (schema.descriptionFile) {
    body += `<dt>Description</dt><dd><a href="${escapeHtml(blob(schema.descriptionFile))}">${escapeHtml(schema.descriptionFile)}</a></dd>\n`;
  }
  body += `<dt>${schema.descriptionFile ? "Derived schema" : "Schema"}</dt><dd><a href="${escapeHtml(blob(schema.file))}">${escapeHtml(schema.file)}</a></dd>\n</dl>\n`;
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
    const texts = /** @type {JsonObject} */ (example ? (rootTexts(schema) ?? {}) : {});
    const label = example
      ? `<td>${escapeHtml(str(texts.emoji))} ${escapeHtml(str(texts.label))}</td>`
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

/** The members of a brick that a value can break (spec/fields.md, section 7). */
const CHECKS = new Set(["min_length", "max_length", "pattern", "min", "max"]);

/**
 * The members of a record as the rows of a table: name, type, default and doc.
 * @param {JsonObject[]} fields
 * @param {string} space
 * @param {RenderContext} ctx
 * @returns {string}
 */
function membersTable(fields, space, ctx) {
  const rows = fields.map(
    (f) =>
      `<tr><td><code>${escapeHtml(str(f.name))}</code></td><td>${typeHtml(f.type, space, ctx)}</td>` +
      `<td>${defaultHtml(f)}</td><td>${docHtml(f.doc, ctx)}</td></tr>`,
  );
  return (
    "<table>\n<thead><tr><th>Member</th><th>Type</th><th>Default</th><th>What it is</th></tr></thead>\n" +
    `<tbody>\n${rows.join("\n")}\n</tbody>\n</table>\n`
  );
}

/**
 * The checks of a brick: the members a value can break, and the format of a semantic brick,
 * which its doc names.
 * @param {JsonObject} brick
 * @returns {string}
 */
export function brickChecks(brick) {
  /** @type {string[]} */
  const checks = [];
  const format = /\bthe format ([a-z-]+) of\b/i.exec(str(brick.doc));
  if (format) checks.push(`<code>format</code> (<code>${escapeHtml(format[1] ?? "")}</code>)`);
  for (const f of objects(brick.fields)) {
    if (CHECKS.has(str(f.name))) checks.push(`<code>${escapeHtml(str(f.name))}</code>`);
  }
  return checks.join(", ");
}

/**
 * The page of the bricks: the common part of axt.Field and each brick of its union `kind`,
 * with its members and its checks.
 * @param {SchemaFile} field the schema of axt.Field
 * @param {Map<string, SchemaFile>} pages
 * @param {ConvertContext} convert
 * @param {number} order
 * @returns {GeneratedPage}
 */
function bricksPage(field, pages, convert, order) {
  const base = path.posix.basename(field.url);
  /** @type {RenderContext} */
  const ctx = { convert, pages, current: field, base };
  const space = namespaceOf(field.name);
  const members = objects(field.schema.fields);
  const kind = members.find((m) => m.name === "kind");
  const bricks = objects(kind?.type).map((b) => ({
    full: fullName(str(b.name), b.namespace, space),
    brick: b,
  }));
  let body =
    '<p class="lede">The bricks of AXT: a typed field describes one field of a type, its name, ' +
    "the texts a receiver shows for it and the checks its values keep, and a type is described " +
    `by typed fields put together. Generated from <a href="${base}"><code>axt.Field</code></a>; ` +
    'the rules are in <a href="fields.html">fields.md</a>.</p>\n' +
    '<h2 id="common-part">The common part</h2>\n' +
    "<p>Every typed field has these members beside its brick. Its <code>required</code> is a check " +
    "of every brick.</p>\n" +
    membersTable(
      members.filter((m) => m !== kind),
      space,
      ctx,
    ) +
    '<h2 id="bricks">The bricks</h2>\n' +
    "<table>\n<thead><tr><th>Brick</th><th>Values</th><th>Checks</th></tr></thead>\n<tbody>\n" +
    bricks
      .map(
        ({ full, brick }) =>
          `<tr><td><a href="#${escapeHtml(full)}"><code>${escapeHtml(full)}</code></a></td>` +
          `<td>${docHtml(brick.doc, ctx)}</td><td>${brickChecks(brick)}</td></tr>`,
      )
      .join("\n") +
    "\n</tbody>\n</table>\n";
  for (const { full, brick } of bricks) {
    body += `<h2 id="${escapeHtml(full)}"><code>${escapeHtml(full)}</code></h2>\n<p>${docHtml(brick.doc, ctx)}</p>\n`;
    const own = objects(brick.fields);
    body += own.length ? membersTable(own, space, ctx) : "<p>It has no members.</p>\n";
  }
  return {
    title: "Bricks",
    track: "spec",
    order,
    summary:
      "The bricks of axt.Field: the common part of a typed field, and each brick with its members and checks.",
    url: "spec/bricks.html",
    body,
  };
}

/**
 * A limit's value, with the larger unit it is a whole number of, such as 16 MiB or 14 days.
 * @param {unknown} value
 * @param {unknown} unit
 * @returns {string}
 */
export function limitValue(value, unit) {
  const n = Number(value);
  const text = n.toLocaleString("en-US");
  /** @type {[number, string][]} */
  const scales =
    unit === "bytes"
      ? [
          [2 ** 30, "GiB"],
          [2 ** 20, "MiB"],
          [2 ** 10, "KiB"],
        ]
      : unit === "seconds"
        ? [
            [86400, "days"],
            [3600, "hours"],
            [60, "minutes"],
          ]
        : [];
  for (const [size, name] of scales) {
    if (n >= size && n % size === 0) {
      const count = n / size;
      return `${text} (${String(count)} ${count === 1 ? name.replace(/s$/, "") : name})`;
    }
  }
  return text;
}

/**
 * The page of the limits of types/axt/limits.json, one row per limit, its id its key.
 * @param {string} repoRoot
 * @param {ConvertContext} convert
 * @param {number} order
 * @returns {GeneratedPage | undefined}
 */
function limitsPage(repoRoot, convert, order) {
  const file = "types/axt/limits.json";
  const full = path.join(repoRoot, file);
  if (!fs.existsSync(full)) return undefined;
  const data = /** @type {unknown} */ (JSON.parse(fs.readFileSync(full, "utf8")));
  const limits = isObject(data) && isObject(data.limits) ? data.limits : {};
  const rows = Object.entries(limits).map(([key, limit]) => {
    const l = isObject(limit) ? limit : {};
    const doc = /^([a-z0-9-]+)\.md(,.*)?$/.exec(str(l.section));
    const section = doc
      ? inline(`[${doc[1] ?? ""}.md](${doc[1] ?? ""}.md)${doc[2] ?? ""}`, convert, newBlock())
      : escapeHtml(str(l.section));
    return (
      `<tr id="${escapeHtml(key)}"><td><code>${escapeHtml(key)}</code></td>` +
      `<td>${escapeHtml(limitValue(l.value, l.unit))}</td><td>${escapeHtml(str(l.unit))}</td>` +
      `<td>${escapeHtml(str(l.what))}</td><td>${section}</td></tr>`
    );
  });
  const source = `${convert.repoUrl}/blob/${convert.ref}/${file}`;
  return {
    title: "Limits",
    track: "spec",
    order,
    summary:
      "Every limit of the specification by its key, with its value, its unit and the section that applies it.",
    url: "spec/limits.html",
    body:
      '<p class="lede">The limits of AXT, generated from ' +
      `<a href="${escapeHtml(source)}">${file}</a>: every bound on a size, a count, a length, a depth ` +
      "or a time. The documents name each limit by its key; the value is here.</p>\n" +
      "<table>\n<thead><tr><th>Key</th><th>Value</th><th>Unit</th><th>What it bounds</th><th>Section</th></tr></thead>\n" +
      `<tbody>\n${rows.join("\n")}\n</tbody>\n</table>`,
  };
}

/**
 * The definitions of the specification beside its schemas, each linked where the build's tree
 * holds it.
 * @param {string} repoRoot
 * @param {ConvertContext} convert
 * @returns {string}
 */
function otherDefinitions(repoRoot, convert) {
  /** @type {[string, string][]} */
  const files = [
    ["types/axt/limits.json", 'The limits, also as the page <a href="limits.html">Limits</a>'],
    ["spec/relay-api.json", "The interface every relay offers, as OpenAPI 3.1"],
    [
      "vectors/adapter.schema.json",
      "The adapter protocol of the conformance suite, as JSON Schema",
    ],
  ];
  const items = files
    .filter(([file]) => fs.existsSync(path.join(repoRoot, file)))
    .map(
      ([file, what]) =>
        `<li><a href="${escapeHtml(`${convert.repoUrl}/blob/${convert.ref}/${file}`)}"><code>${file}</code></a>: ${what}.</li>`,
    );
  return items.length
    ? `\n<h2 id="other-definitions">Other definitions</h2>\n<ul>\n${items.join("\n")}\n</ul>`
    : "";
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
    const text = paragraph
      .split("\n")
      .map((line) => line.trim())
      .join(" ")
      .trim();
    if (!text || text.startsWith("# ")) continue;
    // CONTEXT.md is at the repository's root, the glossary page in spec/.
    const md = text.replace(/\]\((?!https?:|#)([^)]+)\)/g, (_, url) => {
      const target = String(url);
      return `](${target.startsWith("spec/") ? target.slice(5) : `../${target}`})`;
    });
    const term = /^(\*\*[^*]+\*\*(?:(?: and | or |, )\*\*[^*]+\*\*)*):\s(.*)$/.exec(md);
    if (!term) {
      intro.push(`<p>${inline(md, convert, newBlock())}</p>`);
      continue;
    }
    const names = [...(term[1] ?? "").matchAll(/\*\*([^*]+)\*\*/g)].map((m) => m[1] ?? "");
    const id = `term-${(names[0] ?? "").toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
    items.push(
      `<dt id="${id}">${inline(term[1] ?? "", convert, newBlock())}</dt>\n<dd>${inline((term[2] ?? "").trimStart(), convert, newBlock())}</dd>`,
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
        overviewTable(spec, false) +
        otherDefinitions(repoRoot, convert("schemas")),
    },
    {
      title: "Example types",
      track: "spec",
      order: order + 1,
      summary: "The example types, with their labels, help, emoji, checks and fingerprints.",
      url: "spec/example-types.html",
      body:
        '<p class="lede">The example types under <code>types/axt/example/v1/</code>, which work ' +
        "between apps without prior agreement, with the labels and checks of their descriptions.</p>\n" +
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
  const field = pages.get("axt.Field");
  if (field) out.push(bricksPage(field, pages, convert("bricks"), order + 4));
  const limits = limitsPage(repoRoot, convert("limits"), order + 5);
  if (limits) out.push(limits);
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
