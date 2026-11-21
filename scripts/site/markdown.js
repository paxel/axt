// SPDX-License-Identifier: Apache-2.0 OR MIT
// The Markdown of spec/ as pages of the Specification track. The converter knows exactly the
// subset the specification uses: headings, paragraphs, lists (nested, with continued
// paragraphs), tables, fenced code blocks, links, bold and code spans. It links the section
// references of the prose: "[keys.md](keys.md), section 5.3" to that page's section 5.3,
// "(sections 3.2 and 8.2 there)" to the page linked last, and a bare "section 5.3" to the
// page itself. Numbered headings get stable ids from their numbers (section-5-3).

import fs from "node:fs";
import path from "node:path";
import { escapeHtml } from "./html.js";

/**
 * @typedef {object} SpecDocument
 * @property {string} name the file name without .md, such as "keys"; "index" for README.md
 * @property {string} file the file name, such as "keys.md"
 * @property {string} title the text of its first heading
 * @property {string} source the Markdown
 * @property {Set<string>} sections the numbers of its sections, such as "5" and "5.3"
 */

/**
 * @typedef {object} ConvertContext
 * @property {SpecDocument} doc the document being converted
 * @property {Map<string, SpecDocument>} docs every document, by file name
 * @property {string} repoUrl the repository, for links to files outside spec/
 * @property {string} ref the tag or branch those links point at
 * @property {boolean} strict a reference to a missing section throws; otherwise it is reported
 * @property {string[]} warnings where the references that were not linked are reported
 */

/** @typedef {{ kind: "doc", doc: string } | { kind: "external" } | null} LinkTarget */

const NUMBER = String.raw`\d+(?:\.\d+)*`;
const HEADING = /^(#{1,6})[ \t]+(.*?)[ \t]*$/;
const NUMBERED_HEADING = /^(\d+(?:\.\d+)*)\.?[ \t]+/;
const LIST_ITEM = /^( *)([-*]|\d+\.)[ \t]+(.*)$/;
const FENCE = /^```(\S*)\s*$/;
const TABLE_RULE = /^\|(?:[ \t]*:?-{3,}:?[ \t]*\|)+[ \t]*$/;
// A singular "section" takes one number ("section 5.2, the …" is no list); a plural one a list
// or a range. " there" names the document linked last.
const REFERENCE = new RegExp(
  String.raw`\b(?:([Ss]ection)([ \t]+)(${NUMBER})|([Ss]ections)([ \t]+)(${NUMBER}(?:(?:,[ \t]+|[ \t]+(?:and|to|or)[ \t]+)${NUMBER})*))( there\b)?`,
  "g",
);

/**
 * The id of a numbered section, such as "section-5-3" for 5.3.
 * @param {string} number
 * @returns {string}
 */
export function sectionId(number) {
  return `section-${number.replaceAll(".", "-")}`;
}

/**
 * The numbers of the numbered headings of a document.
 * @param {string} source
 * @returns {Set<string>}
 */
export function sectionNumbers(source) {
  /** @type {Set<string>} */
  const numbers = new Set();
  let fenced = false;
  for (const line of source.split("\n")) {
    if (FENCE.test(line)) fenced = !fenced;
    if (fenced) continue;
    const heading = HEADING.exec(line);
    const numbered = heading && NUMBERED_HEADING.exec(/** @type {string} */ (heading[2]));
    if (numbered) numbers.add(/** @type {string} */ (numbered[1]));
  }
  return numbers;
}

/**
 * Reads one document of spec/.
 * @param {string} file the file name, such as "keys.md"
 * @param {string} source
 * @returns {SpecDocument}
 */
export function readDocument(file, source) {
  const title = /^#[ \t]+(.+?)[ \t]*$/m.exec(source);
  if (!title) throw new Error(`spec/${file}: no heading to take the title from`);
  return {
    name: file === "README.md" ? "index" : file.replace(/\.md$/, ""),
    file,
    title: /** @type {string} */ (title[1]).replaceAll("`", ""),
    source,
    sections: sectionNumbers(source),
  };
}

// ---------------------------------------------------------------------------
// Inline: code spans, links, bold, backslash escapes, section references

/**
 * Where a link of the specification goes, and what it is.
 * @param {string} url
 * @param {ConvertContext} ctx
 * @returns {{ href: string, target: LinkTarget }}
 */
function resolveLink(url, ctx) {
  if (/^(https?:|mailto:)/i.test(url)) return { href: url, target: { kind: "external" } };
  if (url.startsWith("#")) return { href: url, target: null };
  const hashAt = url.indexOf("#");
  const file = hashAt >= 0 ? url.slice(0, hashAt) : url;
  const fragment = hashAt >= 0 ? url.slice(hashAt) : "";
  const doc = ctx.docs.get(file);
  if (doc) return { href: `${doc.name}.html${fragment}`, target: { kind: "doc", doc: doc.file } };
  // Anything else lives in the repository, beside spec/: on GitHub, at the build's tag.
  const inRepo = path.posix.normalize(path.posix.join("spec", file));
  if (inRepo.startsWith(".."))
    throw new Error(`spec/${ctx.doc.file}: "${url}" leaves the repository`);
  const kind = url.endsWith("/") ? "tree" : "blob";
  return {
    href: `${ctx.repoUrl}/${kind}/${ctx.ref}/${inRepo}${fragment}`,
    target: { kind: "external" },
  };
}

/**
 * The HTML of one reference group, such as "sections 3.2 and 8.2", with each number linked.
 * @param {string} word "section", "Sections", …
 * @param {string} gap the space between the word and the numbers
 * @param {string} numbers "3.2 and 8.2"
 * @param {string} suffix " there" or ""
 * @param {SpecDocument} target
 * @param {ConvertContext} ctx
 * @returns {string}
 */
function linkReference(word, gap, numbers, suffix, target, ctx) {
  const parts = numbers.split(new RegExp(`(${NUMBER})`));
  let html = `${escapeHtml(word)}${gap}`;
  for (const [i, part] of parts.entries()) {
    if (i % 2 === 0) {
      html += escapeHtml(part);
      continue;
    }
    if (target.sections.has(part)) {
      const page = target === ctx.doc ? "" : `${target.name}.html`;
      html += `<a href="${page}#${sectionId(part)}">${part}</a>`;
      continue;
    }
    const what = `"${word} ${part}" in spec/${ctx.doc.file} names no section of spec/${target.file}`;
    if (ctx.strict) throw new Error(what);
    ctx.warnings.push(what);
    html += part;
  }
  return html + escapeHtml(suffix);
}

/**
 * What the references of one block (a paragraph, a list, a table cell) remember: the documents
 * linked so far, for "there", and, inside a parenthesis that began with a reference to another
 * document, that document, for the bare references after it up to the closing parenthesis.
 * @typedef {object} BlockState
 * @property {string[]} linked the documents linked so far, the last one last; a nested list
 *   starts with those of its item
 * @property {SpecDocument | null} scope
 * @property {number} depth how many parentheses of the prose are open
 * @property {number} scopeDepth the depth at which the scope was opened
 */

/**
 * @param {string[]} [linked]
 * @returns {BlockState}
 */
export function newBlock(linked = []) {
  return { linked: [...linked], scope: null, depth: 0, scopeDepth: 0 };
}

/**
 * Whether a document has every section a reference names.
 * @param {SpecDocument} doc
 * @param {string} numbers
 * @returns {boolean}
 */
function hasAll(doc, numbers) {
  return (numbers.match(new RegExp(NUMBER, "g")) ?? []).every((n) => doc.sections.has(n));
}

/**
 * The document "there" means: the one linked last that has every section the reference names.
 * @param {string} numbers
 * @param {BlockState} block
 * @param {ConvertContext} ctx
 * @returns {SpecDocument | null}
 */
function thereDocument(numbers, block, ctx) {
  const docs = block.linked.map((file) => ctx.docs.get(file)).filter((d) => d !== undefined);
  for (const doc of [...docs].reverse()) if (hasAll(doc, numbers)) return doc;
  return docs.at(-1) ?? null;
}

/**
 * Follows the parentheses of a piece of prose; a scope ends with the parenthesis it was opened
 * in, or at a semicolon, after which "(…, section 4.1; section 15.2)" returns to the page itself.
 * @param {string} text
 * @param {BlockState} block
 */
function trackParentheses(text, block) {
  for (const ch of text) {
    if (ch === "(") block.depth++;
    else if (ch === ";") block.scope = null;
    else if (ch === ")" && block.depth > 0) {
      block.depth--;
      if (block.scope && block.depth < block.scopeDepth) block.scope = null;
    }
  }
}

/**
 * A run of plain text: escaped, with its section references linked.
 * @param {string} text
 * @param {LinkTarget} previous the link right before the run
 * @param {BlockState} block
 * @param {ConvertContext} ctx
 * @returns {string}
 */
function textRun(text, previous, block, ctx) {
  let html = "";
  let cursor = 0;
  for (const m of text.matchAll(REFERENCE)) {
    const [whole, one, oneGap, oneNumber, many, manyGap, manyNumbers, there = ""] = m;
    const word = one ?? many ?? "";
    const gap = oneGap ?? manyGap ?? " ";
    const numbers = oneNumber ?? manyNumbers ?? "";
    const before = text.slice(0, m.index);
    trackParentheses(text.slice(cursor, m.index), block);
    const directlyAfterLink = /^,[ \t]+$/.test(before) && previous !== null;
    /** @type {SpecDocument | undefined | null} */
    let target = block.scope ?? ctx.doc;
    let opensScope = false;
    if (directlyAfterLink) {
      target = previous.kind === "doc" ? ctx.docs.get(previous.doc) : null;
      opensScope = true;
    } else if (/(?:\bRFC[ \t]+\d+,?[ \t]+\(?|\bits[ \t]+)$/.test(before)) {
      target = null; // a section of another standard
    } else if (there) {
      target = thereDocument(numbers, block, ctx);
      opensScope = true;
    }
    if (target === ctx.doc && !opensScope && !hasAll(ctx.doc, numbers)) {
      // A bare reference to a section this document lacks continues one linked before it.
      const linked = thereDocument(numbers, block, ctx);
      if (linked && hasAll(linked, numbers)) target = linked;
    }
    if (opensScope && target && target !== ctx.doc && block.depth > 0) {
      block.scope = target;
      block.scopeDepth = block.depth;
    }
    html += escapeHtml(text.slice(cursor, m.index));
    const end = m.index + whole.length;
    html += target
      ? linkReference(word, gap, numbers, there, target, ctx)
      : escapeHtml(text.slice(m.index, end));
    cursor = end;
  }
  trackParentheses(text.slice(cursor), block);
  return html + escapeHtml(text.slice(cursor));
}

/**
 * The HTML of a line of inline Markdown.
 * @param {string} text
 * @param {ConvertContext} ctx
 * @param {BlockState} [block] what the block's references so far remember
 * @param {boolean} [inLink] inside a link's text: no references, no further links
 * @returns {string}
 */
export function inline(text, ctx, block = newBlock(), inLink = false) {
  let html = "";
  let plain = "";
  /** @type {LinkTarget} */
  let previous = null;
  const flush = () => {
    if (!plain) return;
    html += inLink ? escapeHtml(plain) : textRun(plain, previous, block, ctx);
    plain = "";
    previous = null;
  };
  let i = 0;
  while (i < text.length) {
    const ch = /** @type {string} */ (text[i]);
    const escaped = text[i + 1] ?? "";
    if (ch === "\\" && /^[!-/:-@[-`{-~]$/.test(escaped)) {
      plain += escaped;
      i += 2;
      continue;
    }
    if (ch === "`") {
      const ticks = /^`+/.exec(text.slice(i))?.[0] ?? "`";
      const close = text.indexOf(ticks, i + ticks.length);
      if (close > i) {
        flush();
        const code = text.slice(i + ticks.length, close);
        html += `<code>${escapeHtml(ticks.length > 1 ? code.trim() : code)}</code>`;
        i = close + ticks.length;
        continue;
      }
    }
    if (ch === "*" && text[i + 1] === "*") {
      const close = text.indexOf("**", i + 2);
      if (close > i + 2) {
        flush();
        html += `<strong>${inline(text.slice(i + 2, close), ctx, block, inLink)}</strong>`;
        i = close + 2;
        continue;
      }
    }
    if (ch === "[" && !inLink) {
      const link = /^\[((?:[^\]`]|`[^`]*`)*)\]\(([^)\s]+)\)/.exec(text.slice(i));
      if (link) {
        flush();
        const [whole, label = "", url = ""] = link;
        const { href, target } = resolveLink(url, ctx);
        html += `<a href="${escapeHtml(href)}">${inline(label, ctx, block, true)}</a>`;
        if (target?.kind === "doc") block.linked.push(target.doc);
        i += whole.length;
        previous = target;
        continue;
      }
    }
    plain += ch;
    i += 1;
  }
  flush();
  return html;
}

// ---------------------------------------------------------------------------
// Blocks

/**
 * The cells of a table row; a pipe inside a code span belongs to the cell.
 * @param {string} line
 * @returns {string[]}
 */
export function splitRow(line) {
  const inner = line.trim().replace(/^\|/, "").replace(/\|$/, "");
  /** @type {string[]} */
  const cells = [];
  let cell = "";
  let inCode = false;
  for (let i = 0; i < inner.length; i++) {
    const ch = /** @type {string} */ (inner[i]);
    if (ch === "\\" && inner[i + 1] === "|") {
      cell += "\\|";
      i++;
    } else if (ch === "`") {
      inCode = !inCode;
      cell += ch;
    } else if (ch === "|" && !inCode) {
      cells.push(cell.trim());
      cell = "";
    } else cell += ch;
  }
  cells.push(cell.trim());
  return cells;
}

/**
 * @param {string} line
 * @returns {boolean}
 */
const isBlank = (line) => line.trim() === "";

/**
 * @param {string} line
 * @returns {number}
 */
const indentOf = (line) => /^ */.exec(line)?.[0].length ?? 0;

/**
 * Parses the list that starts at lines[start], at that line's indent.
 * @param {string[]} lines
 * @param {number} start
 * @param {ConvertContext} ctx
 * @param {string[]} [linked] the documents the enclosing item linked so far
 * @returns {{ html: string, next: number }}
 */
function parseList(lines, start, ctx, linked = []) {
  const first = /** @type {RegExpExecArray} */ (
    LIST_ITEM.exec(/** @type {string} */ (lines[start]))
  );
  const base = (first[1] ?? "").length;
  const ordered = /\d/.test(first[2] ?? "");
  const startNo = ordered ? Number.parseInt(first[2] ?? "1", 10) : 1;
  /** @type {string[][]} */
  const items = []; // each item: its blocks as HTML
  /** @type {string[]} */
  let paragraph = [];
  const block = newBlock(linked);
  const closeParagraph = () => {
    if (paragraph.length) items[items.length - 1]?.push(inline(paragraph.join(" "), ctx, block));
    paragraph = [];
    // "there" may point back to an earlier item; a parenthesis never spans two.
    block.depth = 0;
    block.scope = null;
  };
  let loose = false;
  let i = start;
  while (i < lines.length) {
    const line = /** @type {string} */ (lines[i]);
    const item = LIST_ITEM.exec(line);
    const indent = indentOf(line);
    if (isBlank(line)) {
      // A blank line ends the list unless an item of it, or more of the last item, follows.
      let j = i + 1;
      while (j < lines.length && isBlank(/** @type {string} */ (lines[j]))) j++;
      const nextLine = lines[j];
      if (nextLine === undefined) break;
      const nextItem = LIST_ITEM.exec(nextLine);
      const sameList =
        nextItem && (nextItem[1] ?? "").length === base && /\d/.test(nextItem[2] ?? "") === ordered;
      if (!sameList && indentOf(nextLine) <= base) break;
      closeParagraph();
      loose = true;
      i = j;
      continue;
    }
    if (item && indent === base) {
      if (/\d/.test(item[2] ?? "") !== ordered) break;
      closeParagraph();
      items.push([]);
      paragraph = [item[3] ?? ""];
      i++;
      continue;
    }
    if (item && indent > base) {
      closeParagraph();
      // The nested list sees what its item linked so far.
      const nested = parseList(lines, i, ctx, block.linked);
      items[items.length - 1]?.push(nested.html);
      i = nested.next;
      continue;
    }
    if (indent > base) {
      paragraph.push(line.trim());
      i++;
      continue;
    }
    break;
  }
  closeParagraph();
  const tag = ordered ? "ol" : "ul";
  const attrs = ordered && startNo !== 1 ? ` start="${String(startNo)}"` : "";
  const body = items
    .map((blocks) => {
      const parts = blocks.map((b) => (loose && !/^<[ou]l\b/.test(b) ? `<p>${b}</p>` : b));
      return `<li>${parts.join("\n")}</li>`;
    })
    .join("\n");
  return { html: `<${tag}${attrs}>\n${body}\n</${tag}>`, next: i };
}

/**
 * Converts one document of spec/ to the HTML of its page, without its first heading, which
 * becomes the page's title.
 * @param {ConvertContext} ctx
 * @returns {string}
 */
export function convertDocument(ctx) {
  const lines = ctx.doc.source.replace(/\r\n?/g, "\n").split("\n");
  /** @type {string[]} */
  const out = [];
  let titled = false;
  let i = 0;
  while (i < lines.length) {
    const line = /** @type {string} */ (lines[i]);
    if (isBlank(line)) {
      i++;
      continue;
    }
    const fence = FENCE.exec(line);
    if (fence) {
      const close = lines.findIndex((l, j) => j > i && /^```\s*$/.test(l));
      if (close < 0) throw new Error(`spec/${ctx.doc.file}:${String(i + 1)}: unclosed code block`);
      const lang = fence[1] ? ` class="language-${escapeHtml(fence[1])}"` : "";
      out.push(
        `<pre><code${lang}>${escapeHtml(lines.slice(i + 1, close).join("\n"))}</code></pre>`,
      );
      i = close + 1;
      continue;
    }
    const heading = HEADING.exec(line);
    if (heading) {
      const level = (heading[1] ?? "").length;
      const text = heading[2] ?? "";
      if (level === 1 && !titled) {
        titled = true;
      } else {
        const numbered = NUMBERED_HEADING.exec(text);
        const id = numbered ? ` id="${sectionId(numbered[1] ?? "")}"` : "";
        const tag = `h${String(Math.min(level, 6))}`;
        out.push(`<${tag}${id}>${inline(text, ctx)}</${tag}>`);
      }
      i++;
      continue;
    }
    if (line.startsWith("|") && TABLE_RULE.test(lines[i + 1] ?? "")) {
      const head = splitRow(line)
        .map((c) => `<th>${inline(c, ctx)}</th>`)
        .join("");
      let j = i + 2;
      /** @type {string[]} */
      const rows = [];
      while (j < lines.length && (lines[j] ?? "").startsWith("|")) {
        const cells = splitRow(/** @type {string} */ (lines[j]));
        rows.push(`<tr>${cells.map((c) => `<td>${inline(c, ctx)}</td>`).join("")}</tr>`);
        j++;
      }
      out.push(
        `<table>\n<thead><tr>${head}</tr></thead>\n<tbody>\n${rows.join("\n")}\n</tbody>\n</table>`,
      );
      i = j;
      continue;
    }
    if (LIST_ITEM.exec(line)) {
      const list = parseList(lines, i, ctx);
      out.push(list.html);
      i = list.next;
      continue;
    }
    if (/^-{3,}\s*$/.test(line)) {
      out.push("<hr>");
      i++;
      continue;
    }
    /** @type {string[]} */
    const paragraph = [];
    while (i < lines.length) {
      const l = /** @type {string} */ (lines[i]);
      if (isBlank(l) || HEADING.test(l) || FENCE.test(l) || LIST_ITEM.test(l)) break;
      if (l.startsWith("|") && TABLE_RULE.test(lines[i + 1] ?? "")) break;
      paragraph.push(l.trim());
      i++;
    }
    out.push(`<p>${inline(paragraph.join(" "), ctx)}</p>`);
  }
  return out.join("\n");
}

// ---------------------------------------------------------------------------
// The Specification track

/**
 * The documents of the index, in its order, each with the purpose its table gives.
 * @param {SpecDocument} index
 * @returns {Map<string, { order: number, purpose: string }>}
 */
export function readIndex(index) {
  /** @type {Map<string, { order: number, purpose: string }>} */
  const entries = new Map();
  for (const line of index.source.split("\n")) {
    if (!line.startsWith("|")) continue;
    const [first = "", purpose = ""] = splitRow(line);
    const link = /^\[[^\]]*\]\(([a-z0-9-]+\.md)\)$/.exec(first);
    if (link && !entries.has(link[1] ?? "")) {
      entries.set(link[1] ?? "", { order: entries.size + 1, purpose: purpose.replaceAll("`", "") });
    }
  }
  return entries;
}

/**
 * Every document of a spec/ folder as a page of the Specification track, under spec/. The
 * README becomes the track's start page.
 * @param {string} specDir
 * @param {{ repoUrl: string, ref: string, strict: boolean }} options
 * @returns {{ pages: { title: string, track: string, order: number, summary: string, url: string, body: string }[], warnings: string[], docs: Map<string, SpecDocument> }}
 */
export function specPages(specDir, { repoUrl, ref, strict }) {
  const files = fs
    .readdirSync(specDir)
    .filter((f) => f.endsWith(".md"))
    .sort();
  /** @type {Map<string, SpecDocument>} */
  const docs = new Map();
  for (const file of files) {
    docs.set(file, readDocument(file, fs.readFileSync(path.join(specDir, file), "utf8")));
  }
  const index = docs.get("README.md");
  const order = index
    ? readIndex(index)
    : new Map(/** @type {[string, { order: number, purpose: string }][]} */ ([]));
  /** @type {string[]} */
  const warnings = [];
  const pages = [...docs.values()].map((doc) => {
    const entry = order.get(doc.file);
    const html = convertDocument({ doc, docs, repoUrl, ref, strict, warnings });
    return {
      title: doc.name === "index" ? "Specification" : doc.title,
      track: "spec",
      order: doc.name === "index" ? 0 : (entry?.order ?? order.size + 1),
      summary:
        doc.name === "index" ? "The documents of the AXT specification." : (entry?.purpose ?? ""),
      url: `spec/${doc.name}.html`,
      body: html,
    };
  });
  return { pages, warnings, docs };
}
