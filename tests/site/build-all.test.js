// SPDX-License-Identifier: Apache-2.0 OR MIT
// Tests for scripts/build-site-all.js: a throwaway git repository with two
// release tags and an unreleased working tree, built into one folder.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  buildAll,
  compareVersions,
  extractTag,
  listReleaseTags,
  planVersions,
} from "../../scripts/build-site-all.js";

const SITE_V1 = {
  "site/index.html": `<!-- page: title="Home" summary="Landing" -->
<p>Version one. See the <a href="https://github.com/paxel/axt/blob/summer/CHANGELOG.md">changelog</a>.</p>`,
  "site/start/install.html": `<!-- page: title="Install" track="start" order=1 -->
<h2>Docker</h2><p>Run it.</p>`,
  "site/guide/legacy.html": `<!-- page: title="Legacy" track="design" order=1 -->
<h2>Old</h2><p>Only version one has this chapter.</p>`,
  "site/assets/site.css": "body{color:black}",
  "site/assets/site.js": "/* v1 */",
  "site/assets/favicon.svg": "<svg/>",
  "pyproject.toml": '[project]\nname = "x"\nversion = "1.0.0"\n',
};

const SPEC_V095 = {
  "spec/README.md":
    "# The specification\n\n| Document | Purpose |\n| --- | --- |\n| [A](a.md) | The first |\n",
  "spec/a.md": "# A\n\n## 1. One\n\nAs section 9 says.\n",
  "pyproject.toml": '[project]\nname = "x"\nversion = "0.9.5"\n',
};

/** @type {string} */
let tmp;
/** @type {string} */
let repo;
/** @type {string} */
let outDir;

/**
 * @param {string[]} args
 * @param {import("node:child_process").ExecFileSyncOptions} [options]
 */
function git(args, options = {}) {
  return execFileSync("git", args, { cwd: repo, encoding: "utf8", stdio: "pipe", ...options });
}

/** @param {Record<string, string>} files */
function write(files) {
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(repo, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
}

/** @param {string} message */
function commitAll(message) {
  git(["add", "-A"]);
  git(["commit", "-q", "-m", message]);
}

before(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "axt-site-all-"));
  repo = path.join(tmp, "repo");
  outDir = path.join(tmp, "dist");
  fs.mkdirSync(repo);
  git(["init", "-q", "-b", "summer"]);
  git(["config", "user.email", "test@example.invalid"]);
  git(["config", "user.name", "Test"]);
  git(["config", "commit.gpgsign", "false"]);
  // v0.9.0: a release before the site existed; it must not be listed.
  write({ "pyproject.toml": '[project]\nname = "x"\nversion = "0.9.0"\n', "README.md": "old" });
  commitAll("v0.9.0 without a site");
  git(["tag", "v0.9.0"]);
  // v0.9.5: the specification only, with a reference that was never checked.
  write(SPEC_V095);
  commitAll("v0.9.5 with the specification only");
  git(["tag", "v0.9.5"]);
  write({ "spec/a.md": "# A\n\n## 1. One\n\nAs section 1 says.\n" });
  write(SITE_V1);
  commitAll("v1.0.0 with the site");
  git(["tag", "v1.0.0"]);
  git(["tag", "v1.0.0-rc1"]); // not a release
  git(["tag", "nightly"]);
  // v1.1.0 drops the legacy chapter and gains a new one; today's assets differ.
  fs.rmSync(path.join(repo, "site/guide/legacy.html"));
  write({
    "site/guide/helm.html": `<!-- page: title="Helm chart" track="design" order=1 -->
<h2>Values</h2><p>New in 1.1.</p>`,
    "site/assets/site.css": "body{color:navy}",
    "pyproject.toml": '[project]\nname = "x"\nversion = "1.1.0"\n',
  });
  commitAll("v1.1.0");
  git(["tag", "v1.1.0"]);
  // The working tree is the unreleased 1.2.0 with one more chapter.
  write({
    "site/reference/mcp.html": `<!-- page: title="MCP" track="spec" order=1 -->
<h2>Tools</h2><p>Unreleased.</p>`,
    "pyproject.toml": '[project]\nname = "x"\nversion = "1.2.0"\n',
  });
  buildAll({
    repoRoot: repo,
    outDir,
    base: "/docs/",
  });
});

after(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

const read = (/** @type {string} */ rel) => fs.readFileSync(path.join(outDir, rel), "utf8");
const exists = (/** @type {string} */ rel) => fs.existsSync(path.join(outDir, rel));

void test("compareVersions sorts newest first, numerically per part", () => {
  assert.deepEqual(["2.9.0", "2.10.0", "10.0.0", "2.9.1"].sort(compareVersions), [
    "10.0.0",
    "2.10.0",
    "2.9.1",
    "2.9.0",
  ]);
});

void test("release tags are the vX.Y.Z tags whose tree carries the site or the specification, newest first", () => {
  assert.deepEqual(listReleaseTags(repo), ["v1.1.0", "v1.0.0", "v0.9.5"]);
});

void test("the plan puts the working tree in place of its tag and marks the newest as latest", () => {
  assert.deepEqual(planVersions({ tags: ["v1.1.0", "v1.0.0"], workingVersion: "1.2.0" }), [
    { version: "1.2.0", tag: null, source: "worktree", latest: true },
    { version: "1.1.0", tag: "v1.1.0", source: "tag", latest: false },
    { version: "1.0.0", tag: "v1.0.0", source: "tag", latest: false },
  ]);
  // On a release tag the working tree is that tag: one entry, carrying the tag.
  assert.deepEqual(planVersions({ tags: ["v1.1.0", "v1.0.0"], workingVersion: "1.1.0" }), [
    { version: "1.1.0", tag: "v1.1.0", source: "worktree", latest: true },
    { version: "1.0.0", tag: "v1.0.0", source: "tag", latest: false },
  ]);
  // A maintenance branch below the newest tag is not the latest.
  const plan = planVersions({ tags: ["v1.1.0", "v1.0.0"], workingVersion: "1.0.1" });
  assert.equal(plan[0]?.version, "1.1.0");
  assert.equal(plan[1]?.version, "1.0.1");
});

void test("extractTag unpacks the release paths of a tag and fails on a tag that lacks one", () => {
  const dest = path.join(tmp, "extract");
  extractTag(repo, "v1.0.0", dest);
  assert.ok(fs.existsSync(path.join(dest, "site/guide/legacy.html")));
  assert.match(fs.readFileSync(path.join(dest, "pyproject.toml"), "utf8"), /1\.0\.0/);
  assert.throws(() => {
    extractTag(repo, "v0.9.0", path.join(tmp, "extract-old"));
  }, /v0\.9\.0: holds neither site\/ nor spec\//);
  const specOnly = path.join(tmp, "extract-spec");
  extractTag(repo, "v0.9.5", specOnly);
  assert.ok(fs.existsSync(path.join(specOnly, "spec/a.md")));
  assert.ok(!fs.existsSync(path.join(specOnly, "site")));
});

void test("the root is the latest version, every version lives under /vX.Y.Z/, versions.json lists them", () => {
  assert.match(read("index.html"), /<summary class="chip"[^>]*>v1\.2\.0<\/summary>/);
  assert.ok(exists("reference/mcp.html"), "the unreleased chapter is in the root");
  assert.ok(exists("v1.2.0/reference/mcp.html"));
  assert.ok(exists("v1.1.0/guide/helm.html"));
  assert.ok(!exists("v1.1.0/guide/legacy.html"));
  assert.ok(exists("v1.0.0/guide/legacy.html"));
  assert.ok(!exists("v0.9.0"), "a release without a site is not built");
  assert.ok(exists("404.html") && exists("v1.0.0/404.html"));
  assert.ok(exists(".nojekyll"));
  assert.deepEqual(JSON.parse(read("versions.json")), [
    { version: "1.2.0", tag: null, path: "v1.2.0/", latest: true },
    { version: "1.1.0", tag: "v1.1.0", path: "v1.1.0/", latest: false },
    { version: "1.0.0", tag: "v1.0.0", path: "v1.0.0/", latest: false },
    { version: "0.9.5", tag: "v0.9.5", path: "v0.9.5/", latest: false },
  ]);
});

void test("a release with the specification only is built from its spec/, tolerating its old references", () => {
  assert.match(read("v0.9.5/index.html"), /The specification of AXT as it was released\./);
  assert.match(
    read("v0.9.5/index.html"),
    /<a href="spec\/index\.html">Read the specification<\/a>/,
  );
  const a = read("v0.9.5/spec/a.html");
  assert.match(a, /<title>A — AXT<\/title>/);
  assert.match(a, /As section 9 says\./, "the dead reference stays text");
  assert.match(read("v0.9.5/spec/index.html"), /The first/);
  assert.match(read("v1.0.0/spec/a.html"), /As section <a href="#section-1">1<\/a> says\./);
  assert.match(read("spec/a.html"), /blob\/summer|section-1/);
});

void test("the menu of an old version links the same chapter where it exists and the start page elsewhere", () => {
  const legacy = read("v1.0.0/guide/legacy.html");
  assert.match(
    legacy,
    /<li><a href="\/docs\/index\.html">v1\.2\.0 \(latest\)<\/a><\/li><li><a href="\/docs\/v1\.1\.0\/index\.html">v1\.1\.0<\/a><\/li><li><span aria-current="true">v1\.0\.0<\/span><\/li>/,
  );
  assert.match(
    legacy,
    /<p class="version-notice">Documentation for v1\.0\.0\. <a href="\/docs\/index\.html">Read the latest, v1\.2\.0<\/a>\./,
  );
  const install = read("v1.0.0/start/install.html");
  assert.match(install, /<a href="\/docs\/start\/install\.html">v1\.2\.0 \(latest\)<\/a>/);
  assert.match(install, /<a href="\/docs\/v1\.1\.0\/start\/install\.html">v1\.1\.0<\/a>/);
  const latest = read("start/install.html");
  assert.doesNotMatch(latest, /version-notice/);
  assert.match(latest, /<a href="\/docs\/v1\.0\.0\/start\/install\.html">v1\.0\.0<\/a>/);
  assert.match(
    read("v1.2.0/start/install.html"),
    /<span aria-current="true">v1\.2\.0 \(latest\)<\/span>/,
  );
});

void test("changelog links follow the tag; the working tree without a tag keeps summer", () => {
  assert.match(read("v1.0.0/index.html"), /blob\/v1\.0\.0\/CHANGELOG\.md">changelog<\/a>/);
  assert.match(read("v1.0.0/index.html"), /blob\/v1\.0\.0\/CHANGELOG\.md">Changelog<\/a>/);
  assert.match(read("v1.1.0/index.html"), /blob\/v1\.1\.0\/CHANGELOG\.md">Changelog<\/a>/);
  assert.match(read("index.html"), /blob\/summer\/CHANGELOG\.md">Changelog<\/a>/);
});

void test("every version is served with today's assets, its pages from its own tree", () => {
  assert.equal(read("v1.0.0/assets/site.css"), "body{color:navy}");
  assert.equal(read("v1.0.0/assets/site.js"), "/* v1 */");
  assert.match(read("v1.0.0/index.html"), /Version one\./);
  assert.match(read("v1.0.0/index.html"), /href="assets\/site\.css"/, "assets stay relative");
  assert.match(read("v1.0.0/404.html"), /href="\/docs\/v1\.0\.0\/assets\/site\.css"/);
});

void test("a release that no longer builds fails the whole build naming the tag", () => {
  const broken = path.join(tmp, "broken");
  fs.cpSync(repo, broken, { recursive: true });
  // Today's build requires an index page; v1.0.0 in the copy loses its front matter.
  const b = (/** @type {string[]} */ args) =>
    execFileSync("git", args, { cwd: broken, encoding: "utf8", stdio: "pipe" });
  b(["stash", "-q"]); // the copied working tree carries the unreleased 1.2.0
  b(["checkout", "-q", "v1.0.0"]);
  fs.writeFileSync(path.join(broken, "site/index.html"), "<p>no front matter</p>");
  b(["commit", "-q", "-a", "-m", "break v1.0.0"]);
  b(["tag", "-f", "v1.0.0"]);
  b(["checkout", "-q", "summer"]);
  b(["stash", "pop", "-q"]);
  assert.throws(
    () =>
      buildAll({
        repoRoot: broken,
        outDir: path.join(tmp, "broken-dist"),
      }),
    /^Error: v1\.0\.0: index\.html: missing front matter/,
  );
});
