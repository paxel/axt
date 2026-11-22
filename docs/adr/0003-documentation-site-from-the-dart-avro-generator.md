# 3. A documentation site, built with dart-avro's generator

Date: 2026-11-21

## Status

Accepted.

## Context

The documentation of AXT is the Markdown of `spec/`, read on GitHub. It states the rules, but it does not lead an app's maker, a library's author or a relay's operator to the parts they need, and nothing shows the schemas as reference pages. The owner wants user documentation on GitHub Pages, done the way `paxel/dart-avro` and `paxel/sanshain-service` do it ([axt-1029](https://github.com/paxel/axt/issues/37)).

## Decision

- `paxel/axt` has one site, for the standard. Each library has a site of its own in its own repository, which links to the standard's.
- The site copies dart-avro's generator (`scripts/build-site.js`, `scripts/build-site-all.js`, `scripts/site/`), its tests (`tests/site/`), its lint step and `.github/workflows/pages.yml`, as dart-avro copied them from sanshain-service: HTML fragments in `site/` with a front-matter comment, built by a Node script without dependencies into `site-dist/`, with navigation, tables of contents, a search index and every released version under `/vX.Y.Z/`.
- The version of a build is the `version` of the `[project]` table of `pyproject.toml`.
- Five tracks:
  - **Start**: what AXT is, how an exchange goes, the terms.
  - **Design an app**: for the maker of an app.
  - **Implement a library**: for the author of a library.
  - **Run a relay**: for whoever runs a relay.
  - **Specification**: the documents of `spec/`, converted at build time, and reference pages generated from the schemas.
- The site's tooling is a second stack of paxel/gates beside Python: `package.json`, `package-lock.json`, `.nvmrc`, the `ts` gate (prettier, eslint, tsc, the site tests), a coverage part `site`, CodeQL for `javascript-typescript`, and Dependabot for npm.
- The site is served at `https://paxel.github.io/axt/` and deployed only from `v*` tags; every push and pull request builds it.
- The header carries the AXT axe of `docs/logo/`, the footer the links to GitHub and the changelog.

## Considered options

- Rewriting the generator in Python, the repository's only stack until now: about 1,300 tested lines to redo before the first page, and the copies in dart-avro and sanshain-service would drift apart from a third.
- The Markdown on GitHub alone: no tracks, no search, no versions, no generated reference pages.

## Consequences

- A specification repository carries Node tooling, used by the site job and the `ts` gate only.
- The owner sets two things once: Settings, Pages, Source "GitHub Actions"; and Settings, Environments, `github-pages`, deployment from tags matching `v*`.
- The required checks of the ruleset on `summer` gain the `ts` gate once it has run.
- The working tree's version names the root of the site. As long as it equals the latest tag's, the working tree takes that tag's place.
