# docs-site/ — GitHub Pages build for the documentation

The public docs site (<https://malchikserega.github.io/upside-fuzzer/>) is built with
[MkDocs](https://www.mkdocs.org/) + [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/)
straight from the Markdown in `docs/`. **Nothing in `docs/` needs to change for the site** —
keep writing docs for github.com and the site follows.

| Path | What it is |
|------|------------|
| `../mkdocs.yml` | Site config: theme, Markdown extensions, navigation |
| `hooks.py` | Pulls Markdown that lives outside `docs/` into the site (README, TeamFlow demo, void CLI reference, component READMEs, …), rewrites repo-relative links (site page → site link, other repo file → github.com link, missing file → plain text), and fixes "edit this page" URLs |
| `overrides/home.html` | The custom landing page |
| `overrides/assets/stylesheets/upsidefuzz.css` | Theme (colors, typography, landing-page layout) |
| `overrides/assets/brand/logo.svg` | Logo + favicon |
| `requirements.txt` | Pinned-range build dependencies |
| `../.github/workflows/pages.yml` | Builds and deploys on push to `main` |

## Preview locally

```bash
pip install -r docs-site/requirements.txt
mkdocs serve            # http://127.0.0.1:8000/upside-fuzzer/
mkdocs build            # static output in ./site (git-ignored)
```

## Adding a page

* A new file under `docs/` → add it to `nav:` in `mkdocs.yml`.
* A Markdown file elsewhere in the repo → add `"<repo path>": "<site path>"` to
  `EXTERNAL_PAGES` in `hooks.py`, then add the site path to `nav:`.

Links to missing files are reported as `INFO` lines during `mkdocs build` (look for
`dropping link to missing path`).

## One-time GitHub setup

Repository **Settings → Pages → Build and deployment → Source: GitHub Actions**.
