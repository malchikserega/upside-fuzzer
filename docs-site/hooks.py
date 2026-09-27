"""MkDocs hooks for the UpsideFuzz GitHub Pages site.

The repository's Markdown is written for github.com: links are repo-relative
(``../../README.md``, ``../src/void/cmd/void/README.md``, ``tools/campaign/security_scenarios.yaml``).
This hook lets the exact same files render as a documentation site without editing them:

1. ``EXTERNAL_PAGES`` pulls selected Markdown files that live *outside* ``docs/`` into the
   site at a new location (and moves ``docs/index.md`` aside so the custom landing page can
   own ``/``).
2. Every Markdown link / image is resolved against the file's real location in the repo:
     * target is a page of this site   -> relative link to that page
     * target is an asset under docs/  -> relative link to the copied asset
     * target exists elsewhere in repo -> absolute github.com blob/tree URL
     * target doesn't exist at all     -> link is dropped, text kept (logged as info)
3. "Edit this page" / "View source" point at the file's real repo path.

Nothing here modifies files on disk.
"""

from __future__ import annotations

import logging
import os
import posixpath
import re

from mkdocs.structure.files import File, Files

log = logging.getLogger("mkdocs.hooks.upsidefuzz")

REPO_URL = "https://github.com/malchikserega/upside-fuzzer"
BRANCH = "main"

# repo path (relative to repo root)  ->  site source path (relative to docs_dir)
EXTERNAL_PAGES = {
    "docs/index.md": "docs-index.md",
    "README.md": "project/readme.md",
    "CONTRIBUTING.md": "development/contributing.md",
    "fixtures/demo-app/README.md": "demo/teamflow.md",
    "fixtures/planted-bug-api/README.md": "reference/planted-bug-api.md",
    "src/void/cmd/void/README.md": "reference/void-cli.md",
    "tools/grammar/grammarc/README.md": "reference/grammarc.md",
    "tools/dotnet/analyzer/README.md": "reference/analyzer.md",
    "tools/dotnet/instrumentor/README.md": "reference/instrumentor.md",
    "tests/README.md": "development/tests.md",
    ".work/README.md": "development/work-dir.md",
}

HOME_PAGE = """---
title: Coverage-guided REST API fuzzing for .NET
template: home.html
hide:
  - navigation
  - toc
  - footer
---
"""

_state: dict = {"root": None, "docs_dir": None, "src_to_repo": {}, "repo_to_src": {}}

FENCE_RE = re.compile(r"^( {0,3})(`{3,}|~{3,})")
# [text](target "title")  and  ![alt](target)
INLINE_LINK_RE = re.compile(r"(!?\[(?:[^\[\]]|\[[^\]]*\])*\])\(\s*<?([^)\s>]+)>?((?:\s+\"[^\"]*\")?)\s*\)")
REF_DEF_RE = re.compile(r"^( {0,3}\[[^\]]+\]:\s*)(\S+)(.*)$", re.M)
HTML_ATTR_RE = re.compile(r"""\b(src|href)=(["'])([^"']+)\2""")
DETAILS_RE = re.compile(r"<details(?![^>]*markdown=)([^>]*)>")
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


# --------------------------------------------------------------------------- events

def on_config(config, **kwargs):
    root = os.path.dirname(os.path.abspath(config.config_file_path))
    _state["root"] = root
    _state["docs_dir"] = os.path.abspath(config.docs_dir)
    _state["repo_to_src"] = dict(EXTERNAL_PAGES)
    _state["src_to_repo"] = {v: k for k, v in EXTERNAL_PAGES.items()}
    return config


def on_files(files: Files, config, **kwargs):
    root = _state["root"]
    # docs/index.md becomes /docs-index/; the landing page takes over /.
    original_index = files.get_file_from_path("index.md")
    if original_index is not None:
        files.remove(original_index)

    for repo_path, src_uri in EXTERNAL_PAGES.items():
        abs_path = os.path.join(root, repo_path)
        if not os.path.isfile(abs_path):
            log.info("external page missing, skipped: %s", repo_path)
            continue
        with open(abs_path, encoding="utf-8") as fh:
            content = fh.read()
        files.append(File.generated(config, src_uri, content=content))

    files.append(File.generated(config, "index.md", content=HOME_PAGE))

    # macOS / editor noise that may exist in a local checkout
    for f in list(files):
        if os.path.basename(f.src_uri) in (".DS_Store",):
            files.remove(f)
    return files


def on_page_markdown(markdown: str, page, config, files: Files, **kwargs):
    src_uri = page.file.src_uri
    if src_uri == "index.md":
        page.edit_url = None
        return markdown
    repo_path = _state["src_to_repo"].get(src_uri, "docs/" + src_uri)
    page.edit_url = f"{REPO_URL}/edit/{BRANCH}/{repo_path}"
    return _rewrite(markdown, repo_path, src_uri, files)


# --------------------------------------------------------------------------- rewriting

def _rewrite(markdown: str, repo_path: str, src_uri: str, files: Files) -> str:
    out, chunk, fence = [], [], None
    for line in markdown.splitlines(keepends=True):
        m = FENCE_RE.match(line)
        if fence is None:
            if m:
                out.append(_rewrite_prose("".join(chunk), repo_path, src_uri, files))
                chunk = []
                fence = m.group(2)
                out.append(line)
            else:
                chunk.append(line)
        else:
            out.append(line)
            if m and m.group(2)[0] == fence[0] and len(m.group(2)) >= len(fence) and not line.strip()[len(m.group(2)):].strip():
                fence = None
    out.append(_rewrite_prose("".join(chunk), repo_path, src_uri, files))
    return "".join(out)


def _rewrite_prose(text: str, repo_path: str, src_uri: str, files: Files) -> str:
    if not text:
        return text

    def inline(m):
        label, target, title = m.group(1), m.group(2), m.group(3)
        new = _resolve(target, repo_path, src_uri, files)
        if new is None:
            if label.startswith("!"):
                return ""
            return label[1:-1]
        return f"{label}({new}{title})"

    def refdef(m):
        new = _resolve(m.group(2), repo_path, src_uri, files)
        return f"{m.group(1)}{new or '#'}{m.group(3)}"

    def html_attr(m):
        new = _resolve(m.group(3), repo_path, src_uri, files, html=True)
        return f"{m.group(1)}={m.group(2)}{new or '#'}{m.group(2)}"

    text = INLINE_LINK_RE.sub(inline, text)
    text = REF_DEF_RE.sub(refdef, text)
    text = HTML_ATTR_RE.sub(html_attr, text)
    text = DETAILS_RE.sub(r'<details markdown="1"\1>', text)
    return text


def _resolve(target: str, repo_path: str, src_uri: str, files: Files, html: bool = False):
    """Return the rewritten link target, or None if it points at nothing."""
    if not target or target.startswith("#") or SCHEME_RE.match(target) or target.startswith("//"):
        return target
    path, sep, frag = target.partition("#")
    anchor = sep + frag
    path = path.split("?", 1)[0]
    if not path:
        return target

    root = _state["root"]
    if path.startswith("/"):
        resolved = posixpath.normpath(path.lstrip("/"))
    else:
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(repo_path), path))
    if resolved.startswith("../") or resolved == "..":
        log.info("link escapes repo in %s: %s", repo_path, target)
        return None
    resolved = resolved.rstrip("/") or "."

    page_dir = posixpath.dirname(src_uri)

    # 1. A page of this site (docs/*.md or a pulled-in external page)
    site_src = _state["repo_to_src"].get(resolved)
    if site_src is None and resolved.startswith("docs/") and resolved.endswith(".md"):
        candidate = resolved[len("docs/"):]
        if files.get_file_from_path(candidate) is not None:
            site_src = candidate
    if site_src is not None and files.get_file_from_path(site_src) is not None:
        if html:  # raw HTML is not processed by MkDocs' .md -> URL conversion
            return _url_rel(_src_url(site_src), src_uri) + anchor
        return posixpath.relpath(site_src, page_dir or ".") + anchor

    # 2. A static asset under docs/
    if resolved.startswith("docs/"):
        candidate = resolved[len("docs/"):]
        f = files.get_file_from_path(candidate)
        if f is not None and not candidate.endswith(".md"):
            if html:
                return _url_rel(candidate, src_uri) + anchor
            return posixpath.relpath(candidate, page_dir or ".") + anchor

    # 3. Anything else that exists in the repository -> github.com
    abs_path = os.path.join(root, resolved)
    if os.path.isdir(abs_path):
        return f"{REPO_URL}/tree/{BRANCH}/{resolved}{anchor}"
    if os.path.isfile(abs_path):
        return f"{REPO_URL}/blob/{BRANCH}/{resolved}{anchor}"

    log.info("dropping link to missing path in %s: %s", repo_path, target)
    return None


def _src_url(src: str) -> str:
    """Site URL path (directory URLs) of a Markdown source path."""
    base = posixpath.basename(src)
    if base in ("index.md", "README.md"):
        return posixpath.dirname(src) + "/" if posixpath.dirname(src) else ""
    return src[:-3] + "/"


def _url_rel(target_url: str, from_src: str) -> str:
    """Relative URL from the rendered page of ``from_src`` to ``target_url``."""
    from_dir = _src_url(from_src).rstrip("/") or "."
    rel = posixpath.relpath(target_url.rstrip("/") or ".", from_dir)
    return rel + ("/" if target_url.endswith("/") and rel != "." else "")
