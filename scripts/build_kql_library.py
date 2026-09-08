#!/usr/bin/env python3
"""
Generate the DevSecOpsDadAttack KQL Library section from a checkout of the
attack-pack repository (https://github.com/een421/attack-pack — the folder
tree lives on disk somewhere and this script walks it).

Outputs (all under the Jekyll site root, --site-dir):

    _data/kql_library.yml                # index the landing/category pages read
    kql-library/index.html               # library landing page
    kql-library/<cat>/index.html         # one page per top-level category
    kql-library/<cat>/<slug>/index.md    # one page per .kql file, code inlined
    assets/kql/<cat>/[<sub>/]<file>.kql  # raw .kql copies so visitors can download

Everything the script writes is deterministic — running it again just
overwrites. Nothing outside these paths is touched.

Usage:
    python scripts/build_kql_library.py [--source ../attack-pack-main] [--site-dir .]

The script only uses the Python 3.8+ standard library, so it works in CI
with a bare `actions/setup-python` step.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Category metadata — human titles + Font Awesome icons for the landing cards.
# Any folder not listed here still renders; it just gets a title inferred from
# its slug and a generic icon.
# ---------------------------------------------------------------------------
CATEGORY_META: Dict[str, Dict[str, str]] = {
    "analytics-rules":    {"title": "Analytics Rules",   "icon": "fa-shield-halved"},
    "cost-and-ingest":    {"title": "Cost & Ingest",     "icon": "fa-coins"},
    "email-and-phishing": {"title": "Email & Phishing",  "icon": "fa-envelope-open-text"},
    "health-checks":      {"title": "Health Checks",     "icon": "fa-heart-pulse"},
    "hunting":            {"title": "Hunting",           "icon": "fa-magnifying-glass"},
    "identity":           {"title": "Identity",          "icon": "fa-user-shield"},
    "mitre-attack":       {"title": "MITRE ATT&CK",      "icon": "fa-crosshairs"},
    "pihole":             {"title": "Pi-hole",           "icon": "fa-network-wired"},
    "posture":            {"title": "Posture",           "icon": "fa-server"},
    "reference":          {"title": "Reference",         "icon": "fa-book"},
    "reporting":          {"title": "Reporting",         "icon": "fa-chart-line"},
}

DEFAULT_ICON = "fa-code"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class Query:
    slug: str                    # e.g. "gb-per-table"
    title: str                   # human display title
    description: str             # one-line description (from README table or KQL comment)
    file_name: str               # "gb-per-table.kql"
    source_path: Path            # abs path to .kql in the source repo
    category_slug: str           # top-level, e.g. "cost-and-ingest"
    subcategory_slug: Optional[str]  # second-level, e.g. "billable-volume", or None
    subcategory_title: Optional[str] = None
    relative_asset_path: str = ""    # e.g. "cost-and-ingest/billable-volume/gb-per-table.kql"


@dataclass
class Subcategory:
    slug: str
    title: str
    description: str = ""
    queries: List[Query] = field(default_factory=list)


@dataclass
class Category:
    slug: str
    title: str
    icon: str
    description: str = ""
    # If the category has no subfolders, subcategories is empty and queries is populated.
    # If it has subfolders, subcategories is populated and queries is empty.
    subcategories: List[Subcategory] = field(default_factory=list)
    queries: List[Query] = field(default_factory=list)

    @property
    def total_query_count(self) -> int:
        return len(self.queries) + sum(len(s.queries) for s in self.subcategories)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def slugify(name: str) -> str:
    """Path- and URL-safe slug: lowercase, alphanum plus dashes."""
    s = name.lower()
    s = re.sub(r"\.kql$", "", s)
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")


def titleize(slug: str) -> str:
    words = slug.replace("_", "-").split("-")
    return " ".join(w.capitalize() for w in words if w)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# README table row: `| [`filename.kql`](./filename.kql) | Description text |`
README_ROW_RE = re.compile(
    r"^\|\s*\[`?([^`\]]+\.kql)`?\]\([^)]+\)\s*\|\s*(.+?)\s*\|\s*$",
    re.MULTILINE,
)

# README first paragraph after the # heading (until a blank line).
README_INTRO_RE = re.compile(
    r"^#\s+[^\n]+\n+([^\n#][^\n]*(?:\n[^\n#][^\n]*)*)",
    re.MULTILINE,
)


def parse_readme_descriptions(readme_path: Path) -> Dict[str, str]:
    """Return {filename.kql: description} for each row in the README's table."""
    if not readme_path.exists():
        return {}
    text = read_text(readme_path)
    out: Dict[str, str] = {}
    for match in README_ROW_RE.finditer(text):
        filename, desc = match.group(1).strip(), match.group(2).strip()
        # Strip surrounding markdown code fences from the description if any.
        out[filename] = desc
    return out


def parse_readme_intro(readme_path: Path) -> str:
    """Return the first paragraph of a README (used for category descriptions)."""
    if not readme_path.exists():
        return ""
    text = read_text(readme_path)
    m = README_INTRO_RE.search(text)
    if not m:
        return ""
    para = m.group(1).strip()
    # Collapse hard-wrapped lines into one paragraph.
    return re.sub(r"\s+", " ", para)


AUTHOR_LINE_RE = re.compile(r"^//\s*Author\b", re.IGNORECASE)


def extract_kql_description(kql_path: Path) -> str:
    """Fallback description: first non-author `//` comment line in the .kql."""
    try:
        for raw in kql_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line.startswith("//"):
                # Comments are contiguous at the top; stop at first non-comment.
                if line:
                    break
                continue
            if AUTHOR_LINE_RE.match(line):
                continue
            return line.lstrip("/ ").strip()
    except OSError:
        pass
    return ""


def title_from_slug(slug: str) -> str:
    # "gb-per-table" -> "GB Per Table"; special-case a few acronyms.
    acronyms = {"kql", "gb", "ad", "pim", "mde", "dns", "eol", "rdp", "smtp",
                "ip", "ipv4", "ipv6", "usa", "us"}
    words = slug.split("-")
    out = []
    for w in words:
        if w in acronyms:
            out.append(w.upper())
        else:
            out.append(w.capitalize())
    return " ".join(out)


# ---------------------------------------------------------------------------
# Walker
# ---------------------------------------------------------------------------
def scan_source(source_dir: Path) -> List[Category]:
    """Walk the attack-pack repo and build the Category/Subcategory/Query tree."""
    categories: List[Category] = []

    for entry in sorted(source_dir.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name.startswith(".") or entry.name.startswith("_"):
            continue

        cat_slug = entry.name
        meta = CATEGORY_META.get(cat_slug, {})
        cat = Category(
            slug=cat_slug,
            title=meta.get("title", titleize(cat_slug)),
            icon=meta.get("icon", DEFAULT_ICON),
            description=parse_readme_intro(entry / "README.md"),
        )

        # Direct-child .kql files -> leaf category
        direct_kql = sorted(p for p in entry.iterdir()
                            if p.is_file() and p.suffix.lower() == ".kql")
        # Subfolders -> nested category
        subfolders = sorted(p for p in entry.iterdir()
                            if p.is_dir() and not p.name.startswith("."))

        cat_readme_descs = parse_readme_descriptions(entry / "README.md")

        # Queries directly under the category
        for kql_path in direct_kql:
            q = make_query(kql_path, cat_slug, None, None, cat_readme_descs)
            cat.queries.append(q)

        # Nested subfolders
        for sub in subfolders:
            sub_readme_descs = parse_readme_descriptions(sub / "README.md")
            sub_intro = parse_readme_intro(sub / "README.md")
            sub_obj = Subcategory(
                slug=sub.name,
                title=titleize(sub.name),
                description=sub_intro,
            )
            for kql_path in sorted(p for p in sub.iterdir()
                                   if p.is_file() and p.suffix.lower() == ".kql"):
                q = make_query(kql_path, cat_slug, sub.name, sub_obj.title,
                               sub_readme_descs)
                sub_obj.queries.append(q)
            # Also descend one more level in case someone nests further
            for deep in sorted(p for p in sub.iterdir() if p.is_dir()):
                deep_readme_descs = parse_readme_descriptions(deep / "README.md")
                for kql_path in sorted(p for p in deep.iterdir()
                                       if p.is_file() and p.suffix.lower() == ".kql"):
                    q = make_query(kql_path, cat_slug,
                                   f"{sub.name}/{deep.name}",
                                   f"{sub_obj.title} / {titleize(deep.name)}",
                                   deep_readme_descs)
                    sub_obj.queries.append(q)
            if sub_obj.queries:
                cat.subcategories.append(sub_obj)

        if cat.queries or cat.subcategories:
            categories.append(cat)

    # De-duplicate query slugs within a category (subcategory prefix on collision).
    for cat in categories:
        seen: Dict[str, Query] = {}
        for q in _all_queries(cat):
            if q.slug in seen and seen[q.slug] is not q:
                q.slug = f"{q.subcategory_slug.replace('/', '-')}-{q.slug}" \
                    if q.subcategory_slug else f"{q.slug}-dup"
            seen[q.slug] = q

    return categories


def _all_queries(cat: Category):
    for q in cat.queries:
        yield q
    for s in cat.subcategories:
        for q in s.queries:
            yield q


def make_query(kql_path: Path, cat_slug: str, sub_slug: Optional[str],
               sub_title: Optional[str], readme_descs: Dict[str, str]) -> Query:
    file_name = kql_path.name
    slug = slugify(file_name)
    title = title_from_slug(slug)
    desc = readme_descs.get(file_name) or extract_kql_description(kql_path)
    rel = kql_path.name if sub_slug is None else f"{sub_slug}/{kql_path.name}"
    return Query(
        slug=slug,
        title=title,
        description=desc,
        file_name=file_name,
        source_path=kql_path,
        category_slug=cat_slug,
        subcategory_slug=sub_slug,
        subcategory_title=sub_title,
        relative_asset_path=f"{cat_slug}/{rel}",
    )


# ---------------------------------------------------------------------------
# YAML emit — hand-rolled so the script has no third-party deps.
# The data we emit is simple (strings, lists of dicts) so a small emitter is
# safer than depending on PyYAML.
# ---------------------------------------------------------------------------
def yaml_escape(s: str) -> str:
    if s is None:
        return '""'
    if s == "":
        return '""'
    # Force-quote anything that could confuse the YAML parser.
    needs_quote = any(c in s for c in ':#&*!|>%@`\n"\'') or s.lstrip() != s or s.rstrip() != s
    if needs_quote:
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def dump_yaml(categories: List[Category]) -> str:
    lines = ["# Generated by scripts/build_kql_library.py — do not edit by hand.",
             "categories:"]
    for cat in categories:
        lines.append(f"  - slug: {yaml_escape(cat.slug)}")
        lines.append(f"    title: {yaml_escape(cat.title)}")
        lines.append(f"    icon: {yaml_escape(cat.icon)}")
        lines.append(f"    description: {yaml_escape(cat.description)}")
        lines.append(f"    query_count: {cat.total_query_count}")
        # Flat queries at category root
        if cat.queries:
            lines.append("    queries:")
            for q in cat.queries:
                _emit_query_yaml(lines, q, indent=6)
        else:
            lines.append("    queries: []")
        if cat.subcategories:
            lines.append("    subcategories:")
            for sub in cat.subcategories:
                lines.append(f"      - slug: {yaml_escape(sub.slug)}")
                lines.append(f"        title: {yaml_escape(sub.title)}")
                lines.append(f"        description: {yaml_escape(sub.description)}")
                lines.append("        queries:")
                for q in sub.queries:
                    _emit_query_yaml(lines, q, indent=10)
        else:
            lines.append("    subcategories: []")
    return "\n".join(lines) + "\n"


def _emit_query_yaml(lines: List[str], q: Query, indent: int) -> None:
    pad = " " * indent
    lines.append(f"{pad}- slug: {yaml_escape(q.slug)}")
    lines.append(f"{pad}  title: {yaml_escape(q.title)}")
    lines.append(f"{pad}  description: {yaml_escape(q.description)}")
    lines.append(f"{pad}  file_name: {yaml_escape(q.file_name)}")
    lines.append(f"{pad}  asset_path: {yaml_escape(q.relative_asset_path)}")
    lines.append(f"{pad}  category_slug: {yaml_escape(q.category_slug)}")
    if q.subcategory_slug:
        lines.append(f"{pad}  subcategory_slug: {yaml_escape(q.subcategory_slug)}")
        lines.append(f"{pad}  subcategory_title: {yaml_escape(q.subcategory_title)}")


# ---------------------------------------------------------------------------
# Page emit
# ---------------------------------------------------------------------------
LANDING_TEMPLATE = """\
---
layout: page
title: KQL Library
subtitle: A browsable catalog of KQL queries for Microsoft Sentinel, Defender XDR, and Log Analytics.
permalink: /kql-library/
full-width: true
js:
  - "/assets/js/kql-library.js"
---

<section class="attack-home-intro attack-home-intro-lib">
  <p class="attack-eyebrow">A running library of deceptively simple KQL.</p>

  <img
    src="{{ '/assets/img/DevSecOpsDadAttack.png' | relative_url }}"
    alt="DevSecOpsDad">

  <h2>The KQL Library.</h2>

  <p>The queries I keep coming back to whenever a complicated problem shows up in
  Microsoft Sentinel, Defender XDR, or Log Analytics. Grouped by what they answer,
  each one shipped with the description of when to reach for it.</p>
</section>

<hr class="attack-separator">

<div class="kql-lib-toolbar">
  <input
    type="search"
    id="kql-lib-search"
    class="tag-filter-input kql-lib-search"
    placeholder="Search __TOTAL_QUERIES__ queries by title, description, or category…"
    aria-label="Search KQL queries">
  <p class="kql-lib-hint" id="kql-lib-hint">
    Type to search all queries, or pick a category below.
  </p>
</div>

<div class="kql-lib-categories" id="kql-lib-categories">
{% for cat in site.data.kql_library.categories %}
  <a class="kql-lib-cat-card" href="{{ '/kql-library/' | relative_url }}{{ cat.slug }}/">
    <span class="kql-lib-cat-icon"><i class="fas {{ cat.icon }}" aria-hidden="true"></i></span>
    <span class="kql-lib-cat-title">{{ cat.title }}</span>
    <span class="kql-lib-cat-count">{{ cat.query_count }} quer{% if cat.query_count == 1 %}y{% else %}ies{% endif %}</span>
    <span class="kql-lib-cat-desc">{{ cat.description }}</span>
  </a>
{% endfor %}
</div>

<ul class="kql-lib-results list-unstyled" id="kql-lib-results" role="list" hidden>
{% for cat in site.data.kql_library.categories %}
  {% for q in cat.queries %}
    <li class="kql-lib-result"
        data-title="{{ q.title | downcase }}"
        data-desc="{{ q.description | downcase }}"
        data-cat="{{ cat.title | downcase }}"
        data-catslug="{{ cat.slug }}">
      <a href="{{ '/kql-library/' | relative_url }}{{ cat.slug }}/{{ q.slug }}/">
        <span class="attack-badge attack-badge-lib">{{ cat.title }}</span>
        <span class="kql-lib-result-title">{{ q.title }}</span>
      </a>
      <p class="kql-lib-result-desc">{{ q.description }}</p>
    </li>
  {% endfor %}
  {% for sub in cat.subcategories %}
    {% for q in sub.queries %}
      <li class="kql-lib-result"
          data-title="{{ q.title | downcase }}"
          data-desc="{{ q.description | downcase }}"
          data-cat="{{ cat.title | downcase }} {{ sub.title | downcase }}"
          data-catslug="{{ cat.slug }}">
        <a href="{{ '/kql-library/' | relative_url }}{{ cat.slug }}/{{ q.slug }}/">
          <span class="attack-badge attack-badge-lib">{{ cat.title }}</span>
          <span class="attack-badge attack-badge-sub">{{ sub.title }}</span>
          <span class="kql-lib-result-title">{{ q.title }}</span>
        </a>
        <p class="kql-lib-result-desc">{{ q.description }}</p>
      </li>
    {% endfor %}
  {% endfor %}
{% endfor %}
</ul>

<p class="kql-lib-empty" id="kql-lib-empty" hidden>No queries match that search.</p>
"""


def emit_landing(site_dir: Path, categories: List[Category]) -> Path:
    total = sum(c.total_query_count for c in categories)
    body = LANDING_TEMPLATE.replace("__TOTAL_QUERIES__", str(total))
    out = site_dir / "kql-library" / "index.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body, encoding="utf-8")
    return out


def emit_category_page(site_dir: Path, cat: Category) -> Path:
    out = site_dir / "kql-library" / cat.slug / "index.html"
    out.parent.mkdir(parents=True, exist_ok=True)

    lines: List[str] = []
    lines.append("---")
    lines.append("layout: page")
    lines.append(f"title: {cat.title}")
    if cat.description:
        # Trim to a single line for the subtitle.
        subtitle = re.sub(r"\s+", " ", cat.description).strip()
        # Escape any yaml-hostile chars minimally.
        subtitle = subtitle.replace('"', "'")
        lines.append(f'subtitle: "{subtitle}"')
    lines.append(f"permalink: /kql-library/{cat.slug}/")
    lines.append("---")
    lines.append("")
    lines.append('<section class="attack-home-intro attack-home-intro-lib">')
    lines.append(f'  <p class="attack-eyebrow"><i class="fas {cat.icon}" aria-hidden="true"></i>&nbsp;KQL Library / {cat.title}</p>')
    lines.append(f'  <h2>{cat.title}</h2>')
    if cat.description:
        lines.append(f'  <p>{cat.description}</p>')
    lines.append('</section>')
    lines.append('')
    lines.append('<p class="kql-lib-crumbs"><a href="{{ \'/kql-library/\' | relative_url }}">&larr; All KQL categories</a></p>')
    lines.append('')

    def render_query_list(queries: List[Query], heading: Optional[str] = None,
                          intro: Optional[str] = None) -> None:
        if heading:
            lines.append(f'<h3 class="kql-lib-subcat-heading">{heading}</h3>')
        if intro:
            lines.append(f'<p class="kql-lib-subcat-intro">{intro}</p>')
        lines.append('<ul class="kql-lib-query-list list-unstyled" role="list">')
        for q in queries:
            url = f"/kql-library/{cat.slug}/{q.slug}/"
            lines.append(f'  <li class="kql-lib-query-item">')
            lines.append(f'    <a href="{{{{ \'{url}\' | relative_url }}}}">')
            lines.append(f'      <span class="kql-lib-query-title">{q.title}</span>')
            lines.append(f'      <code class="kql-lib-query-file">{q.file_name}</code>')
            lines.append(f'    </a>')
            if q.description:
                lines.append(f'    <p class="kql-lib-query-desc">{q.description}</p>')
            lines.append(f'  </li>')
        lines.append('</ul>')

    if cat.queries:
        render_query_list(cat.queries)
    for sub in cat.subcategories:
        render_query_list(sub.queries, heading=sub.title, intro=sub.description or None)

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


QUERY_PAGE_TEMPLATE = """\
---
layout: page
title: {title}
subtitle: "{subtitle}"
permalink: /kql-library/{cat_slug}/{query_slug}/
js:
  - "/assets/js/kql-library.js"
---

<p class="kql-lib-crumbs">
  <a href="{{{{ '/kql-library/' | relative_url }}}}">KQL Library</a>
  &nbsp;/&nbsp;
  <a href="{{{{ '/kql-library/{cat_slug}/' | relative_url }}}}">{cat_title}</a>
</p>

<div class="kql-lib-query-header">
  <span class="attack-badge attack-badge-lib"><i class="fas {cat_icon}" aria-hidden="true"></i>&nbsp;{cat_title}</span>
{sub_badge}\
  <code class="kql-lib-query-file">{file_name}</code>
</div>

{description_block}\

<div class="kql-lib-query-actions">
  <button type="button" class="kql-lib-copy-btn" data-copy-target="kql-code-{query_slug}">
    <i class="far fa-copy" aria-hidden="true"></i>&nbsp;Copy query
  </button>
  <a class="kql-lib-download-btn"
     href="{{{{ '/assets/kql/{asset_path}' | relative_url }}}}"
     download="{file_name}">
    <i class="fas fa-download" aria-hidden="true"></i>&nbsp;Download .kql
  </a>
</div>

<div id="kql-code-{query_slug}" markdown="1">

```kusto
{kql_body}
```

</div>
"""


def emit_query_page(site_dir: Path, cat: Category, q: Query) -> Path:
    out = site_dir / "kql-library" / cat.slug / q.slug / "index.md"
    out.parent.mkdir(parents=True, exist_ok=True)

    kql_body = q.source_path.read_text(encoding="utf-8").rstrip()

    subtitle = (q.description or "KQL query").replace('"', "'")
    subtitle = re.sub(r"\s+", " ", subtitle).strip()
    # Front-matter subtitles are one line; truncate rather than smuggle newlines.
    if len(subtitle) > 240:
        subtitle = subtitle[:237].rstrip() + "..."

    sub_badge = ""
    if q.subcategory_title:
        sub_badge = (
            f'  <span class="attack-badge attack-badge-sub">{q.subcategory_title}</span>\n'
        )

    description_block = ""
    if q.description:
        description_block = f'<p class="kql-lib-query-longdesc">{q.description}</p>\n\n'

    body = QUERY_PAGE_TEMPLATE.format(
        title=q.title,
        subtitle=subtitle,
        cat_slug=cat.slug,
        cat_title=cat.title,
        cat_icon=cat.icon,
        query_slug=q.slug,
        file_name=q.file_name,
        sub_badge=sub_badge,
        description_block=description_block,
        asset_path=q.relative_asset_path,
        kql_body=kql_body,
    )
    out.write_text(body, encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Raw asset copy
# ---------------------------------------------------------------------------
def copy_raw_asset(site_dir: Path, q: Query) -> Path:
    dest = site_dir / "assets" / "kql" / q.relative_asset_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(q.source_path, dest)
    return dest


# ---------------------------------------------------------------------------
# Cleanup — wipe previous outputs so removed queries don't linger.
# ---------------------------------------------------------------------------
def clean(site_dir: Path) -> None:
    for path in [site_dir / "kql-library",
                 site_dir / "assets" / "kql",
                 site_dir / "_data" / "kql_library.yml"]:
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path,
                        default=Path("../attack-pack-main"),
                        help="Path to a checkout of the attack-pack repo "
                             "(default: ../attack-pack-main)")
    parser.add_argument("--site-dir", type=Path, default=Path("."),
                        help="Jekyll site root (default: current dir)")
    parser.add_argument("--clean", action="store_true",
                        help="Wipe previous outputs before generating.")
    args = parser.parse_args(argv)

    source = args.source.resolve()
    site_dir = args.site_dir.resolve()

    if not source.is_dir():
        print(f"error: --source {source} is not a directory", file=sys.stderr)
        return 1
    if not (site_dir / "_config.yml").is_file():
        print(f"error: --site-dir {site_dir} does not look like a Jekyll site "
              f"(no _config.yml)", file=sys.stderr)
        return 1

    if args.clean:
        clean(site_dir)

    categories = scan_source(source)
    if not categories:
        print("error: no categories found in source directory", file=sys.stderr)
        return 1

    # 1. YAML data file
    data_path = site_dir / "_data" / "kql_library.yml"
    data_path.parent.mkdir(parents=True, exist_ok=True)
    data_path.write_text(dump_yaml(categories), encoding="utf-8")

    # 2. Landing page
    emit_landing(site_dir, categories)

    # 3. Category + query pages, plus raw asset copies
    query_count = 0
    for cat in categories:
        emit_category_page(site_dir, cat)
        for q in _all_queries(cat):
            emit_query_page(site_dir, cat, q)
            copy_raw_asset(site_dir, q)
            query_count += 1

    print(f"OK: built KQL Library — {len(categories)} categories, "
          f"{query_count} queries.")
    print(f"  data:    {data_path.relative_to(site_dir)}")
    print(f"  landing: kql-library/index.html")
    print(f"  raw:     assets/kql/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
