# scripts/

Small helpers that generate parts of the site from external sources.
They're written to be re-runnable — every run is a clean overwrite of the
paths they own.

## build_kql_library.py

Generates the **KQL Library** section (`/kql-library/`) from a checkout of
the [`attack-pack`](https://github.com/DevSecOpsDadAttack/attack-pack) repository.

### What it writes

- `_data/kql_library.yml` — the index (categories → subcategories → queries)
- `kql-library/index.html` — landing page with the searchable catalog
- `kql-library/<cat>/index.html` — one page per top-level category
- `kql-library/<cat>/<slug>/index.md` — one page per `.kql` file, with the
  query inlined as a `kusto` code block
- `assets/kql/<cat>/[<sub>/]<file>.kql` — raw `.kql` copies so visitors can
  download the source

Every one of those paths is in `.gitignore`; they never get committed. CI
regenerates them on each build.

### Where it gets the source from

The GitHub Actions workflow (`.github/workflows/ci.yml`) checks out the
`attack-pack` repo into `kql-library-src/` and then runs:

```bash
python scripts/build_kql_library.py \
  --source kql-library-src \
  --site-dir . \
  --clean
```

The source repo and ref are controlled by the `KQL_LIBRARY_REPO` and
`KQL_LIBRARY_REF` env vars at the top of the workflow.

### Running it locally

You need Python 3.8+ (stdlib only — no `pip install` needed) and a local
checkout of `attack-pack` sitting next to this site:

```
Claude/
├── attack-pack-main/                       # ← source
└── DevSecOpsDadAttack.github.io-master/    # ← this repo
```

Then from this repo's root:

```bash
python scripts/build_kql_library.py --clean
```

`--source` defaults to `../attack-pack-main`. Pass `--source PATH` if
your layout differs.

### Adding categories or changing titles/icons

The script infers a title and icon from each top-level folder in the
source repo. Overrides live in the `CATEGORY_META` dict at the top of
`build_kql_library.py` — add or edit an entry (title, Font Awesome icon
slug) and re-run.

### Adding descriptions

The script pulls each query's one-liner from:

1. the row for that filename in the folder's `README.md` table, then
2. the first non-`Author` `//` comment in the `.kql` file itself.

So the easiest way to give a query a better blurb is to add or refine a
README row in `attack-pack`.
