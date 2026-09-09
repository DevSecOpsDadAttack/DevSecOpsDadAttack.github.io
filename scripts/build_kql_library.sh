#!/usr/bin/env bash
# scripts/build_kql_library.sh
#
# Bash port of scripts/build_kql_library.py — same output layout, but with
# nothing beyond gawk / sed / coreutils, so a GitHub Actions Ubuntu runner
# can run it with no setup step.
#
# Reads structured metadata from each .kql's comment header:
#   // Tactics: / // Techniques: / // Actors: / // Platforms: / // Data:
#     -> pills on each query + a per-tag index page. A full grouped Browse
#        by tag index is emitted at /kql-library/tags/; the landing page
#        carries only a compact CTA banner that links to it.
#   // Source: <URL>
#     -> counts as a Deep Dive. Renders the ⚡ button on the detail page,
#        adds a "Deep Dive" pill in the tag block, records the query on
#        /kql-library/tag/deep-dive/, feeds the landing hero counts row.
#
# Usage: bash scripts/build_kql_library.sh <attack-pack checkout> <site root>
# Bash port of scripts/build_kql_library.py — same output layout.
set -euo pipefail

SRC="${1:?source dir}"
OUT="${2:?output dir}"

declare -A TITLE ICON
TITLE[analytics-rules]="Analytics Rules";       ICON[analytics-rules]="fa-shield-halved"
TITLE[cost-and-ingest]="Cost & Ingest";         ICON[cost-and-ingest]="fa-coins"
TITLE[email-and-phishing]="Email & Phishing";   ICON[email-and-phishing]="fa-envelope-open-text"
TITLE[health-checks]="Health Checks";           ICON[health-checks]="fa-heart-pulse"
TITLE[hunting]="Hunting";                       ICON[hunting]="fa-magnifying-glass"
TITLE[identity]="Identity";                     ICON[identity]="fa-user-shield"
TITLE[mitre-attack]="MITRE ATT&CK";             ICON[mitre-attack]="fa-crosshairs"
TITLE[pihole]="Pi-hole";                        ICON[pihole]="fa-network-wired"
TITLE[posture]="Posture";                       ICON[posture]="fa-server"
TITLE[reference]="Reference";                   ICON[reference]="fa-book"
TITLE[reporting]="Reporting";                   ICON[reporting]="fa-chart-line"

# Acronyms to keep uppercase when we titleize a slug like "gb-per-table".
ACR=" kql gb ad pim mde dns eol rdp smtp ip ipv4 ipv6 usa us "

# ---- helpers ----
titleize() {
  local s="$1" out="" w
  IFS='-' read -ra parts <<<"$s"
  for w in "${parts[@]}"; do
    [[ -z "$w" ]] && continue
    if [[ "$ACR" == *" $w "* ]]; then
      out+="${w^^} "
    else
      out+="${w^} "
    fi
  done
  echo "${out% }"
}

slugify() {
  # lowercase, strip .kql, non-alphanum -> "-"
  local s="${1,,}"
  s="${s%.kql}"
  s="$(echo "$s" | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//')"
  echo "$s"
}

# Extract a filename->description map from a folder's README table.
# Emits lines "filename.kql|description".
readme_table() {
  local rf="$1"
  [[ -f "$rf" ]] || return 0
  gawk '
    match($0, /^\|[[:space:]]*\[`?([^`\]]+\.kql)`?\]\([^)]+\)[[:space:]]*\|[[:space:]]*(.+)[[:space:]]*\|[[:space:]]*$/, m) {
      desc = m[2]
      sub(/[[:space:]]+$/, "", desc)
      print m[1] "|" desc
    }
  ' "$rf"
}

# First paragraph of a README after the top-level heading.
readme_intro() {
  local rf="$1"
  [[ -f "$rf" ]] || return 0
  gawk '
    BEGIN { grabbing = 0; buf = ""; done = 0 }
    done { next }
    /^#[[:space:]]/ && !grabbing { grabbing = 1; next }
    grabbing && /^[[:space:]]*$/ && buf != "" { print buf; done = 1; next }
    grabbing && /^#/ { if (buf != "") print buf; done = 1; next }
    grabbing { buf = (buf == "" ? $0 : buf " " $0) }
    END { if (!done && buf != "") print buf }
  ' "$rf"
}

# First non-Author // comment in a .kql, used as description fallback.
kql_first_comment() {
  local f="$1"
  gawk '
    /^\/\// {
      line = $0
      sub(/^\/\/[[:space:]]*/, "", line)
      if (tolower(line) ~ /^author[[:space:]]*[:|]/ || tolower(line) ~ /^author\b/) next
      if (line == "") next
      print line
      exit
    }
    /^[^\/]/ { exit }
  ' "$f"
}

# YAML-quote a string.
yaml_q() {
  local s="$1"
  if [[ -z "$s" ]]; then echo '""'; return; fi
  if [[ "$s" == *[:\#\&\*\!\|\>\%\@\`\"\']* ]] || [[ "$s" != "${s# }" ]] || [[ "$s" != "${s% }" ]]; then
    printf '"%s"' "${s//\"/\\\"}"
  else
    printf '%s' "$s"
  fi
}

# HTML-escape (minimal: only what appears in our text)
html_esc() {
  local s="$1"
  s="${s//&/&amp;}"
  s="${s//</&lt;}"
  s="${s//>/&gt;}"
  echo "$s"
}

# ---- tag helpers -----------------------------------------------------------

# MITRE Tactic name -> TA number, for external links from a tactic tag page.
declare -A TACTIC_TA
TACTIC_TA["Reconnaissance"]="TA0043"
TACTIC_TA["Resource Development"]="TA0042"
TACTIC_TA["Initial Access"]="TA0001"
TACTIC_TA["Execution"]="TA0002"
TACTIC_TA["Persistence"]="TA0003"
TACTIC_TA["Privilege Escalation"]="TA0004"
TACTIC_TA["Defense Evasion"]="TA0005"
TACTIC_TA["Credential Access"]="TA0006"
TACTIC_TA["Discovery"]="TA0007"
TACTIC_TA["Lateral Movement"]="TA0008"
TACTIC_TA["Collection"]="TA0009"
TACTIC_TA["Exfiltration"]="TA0010"
TACTIC_TA["Command and Control"]="TA0011"
TACTIC_TA["Impact"]="TA0040"

# Slugify a tag label into a URL-safe form. Preserves technique-id shape by
# keeping the T-prefix but turning the "." into "-".
tag_slug() {
  local s="$1"
  s="${s,,}"
  s="$(echo "$s" | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//')"
  echo "$s"
}

# Build the MITRE ATT&CK URL for a technique id like "T1036.005".
# Returns empty string for non-technique tags.
mitre_technique_url() {
  local id="$1"
  if [[ "$id" =~ ^T([0-9]{4})\.([0-9]{3})$ ]]; then
    echo "https://attack.mitre.org/techniques/T${BASH_REMATCH[1]}/${BASH_REMATCH[2]}/"
  elif [[ "$id" =~ ^T([0-9]{4})$ ]]; then
    echo "https://attack.mitre.org/techniques/T${BASH_REMATCH[1]}/"
  fi
}

# Read all 5 tag fields (Tactics / Techniques / Actors / Platforms / Data)
# from a .kql file's header in ONE awk pass. Emits 5 lines to stdout in that
# fixed order; empty lines mean "field not present." Callers slurp with
# mapfile -t. One gawk process per query instead of five — several-x speedup
# on Git Bash / Windows where fork is expensive.
read_all_tag_fields() {
  local file="$1"
  gawk '
    BEGIN { tac=""; tech=""; act=""; plat=""; data=""; src="" }
    /^\/\// {
      line = $0
      sub(/^\/\/[[:space:]]*/, "", line)
      if      (line ~ /^Tactics[[:space:]]*:/)    { sub(/^Tactics[[:space:]]*:[[:space:]]*/,    "", line); sub(/[[:space:]]+$/, "", line); tac=line;  next }
      else if (line ~ /^Techniques[[:space:]]*:/) { sub(/^Techniques[[:space:]]*:[[:space:]]*/, "", line); sub(/[[:space:]]+$/, "", line); tech=line; next }
      else if (line ~ /^Actors[[:space:]]*:/)     { sub(/^Actors[[:space:]]*:[[:space:]]*/,     "", line); sub(/[[:space:]]+$/, "", line); act=line;  next }
      else if (line ~ /^Platforms[[:space:]]*:/)  { sub(/^Platforms[[:space:]]*:[[:space:]]*/,  "", line); sub(/[[:space:]]+$/, "", line); plat=line; next }
      else if (line ~ /^Data[[:space:]]*:/)       { sub(/^Data[[:space:]]*:[[:space:]]*/,       "", line); sub(/[[:space:]]+$/, "", line); data=line; next }
      else if (line ~ /^Source[[:space:]]*:/) {
        # A Source line typically looks like:
        #   // Source: KQL Detection of the Week: Foo (2026-XX-XX) — https://...
        # Take the LAST http/https token as the URL. If no URL appears,
        # the field stays empty (the article write-up section is what we
        # gate the Deep Dive button on, so no URL == no button).
        rest = line
        while (match(rest, /https?:\/\/[^[:space:]]+/)) {
          src = substr(rest, RSTART, RLENGTH)
          rest = substr(rest, RSTART + RLENGTH)
        }
        # trim a trailing comma or period that occasionally lands on a URL
        sub(/[.,)]+$/, "", src)
        next
      }
      next
    }
    { exit }
    END { print tac; print tech; print act; print plat; print data; print src }
  ' "$file"
}

# Split a comma-separated tag string into an array (one value per line).
split_tags() {
  local raw="$1"
  [[ -z "$raw" ]] && return 0
  echo "$raw" | tr ',' '\n' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' | awk 'NF'
}

# ---- reset outputs ----
rm -rf "$OUT/kql-library" "$OUT/assets/kql"
rm -f  "$OUT/_data/kql_library.yml"
mkdir -p "$OUT/_data" "$OUT/kql-library" "$OUT/assets/kql"

# Per-tag scratch dir: one file per tag slug that we append query-<li>s to as
# we walk. After the main loop we turn each into /kql-library/tag/<slug>/index.html.
TAG_DIR="$(mktemp -d)"
trap "rm -rf '$TAG_DIR'" EXIT
# Manifest: slug<TAB>type<TAB>label — sorted / deduped at the end.
: > "$TAG_DIR/_manifest"

# Emit the tag-pill block for a query to a Jekyll page file and, at the same
# time, record a per-tag <li> so we can build /kql-library/tag/<slug>/ pages.
# Sets LAST_TAG_LIST (space-separated slugs) for the caller's landing-page
# data-attribute.
LAST_TAG_LIST=""
emit_pills_to_file() {
  # Args:  out_file  tactics  techniques  actors  platforms  data
  #        qurl  qtitle  qdesc  qcat  deepdive_url
  # Tag values are pre-read by the caller (one gawk call per query, hoisted
  # into the outer loop) so we don't fork for a re-read here.
  # deepdive_url is either the query's `// Source:` URL or empty.
  local out_file="$1"
  local tactics="$2" techniques="$3" actors="$4" platforms="$5" data="$6"
  local qurl="$7" qtitle="$8" qdesc="$9" qcat="${10}" deepdive_url="${11:-}"
  LAST_TAG_LIST=""

  if [[ -z "$tactics$techniques$actors$platforms$data$deepdive_url" ]]; then
    return
  fi

  {
    echo '<div class="kql-lib-tags-block">'
    local pair label rest ttype values v slug
    for pair in "Tactics|tactic|$tactics" \
                "Techniques|technique|$techniques" \
                "Actors|actor|$actors" \
                "Platforms|platform|$platforms" \
                "Data|data|$data"; do
      label="${pair%%|*}"; rest="${pair#*|}"
      ttype="${rest%%|*}"; values="${rest#*|}"
      [[ -z "$values" ]] && continue
      echo "  <div class=\"kql-lib-tag-row\">"
      echo "    <span class=\"kql-lib-tag-label\">$label</span>"
      while IFS= read -r v; do
        [[ -z "$v" ]] && continue
        slug="$(tag_slug "$v")"
        echo "    <a class=\"kql-lib-tag kql-lib-tag-$ttype\" href=\"{{ '/kql-library/tag/$slug/' | relative_url }}\">$(html_esc "$v")</a>"
        printf '%s\t%s\t%s\n' "$slug" "$ttype" "$v" >> "$TAG_DIR/_manifest"
        {
          echo "  <li class=\"kql-lib-query-item\">"
          echo "    <a href=\"{{ '$qurl' | relative_url }}\">"
          echo "      <span class=\"attack-badge attack-badge-lib\">$(html_esc "$qcat")</span>"
          echo "      <span class=\"kql-lib-query-title\">$(html_esc "$qtitle")</span>"
          echo "    </a>"
          [[ -n "$qdesc" ]] && echo "    <p class=\"kql-lib-query-desc\">$(html_esc "$qdesc")</p>"
          echo "  </li>"
        } >> "$TAG_DIR/$slug.entries"
        # Store both the slug ("t1562-008") and the raw label lowercased
        # ("t1562.008") so the landing search matches either spelling.
        LAST_TAG_LIST+="$slug $(echo "$v" | tr '[:upper:]' '[:lower:]') "
      done < <(split_tags "$values")
      echo "  </div>"
    done
    # Deep Dive: a boolean tag, so it's always a single "Deep Dive" pill,
    # slug "deep-dive". Rendered as its own row at the bottom of the block
    # so it reads as a distinct dimension (research-backed) rather than a
    # normal metadata field.
    if [[ -n "$deepdive_url" ]]; then
      echo "  <div class=\"kql-lib-tag-row\">"
      echo "    <span class=\"kql-lib-tag-label\">Deep Dive</span>"
      echo "    <a class=\"kql-lib-tag kql-lib-tag-deepdive\" href=\"{{ '/kql-library/tag/deep-dive/' | relative_url }}\"><i class=\"fas fa-bolt\" aria-hidden=\"true\"></i>&nbsp;Deep Dive</a>"
      printf '%s\t%s\t%s\n' "deep-dive" "deepdive" "Deep Dive" >> "$TAG_DIR/_manifest"
      {
        echo "  <li class=\"kql-lib-query-item\">"
        echo "    <a href=\"{{ '$qurl' | relative_url }}\">"
        echo "      <span class=\"attack-badge attack-badge-lib\">$(html_esc "$qcat")</span>"
        echo "      <span class=\"kql-lib-query-title\">$(html_esc "$qtitle")</span>"
        echo "      <span class=\"kql-lib-deep-dive-mini\" title=\"Deep Dive article available\"><i class=\"fas fa-bolt\" aria-hidden=\"true\"></i></span>"
        echo "    </a>"
        [[ -n "$qdesc" ]] && echo "    <p class=\"kql-lib-query-desc\">$(html_esc "$qdesc")</p>"
        echo "  </li>"
      } >> "$TAG_DIR/deep-dive.entries"
      LAST_TAG_LIST+="deep-dive deep dive "
    fi
    echo '</div>'
  } >> "$out_file"
}

# Discover categories in stable order (11 known, plus any others)
CATS=()
for slug in analytics-rules cost-and-ingest email-and-phishing health-checks hunting identity mitre-attack pihole posture reference reporting; do
  [[ -d "$SRC/$slug" ]] && CATS+=("$slug")
done
# any straggler dirs we didn't preconfigure
for d in "$SRC"/*/; do
  [[ -d "$d" ]] || continue
  slug="$(basename "$d")"
  [[ "$slug" == .* || "$slug" == _* ]] && continue
  [[ " ${CATS[*]} " == *" $slug "* ]] && continue
  CATS+=("$slug"); TITLE[$slug]="$(titleize "$slug")"; ICON[$slug]="fa-code"
done

# ---- generate ----
YAML="$OUT/_data/kql_library.yml"
{
  echo "# Generated by scripts/build_kql_library.py — do not edit by hand."
  echo "categories:"
} > "$YAML"

TOTAL_QUERIES=0
DEEP_DIVE_COUNT=0
LANDING_RESULTS=""   # accumulator for the search-results <li>s
# Per-category counts we surface in the landing hero counter row.
declare -A CAT_QCOUNT

for cat in "${CATS[@]}"; do
  cat_title="${TITLE[$cat]:-$(titleize "$cat")}"
  cat_icon="${ICON[$cat]:-fa-code}"
  cat_desc="$(readme_intro "$SRC/$cat/README.md")"

  # Load table descriptions from the category-level README.
  declare -A ROOT_DESC=()
  while IFS='|' read -r fn ds; do [[ -n "$fn" ]] && ROOT_DESC["$fn"]="$ds"; done < <(readme_table "$SRC/$cat/README.md")

  # Enumerate immediate .kql files and subfolders
  root_kqls=()
  while IFS= read -r -d '' f; do root_kqls+=("$f"); done < <(find "$SRC/$cat" -maxdepth 1 -type f -name "*.kql" -print0 | sort -z)

  sub_dirs=()
  while IFS= read -r -d '' d; do sub_dirs+=("$d"); done < <(find "$SRC/$cat" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)

  cat_query_count=0
  # We build the category page as we go.
  CAT_PAGE="$OUT/kql-library/$cat/index.html"
  mkdir -p "$(dirname "$CAT_PAGE")"
  {
    subtitle="$(echo "$cat_desc" | tr -s ' ' | sed "s/\"/'/g")"
    echo "---"
    echo "layout: page"
    echo "title: $cat_title"
    [[ -n "$cat_desc" ]] && echo "subtitle: \"$subtitle\""
    echo "permalink: /kql-library/$cat/"
    echo "---"
    echo ""
    echo '<section class="attack-home-intro attack-home-intro-lib">'
    echo "  <p class=\"attack-eyebrow\"><i class=\"fas $cat_icon\" aria-hidden=\"true\"></i>&nbsp;KQL Library / $(html_esc "$cat_title")</p>"
    echo "  <h2>$(html_esc "$cat_title")</h2>"
    [[ -n "$cat_desc" ]] && echo "  <p>$(html_esc "$cat_desc")</p>"
    echo '</section>'
    echo ''
    echo '<p class="kql-lib-crumbs"><a href="{{ '"'"'/kql-library/'"'"' | relative_url }}">&larr; All KQL categories</a></p>'
    echo ''
  } > "$CAT_PAGE"

  # --- YAML: category header
  {
    echo "  - slug: $(yaml_q "$cat")"
    echo "    title: $(yaml_q "$cat_title")"
    echo "    icon: $(yaml_q "$cat_icon")"
    echo "    description: $(yaml_q "$cat_desc")"
  } >> "$YAML"

  # Root queries — if the category ALSO has subfolders, header them so the
  # visual split matches the READMEs' "Standalone" / subfolder structure.
  if [[ ${#root_kqls[@]} -gt 0 ]]; then
    echo '    queries:' >> "$YAML"
    if [[ ${#sub_dirs[@]} -gt 0 ]]; then
      echo '<h3 class="kql-lib-subcat-heading">Standalone</h3>' >> "$CAT_PAGE"
    fi
    echo '<ul class="kql-lib-query-list list-unstyled" role="list">' >> "$CAT_PAGE"
    for kq in "${root_kqls[@]}"; do
      fn="$(basename "$kq")"
      slug="$(slugify "$fn")"
      title="$(titleize "$slug")"
      desc="${ROOT_DESC[$fn]:-}"
      [[ -z "$desc" ]] && desc="$(kql_first_comment "$kq")"
      cat_query_count=$((cat_query_count+1))
      TOTAL_QUERIES=$((TOTAL_QUERIES+1))
      # Read tag fields + source URL from the .kql (one gawk pass, hoisted
      # so category-page item / landing card can also branch on has-deep-dive).
      _md=()
      mapfile -t _md < <(read_all_tag_fields "$kq")
      q_tactics="${_md[0]:-}"
      q_techniques="${_md[1]:-}"
      q_actors="${_md[2]:-}"
      q_platforms="${_md[3]:-}"
      q_data="${_md[4]:-}"
      q_source="${_md[5]:-}"
      dd_badge=""
      if [[ -n "$q_source" ]]; then
        DEEP_DIVE_COUNT=$((DEEP_DIVE_COUNT+1))
        dd_badge="      <span class=\"kql-lib-deep-dive-mini\" title=\"Deep Dive article available\"><i class=\"fas fa-bolt\" aria-hidden=\"true\"></i></span>"
      fi
      # yaml
      {
        echo "      - slug: $(yaml_q "$slug")"
        echo "        title: $(yaml_q "$title")"
        echo "        description: $(yaml_q "$desc")"
        echo "        file_name: $(yaml_q "$fn")"
        echo "        asset_path: $(yaml_q "$cat/$fn")"
        echo "        category_slug: $(yaml_q "$cat")"
        [[ -n "$q_source" ]] && echo "        deep_dive_url: $(yaml_q "$q_source")"
      } >> "$YAML"
      # category page entry
      {
        echo "  <li class=\"kql-lib-query-item\">"
        echo "    <a href=\"{{ '/kql-library/$cat/$slug/' | relative_url }}\">"
        echo "      <span class=\"kql-lib-query-title\">$(html_esc "$title")</span>"
        [[ -n "$dd_badge" ]] && echo "$dd_badge"
        echo "      <code class=\"kql-lib-query-file\">$(html_esc "$fn")</code>"
        echo "    </a>"
        [[ -n "$desc" ]] && echo "    <p class=\"kql-lib-query-desc\">$(html_esc "$desc")</p>"
        echo "  </li>"
      } >> "$CAT_PAGE"
      # asset copy
      mkdir -p "$OUT/assets/kql/$cat"
      cp "$kq" "$OUT/assets/kql/$cat/$fn"
      # query detail page
      QD="$OUT/kql-library/$cat/$slug/index.md"
      mkdir -p "$(dirname "$QD")"
      qsub="${desc:-KQL query}"
      qsub="$(echo "$qsub" | tr -s ' ' | sed "s/\"/'/g")"
      [[ ${#qsub} -gt 240 ]] && qsub="${qsub:0:237}..."
      {
        echo "---"
        echo "layout: page"
        echo "title: $title"
        echo "subtitle: \"$qsub\""
        echo "permalink: /kql-library/$cat/$slug/"
        echo "js:"
        echo "  - \"/assets/js/kql-library.js\""
        echo "---"
        echo ""
        echo "<p class=\"kql-lib-crumbs\">"
        echo "  <a href=\"{{ '/kql-library/' | relative_url }}\">KQL Library</a>"
        echo "  &nbsp;/&nbsp;"
        echo "  <a href=\"{{ '/kql-library/$cat/' | relative_url }}\">$(html_esc "$cat_title")</a>"
        echo "</p>"
        echo ""
        echo "<div class=\"kql-lib-query-header\">"
        echo "  <span class=\"attack-badge attack-badge-lib\"><i class=\"fas $cat_icon\" aria-hidden=\"true\"></i>&nbsp;$(html_esc "$cat_title")</span>"
        echo "  <code class=\"kql-lib-query-file\">$(html_esc "$fn")</code>"
        echo "</div>"
        echo ""
        [[ -n "$desc" ]] && echo "<p class=\"kql-lib-query-longdesc\">$(html_esc "$desc")</p>" && echo ""
      } > "$QD"
      # Tag pills (also records per-tag <li>s in $TAG_DIR/<slug>.entries)
      emit_pills_to_file "$QD" \
        "$q_tactics" "$q_techniques" "$q_actors" "$q_platforms" "$q_data" \
        "/kql-library/$cat/$slug/" "$title" "$desc" "$cat_title" "$q_source"
      TAGS_FOR_LANDING="$LAST_TAG_LIST"
      {
        echo "<div class=\"kql-lib-query-actions\">"
        if [[ -n "$q_source" ]]; then
          echo "  <a class=\"kql-lib-deep-dive-btn\" href=\"$q_source\" target=\"_blank\" rel=\"noopener\">"
          echo "    <i class=\"fas fa-bolt\" aria-hidden=\"true\"></i>&nbsp;Deep Dive"
          echo "  </a>"
        fi
        echo "  <button type=\"button\" class=\"kql-lib-copy-btn\" data-copy-target=\"kql-code-$slug\">"
        echo "    <i class=\"far fa-copy\" aria-hidden=\"true\"></i>&nbsp;Copy query"
        echo "  </button>"
        echo "  <a class=\"kql-lib-download-btn\" href=\"{{ '/assets/kql/$cat/$fn' | relative_url }}\" download=\"$fn\">"
        echo "    <i class=\"fas fa-download\" aria-hidden=\"true\"></i>&nbsp;Download .kql"
        echo "  </a>"
        echo "</div>"
        echo ""
        echo "<div id=\"kql-code-$slug\" markdown=\"1\">"
        echo ""
        echo '```kusto'
        cat "$kq"
        echo '```'
        echo ""
        echo "</div>"
      } >> "$QD"
      # search-result <li> for landing
      dtitle="$(echo "$title" | tr '[:upper:]' '[:lower:]')"
      ddesc="$(echo "$desc"   | tr '[:upper:]' '[:lower:]')"
      dcat="$(echo "$cat_title" | tr '[:upper:]' '[:lower:]')"
      dd_extra=""
      [[ -n "$q_source" ]] && dd_extra=" data-deepdive=\"1\""
      LANDING_RESULTS+="  <li class=\"kql-lib-result\" data-title=\"$(html_esc "$dtitle")\" data-desc=\"$(html_esc "$ddesc")\" data-cat=\"$(html_esc "$dcat")\" data-catslug=\"$cat\" data-tags=\"$(html_esc "$TAGS_FOR_LANDING")\"$dd_extra>"$'\n'
      LANDING_RESULTS+="    <a href=\"{{ '/kql-library/$cat/$slug/' | relative_url }}\">"$'\n'
      LANDING_RESULTS+="      <span class=\"attack-badge attack-badge-lib\">$(html_esc "$cat_title")</span>"$'\n'
      [[ -n "$q_source" ]] && LANDING_RESULTS+="      <span class=\"kql-lib-deep-dive-mini\" title=\"Deep Dive available\"><i class=\"fas fa-bolt\" aria-hidden=\"true\"></i></span>"$'\n'
      LANDING_RESULTS+="      <span class=\"kql-lib-result-title\">$(html_esc "$title")</span>"$'\n'
      LANDING_RESULTS+="    </a>"$'\n'
      [[ -n "$desc" ]] && LANDING_RESULTS+="    <p class=\"kql-lib-result-desc\">$(html_esc "$desc")</p>"$'\n'
      LANDING_RESULTS+="  </li>"$'\n'
    done
    echo '</ul>' >> "$CAT_PAGE"
  else
    echo '    queries: []' >> "$YAML"
  fi

  # Subfolders
  if [[ ${#sub_dirs[@]} -gt 0 ]]; then
    echo '    subcategories:' >> "$YAML"
    for sd in "${sub_dirs[@]}"; do
      sub_slug="$(basename "$sd")"
      sub_title="$(titleize "$sub_slug")"
      sub_intro="$(readme_intro "$sd/README.md")"
      declare -A SUB_DESC=()
      while IFS='|' read -r fn ds; do [[ -n "$fn" ]] && SUB_DESC["$fn"]="$ds"; done < <(readme_table "$sd/README.md")

      sub_kqls=()
      while IFS= read -r -d '' f; do sub_kqls+=("$f"); done < <(find "$sd" -maxdepth 1 -type f -name "*.kql" -print0 | sort -z)
      [[ ${#sub_kqls[@]} -eq 0 ]] && continue

      {
        echo "      - slug: $(yaml_q "$sub_slug")"
        echo "        title: $(yaml_q "$sub_title")"
        echo "        description: $(yaml_q "$sub_intro")"
        echo '        queries:'
      } >> "$YAML"

      {
        echo "<h3 class=\"kql-lib-subcat-heading\">$(html_esc "$sub_title")</h3>"
        [[ -n "$sub_intro" ]] && echo "<p class=\"kql-lib-subcat-intro\">$(html_esc "$sub_intro")</p>"
        echo '<ul class="kql-lib-query-list list-unstyled" role="list">'
      } >> "$CAT_PAGE"

      for kq in "${sub_kqls[@]}"; do
        fn="$(basename "$kq")"
        slug="$(slugify "$fn")"
        title="$(titleize "$slug")"
        desc="${SUB_DESC[$fn]:-}"
        [[ -z "$desc" ]] && desc="$(kql_first_comment "$kq")"
        cat_query_count=$((cat_query_count+1))
        TOTAL_QUERIES=$((TOTAL_QUERIES+1))
        _md=()
        mapfile -t _md < <(read_all_tag_fields "$kq")
        q_tactics="${_md[0]:-}"
        q_techniques="${_md[1]:-}"
        q_actors="${_md[2]:-}"
        q_platforms="${_md[3]:-}"
        q_data="${_md[4]:-}"
        q_source="${_md[5]:-}"
        dd_badge=""
        if [[ -n "$q_source" ]]; then
          DEEP_DIVE_COUNT=$((DEEP_DIVE_COUNT+1))
          dd_badge="      <span class=\"kql-lib-deep-dive-mini\" title=\"Deep Dive article available\"><i class=\"fas fa-bolt\" aria-hidden=\"true\"></i></span>"
        fi
        {
          echo "          - slug: $(yaml_q "$slug")"
          echo "            title: $(yaml_q "$title")"
          echo "            description: $(yaml_q "$desc")"
          echo "            file_name: $(yaml_q "$fn")"
          echo "            asset_path: $(yaml_q "$cat/$sub_slug/$fn")"
          echo "            category_slug: $(yaml_q "$cat")"
          echo "            subcategory_slug: $(yaml_q "$sub_slug")"
          echo "            subcategory_title: $(yaml_q "$sub_title")"
          [[ -n "$q_source" ]] && echo "            deep_dive_url: $(yaml_q "$q_source")"
        } >> "$YAML"

        {
          echo "  <li class=\"kql-lib-query-item\">"
          echo "    <a href=\"{{ '/kql-library/$cat/$slug/' | relative_url }}\">"
          echo "      <span class=\"kql-lib-query-title\">$(html_esc "$title")</span>"
          [[ -n "$dd_badge" ]] && echo "$dd_badge"
          echo "      <code class=\"kql-lib-query-file\">$(html_esc "$fn")</code>"
          echo "    </a>"
          [[ -n "$desc" ]] && echo "    <p class=\"kql-lib-query-desc\">$(html_esc "$desc")</p>"
          echo "  </li>"
        } >> "$CAT_PAGE"

        mkdir -p "$OUT/assets/kql/$cat/$sub_slug"
        cp "$kq" "$OUT/assets/kql/$cat/$sub_slug/$fn"

        QD="$OUT/kql-library/$cat/$slug/index.md"
        mkdir -p "$(dirname "$QD")"
        qsub="${desc:-KQL query}"
        qsub="$(echo "$qsub" | tr -s ' ' | sed "s/\"/'/g")"
        [[ ${#qsub} -gt 240 ]] && qsub="${qsub:0:237}..."
        {
          echo "---"
          echo "layout: page"
          echo "title: $title"
          echo "subtitle: \"$qsub\""
          echo "permalink: /kql-library/$cat/$slug/"
          echo "js:"
          echo "  - \"/assets/js/kql-library.js\""
          echo "---"
          echo ""
          echo "<p class=\"kql-lib-crumbs\">"
          echo "  <a href=\"{{ '/kql-library/' | relative_url }}\">KQL Library</a>"
          echo "  &nbsp;/&nbsp;"
          echo "  <a href=\"{{ '/kql-library/$cat/' | relative_url }}\">$(html_esc "$cat_title")</a>"
          echo "</p>"
          echo ""
          echo "<div class=\"kql-lib-query-header\">"
          echo "  <span class=\"attack-badge attack-badge-lib\"><i class=\"fas $cat_icon\" aria-hidden=\"true\"></i>&nbsp;$(html_esc "$cat_title")</span>"
          echo "  <span class=\"attack-badge attack-badge-sub\">$(html_esc "$sub_title")</span>"
          echo "  <code class=\"kql-lib-query-file\">$(html_esc "$fn")</code>"
          echo "</div>"
          echo ""
          [[ -n "$desc" ]] && echo "<p class=\"kql-lib-query-longdesc\">$(html_esc "$desc")</p>" && echo ""
        } > "$QD"
        # Tag pills (also records per-tag <li>s in $TAG_DIR/<slug>.entries)
        emit_pills_to_file "$QD" \
          "$q_tactics" "$q_techniques" "$q_actors" "$q_platforms" "$q_data" \
          "/kql-library/$cat/$slug/" "$title" "$desc" "$cat_title / $sub_title" "$q_source"
        TAGS_FOR_LANDING="$LAST_TAG_LIST"
        {
          echo "<div class=\"kql-lib-query-actions\">"
          if [[ -n "$q_source" ]]; then
            echo "  <a class=\"kql-lib-deep-dive-btn\" href=\"$q_source\" target=\"_blank\" rel=\"noopener\">"
            echo "    <i class=\"fas fa-bolt\" aria-hidden=\"true\"></i>&nbsp;Deep Dive"
            echo "  </a>"
          fi
          echo "  <button type=\"button\" class=\"kql-lib-copy-btn\" data-copy-target=\"kql-code-$slug\">"
          echo "    <i class=\"far fa-copy\" aria-hidden=\"true\"></i>&nbsp;Copy query"
          echo "  </button>"
          echo "  <a class=\"kql-lib-download-btn\" href=\"{{ '/assets/kql/$cat/$sub_slug/$fn' | relative_url }}\" download=\"$fn\">"
          echo "    <i class=\"fas fa-download\" aria-hidden=\"true\"></i>&nbsp;Download .kql"
          echo "  </a>"
          echo "</div>"
          echo ""
          echo "<div id=\"kql-code-$slug\" markdown=\"1\">"
          echo ""
          echo '```kusto'
          cat "$kq"
          echo '```'
          echo ""
          echo "</div>"
        } >> "$QD"

        dtitle="$(echo "$title" | tr '[:upper:]' '[:lower:]')"
        ddesc="$(echo "$desc"   | tr '[:upper:]' '[:lower:]')"
        dcat="$(echo "$cat_title $sub_title" | tr '[:upper:]' '[:lower:]')"
        dd_extra=""
        [[ -n "$q_source" ]] && dd_extra=" data-deepdive=\"1\""
        LANDING_RESULTS+="  <li class=\"kql-lib-result\" data-title=\"$(html_esc "$dtitle")\" data-desc=\"$(html_esc "$ddesc")\" data-cat=\"$(html_esc "$dcat")\" data-catslug=\"$cat\" data-tags=\"$(html_esc "$TAGS_FOR_LANDING")\"$dd_extra>"$'\n'
        LANDING_RESULTS+="    <a href=\"{{ '/kql-library/$cat/$slug/' | relative_url }}\">"$'\n'
        LANDING_RESULTS+="      <span class=\"attack-badge attack-badge-lib\">$(html_esc "$cat_title")</span>"$'\n'
        LANDING_RESULTS+="      <span class=\"attack-badge attack-badge-sub\">$(html_esc "$sub_title")</span>"$'\n'
        [[ -n "$q_source" ]] && LANDING_RESULTS+="      <span class=\"kql-lib-deep-dive-mini\" title=\"Deep Dive available\"><i class=\"fas fa-bolt\" aria-hidden=\"true\"></i></span>"$'\n'
        LANDING_RESULTS+="      <span class=\"kql-lib-result-title\">$(html_esc "$title")</span>"$'\n'
        LANDING_RESULTS+="    </a>"$'\n'
        [[ -n "$desc" ]] && LANDING_RESULTS+="    <p class=\"kql-lib-result-desc\">$(html_esc "$desc")</p>"$'\n'
        LANDING_RESULTS+="  </li>"$'\n'
      done
      echo '</ul>' >> "$CAT_PAGE"
      unset SUB_DESC
    done
  else
    echo '    subcategories: []' >> "$YAML"
  fi
  echo "    query_count: $cat_query_count" >> "$YAML"
  CAT_QCOUNT[$cat]=$cat_query_count
  unset ROOT_DESC
done

# ---- per-tag pages ----
# For every distinct tag slug encountered during the walk, emit one
# /kql-library/tag/<slug>/index.html listing every query with that tag.
declare -A SEEN_SLUG
declare -A TAG_TYPE_OF TAG_LABEL_OF TAG_COUNT_OF
if [[ -s "$TAG_DIR/_manifest" ]]; then
  sort -u "$TAG_DIR/_manifest" > "$TAG_DIR/_manifest.sorted"
  while IFS=$'\t' read -r slug ttype label; do
    # First occurrence wins for the display label / type mapping
    if [[ -z "${SEEN_SLUG[$slug]:-}" ]]; then
      SEEN_SLUG[$slug]=1
      TAG_TYPE_OF[$slug]="$ttype"
      TAG_LABEL_OF[$slug]="$label"
    fi
  done < "$TAG_DIR/_manifest.sorted"

  # Compute per-tag counts (# distinct queries)
  for slug in "${!SEEN_SLUG[@]}"; do
    if [[ -f "$TAG_DIR/$slug.entries" ]]; then
      TAG_COUNT_OF[$slug]=$(grep -c '^  <li class="kql-lib-query-item">' "$TAG_DIR/$slug.entries" || true)
    else
      TAG_COUNT_OF[$slug]=0
    fi
  done

  # Emit one page per tag
  for slug in "${!SEEN_SLUG[@]}"; do
    ttype="${TAG_TYPE_OF[$slug]}"
    label="${TAG_LABEL_OF[$slug]}"
    count="${TAG_COUNT_OF[$slug]:-0}"
    q_word="queries"; [[ "$count" -eq 1 ]] && q_word="query"

    mitre_url=""
    type_label=""
    type_noun=""
    case "$ttype" in
      tactic)
        ta="${TACTIC_TA[$label]:-}"
        [[ -n "$ta" ]] && mitre_url="https://attack.mitre.org/tactics/$ta/"
        type_label="MITRE ATT&amp;CK Tactic"
        type_noun="tactic"
        ;;
      technique)
        mitre_url="$(mitre_technique_url "$label")"
        type_label="MITRE ATT&amp;CK Technique"
        type_noun="technique"
        ;;
      actor)    type_label="Actor / Malware Family"; type_noun="actor";;
      platform) type_label="Platform"; type_noun="platform";;
      data)     type_label="Data Source"; type_noun="data source";;
      deepdive) type_label="Deep Dive"; type_noun="deep dive article";;
    esac

    TP="$OUT/kql-library/tag/$slug/index.html"
    mkdir -p "$(dirname "$TP")"
    esc_label="$(html_esc "$label")"
    {
      echo "---"
      echo "layout: page"
      echo "title: \"$esc_label\""
      echo "subtitle: \"$type_label — $count $q_word\""
      echo "permalink: /kql-library/tag/$slug/"
      echo "---"
      echo ""
      echo "<p class=\"kql-lib-crumbs\"><a href=\"{{ '/kql-library/' | relative_url }}\">&larr; All KQL categories</a></p>"
      echo ""
      echo "<section class=\"attack-home-intro attack-home-intro-lib\">"
      echo "  <p class=\"attack-eyebrow\">$type_label</p>"
      echo "  <h2>$esc_label</h2>"
      if [[ "$ttype" == "deepdive" ]]; then
        # The Deep Dive tag isn't a metadata bucket — it's the queries backed
        # by a KQL Detection of the Week write-up. Give it a description that
        # reflects that instead of the generic "tagged with this ..." line.
        echo "  <p>$count $q_word backed by a KQL Detection of the Week Deep Dive article — long-form research explaining the design rationale, telemetry assumptions, tuning, and ATT&amp;CK context behind each detection.</p>"
      else
        echo "  <p>$count $q_word tagged with this $type_noun."
        if [[ -n "$mitre_url" ]]; then
          echo "  <br><a href=\"$mitre_url\" target=\"_blank\" rel=\"noopener\">View on MITRE ATT&amp;CK &rarr;</a>"
        fi
        echo "  </p>"
      fi
      echo "</section>"
      echo ""
      echo "<ul class=\"kql-lib-query-list list-unstyled\" role=\"list\">"
      if [[ -f "$TAG_DIR/$slug.entries" ]]; then
        cat "$TAG_DIR/$slug.entries"
      fi
      echo "</ul>"
    } > "$TP"
  done
fi

# ---- landing page ----
LP="$OUT/kql-library/index.html"
mkdir -p "$(dirname "$LP")"

# Build the "Browse by tag" index — grouped by tag type, pills sorted by
# tag frequency (most-tagged first) then alphabetically. Uses the
# SEEN_SLUG / TAG_TYPE_OF / TAG_LABEL_OF / TAG_COUNT_OF arrays populated by
# the tag-page emission block above. Emitted to its own page
# (/kql-library/tags/) rather than inline on the landing, so the landing
# stays scannable as the library grows.
TAG_INDEX_TOTAL=${#SEEN_SLUG[@]}
if [[ $TAG_INDEX_TOTAL -gt 0 ]]; then
  TIP="$OUT/kql-library/tags/index.html"
  mkdir -p "$(dirname "$TIP")"

  # Group counts for the intro copy: "N tactics · M techniques · ..."
  declare -A TYPE_COUNT=([tactic]=0 [technique]=0 [actor]=0 [platform]=0 [data]=0 [deepdive]=0)
  for slug in "${!SEEN_SLUG[@]}"; do
    t="${TAG_TYPE_OF[$slug]}"
    TYPE_COUNT[$t]=$(( ${TYPE_COUNT[$t]:-0} + 1 ))
  done

  {
    echo "---"
    echo "layout: page"
    echo "title: Browse by tag"
    echo "subtitle: \"$TAG_INDEX_TOTAL tags across the KQL Library — MITRE ATT&amp;CK, actors, platforms, data sources.\""
    echo "permalink: /kql-library/tags/"
    echo "---"
    echo ""
    echo "<p class=\"kql-lib-crumbs\"><a href=\"{{ '/kql-library/' | relative_url }}\">&larr; All KQL categories</a></p>"
    echo ""
    echo "<section class=\"kql-lib-tag-index\">"
    echo "  <p class=\"kql-lib-tag-index-lede\">"
    echo "    Every query in the library indexed by MITRE ATT&amp;CK tactic and technique,"
    echo "    by actor / malware family (where the write-up named one), by platform and"
    echo "    data source, and by whether a KQL Detection of the Week Deep Dive article"
    echo "    walks through its design. Pills are sorted by how many queries carry them."
    echo "  </p>"

    for ttype in tactic technique actor platform data deepdive; do
      case "$ttype" in
        tactic)    display="MITRE Tactics";;
        technique) display="MITRE Techniques";;
        actor)     display="Actors";;
        platform)  display="Platforms";;
        data)      display="Data Sources";;
        deepdive)  display="Deep Dive";;
      esac
      tmp="$TAG_DIR/_index_$ttype"
      : > "$tmp"
      for slug in "${!SEEN_SLUG[@]}"; do
        [[ "${TAG_TYPE_OF[$slug]}" == "$ttype" ]] || continue
        printf '%s|%s|%s\n' "${TAG_COUNT_OF[$slug]:-0}" "${TAG_LABEL_OF[$slug]}" "$slug" >> "$tmp"
      done
      [[ -s "$tmp" ]] || continue
      sort -t'|' -k1,1nr -k2,2 -o "$tmp" "$tmp"
      grp_count="${TYPE_COUNT[$ttype]:-0}"

      echo "  <div class=\"kql-lib-tag-index-group\" id=\"tags-$ttype\">"
      echo "    <h3 class=\"kql-lib-tag-index-heading\">$display <span class=\"kql-lib-tag-index-group-count\">$grp_count</span></h3>"
      echo "    <div class=\"kql-lib-tag-index-pills\">"
      while IFS='|' read -r _cnt _lbl _slg; do
        icon=""
        [[ "$ttype" == "deepdive" ]] && icon="<i class=\"fas fa-bolt\" aria-hidden=\"true\"></i>&nbsp;"
        echo "      <a class=\"kql-lib-tag kql-lib-tag-$ttype\" href=\"{{ '/kql-library/tag/$_slg/' | relative_url }}\">$icon$(html_esc "$_lbl")<span class=\"kql-lib-tag-count\">$_cnt</span></a>"
      done < "$tmp"
      echo "    </div>"
      echo "  </div>"
    done

    echo "</section>"
  } > "$TIP"
fi

# Build category cards HTML by re-reading the CATS array
CARDS=""
for cat in "${CATS[@]}"; do
  ct="${TITLE[$cat]:-$(titleize "$cat")}"
  ci="${ICON[$cat]:-fa-code}"
  cd_="$(readme_intro "$SRC/$cat/README.md")"
  # count queries from what we already wrote
  count=$(find "$OUT/kql-library/$cat" -mindepth 2 -name "index.md" 2>/dev/null | wc -l)
  q_word="queries"; [[ "$count" -eq 1 ]] && q_word="query"
  CARDS+="  <a class=\"kql-lib-cat-card\" href=\"{{ '/kql-library/$cat/' | relative_url }}\">"$'\n'
  CARDS+="    <span class=\"kql-lib-cat-icon\"><i class=\"fas $ci\" aria-hidden=\"true\"></i></span>"$'\n'
  CARDS+="    <span class=\"kql-lib-cat-title\">$(html_esc "$ct")</span>"$'\n'
  CARDS+="    <span class=\"kql-lib-cat-count\">$count $q_word</span>"$'\n'
  CARDS+="    <span class=\"kql-lib-cat-desc\">$(html_esc "$cd_")</span>"$'\n'
  CARDS+="  </a>"$'\n'
done

{
  cat <<'FM'
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
FM
  # Counts row: Total · Analytics Rules · Hunts · Deep Dives. Emit only the
  # buckets that actually have a value so it stays clean if categories change.
  ar_count="${CAT_QCOUNT[analytics-rules]:-0}"
  hunt_count="${CAT_QCOUNT[hunting]:-0}"
  {
    echo "  <p class=\"kql-lib-hero-counts\">"
    echo "    <span><strong>$TOTAL_QUERIES</strong>&nbsp;Queries</span>"
    if [[ "$ar_count" -gt 0 ]]; then
      echo "    <span aria-hidden=\"true\">·</span>"
      echo "    <span><strong>$ar_count</strong>&nbsp;Analytics&nbsp;Rules</span>"
    fi
    if [[ "$hunt_count" -gt 0 ]]; then
      echo "    <span aria-hidden=\"true\">·</span>"
      echo "    <span><strong>$hunt_count</strong>&nbsp;Hunts</span>"
    fi
    if [[ "$DEEP_DIVE_COUNT" -gt 0 ]]; then
      echo "    <span aria-hidden=\"true\">·</span>"
      echo "    <span class=\"kql-lib-hero-count-dd\"><i class=\"fas fa-bolt\" aria-hidden=\"true\"></i>&nbsp;<strong>$DEEP_DIVE_COUNT</strong>&nbsp;Deep&nbsp;Dives</span>"
    fi
    echo "  </p>"
  }
  cat <<'FM_TAIL_INTRO'
</section>

<hr class="attack-separator">

<div class="kql-lib-toolbar">
  <input
    type="search"
    id="kql-lib-search"
    class="tag-filter-input kql-lib-search"
FM_TAIL_INTRO
  echo "    placeholder=\"Search $TOTAL_QUERIES queries by title, description, or category…\""
  cat <<'FM2'
    aria-label="Search KQL queries">
  <p class="kql-lib-hint" id="kql-lib-hint">
    Type to search all queries, or pick a category below.
  </p>
</div>

<div class="kql-lib-categories" id="kql-lib-categories">
FM2
  echo "$CARDS"
  cat <<'FM3'
</div>

<div class="kql-lib-tag-cta" id="kql-lib-tag-cta">
  <div class="kql-lib-tag-cta-copy">
    <strong>Browse by tag</strong>
    <span>MITRE ATT&amp;CK, actors, platforms, data sources, Deep Dive.</span>
  </div>
  <a class="kql-lib-tag-cta-link" href="{{ '/kql-library/tags/' | relative_url }}">
    See all tags&nbsp;<i class="fas fa-arrow-right" aria-hidden="true"></i>
  </a>
</div>

<ul class="kql-lib-results list-unstyled" id="kql-lib-results" role="list" hidden>
FM3
  echo "$LANDING_RESULTS"
  cat <<'FM4'
</ul>

<p class="kql-lib-empty" id="kql-lib-empty" hidden>No queries match that search.</p>
FM4
} > "$LP"

echo "TOTAL_QUERIES=$TOTAL_QUERIES"
echo "CATEGORIES=${#CATS[@]}"
