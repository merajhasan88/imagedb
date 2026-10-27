#!/bin/sh
# Recomputes every number in docs/CVE_STUDY.md from the committed data
# (POSIX sh + awk only).
#
#   pg_cves.json        all CVEs listed on postgresql.org/support/security
#                       (scraped 2026-10-20; first_fix = earliest "Fix Published")
#   classification.csv  root-cause class for every CVE from 2021 on
#
# Usage: sh docs/cve/analyze.sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)

# pg_cves.json is pretty-printed with one field per line: pick "cve" and "first_fix".
awk '
/"cve": *"CVE-/ { match($0, /CVE-[0-9]+/); y = substr($0, RSTART + 4, RLENGTH - 4); n++; idy[y]++ }
/"first_fix": *"/ { if (match($0, /"[0-9][0-9][0-9][0-9]-/)) fx[substr($0, RSTART + 1, 4)]++ }
END {
  printf "total CVEs listed: %d\n\nby CVE-ID year:\n", n
  m = 0; for (y in idy) ys[++m] = y
  for (i = 1; i <= m; i++) for (j = i + 1; j <= m; j++) if (ys[j] < ys[i]) { t = ys[i]; ys[i] = ys[j]; ys[j] = t }
  mn = -1; mx = 0; s = 0; k = 0
  for (i = 1; i <= m; i++) {
    bar = ""; for (b = 0; b < idy[ys[i]]; b++) bar = bar "#"
    printf "  %d  %3d  %s\n", ys[i], idy[ys[i]], bar
    if (ys[i] >= 2004 && ys[i] <= 2025) { c = idy[ys[i]]; if (mn < 0 || c < mn) mn = c; if (c > mx) mx = c; s += c; k++ }
  }
  printf "  2004-2025: min %d, max %d, mean %.1f per CVE-year\n", mn, mx, s / k
  printf "\nby year of first fix (dates published for CVEs fixed since 2015):\n"
  m = 0; for (y in fx) fs[++m] = y
  for (i = 1; i <= m; i++) for (j = i + 1; j <= m; j++) if (fs[j] < fs[i]) { t = fs[i]; fs[i] = fs[j]; fs[j] = t }
  for (i = 1; i <= m; i++) printf "  %s  %3d\n", fs[i], fx[fs[i]]
}' "$HERE/pg_cves.json"

# classification.csv: the first seven fields never contain commas; the title
# (field 8) may be quoted and contain commas.
awk -F, '
BEGIN {
  split("A B C D E F G H I J", L, " ")
  D["A"] = "size arithmetic wraparound -> undersized allocation"
  D["B"] = "bounds: buffer overflow, over-read, memory disclosure"
  D["C"] = "encoding / multibyte validation"
  D["D"] = "type confusion"
  D["E"] = "injection via generated SQL, scripts or client meta-commands"
  D["F"] = "privilege context: search_path, sandbox, user code, late privilege drop, TOCTOU"
  D["G"] = "row security applied under the wrong role (plan/cache reuse)"
  D["H"] = "missing authorization, metadata and statistics leaks"
  D["I"] = "protocol, authentication, crypto"
  D["J"] = "filesystem trust (symlink following)"
}
NR == 1 { next }
{
  fix = $3; comp = $4; cvss = $5 + 0; cls = $6
  title = $0; for (f = 1; f <= 7; f++) sub(/^[^,]*,/, "", title)
  if (substr(fix, 1, 4) == "2026") {
    n26++; rel[fix]++
    if (!(comp in cc)) corder[++nc] = comp
    cc[comp]++; c26[cls]++
    if (cvss >= 8.0) high++
    if (index(title, "arbitrary code")) arb++
  } else if (substr(fix, 1, 4) >= "2021" && substr(fix, 1, 4) <= "2025") {
    nold++; cold[cls]++
  }
}
END {
  printf "\n2026 by release (first fix date):\n"
  m = 0; for (d in rel) ds[++m] = d
  for (i = 1; i <= m; i++) for (j = i + 1; j <= m; j++) if (ds[j] < ds[i]) { t = ds[i]; ds[i] = ds[j]; ds[j] = t }
  for (i = 1; i <= m; i++) printf "  %s  %2d\n", ds[i], rel[ds[i]]
  printf "\n2026 by component (official label):\n"
  # most common first; ties keep first-seen order
  for (i = 1; i <= nc; i++) for (j = i + 1; j <= nc; j++)
    if (cc[corder[j]] > cc[corder[i]]) { t = corder[i]; corder[i] = corder[j]; corder[j] = t }
  for (i = 1; i <= nc; i++) printf "  %-15s %2d\n", corder[i], cc[corder[i]]
  printf "\n2026 by root-cause class:\n"
  mem = 0
  for (i = 1; i <= 10; i++) { k = L[i]; if (c26[k]) printf "  %s %2d  %s\n", k, c26[k], D[k]; if (i <= 4) mem += c26[k] }
  printf "  memory safety (A+B+C+D): %d of %d = %.0f%%\n", mem, n26, 100.0 * mem / n26
  printf "  CVSS >= 8.0: %d of %d; \"arbitrary code\" in the title: %d\n", high, n26, arb
  printf "\n2021-2025 by root-cause class (for comparison):\n"
  om = 0
  for (i = 1; i <= 10; i++) { k = L[i]; if (cold[k]) printf "  %s %2d\n", k, cold[k]; if (i <= 4) om += cold[k] }
  printf "  memory safety (A+B+C+D): %d of %d = %.0f%%\n", om, nold, 100.0 * om / nold
}' "$HERE/classification.csv"
