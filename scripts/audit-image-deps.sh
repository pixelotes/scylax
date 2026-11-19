#!/bin/sh
# Audit the Python dependencies baked into the Scylax Docker image.
#
#   scripts/audit-image-deps.sh [IMAGE] [OUT_DIR]    (defaults: scylax:core, audit-out)
#
# Needs docker, and either `pip-audit` or `uvx`, on PATH. Writes per-venv
# requirement files, JSON reports and summary.md into OUT_DIR. Vulnerability
# IDs in .github/pip-audit-ignore.txt are ignored.
#
# Failure policy (FAIL_ON, default "fixable"):
#   fixable  exit 1 only if a finding has a fixed version available
#   any      exit 1 on any finding
#   never    always exit 0 (report only)
# Exit 2 means setup error (docker/pip-audit failure).
set -u
IMAGE=${1:-scylax:core}
OUT=${2:-audit-out}
FAIL_ON=${FAIL_ON:-fixable}
PIP_AUDIT_VERSION=${PIP_AUDIT_VERSION:-2.10.1}
HERE=$(cd "$(dirname "$0")" && pwd)
IGNORE_FILE=${IGNORE_FILE:-$HERE/../.github/pip-audit-ignore.txt}

if command -v pip-audit >/dev/null 2>&1; then PA="pip-audit"
elif command -v uvx >/dev/null 2>&1; then PA="uvx pip-audit@$PIP_AUDIT_VERSION"
else echo "need pip-audit or uvx" >&2; exit 2; fi

mkdir -p "$OUT" || exit 2
OUT=$(cd "$OUT" && pwd)

# Collect metadata inside the image with each interpreter's own metadata
# (set COLLECT_LOCAL_VENV=path to skip docker and inspect a local venv).
if [ -n "${COLLECT_LOCAL_VENV:-}" ]; then
  "$COLLECT_LOCAL_VENV/bin/python" "$HERE/list_venv_deps.py" "$OUT" "$(basename "$COLLECT_LOCAL_VENV")" || exit 2
else
  docker run --rm --entrypoint sh -v "$HERE/list_venv_deps.py:/list_venv_deps.py:ro" \
    -v "$OUT:/out" "$IMAGE" -c '
      for v in /opt/venvs/*; do "$v/bin/python" /list_venv_deps.py /out "$(basename "$v")" || exit 1; done
      python /list_venv_deps.py /out base' || exit 2
fi

IGN=""
if [ -f "$IGNORE_FILE" ]; then
  for id in $(sed 's/#.*//' "$IGNORE_FILE"); do IGN="$IGN --ignore-vuln $id"; done
fi

found=0; fixable=0; err=0
{ echo "## Python dependency audit of \`$IMAGE\`"; echo; } > "$OUT/summary.md"
for req in "$OUT"/*.txt; do
  case $req in *.unauditable.txt) continue;; esac
  name=$(basename "$req" .txt)
  [ -s "$req" ] || continue
  # pip-audit exits 1 on findings; the JSON report is written either way.
  # shellcheck disable=SC2086
  $PA -r "$req" --no-deps --disable-pip --progress-spinner off $IGN \
      -f json -o "$OUT/$name.json" >/dev/null 2>"$OUT/$name.err"
  [ -s "$OUT/$name.json" ] || { err=1; echo "pip-audit failed for $name:" >&2; cat "$OUT/$name.err" >&2; continue; }
  # shellcheck disable=SC2086
  $PA -r "$req" --no-deps --disable-pip --progress-spinner off $IGN \
      -f markdown > "$OUT/$name.md" 2>/dev/null
  counts=$(python3 - "$OUT/$name.json" <<'PY'
import json, sys
deps = json.load(open(sys.argv[1]))["dependencies"]
v = [x for d in deps for x in d.get("vulns", [])]
print(len(v), sum(1 for x in v if x.get("fix_versions")))
PY
  )
  n=${counts% *}; f=${counts#* }
  found=$((found + n)); fixable=$((fixable + f))
  {
    echo "### $name ($(wc -l < "$req" | tr -d ' ') packages, $n finding(s), $f with a fix)"
    if [ "$n" -eq 0 ]; then echo "No known vulnerabilities."; else cat "$OUT/$name.md"; fi
    if [ -s "$OUT/$name.unauditable.txt" ]; then
      echo; echo "Not auditable (VCS/local install):"
      sed 's/^/- /' "$OUT/$name.unauditable.txt"
    fi
    echo
  } >> "$OUT/summary.md"
done
echo "Total: $found finding(s), $fixable with a fix available (policy: $FAIL_ON)." >> "$OUT/summary.md"
cat "$OUT/summary.md"
[ "$err" -eq 1 ] && exit 2
case $FAIL_ON in
  any) [ "$found" -gt 0 ] && exit 1;;
  fixable) [ "$fixable" -gt 0 ] && exit 1;;
esac
exit 0
