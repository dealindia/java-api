#!/usr/bin/env bash
# Security gate for Snyk results.
#
# Usage: snyk-gate.sh <label> <max-allowed> <result-file>...
#
# Counts unique HIGH and CRITICAL findings across Snyk result files and
# fails (exit 1) when the count is greater than <max-allowed>.
#   - SARIF files (Snyk Code / SAST): results with level "error" are High.
#   - JSON files (Snyk Open Source, Snyk Container / SCA): vulnerabilities
#     with severity "high" or "critical", counted once per Snyk issue ID.
# Missing files are skipped (for example, no supported manifests).
set -euo pipefail

label=$1
max=$2
shift 2

files=()
for f in "$@"; do
  [ -s "$f" ] && files+=("$f")
done

count=0
if [ ${#files[@]} -gt 0 ]; then
  count=$(jq -s '
    [ .[] |
      if type == "object" and has("runs") then
        .runs[].results[]?
        | select(.level == "error")
        | "\(.ruleId)|\(.locations[0].physicalLocation.artifactLocation.uri // "")|\(.locations[0].physicalLocation.region.startLine // 0)"
      else
        .. | objects | select(has("vulnerabilities")) | .vulnerabilities[]?
        | select(.severity == "high" or .severity == "critical")
        | .id
      end
    ] | unique | length' "${files[@]}")
fi

summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
if [ "$count" -gt "$max" ]; then
  echo "### ❌ $label: $count high/critical findings (allowed: $max)" >> "$summary"
  echo "::error::$label found $count high/critical findings, more than the allowed $max."
  exit 1
fi

echo "### ✅ $label: $count high/critical findings (allowed: $max)" >> "$summary"
echo "$label: $count high/critical findings, within the allowed $max."
