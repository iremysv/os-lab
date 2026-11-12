#!/usr/bin/env bash
# os-lab local test runner — the CI replacement.
#
# GitHub Actions is disabled for this repo; run this script locally instead.
# It mirrors what the old workflow did, plus repo-wide shell and graph checks.
#
# Usage:
#   scripts/run-tests.sh            run everything
#   scripts/run-tests.sh --quick    OS-30 mocks and android unit tests only
#   scripts/run-tests.sh --no-venv  use the current environment, do not create .venv
#   scripts/run-tests.sh -h|--help  show this help
#
# Stages:
#   0. OS-30 hardening mocks (unittest)      [required]
#   1. android unit tests (pytest)          [required]
#   2. android sample analysis pipeline     [smoke, non-fatal]
#   3. shell script syntax check (bash -n)  [required]
#   4. lat.md knowledge-graph check         [if `lat` is installed]
#   5. dashboard typecheck + build freshness [if dashboard/node_modules exists]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
ANDROID_LAB="$ROOT/android-lab/lab"

QUICK=0
USE_VENV=1
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    --no-venv) USE_VENV=0 ;;
    -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [ -t 1 ]; then
  RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; BOLD=""; RESET=""
fi
PASS=0; FAIL=0; SKIP=0
hdr()  { printf '\n%s== %s ==%s\n' "$BOLD" "$*" "$RESET"; }
ok()   { printf '%s[ok]%s   %s\n'   "$GREEN"  "$RESET" "$*"; PASS=$((PASS+1)); }
bad()  { printf '%s[fail]%s %s\n'   "$RED"    "$RESET" "$*"; FAIL=$((FAIL+1)); }
skip() { printf '%s[skip]%s %s\n'   "$YELLOW" "$RESET" "$*"; SKIP=$((SKIP+1)); }

# --- Resolve a Python with pytest ------------------------------------------
PY=""
pick_python() {
  for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then PY="$(command -v "$cand")"; return 0; fi
  done
  return 1
}
ensure_pytest() {
  pick_python || { bad "no python3 found; install Python 3.11+"; return 1; }
  if "$PY" -c 'import pytest' >/dev/null 2>&1; then return 0; fi
  if [ "$USE_VENV" = "1" ]; then
    local venv="$ROOT/.venv-test"
    if [ ! -d "$venv" ]; then
      printf 'creating test virtualenv at .venv-test ...\n'
      "$PY" -m venv "$venv" || { bad "could not create venv"; return 1; }
    fi
    # shellcheck disable=SC1091
    . "$venv/bin/activate"
    PY="$(command -v python)"
    "$PY" -m pip install --quiet --upgrade pip
    "$PY" -m pip install --quiet pytest requests
    [ -f "$ANDROID_LAB/requirements.txt" ] && "$PY" -m pip install --quiet -r "$ANDROID_LAB/requirements.txt"
  else
    "$PY" -m pip install --quiet pytest requests || { bad "pytest unavailable and --no-venv set"; return 1; }
  fi
  "$PY" -c 'import pytest' >/dev/null 2>&1
}

# --- OS-30: isolated hardening command mocks -------------------------------
hdr "OS-30: hardening mock tests"
if python3 -m unittest discover -s "$ROOT/linux-lab/tests" -v; then
  ok "OS-30 hardening mock tests"
else
  bad "OS-30 hardening mock tests"
fi

# --- Stage 1: android unit tests -------------------------------------------
hdr "Stage 1: android unit tests (pytest)"
if ensure_pytest; then
  if ( cd "$ANDROID_LAB" && "$PY" -m pytest tests -q ); then
    ok "android-lab/lab test suite"
  else
    bad "android-lab/lab test suite"
  fi
else
  bad "could not prepare a Python environment with pytest"
fi

if [ "$QUICK" = "1" ]; then
  printf '\n%s--quick: skipping remaining stages%s\n' "$YELLOW" "$RESET"
else
  # --- Stage 2: sample analysis smoke test ---------------------------------
  hdr "Stage 2: android sample analysis pipeline (smoke)"
  if [ -n "$PY" ] && [ -f "$ANDROID_LAB/scripts/create_sample_apk.py" ]; then
    if ( cd "$ANDROID_LAB" \
         && "$PY" scripts/create_sample_apk.py \
         && "$PY" scripts/app_analyzer.py scripts/vulnerable-test.apk artifacts/security-scan \
         && "$PY" scripts/app_reporter.py artifacts/security-scan/app-analysis.json -o artifacts/security-scan ); then
      ok "sample analysis + report generated in android-lab/lab/artifacts/security-scan"
    else
      skip "sample analysis pipeline did not complete (non-fatal; needs the analysis deps)"
    fi
  else
    skip "sample analysis scripts unavailable"
  fi

  # --- Stage 3: shell script syntax --------------------------------------
  hdr "Stage 3: shell script syntax (bash -n)"
  sh_fail=0; sh_count=0
  while IFS= read -r -d '' s; do
    sh_count=$((sh_count+1))
    bash -n "$s" 2>/dev/null || { printf '  %s[fail]%s %s\n' "$RED" "$RESET" "${s#"$ROOT"/}"; sh_fail=$((sh_fail+1)); }
  done < <(find "$ROOT" \( -type d \( -name .git -o -name node_modules \) \) -prune -o -type f -name '*.sh' -print0)
  if [ "$sh_fail" -eq 0 ]; then ok "all $sh_count shell scripts parse"; else bad "$sh_fail of $sh_count shell scripts failed bash -n"; fi

  # --- Stage 4: lat graph check ------------------------------------------
  hdr "Stage 4: lat.md knowledge graph"
  if command -v lat >/dev/null 2>&1; then
    if lat check >/dev/null 2>&1; then ok "lat check"; else bad "lat check (run: lat check)"; fi
  else
    skip "lat not installed (npm i -g lat.md) — skipping graph check"
  fi

  # --- Stage 5: dashboard ------------------------------------------------
  # Typecheck, then rebuild into a temp folder and compare with the committed
  # dashboard/dist, so hosts without Node never get a stale prebuilt dashboard.
  hdr "Stage 5: dashboard (typecheck + committed build is current)"
  DASH="$ROOT/dashboard"
  if [ -d "$DASH/node_modules" ] && command -v node >/dev/null 2>&1; then
    if ( cd "$DASH" && ./node_modules/.bin/tsc --noEmit ); then ok "dashboard typecheck"; else bad "dashboard typecheck (cd dashboard && npm run check)"; fi
    # Same filesystem as the project: Astro moves build files with rename(2)
    TMP_OUT="$(mktemp -d "$DASH/.check-build.XXXXXX")"
    if ( cd "$DASH" && ./node_modules/.bin/astro build --outDir "$TMP_OUT" >/dev/null 2>&1 ); then
      if diff -rq "$TMP_OUT" "$DASH/dist" >/dev/null 2>&1; then
        ok "dashboard/dist matches the sources"
      else
        bad "dashboard/dist is stale — run: (cd dashboard && npm run build) and commit dist/"
      fi
    else
      bad "dashboard build failed (cd dashboard && npm run build)"
    fi
    rm -rf "$TMP_OUT"
  else
    skip "dashboard dependencies not installed (cd dashboard && npm ci) — skipping"
  fi
fi

# --- Summary ----------------------------------------------------------------
hdr "Summary"
printf '%s%d passed%s, %s%d failed%s, %s%d skipped%s\n' \
  "$GREEN" "$PASS" "$RESET" "$RED" "$FAIL" "$RESET" "$YELLOW" "$SKIP" "$RESET"
[ "$FAIL" -eq 0 ] || exit 1
printf '%sAll required checks passed.%s\n' "$GREEN" "$RESET"
