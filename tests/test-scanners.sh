#!/usr/bin/env bash
# AI Sentinel — Scanner Validation Against Ground Truth Fixtures
#
# Tests each installed scanner against the fixtures in tests/fixtures/
# and compares results against manifest.json (ground truth).
#
# Exit code:
#   0 — all scanners passed (no false negatives on malicious, no false positives on safe)
#   1 — at least one scanner produced incorrect results
#
# Usage:
#   bash tests/test-scanners.sh           # run all
#   bash tests/test-scanners.sh --verbose # show per-file details

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES_DIR="${SCRIPT_DIR}/fixtures"
MANIFEST="${FIXTURES_DIR}/manifest.json"

# Convert MSYS/Git Bash paths to Windows paths for Python on Windows
to_native() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$1"
    else
        echo "$1"
    fi
}
MANIFEST_NATIVE="$(to_native "$MANIFEST")"
FIXTURES_DIR_NATIVE="$(to_native "$FIXTURES_DIR")"
VERBOSE="${1:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass_count=0
fail_count=0
skip_count=0

info()  { echo -e "==> $*"; }
pass()  { echo -e "  ${GREEN}PASS${NC} $*"; pass_count=$((pass_count + 1)); }
fail()  { echo -e "  ${RED}FAIL${NC} $*"; fail_count=$((fail_count + 1)); }
skip()  { echo -e "  ${YELLOW}SKIP${NC} $*"; skip_count=$((skip_count + 1)); }
detail() { [ "$VERBOSE" = "--verbose" ] && echo "       $*" || true; }

if [ ! -f "$MANIFEST" ]; then
    echo "Manifest not found. Run: python tests/fixtures/generate-fixtures.py"
    exit 1
fi

FIXTURES=$(python -c "
import json
for f in json.load(open(r'$MANIFEST_NATIVE')):
    print(f['file'], f['malicious'], f['category'])
")

# ── Test a single scanner ────────────────────────────────────────────────

test_scanner() {
    local scanner_name="$1"
    local scanner_cmd="$2"

    echo ""
    info "Testing ${scanner_name}..."

    if ! command -v "$scanner_cmd" >/dev/null 2>&1; then
        skip "${scanner_name} not installed"
        return
    fi

    local s_pass=0 s_fail=0

    while IFS=' ' read -r filename is_malicious category; do
        local filepath="${FIXTURES_DIR}/${filename}"
        [ -f "$filepath" ] || continue

        # Skip non-pickle files for pickle-only scanners
        case "$scanner_name" in
            Picklescan|Fickling)
                case "$filename" in
                    *.safetensors|*.onnx|*.h5) continue ;;
                esac
                ;;
        esac

        local flagged=false
        local output=""

        case "$scanner_name" in
            ModelScan)
                output=$(modelscan -p "$filepath" -r json 2>/dev/null || true)
                if echo "$output" | grep -qE '"total_issues": *[1-9]'; then
                    flagged=true
                elif echo "$output" | grep -qE '"PICKLE_GENOPS"'; then
                    # Pickle parsing errors indicate suspicious/malformed payloads
                    flagged=true
                fi
                ;;
            Picklescan)
                output=$(picklescan --path "$filepath" 2>&1 || true)
                if echo "$output" | grep -qiE "dangerous import.*FOUND|Infected files: *[1-9]"; then
                    flagged=true
                fi
                ;;
            ModelAudit)
                output=$(modelaudit "$filepath" --format json 2>/dev/null || true)
                if echo "$output" | grep -qiE '"severity"|"issues"|"findings"'; then
                    flagged=true
                fi
                ;;
            Fickling)
                output=$(fickling --check-safety -p "$filepath" 2>&1 || true)
                if echo "$output" | grep -qiE "unsafe|malicious|dangerous|overtly"; then
                    flagged=true
                fi
                ;;
        esac

        if [ "$is_malicious" = "True" ]; then
            # Should be flagged
            if [ "$flagged" = true ]; then
                pass "${filename} (correctly flagged as malicious)"
                s_pass=$((s_pass + 1))
            else
                fail "${filename} — FALSE NEGATIVE (malicious file not detected)"
                detail "Expected: flagged | Got: clean"
                s_fail=$((s_fail + 1))
            fi
        else
            # Should NOT be flagged
            if [ "$flagged" = false ]; then
                pass "${filename} (correctly reported as clean)"
                s_pass=$((s_pass + 1))
            else
                fail "${filename} — FALSE POSITIVE (safe file incorrectly flagged)"
                detail "Expected: clean | Got: flagged"
                s_fail=$((s_fail + 1))
            fi
        fi
    done <<< "$FIXTURES"

    info "${scanner_name}: ${s_pass} passed, ${s_fail} failed"
}

# ── Run all scanners ─────────────────────────────────────────────────────

echo "AI Sentinel — Scanner Ground Truth Validation"
echo "=============================================="
echo "Fixtures: $(python -c "import json; d=json.load(open(r'$MANIFEST_NATIVE')); print(f\"{sum(1 for x in d if x['malicious'])} malicious, {sum(1 for x in d if not x['malicious'])} safe\")")"

test_scanner "ModelScan"  "modelscan"
test_scanner "Picklescan" "picklescan"
test_scanner "ModelAudit" "modelaudit"
test_scanner "Fickling"   "fickling"

# ── Summary ──────────────────────────────────────────────────────────────

echo ""
echo "=============================================="
echo -e "Results: ${GREEN}${pass_count} passed${NC}, ${RED}${fail_count} failed${NC}, ${YELLOW}${skip_count} skipped${NC}"

if [ "$fail_count" -gt 0 ]; then
    echo -e "${RED}SCANNER VALIDATION FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}ALL SCANNERS PASSED${NC}"
    exit 0
fi
