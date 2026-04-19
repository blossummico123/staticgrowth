#!/usr/bin/env bash
# AI Sentinel — Meta-tool: Validate scanners against ground truth + fuzz samples
set -euo pipefail

RESULTS_DIR="${RESULTS_DIR:-sentinel-results}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

info() { echo "==> [validate] $*"; }
warn() { echo "  [!] $*"; }

# ── Phase 1: Static ground truth fixtures ────────────────────────────
FIXTURES_TEST="${PROJECT_ROOT}/tests/test-scanners.sh"
if [ -f "$FIXTURES_TEST" ]; then
    info "Phase 1: Testing scanners against ground truth fixtures..."
    # Regenerate fixtures to ensure they're current
    python "${PROJECT_ROOT}/tests/fixtures/generate-fixtures.py" 2>/dev/null || true
    bash "$FIXTURES_TEST" || warn "Some scanners failed ground truth validation"
    echo ""
else
    warn "Ground truth test suite not found at ${FIXTURES_TEST}"
fi

# ── Phase 2: Fuzz testing ────────────────────────────────────────────
if ! command -v pickle-fuzzer >/dev/null 2>&1; then
    warn "Pickle-Fuzzer not installed — skipping fuzz validation"
    warn "Install via: cargo install pickle-fuzzer"
    exit 0
fi

FUZZ_DIR="${RESULTS_DIR}/validation/fuzz-samples"
REPORT_DIR="${RESULTS_DIR}/validation"
mkdir -p "$FUZZ_DIR" "$REPORT_DIR"

# ── Generate adversarial samples ───────────────────────────────────
info "Generating 50 adversarial pickle files..."
pickle-fuzzer --dir "$FUZZ_DIR" --samples 50 2>/dev/null || {
    warn "Pickle-Fuzzer failed to generate samples"
    exit 1
}

TOTAL=$(find "$FUZZ_DIR" -name "*.pkl" | wc -l)
info "Generated $TOTAL adversarial pickle files"

# ── Test each installed scanner ────────────────────────────────────
echo ""
echo "Scanner Detection Rates"
echo "========================"

test_scanner() {
    local name="$1"
    local cmd="$2"
    local detected=0

    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "  $name: NOT INSTALLED"
        return
    fi

    for pkl in "$FUZZ_DIR"/*.pkl; do
        case "$name" in
            ModelScan)
                modelscan -p "$pkl" -r json 2>/dev/null | grep -qE '"total_issues": *[1-9]' && detected=$((detected + 1)) || true
                ;;
            Picklescan)
                picklescan --path "$pkl" 2>&1 | grep -qiE "dangerous import.*FOUND|Infected files: *[1-9]" && detected=$((detected + 1)) || true
                ;;
            ModelAudit)
                modelaudit "$pkl" --format json 2>/dev/null | grep -qE '"total_issues": *[1-9]|"severity"' && detected=$((detected + 1)) || true
                ;;
            Fickling)
                fickling --check-safety -p "$pkl" 2>&1 | grep -qiE "unsafe|malicious|dangerous|overtly" && detected=$((detected + 1)) || true
                ;;
        esac
    done

    local rate=0
    if [ "$TOTAL" -gt 0 ]; then
        rate=$((detected * 100 / TOTAL))
    fi
    echo "  $name: ${detected}/${TOTAL} detected (${rate}%)"
    echo "$name,$detected,$TOTAL,$rate" >> "${REPORT_DIR}/detection-rates.csv"
}

echo "scanner,detected,total,rate_pct" > "${REPORT_DIR}/detection-rates.csv"

test_scanner "ModelScan"  "modelscan"
test_scanner "Picklescan" "picklescan"
test_scanner "ModelAudit" "modelaudit"
test_scanner "Fickling"   "fickling"

echo ""
info "Detection rates → ${REPORT_DIR}/detection-rates.csv"
info "Scanner validation complete."
