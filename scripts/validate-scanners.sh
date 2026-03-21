#!/usr/bin/env bash
# AI Sentinel — Meta-tool: Test scanners with adversarial pickle samples
set -euo pipefail

RESULTS_DIR="${RESULTS_DIR:-sentinel-results}"

info() { echo "==> [validate] $*"; }
warn() { echo "  [!] $*"; }

if ! command -v pickle-fuzzer >/dev/null 2>&1; then
    warn "Pickle-Fuzzer not installed — skipping scanner validation"
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
                modelscan -p "$pkl" -r json 2>/dev/null | grep -q '"severity"' && ((detected++)) || true
                ;;
            Picklescan)
                picklescan --path "$pkl" 2>/dev/null | grep -qi "malicious\|dangerous" && ((detected++)) || true
                ;;
            ModelAudit)
                modelaudit "$pkl" --format json 2>/dev/null | grep -q '"severity"' && ((detected++)) || true
                ;;
            Fickling)
                fickling --check-safety -p "$pkl" 2>/dev/null | grep -qi "unsafe\|malicious" && ((detected++)) || true
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
