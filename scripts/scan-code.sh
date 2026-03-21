#!/usr/bin/env bash
# AI Sentinel — Layer 1: Code SAST (Semgrep + CodeQL)
set -euo pipefail

MODE="${1:-full}"
TARGET="${TARGET:-.}"
RESULTS_DIR="${RESULTS_DIR:-sentinel-results}"
CONFIGS_DIR="${CONFIGS_DIR:-configs}"

info() { echo "==> [scan-code] $*"; }
warn() { echo "  [!] $*"; }

# ── Semgrep ─────────────────────────────────────────────────────────
if command -v semgrep >/dev/null 2>&1; then
    info "Running Semgrep..."

    SEMGREP_RULES="${CONFIGS_DIR}/semgrep.yml"
    EXTRA_RULES=""
    if [ -f "$SEMGREP_RULES" ]; then
        EXTRA_RULES="--config $SEMGREP_RULES"
    fi

    semgrep scan \
        --config "p/security-audit" \
        --config "p/owasp-top-ten" \
        $EXTRA_RULES \
        --json-output="${RESULTS_DIR}/code/semgrep.json" \
        --sarif-output="${RESULTS_DIR}/code/semgrep.sarif" \
        --quiet \
        "$TARGET" || true

    info "Semgrep results → ${RESULTS_DIR}/code/semgrep.json"
else
    warn "Semgrep not installed — skipping code SAST"
fi

# ── CodeQL (full mode only) ─────────────────────────────────────────
if [ "$MODE" = "full" ] && command -v codeql >/dev/null 2>&1; then
    info "Running CodeQL analysis..."

    CODEQL_DB="${RESULTS_DIR}/code/codeql-db"
    codeql database create "$CODEQL_DB" \
        --language=python \
        --source-root="$TARGET" \
        --overwrite 2>/dev/null || true

    if [ -d "$CODEQL_DB" ]; then
        codeql database analyze "$CODEQL_DB" \
            --format=sarifv2.1.0 \
            --output="${RESULTS_DIR}/code/codeql.sarif" \
            codeql/python-queries:codeql-suites/python-security-extended.qls \
            2>/dev/null || true
        info "CodeQL results → ${RESULTS_DIR}/code/codeql.sarif"
    fi
elif [ "$MODE" = "full" ]; then
    warn "CodeQL not installed — skipping deep analysis"
fi

info "Code scanning complete."
