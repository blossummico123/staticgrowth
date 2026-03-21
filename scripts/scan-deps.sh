#!/usr/bin/env bash
# AI Sentinel — Layer 4: Dependency Vulnerability Scanning
set -euo pipefail

MODE="${1:-full}"
TARGET="${TARGET:-.}"
RESULTS_DIR="${RESULTS_DIR:-sentinel-results}"
CONFIGS_DIR="${CONFIGS_DIR:-configs}"

info() { echo "==> [scan-deps] $*"; }
warn() { echo "  [!] $*"; }

# ── 1. OSV-Scanner (broadest advisory database) ───────────────────
if command -v osv-scanner >/dev/null 2>&1; then
    info "Running OSV-Scanner..."
    osv-scanner scan \
        --format json \
        --output "${RESULTS_DIR}/deps/osv-scanner.json" \
        "$TARGET" 2>/dev/null || true
    info "OSV-Scanner results → ${RESULTS_DIR}/deps/osv-scanner.json"
else
    warn "OSV-Scanner not installed — skipping"
fi

# Fast mode stops here
if [ "$MODE" = "fast" ]; then
    info "Fast mode — skipping deep dependency scanners."
    exit 0
fi

# ── 2. SafeDep vet (malware detection + reachability) ──────────────
if command -v vet >/dev/null 2>&1; then
    info "Running SafeDep vet..."

    VET_POLICY=""
    if [ -f "${CONFIGS_DIR}/vet-policy.yml" ]; then
        VET_POLICY="--policy ${CONFIGS_DIR}/vet-policy.yml"
    fi

    export VET_DISABLE_TELEMETRY=true
    vet scan \
        $VET_POLICY \
        --report-json "${RESULTS_DIR}/deps/vet.json" \
        --report-sarif "${RESULTS_DIR}/deps/vet.sarif" \
        "$TARGET" 2>/dev/null || true
    info "SafeDep vet results → ${RESULTS_DIR}/deps/vet.json"
else
    warn "SafeDep vet not installed — skipping"
fi

# ── 3. CVE Binary Tool (binary-level scanning) ────────────────────
if command -v cve-bin-tool >/dev/null 2>&1; then
    info "Running CVE Binary Tool..."
    cve-bin-tool \
        --format json \
        --output-file "${RESULTS_DIR}/deps/cve-bin-tool.json" \
        "$TARGET" 2>/dev/null || true
    info "CVE Binary Tool results → ${RESULTS_DIR}/deps/cve-bin-tool.json"
else
    warn "CVE Binary Tool not installed — skipping"
fi

info "Dependency scanning complete."
