#!/usr/bin/env bash
# AI Sentinel — Layer 5: SBOM Generation and Governance
set -euo pipefail

TARGET="${TARGET:-.}"
RESULTS_DIR="${RESULTS_DIR:-sentinel-results}"

info() { echo "==> [scan-sbom] $*"; }
warn() { echo "  [!] $*"; }

# Load Dependency-Track config if available
if [ -f "dependency-track.env" ]; then
    # shellcheck disable=SC1091
    source dependency-track.env
fi

# ── 1. AIsbom (model-layer SBOM) ──────────────────────────────────
if command -v aisbom >/dev/null 2>&1; then
    info "Running AIsbom for model SBOM..."
    aisbom scan "$TARGET" \
        --lint \
        > "${RESULTS_DIR}/sbom/aisbom-models.json" 2>&1 || true
    info "AIsbom results → ${RESULTS_DIR}/sbom/aisbom-models.json"
else
    warn "AIsbom not installed — skipping model SBOM"
fi

# ── 2. Syft (infrastructure-layer SBOM) ───────────────────────────
if command -v syft >/dev/null 2>&1; then
    info "Running Syft for environment SBOM..."
    syft scan "$TARGET" \
        -o cyclonedx-json="${RESULTS_DIR}/sbom/syft-env.json" \
        2>/dev/null || true
    info "Syft results → ${RESULTS_DIR}/sbom/syft-env.json"
else
    warn "Syft not installed — skipping environment SBOM"
fi

# ── 3. Merge SBOMs ────────────────────────────────────────────────
if command -v cyclonedx-cli >/dev/null 2>&1; then
    SBOM_INPUTS=""
    [ -f "${RESULTS_DIR}/sbom/aisbom-models.json" ] && SBOM_INPUTS="$SBOM_INPUTS --input-files ${RESULTS_DIR}/sbom/aisbom-models.json"
    [ -f "${RESULTS_DIR}/sbom/syft-env.json" ] && SBOM_INPUTS="$SBOM_INPUTS --input-files ${RESULTS_DIR}/sbom/syft-env.json"

    if [ -n "$SBOM_INPUTS" ]; then
        info "Merging SBOMs with CycloneDX CLI..."
        cyclonedx-cli merge \
            $SBOM_INPUTS \
            --output-file "${RESULTS_DIR}/sbom/merged-sbom.json" \
            --output-format json \
            2>/dev/null || true
        info "Merged SBOM → ${RESULTS_DIR}/sbom/merged-sbom.json"
    fi
else
    warn "CycloneDX CLI not installed — skipping SBOM merge"
fi

# ── 4. Upload to Dependency-Track ─────────────────────────────────
DT_URL="${DT_URL:-}"
DT_API_KEY="${DT_API_KEY:-}"
DT_PROJECT_UUID="${DT_PROJECT_UUID:-}"

UPLOAD_FILE="${RESULTS_DIR}/sbom/merged-sbom.json"
[ ! -f "$UPLOAD_FILE" ] && UPLOAD_FILE="${RESULTS_DIR}/sbom/syft-env.json"

if [ -n "$DT_URL" ] && [ -n "$DT_API_KEY" ] && [ -n "$DT_PROJECT_UUID" ] && [ -f "$UPLOAD_FILE" ]; then
    info "Uploading SBOM to Dependency-Track..."
    BOM_CONTENT=$(base64 -w0 "$UPLOAD_FILE")
    curl -s -X POST "${DT_URL}/api/v1/bom" \
        -H "Content-Type: application/json" \
        -H "X-Api-Key: ${DT_API_KEY}" \
        -d "{\"project\":\"${DT_PROJECT_UUID}\",\"bom\":\"${BOM_CONTENT}\"}" \
        > /dev/null 2>&1 || warn "Failed to upload to Dependency-Track"
    info "SBOM uploaded to Dependency-Track"
else
    if [ -z "$DT_URL" ]; then
        info "Dependency-Track not configured — skipping upload (set DT_URL, DT_API_KEY, DT_PROJECT_UUID)"
    fi
fi

info "SBOM generation complete."
