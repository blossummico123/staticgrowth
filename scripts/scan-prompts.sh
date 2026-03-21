#!/usr/bin/env bash
# AI Sentinel — Layer 3: Prompt Regression Testing (Promptfoo)
set -euo pipefail

TARGET="${TARGET:-.}"
RESULTS_DIR="${RESULTS_DIR:-sentinel-results}"
CONFIGS_DIR="${CONFIGS_DIR:-configs}"

info() { echo "==> [scan-prompts] $*"; }
warn() { echo "  [!] $*"; }

if ! command -v promptfoo >/dev/null 2>&1; then
    warn "Promptfoo not installed — skipping prompt regression testing"
    exit 0
fi

# Look for config in target project first, then fall back to default
CONFIG=""
if [ -f "${TARGET}/promptfooconfig.yaml" ]; then
    CONFIG="${TARGET}/promptfooconfig.yaml"
    info "Using project config: $CONFIG"
elif [ -f "${TARGET}/promptfooconfig.yml" ]; then
    CONFIG="${TARGET}/promptfooconfig.yml"
    info "Using project config: $CONFIG"
elif [ -f "${CONFIGS_DIR}/promptfoo.yml" ]; then
    CONFIG="${CONFIGS_DIR}/promptfoo.yml"
    info "Using default config: $CONFIG"
else
    warn "No Promptfoo config found — skipping"
    exit 0
fi

info "Running Promptfoo test suite..."
promptfoo eval \
    --config "$CONFIG" \
    --output "${RESULTS_DIR}/prompts/promptfoo-results.json" \
    --no-progress-bar \
    2>/dev/null || true

info "Promptfoo results → ${RESULTS_DIR}/prompts/promptfoo-results.json"
info "Prompt testing complete."
