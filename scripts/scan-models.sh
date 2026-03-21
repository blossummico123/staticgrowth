#!/usr/bin/env bash
# AI Sentinel — Layer 2: Model Artifact Scanning
set -euo pipefail

MODE="${1:-full}"
TARGET="${TARGET:-.}"
RESULTS_DIR="${RESULTS_DIR:-sentinel-results}"
CONFIGS_DIR="${CONFIGS_DIR:-configs}"

info() { echo "==> [scan-models] $*"; }
warn() { echo "  [!] $*"; }

# Find model files
MODEL_EXTENSIONS="*.pt *.pth *.pkl *.pickle *.h5 *.hdf5 *.onnx *.safetensors *.gguf *.joblib *.npy *.bin *.pb *.tflite"
MODEL_FILES=()
for ext in $MODEL_EXTENSIONS; do
    while IFS= read -r -d '' f; do
        MODEL_FILES+=("$f")
    done < <(find "$TARGET" -name "$ext" -type f -print0 2>/dev/null)
done

if [ ${#MODEL_FILES[@]} -eq 0 ]; then
    info "No model files found in $TARGET — skipping model scanning."
    exit 0
fi

info "Found ${#MODEL_FILES[@]} model file(s)"

# ── 1. ModelScan (baseline, fastest) ───────────────────────────────
if command -v modelscan >/dev/null 2>&1; then
    info "Running ModelScan..."
    for f in "${MODEL_FILES[@]}"; do
        modelscan -p "$f" -r json -o "${RESULTS_DIR}/models/modelscan.json" 2>/dev/null || true
    done
    info "ModelScan results → ${RESULTS_DIR}/models/modelscan.json"
else
    warn "ModelScan not installed — skipping"
fi

# ── 2. Picklescan (pickle-specific) ────────────────────────────────
if command -v picklescan >/dev/null 2>&1; then
    info "Running Picklescan..."
    picklescan --path "$TARGET" > "${RESULTS_DIR}/models/picklescan.txt" 2>&1 || true
    info "Picklescan results → ${RESULTS_DIR}/models/picklescan.txt"
else
    warn "Picklescan not installed — skipping"
fi

# ── Fast mode stops here ───────────────────────────────────────────
if [ "$MODE" = "fast" ]; then
    info "Fast mode — skipping deep model scanners."
    exit 0
fi

# ── 3. ModelAudit (widest format coverage) ─────────────────────────
if command -v modelaudit >/dev/null 2>&1; then
    info "Running ModelAudit..."
    modelaudit "${MODEL_FILES[@]}" \
        --format json \
        --output "${RESULTS_DIR}/models/modelaudit.json" 2>/dev/null || true

    modelaudit "${MODEL_FILES[@]}" \
        --format sarif \
        --output "${RESULTS_DIR}/models/modelaudit.sarif" 2>/dev/null || true
    info "ModelAudit results → ${RESULTS_DIR}/models/modelaudit.json"
else
    warn "ModelAudit not installed — skipping"
fi

# ── 4. Veritensor (supply chain + datasets) ────────────────────────
if command -v veritensor >/dev/null 2>&1; then
    info "Running Veritensor..."
    VERI_CONFIG=""
    if [ -f "${CONFIGS_DIR}/veritensor.yml" ]; then
        VERI_CONFIG="--config ${CONFIGS_DIR}/veritensor.yml"
    fi
    veritensor scan "$TARGET" --recursive --jobs 4 $VERI_CONFIG \
        > "${RESULTS_DIR}/models/veritensor.txt" 2>&1 || true
    info "Veritensor results → ${RESULTS_DIR}/models/veritensor.txt"
else
    warn "Veritensor not installed — skipping"
fi

# ── 5. BAIT (nightly only — behavioral backdoor detection) ─────────
if command -v bait-scan >/dev/null 2>&1; then
    info "Running BAIT behavioral backdoor scan..."
    bait-scan --model-zoo-dir "$TARGET" \
        --output-dir "${RESULTS_DIR}/models/bait" 2>/dev/null || true
    info "BAIT results → ${RESULTS_DIR}/models/bait/"
else
    warn "BAIT not installed — skipping behavioral backdoor detection"
fi

# ── 6. Fickling (forensic pickle analysis on flagged files) ────────
if command -v fickling >/dev/null 2>&1; then
    info "Running Fickling analysis on pickle files..."
    mkdir -p "${RESULTS_DIR}/models/fickling"
    for f in "${MODEL_FILES[@]}"; do
        case "$f" in
            *.pkl|*.pickle|*.pt|*.pth|*.joblib|*.bin)
                BASENAME=$(basename "$f" | tr '.' '_')
                fickling --check-safety -p "$f" \
                    > "${RESULTS_DIR}/models/fickling/${BASENAME}.json" 2>&1 || true
                ;;
        esac
    done
    info "Fickling results → ${RESULTS_DIR}/models/fickling/"
else
    warn "Fickling not installed — skipping"
fi

info "Model scanning complete."
