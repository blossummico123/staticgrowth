# Adding a New Tool to AI Sentinel

This guide walks through adding a new scanner to the pipeline. You should be able to complete this in under an hour.

## Steps

### 1. Write the scan script

Create or edit the appropriate script in `scripts/`. Each script follows the same pattern:

```bash
#!/usr/bin/env bash
set -euo pipefail

TARGET="${TARGET:-.}"
RESULTS_DIR="${RESULTS_DIR:-sentinel-results}"

info() { echo "==> [scan-<layer>] $*"; }
warn() { echo "  [!] $*"; }

if ! command -v your-tool >/dev/null 2>&1; then
    warn "your-tool not installed — skipping"
    exit 0
fi

info "Running your-tool..."
your-tool scan "$TARGET" \
    --output "${RESULTS_DIR}/<layer>/your-tool.json" \
    2>/dev/null || true

info "your-tool results → ${RESULTS_DIR}/<layer>/your-tool.json"
```

Key rules:
- **Check if installed first** — never fail because a tool is missing
- **Use `|| true`** — the pipeline continues even if one tool errors
- **Write output to `${RESULTS_DIR}/<layer>/`** — predictable paths for the report
- **Prefer JSON output** — parseable by `report.sh`

### 2. Add to `install.sh`

Add the installation command to the appropriate section in `scripts/install.sh`:

```bash
# In install_full():
pip_install "your-tool" "your-tool"
# or
go_install "github.com/org/your-tool@latest" "your-tool"
# or
npm_install "your-tool" "your-tool"
```

### 3. Add to `report.sh`

Add a section to parse your tool's output in `scripts/report.sh`:

```bash
if [ -f "${RESULTS_DIR}/<layer>/your-tool.json" ]; then
    COUNT=$(count_json_findings "${RESULTS_DIR}/<layer>/your-tool.json")
    echo "- **Your Tool:** ${COUNT} finding(s) → \`<layer>/your-tool.json\`" >> "$REPORT"
else
    echo "- **Your Tool:** not run" >> "$REPORT"
fi
```

### 4. Add to `check-tools` in the Makefile

```makefile
@command -v your-tool >/dev/null 2>&1 && echo "  [✓] your-tool" || echo "  [✗] your-tool"
```

### 5. Wire into GitHub Actions

Add your tool to the appropriate workflow job in `.github/workflows/`:

- **Fast tools** (< 30s) → `pr-scan.yml`
- **Medium tools** (< 5 min) → `full-scan.yml`
- **Slow tools** (> 5 min) → `nightly-deep.yml`

### 6. Add config (if needed)

If your tool has a configuration file, add it to `configs/` and reference it from your scan script.

### 7. Test

```bash
# Verify tool detection
make check-tools

# Run your layer
make scan-<layer> TARGET=tests/fixtures/

# Verify report includes your tool
make report
```

## Checklist

- [ ] Scan script written in `scripts/`
- [ ] Installation added to `scripts/install.sh`
- [ ] Output parsing added to `scripts/report.sh`
- [ ] `check-tools` updated in `Makefile`
- [ ] Wired into appropriate GitHub Actions workflow
- [ ] Config file added to `configs/` (if applicable)
- [ ] Tested with `make check-tools` and `make scan`
