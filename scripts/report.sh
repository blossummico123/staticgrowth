#!/usr/bin/env bash
# AI Sentinel — Unified Report Generator
set -euo pipefail

RESULTS_DIR="${RESULTS_DIR:-sentinel-results}"
REPORT="${RESULTS_DIR}/REPORT.md"

info() { echo "==> [report] $*"; }

# ── Helper: count JSON findings by severity ────────────────────────
count_json_findings() {
    local file="$1"
    if [ -f "$file" ]; then
        local total
        total=$(python3 -c "
import json, sys
try:
    data = json.load(open('$file'))
    if isinstance(data, dict):
        results = data.get('results', data.get('findings', data.get('vulnerabilities', [])))
        if isinstance(results, list):
            print(len(results))
        else:
            print(0)
    elif isinstance(data, list):
        print(len(data))
    else:
        print(0)
except:
    print(0)
" 2>/dev/null)
        echo "${total:-0}"
    else
        echo "—"
    fi
}

# ── Build report ───────────────────────────────────────────────────
info "Generating unified report..."

cat > "$REPORT" << 'HEADER'
# AI Sentinel — Scan Report

HEADER

echo "**Generated:** $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$REPORT"
echo "**Results directory:** \`${RESULTS_DIR}\`" >> "$REPORT"
echo "" >> "$REPORT"

# ── Layer 1: Code SAST ─────────────────────────────────────────────
echo "## Layer 1: Code SAST" >> "$REPORT"
echo "" >> "$REPORT"

if [ -f "${RESULTS_DIR}/code/semgrep.json" ]; then
    COUNT=$(count_json_findings "${RESULTS_DIR}/code/semgrep.json")
    echo "- **Semgrep:** ${COUNT} finding(s) → \`code/semgrep.json\`" >> "$REPORT"
else
    echo "- **Semgrep:** not run" >> "$REPORT"
fi

if [ -f "${RESULTS_DIR}/code/codeql.sarif" ]; then
    echo "- **CodeQL:** results available → \`code/codeql.sarif\`" >> "$REPORT"
else
    echo "- **CodeQL:** not run" >> "$REPORT"
fi
echo "" >> "$REPORT"

# ── Layer 1b: Agent Architecture ───────────────────────────────────
echo "## Layer 1b: Agent Architecture" >> "$REPORT"
echo "" >> "$REPORT"

if [ -f "${RESULTS_DIR}/agents/agentic-radar.txt" ]; then
    echo "- **Agentic Radar:** results available → \`agents/agentic-radar.txt\`" >> "$REPORT"
else
    echo "- **Agentic Radar:** not run" >> "$REPORT"
fi

if [ -f "${RESULTS_DIR}/agents/mcp-scan.txt" ]; then
    echo "- **MCP-Scan:** results available → \`agents/mcp-scan.txt\`" >> "$REPORT"
else
    echo "- **MCP-Scan:** not run" >> "$REPORT"
fi
echo "" >> "$REPORT"

# ── Layer 2: Model Artifacts ──────────────────────────────────────
echo "## Layer 2: Model Artifacts" >> "$REPORT"
echo "" >> "$REPORT"

for tool_file in \
    "modelscan.json:ModelScan" \
    "picklescan.txt:Picklescan" \
    "modelaudit.json:ModelAudit" \
    "veritensor.txt:Veritensor"; do
    FILE="${tool_file%%:*}"
    NAME="${tool_file##*:}"
    if [ -f "${RESULTS_DIR}/models/$FILE" ]; then
        if [[ "$FILE" == *.json ]]; then
            COUNT=$(count_json_findings "${RESULTS_DIR}/models/$FILE")
            echo "- **${NAME}:** ${COUNT} finding(s) → \`models/$FILE\`" >> "$REPORT"
        else
            echo "- **${NAME}:** results available → \`models/$FILE\`" >> "$REPORT"
        fi
    else
        echo "- **${NAME}:** not run" >> "$REPORT"
    fi
done

if [ -d "${RESULTS_DIR}/models/fickling" ] && [ "$(ls -A "${RESULTS_DIR}/models/fickling" 2>/dev/null)" ]; then
    echo "- **Fickling:** results available → \`models/fickling/\`" >> "$REPORT"
else
    echo "- **Fickling:** not run" >> "$REPORT"
fi

if [ -d "${RESULTS_DIR}/models/bait" ]; then
    echo "- **BAIT:** results available → \`models/bait/\`" >> "$REPORT"
else
    echo "- **BAIT:** not run" >> "$REPORT"
fi
echo "" >> "$REPORT"

# ── Layer 3: Prompt Testing ───────────────────────────────────────
echo "## Layer 3: Prompt Testing" >> "$REPORT"
echo "" >> "$REPORT"

if [ -f "${RESULTS_DIR}/prompts/promptfoo-results.json" ]; then
    COUNT=$(count_json_findings "${RESULTS_DIR}/prompts/promptfoo-results.json")
    echo "- **Promptfoo:** ${COUNT} test result(s) → \`prompts/promptfoo-results.json\`" >> "$REPORT"
else
    echo "- **Promptfoo:** not run" >> "$REPORT"
fi
echo "" >> "$REPORT"

# ── Layer 4: Dependencies ────────────────────────────────────────
echo "## Layer 4: Dependencies" >> "$REPORT"
echo "" >> "$REPORT"

if [ -f "${RESULTS_DIR}/deps/osv-scanner.json" ]; then
    COUNT=$(count_json_findings "${RESULTS_DIR}/deps/osv-scanner.json")
    echo "- **OSV-Scanner:** ${COUNT} vulnerability(ies) → \`deps/osv-scanner.json\`" >> "$REPORT"
else
    echo "- **OSV-Scanner:** not run" >> "$REPORT"
fi

if [ -f "${RESULTS_DIR}/deps/vet.json" ]; then
    COUNT=$(count_json_findings "${RESULTS_DIR}/deps/vet.json")
    echo "- **SafeDep vet:** ${COUNT} finding(s) → \`deps/vet.json\`" >> "$REPORT"
else
    echo "- **SafeDep vet:** not run" >> "$REPORT"
fi

if [ -f "${RESULTS_DIR}/deps/cve-bin-tool.json" ]; then
    COUNT=$(count_json_findings "${RESULTS_DIR}/deps/cve-bin-tool.json")
    echo "- **CVE Binary Tool:** ${COUNT} finding(s) → \`deps/cve-bin-tool.json\`" >> "$REPORT"
else
    echo "- **CVE Binary Tool:** not run" >> "$REPORT"
fi
echo "" >> "$REPORT"

# ── Layer 5: SBOM ────────────────────────────────────────────────
echo "## Layer 5: SBOM" >> "$REPORT"
echo "" >> "$REPORT"

[ -f "${RESULTS_DIR}/sbom/aisbom-models.json" ] \
    && echo "- **AIsbom:** generated → \`sbom/aisbom-models.json\`" >> "$REPORT" \
    || echo "- **AIsbom:** not run" >> "$REPORT"

[ -f "${RESULTS_DIR}/sbom/syft-env.json" ] \
    && echo "- **Syft:** generated → \`sbom/syft-env.json\`" >> "$REPORT" \
    || echo "- **Syft:** not run" >> "$REPORT"

[ -f "${RESULTS_DIR}/sbom/merged-sbom.json" ] \
    && echo "- **Merged SBOM:** available → \`sbom/merged-sbom.json\`" >> "$REPORT" \
    || echo "- **Merged SBOM:** not generated" >> "$REPORT"
echo "" >> "$REPORT"

# ── Validation ───────────────────────────────────────────────────
if [ -f "${RESULTS_DIR}/validation/detection-rates.csv" ]; then
    echo "## Scanner Validation" >> "$REPORT"
    echo "" >> "$REPORT"
    echo "| Scanner | Detected | Total | Rate |" >> "$REPORT"
    echo "|---------|----------|-------|------|" >> "$REPORT"
    tail -n +2 "${RESULTS_DIR}/validation/detection-rates.csv" | while IFS=',' read -r name detected total rate; do
        echo "| $name | $detected | $total | ${rate}% |" >> "$REPORT"
    done
    echo "" >> "$REPORT"
fi

echo "---" >> "$REPORT"
echo "*Report generated by AI Sentinel*" >> "$REPORT"

info "Report generated → $REPORT"
