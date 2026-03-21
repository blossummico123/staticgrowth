#!/usr/bin/env bash
# AI Sentinel — Layer 1b: Agent Architecture Analysis
set -euo pipefail

TARGET="${TARGET:-.}"
RESULTS_DIR="${RESULTS_DIR:-sentinel-results}"

info() { echo "==> [scan-agents] $*"; }
warn() { echo "  [!] $*"; }

# ── Agentic Radar ──────────────────────────────────────────────────
if command -v agentic-radar >/dev/null 2>&1; then
    info "Running Agentic Radar..."

    # Auto-detect agent framework
    FRAMEWORK=""
    if grep -rq "langgraph\|LangGraph" "$TARGET" 2>/dev/null; then
        FRAMEWORK="langgraph"
    elif grep -rq "crewai\|CrewAI" "$TARGET" 2>/dev/null; then
        FRAMEWORK="crewai"
    elif grep -rq "openai.*agents\|OpenAI.*Agents" "$TARGET" 2>/dev/null; then
        FRAMEWORK="openai-agents"
    elif grep -rq "autogen\|AutoGen" "$TARGET" 2>/dev/null; then
        FRAMEWORK="autogen"
    fi

    if [ -n "$FRAMEWORK" ]; then
        info "Detected framework: $FRAMEWORK"
    fi

    agentic-radar scan "$TARGET" \
        > "${RESULTS_DIR}/agents/agentic-radar.txt" 2>&1 || true
    info "Agentic Radar results → ${RESULTS_DIR}/agents/agentic-radar.txt"
else
    warn "Agentic Radar not installed — skipping agent analysis"
fi

# ── MCP-Scan ───────────────────────────────────────────────────────
if command -v mcp-scan >/dev/null 2>&1; then
    info "Running MCP-Scan..."

    # Look for MCP config files
    MCP_CONFIGS=$(find "$TARGET" -name "mcp*.json" -o -name "mcp*.yml" -o -name "mcp*.yaml" 2>/dev/null || true)
    if [ -n "$MCP_CONFIGS" ]; then
        mcp-scan "$TARGET" \
            > "${RESULTS_DIR}/agents/mcp-scan.txt" 2>&1 || true
        info "MCP-Scan results → ${RESULTS_DIR}/agents/mcp-scan.txt"
    else
        info "No MCP configurations found — skipping MCP-Scan"
    fi
else
    warn "MCP-Scan not installed — skipping"
fi

info "Agent scanning complete."
