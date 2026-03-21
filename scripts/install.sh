#!/usr/bin/env bash
# AI Sentinel — Tool Installer
# Usage: bash install.sh [minimal|full]
set -euo pipefail

MODE="${1:-full}"

info()  { echo "==> $*"; }
warn()  { echo "  [!] $*"; }
ok()    { echo "  [✓] $*"; }
skip()  { echo "  [—] $* (skipped — installer not available)"; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

pip_install() {
    local pkg="$1"
    local name="${2:-$1}"
    if has_cmd "$name"; then
        ok "$name already installed"
    elif has_cmd pip; then
        pip install "$pkg" && ok "$name installed via pip" || warn "Failed to install $name"
    elif has_cmd pip3; then
        pip3 install "$pkg" && ok "$name installed via pip3" || warn "Failed to install $name"
    else
        skip "$name (pip not found)"
    fi
}

go_install() {
    local pkg="$1"
    local name="$2"
    if has_cmd "$name"; then
        ok "$name already installed"
    elif has_cmd go; then
        go install "$pkg" && ok "$name installed via go" || warn "Failed to install $name"
    else
        skip "$name (go not found)"
    fi
}

npm_install() {
    local pkg="$1"
    local name="${2:-$1}"
    if has_cmd "$name"; then
        ok "$name already installed"
    elif has_cmd npm; then
        npm install -g "$pkg" && ok "$name installed via npm" || warn "Failed to install $name"
    else
        skip "$name (npm not found)"
    fi
}

cargo_install() {
    local pkg="$1"
    local name="${2:-$1}"
    if has_cmd "$name"; then
        ok "$name already installed"
    elif has_cmd cargo; then
        cargo install "$pkg" && ok "$name installed via cargo" || warn "Failed to install $name"
    else
        skip "$name (cargo not found)"
    fi
}

install_syft() {
    if has_cmd syft; then
        ok "syft already installed"
    elif has_cmd brew; then
        brew install syft && ok "syft installed via brew" || warn "Failed to install syft"
    else
        info "Installing syft via install script..."
        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null \
            && ok "syft installed" || warn "Failed to install syft — download manually from https://github.com/anchore/syft/releases"
    fi
}

install_cyclonedx_cli() {
    if has_cmd cyclonedx-cli; then
        ok "cyclonedx-cli already installed"
    else
        info "CycloneDX CLI requires .NET 8 SDK or a prebuilt binary."
        info "Download from: https://github.com/CycloneDX/cyclonedx-cli/releases"
        skip "cyclonedx-cli (manual install required)"
    fi
}

# ── Minimal stack (Phase 1): 5 tools ────────────────────────────────
install_minimal() {
    info "Installing minimal stack (5 tools)..."
    pip_install "modelscan" "modelscan"
    pip_install "aisbom-cli" "aisbom"
    install_syft
    go_install "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest" "osv-scanner"
    info "Dependency-Track: deploy via Docker — see https://docs.dependencytrack.org/getting-started/deploy-docker/"
}

# ── Full stack (Phase 2-4): 16+ tools ──────────────────────────────
install_full() {
    info "Installing full stack (16+ tools)..."

    # Layer 1 — Code SAST
    pip_install "semgrep" "semgrep"
    info "CodeQL: install via GitHub or download from https://github.com/github/codeql-action"

    # Layer 1b — Agent scanning
    pip_install "agentic-radar" "agentic-radar"
    info "MCP-Scan: install via 'uv pip install mcp-scan' — see https://github.com/invariantlabs-ai/mcp-scan"

    # Layer 2 — Model scanning
    pip_install "modelscan" "modelscan"
    pip_install "picklescan" "picklescan"
    pip_install "modelaudit[all]" "modelaudit"
    pip_install "veritensor[all]" "veritensor"
    pip_install "fickling[torch]" "fickling"
    info "BAIT: install from source — git clone https://github.com/SolidShen/BAIT && pip install -e ."

    # Layer 3 — Prompt testing
    npm_install "promptfoo" "promptfoo"

    # Layer 4 — Dependency scanning
    go_install "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest" "osv-scanner"
    info "SafeDep vet: download binary from https://github.com/safedep/vet/releases"
    pip_install "cve-bin-tool" "cve-bin-tool"

    # Layer 5 — SBOM
    pip_install "aisbom-cli" "aisbom"
    install_syft
    install_cyclonedx_cli
    info "Dependency-Track: deploy via Docker — see https://docs.dependencytrack.org/getting-started/deploy-docker/"

    # Meta-tools
    cargo_install "pickle-fuzzer" "pickle-fuzzer"
    info "GitHub Taskflow Agent: run via Codespace — https://github.com/GitHubSecurityLab/seclab-taskflow-agent"
}

# ── Main ────────────────────────────────────────────────────────────
info "AI Sentinel — Tool Installer (mode: $MODE)"
echo ""

case "$MODE" in
    minimal) install_minimal ;;
    full)    install_full ;;
    *)       echo "Usage: $0 [minimal|full]"; exit 1 ;;
esac

echo ""
info "Done. Run 'make check-tools' to verify installation."
