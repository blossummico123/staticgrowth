# AI Sentinel

Orchestration layer for AI/ML security scanning — one pipeline, one config, one report.

AI Sentinel chains 16+ security tools into a unified pipeline covering code analysis, model artifact scanning, prompt testing, dependency auditing, and SBOM generation. It doesn't replace any tool — it makes them work together.

## Quick Start

```bash
# Install tools (minimal 5-tool stack)
make install-minimal

# Or install everything (16+ tools)
make install

# Check what's installed
make check-tools

# Run full scan
make scan TARGET=./your-ai-project

# Run fast PR-level scan (~2 min)
make scan-fast TARGET=./your-ai-project

# Run individual layers
make scan-code TARGET=./your-ai-project
make scan-models TARGET=./your-ai-project
make scan-deps TARGET=./your-ai-project
make scan-prompts TARGET=./your-ai-project
make scan-agents TARGET=./your-ai-project
make scan-sbom TARGET=./your-ai-project
```

## The 6-Layer Model

| Layer | What It Scans | Tools |
|-------|---------------|-------|
| **1. Code SAST** | Source code vulnerabilities | Semgrep, CodeQL |
| **1b. Agent Architecture** | Agent workflow security | Agentic Radar, MCP-Scan |
| **2. Model Artifacts** | Trojaned/malicious models | ModelScan, Picklescan, ModelAudit, Veritensor, BAIT, Fickling |
| **3. Prompt Testing** | LLM behavior regression | Promptfoo |
| **4. Dependencies** | CVEs, malware, binaries | OSV-Scanner, SafeDep vet, CVE Binary Tool |
| **5. SBOM & Governance** | Inventory and compliance | AIsbom, Syft, CycloneDX, Dependency-Track |

## Three Scan Tiers

| Tier | When | Time | Coverage |
|------|------|------|----------|
| **PR Scan** | Every pull request | ~2 min | Semgrep + ModelScan + Picklescan + OSV-Scanner |
| **Full Scan** | Push to main | ~10 min | All 6 layers |
| **Nightly Deep** | Cron (2 AM) | ~30-60 min | CodeQL + BAIT + scanner validation |

## Adoption Path

1. **Week 1** — `make install-minimal` (ModelScan, AIsbom, Syft, OSV-Scanner, Dependency-Track)
2. **Weeks 2-3** — Add ModelAudit, Picklescan, SafeDep vet, Semgrep
3. **Weeks 3-4** — Add Promptfoo, Agentic Radar, Veritensor, CodeQL
4. **Month 2+** — Add BAIT, Pickle-Fuzzer, Dependency-Track monitoring

## Repository Structure

```
ai-sentinel/
├── .github/workflows/    # CI/CD: pr-scan, full-scan, nightly-deep
├── scripts/              # Shell scripts orchestrating each tool
├── configs/              # All tool configs in one place
├── tests/fixtures/       # Known-good and known-bad samples
├── docs/                 # Architecture, tool evaluation, contribution guide
├── Makefile              # Single entry point (make help)
├── pyproject.toml        # Python dependencies
└── README.md             # This file
```

## Configuration

All tool configs live in `configs/`:

- `semgrep.yml` — Custom AI/ML-specific Semgrep rules
- `promptfoo.yml` — OWASP LLM Top 10 test suite
- `veritensor.yml` — Severity thresholds, license firewall, pickle allowlists
- `vet-policy.yml` — CEL expression policies for SafeDep vet
- `dependency-track.env.example` — Dependency-Track connection template

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — 6-layer model, data flow, threat model
- [Tool Evaluation](docs/TOOL-EVALUATION.md) — Strengths and limitations of every tool
- [Adding Tools](docs/ADDING-TOOLS.md) — How to add a new scanner (< 1 hour)

## License

Apache-2.0
