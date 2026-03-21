# AI Sentinel — Architecture

## Overview

AI Sentinel is an orchestration layer that chains 16+ AI/ML security tools into a single pipeline. It doesn't replace any tool — it makes them work together with one command, one config surface, and one unified report.

## The 6-Layer Model

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Code SAST              Semgrep, CodeQL            │
├─────────────────────────────────────────────────────────────┤
│  Layer 1b: Agent Architecture    Agentic Radar, MCP-Scan    │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Model Artifacts        ModelScan, Picklescan,     │
│                                  ModelAudit, Veritensor,    │
│                                  BAIT, Fickling             │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Prompt Testing         Promptfoo                  │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Dependencies           OSV-Scanner, SafeDep vet,  │
│                                  CVE Binary Tool            │
├─────────────────────────────────────────────────────────────┤
│  Layer 5: SBOM & Governance      AIsbom, Syft, CycloneDX,  │
│                                  Dependency-Track           │
└─────────────────────────────────────────────────────────────┘
```

Each layer is independent — they can run in parallel. Missing tools are skipped gracefully.

## Three Scan Tiers

| Tier | Trigger | Time | What Runs |
|------|---------|------|-----------|
| **PR Scan** | Every pull request | ~2 min | Semgrep + ModelScan + Picklescan + OSV-Scanner |
| **Full Scan** | Push to main | ~10 min | All 6 layers in parallel |
| **Nightly Deep** | Cron (2 AM UTC) | ~30-60 min | CodeQL + BAIT + Pickle-Fuzzer validation |

### Why three tiers?

Speed-vs-depth tradeoff. Developers won't tolerate 30-minute scans on every PR, but 2-minute scans miss deep vulnerabilities. Tiered scanning solves this.

## Data Flow

```
make scan TARGET=./project
    │
    ├── _setup: Create sentinel-results/<timestamp>/
    │
    ├── scan-code   → code/semgrep.json, code/semgrep.sarif, code/codeql.sarif
    ├── scan-agents → agents/agentic-radar.txt, agents/mcp-scan.txt
    ├── scan-models → models/modelscan.json, models/picklescan.txt, ...
    ├── scan-prompts→ prompts/promptfoo-results.json
    ├── scan-deps   → deps/osv-scanner.json, deps/vet.json, deps/cve-bin-tool.json
    ├── scan-sbom   → sbom/aisbom-models.json, sbom/syft-env.json, sbom/merged-sbom.json
    │
    └── report      → REPORT.md (unified summary)
```

Every tool writes to a dedicated file in the timestamped results directory. Missing files are reported as "not run," not errors.

## Output Formats

| Format | Purpose | Tools |
|--------|---------|-------|
| **JSON** | Programmatic consumption, report aggregation | Most tools |
| **SARIF** | GitHub Security tab integration | Semgrep, ModelAudit, CodeQL, SafeDep vet |
| **CycloneDX** | SBOM standard, Dependency-Track | AIsbom, Syft, CycloneDX CLI |
| **Markdown** | Human-readable unified report | report.sh |

## Threat Model

### What each layer catches

- **Code SAST**: Unsafe deserialization, hardcoded keys, prompt injection patterns, command injection
- **Agent Architecture**: Tool permission gaps, MCP misconfigurations, workflow vulnerabilities
- **Model Artifacts**: Trojaned models, malicious pickle payloads, embedded backdoors, license violations
- **Prompt Testing**: Jailbreaks, prompt injection, PII leakage, harmful content generation
- **Dependencies**: Known CVEs, malicious packages, vulnerable binaries, typosquatting
- **SBOM**: Complete inventory for audit, compliance, and ongoing monitoring

### What it does NOT catch

- **Dynamic behavioral testing** (live LLM red-teaming) → Use Garak, PyRIT, DeepTeam
- **Runtime monitoring** (production traffic) → Use Vigil-LLM, NeMo Guardrails
- **Adversarial robustness** (CV/audio perturbations) → Use IBM ART
- **Infrastructure-as-Code** (Terraform, K8s misconfig) → Use Checkov, tfsec

## Pipeline Security

- No secrets in configs — API keys go in `.env` files (gitignored)
- Scan results are artifacts, not commits — `sentinel-results/` is gitignored
- SafeDep vet telemetry disabled by default (`VET_DISABLE_TELEMETRY=true`)
- Pickle-Fuzzer samples contain benign PoC payloads only
