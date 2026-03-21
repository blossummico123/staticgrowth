# AI Sentinel — Tool Evaluation

Strengths, weaknesses, and limitations of every tool in the pipeline.

## Layer 1: Code SAST

### Semgrep
- **Repo**: [semgrep/semgrep](https://github.com/semgrep/semgrep)
- **Strengths**: Fast (~10s), pattern-based rules look like source code, 30+ languages, zero config needed
- **Weaknesses**: Pattern matching only — can't trace data flow across functions. No semantic understanding of multi-file flows
- **Why we use it**: Highest value-to-cost ratio. Catches the most common AI security mistakes (unsafe pickle.load, hardcoded keys) in seconds
- **Output**: JSON, SARIF

### CodeQL
- **Repo**: [github/codeql-action](https://github.com/github/codeql-action)
- **Strengths**: Full semantic analysis, multi-file taint tracking, 400+ CVE discoveries, catches complex injection chains
- **Weaknesses**: Slow (10-30 min), requires database compilation, limited language support vs Semgrep
- **Why we use it**: Catches what Semgrep misses — traces how user input flows through 5 function calls to a SQL query
- **Output**: SARIF

## Layer 1b: Agent Architecture

### Agentic Radar
- **Repo**: [splx-ai/agentic-radar](https://github.com/splx-ai/agentic-radar) (922 stars)
- **Strengths**: Maps agent workflow graphs, identifies tools and permissions, OWASP LLM Top 10 aligned, supports 5 frameworks
- **Weaknesses**: Static analysis only — can't test runtime behavior. Framework detection is heuristic-based
- **Why we use it**: Only tool that understands agent-specific attack surfaces (tool permissions, auth gaps between agents and tools)
- **Output**: HTML reports, workflow diagrams

### MCP-Scan
- **Repo**: [invariantlabs-ai/mcp-scan](https://github.com/invariantlabs-ai/mcp-scan)
- **Strengths**: Detects prompt injection, tool poisoning, cross-origin escalation in MCP configs
- **Weaknesses**: Limited to MCP protocol, newer tool with smaller community
- **Why we use it**: MCP is becoming the standard agent-tool protocol; no other tool scans for MCP-specific vulnerabilities
- **Output**: Text reports

## Layer 2: Model Artifacts

### ModelScan
- **Repo**: [protectai/modelscan](https://github.com/protectai/modelscan) (664 stars)
- **Strengths**: Battle-tested, fast, low false-positive rate, enterprise Guardian product available
- **Weaknesses**: Limited format coverage vs ModelAudit (found 3 issues where ModelAudit found 16 in head-to-head)
- **Why we use it**: Baseline scanner — if ModelScan flags it, it's almost certainly real
- **Output**: Console, JSON

### Picklescan
- **Repo**: [mmaitre314/picklescan](https://github.com/mmaitre314/picklescan) (395 stars)
- **Strengths**: Industry standard (used by Hugging Face), focused pickle analysis, HF model scanning via URL
- **Weaknesses**: Known bypass CVEs in 2025 (extension mismatch, CRC error, subclass obfuscation). Blocklist-based — new bypass techniques evade it
- **Why we use it**: It's what Hugging Face runs — your models were already screened against it. Cross-references ModelScan findings
- **Output**: Text, exit codes

### ModelAudit
- **Repo**: [promptfoo/modelaudit](https://github.com/promptfoo/modelaudit)
- **Strengths**: Widest format coverage (42+), detects embedded secrets, network indicators, archive exploits, SARIF output
- **Weaknesses**: Newer tool, less production deployment history than ModelScan
- **Why we use it**: Catches things the first two miss — especially in TFLite, ONNX, and archive formats
- **Output**: Text, JSON, SARIF

### Veritensor
- **Repo**: [ArseniiBrazhnyk/Veritensor](https://github.com/ArseniiBrazhnyk/Veritensor) (69 stars)
- **Strengths**: Deep AST analysis, scans datasets/notebooks/RAG docs (not just models), license compliance, hash verification against HuggingFace
- **Weaknesses**: Smaller community, less battle-tested
- **Why we use it**: Only tool that catches dataset poisoning, scans RAG documents, and verifies model provenance
- **Output**: SARIF, CycloneDX SBOM, JSON

### BAIT
- **Repo**: [SolidShen/BAIT](https://github.com/SolidShen/BAIT)
- **Strengths**: Behavioral backdoor detection via black-box access (no weights needed), top performer in TrojAI leaderboard
- **Weaknesses**: Requires GPU, slower, research-grade (no formal releases), limited to LLMs
- **Why we use it**: Only tool that catches backdoors wired into weights during training — fundamentally different from file-format scanning
- **Output**: Logs, metrics, reports

### Fickling
- **Repo**: [trailofbits/fickling](https://github.com/trailofbits/fickling) (612 stars)
- **Strengths**: Symbolic execution (safe on malicious files), decompiles pickle to readable Python, 100% catch rate, runtime protection mode
- **Weaknesses**: Heuristic-based, edge cases with non-standard ML imports
- **Why we use it**: Forensic deep-dive — when other scanners flag a pickle, Fickling shows exactly what the payload does
- **Output**: Structured JSON

## Layer 3: Prompt Testing

### Promptfoo
- **Repo**: [promptfoo/promptfoo](https://github.com/promptfoo/promptfoo) (7.2k stars)
- **Strengths**: Regression testing (not exploratory), YAML config, multi-provider comparison, CI/CD integration, SARIF output
- **Weaknesses**: Requires LLM API access (costs money per run), test quality depends on test suite quality
- **Why we use it**: Regression testing fills a different need than red-teaming — ensures known vulnerabilities stay fixed across deploys
- **Output**: HTML, JSON, CSV, YAML, SARIF

## Layer 4: Dependencies

### OSV-Scanner
- **Repo**: [google/osv-scanner](https://github.com/google/osv-scanner)
- **Strengths**: Broadest advisory database (30+ sources), guided remediation, 30+ package managers, offline mode, Google-backed
- **Weaknesses**: Package-manifest level only — doesn't know if you actually call the vulnerable function
- **Why we use it**: Broadest coverage at the package level. Fast, free, reliable
- **Output**: JSON, SARIF, CycloneDX, SPDX

### SafeDep vet
- **Repo**: [safedep/vet](https://github.com/safedep/vet) (932 stars)
- **Strengths**: AI malware detection, reachability analysis, CEL policy expressions, typosquatting detection, OpenSSF Scorecard integration
- **Weaknesses**: Some features require SafeDep Cloud API key
- **Why we use it**: The "smart filter" — tells you whether you actually call the vulnerable function, catching what OSV-Scanner misses
- **Output**: CycloneDX, SPDX, SARIF, JSON

### CVE Binary Tool
- **Repo**: [ossf/cve-bin-tool](https://github.com/ossf/cve-bin-tool)
- **Strengths**: Scans compiled binaries (350+ signatures), catches CUDA/system-level vulns, VEX support, OSSF stewardship
- **Weaknesses**: Limited to known binary signatures, can't detect custom/obfuscated components
- **Why we use it**: Catches vulnerabilities in compiled extensions and system libraries that pip-level tools completely miss
- **Output**: CSV, JSON, HTML, PDF, SARIF, VEX

## Layer 5: SBOM & Governance

### AIsbom
- **Repo**: [Lab700xOrg/aisbom](https://github.com/Lab700xOrg/aisbom)
- **Strengths**: Deep binary introspection of model files, understands pickle bytecode/safetensor structures/GGUF headers, air-gapped binary
- **Weaknesses**: Focused on AI models — doesn't cover general dependencies
- **Why we use it**: Only SBOM tool that looks inside model files. Syft treats models as opaque blobs
- **Output**: CycloneDX, SPDX 2.3

### Syft
- **Repo**: [anchore/syft](https://github.com/anchore/syft) (8.5k stars)
- **Strengths**: Industry standard, 40+ ecosystems, container scanning, multiple output formats, Grype integration
- **Weaknesses**: No model-file awareness — treats .pt files as binary blobs
- **Why we use it**: Covers everything AIsbom doesn't — Python packages, system deps, container layers
- **Output**: CycloneDX, SPDX, syft-json

### CycloneDX CLI
- **Repo**: [CycloneDX/cyclonedx-cli](https://github.com/CycloneDX/cyclonedx-cli) (438 stars)
- **Strengths**: Merge/convert/diff/sign SBOMs, stdin/stdout for pipelines, multi-format support
- **Weaknesses**: Requires .NET 8 SDK or prebuilt binary
- **Why we use it**: Merges AIsbom + Syft outputs into one canonical SBOM document
- **Output**: CycloneDX (XML/JSON/Protobuf), SPDX JSON

### Dependency-Track
- **Repo**: [DependencyTrack/dependency-track](https://github.com/DependencyTrack/dependency-track) (3.6k stars)
- **Strengths**: OWASP project, multi-source vulnerability intel, VEX support, policy enforcement, notifications, enterprise-grade
- **Weaknesses**: Requires server deployment (Docker), adds infrastructure complexity
- **Why we use it**: Ongoing SBOM governance — monitors your inventory continuously, not just at scan time
- **Output**: CycloneDX, VEX, API-driven

## Meta-tools

### Pickle-Fuzzer
- **Repo**: [cisco-ai-defense/pickle-fuzzer](https://github.com/cisco-ai-defense/pickle-fuzzer) (12 stars)
- **Strengths**: Structure-aware fuzzing, ~10k pickles/sec, 100% opcode coverage, multiple mutators
- **Weaknesses**: Rust dependency, generates files that are technically "malicious"
- **Why we use it**: Tests whether your scanners actually catch new bypass techniques. "Testing the tests"
- **Output**: .pkl files

### GitHub Taskflow Agent
- **Repo**: [GitHubSecurityLab/seclab-taskflow-agent](https://github.com/GitHubSecurityLab/seclab-taskflow-agent)
- **Strengths**: AI-assisted triage, ~30 real vulns found, auto-creates GitHub issues, cuts false positive noise
- **Weaknesses**: High API credit consumption, requires manual review, needs GitHub Copilot premium
- **Why we use it**: Automated triage — determines which CodeQL/Semgrep findings are actually exploitable
- **Output**: GitHub issues, reports
