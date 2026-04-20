#!/usr/bin/env python3
"""
AI Sentinel — Unified Full-Stack Security Scanner
Runs all 16 tools across 6 layers, collects findings, and generates reports.

Usage:
    python scripts/sentinel-scan.py --target .
    python scripts/sentinel-scan.py --target . --prioritize
    python scripts/sentinel-scan.py --target . --pdf -o report.pdf
"""

import argparse, hashlib, json, os, shutil, subprocess, sys, glob
from datetime import datetime, timezone

# ── Helpers ──────────────────────────────────────────────────────────

def log(layer, msg):
    print(f"  [{layer}] {msg}")

def tool_exists(name):
    return shutil.which(name) is not None

def run(cmd, args, timeout=180):
    try:
        r = subprocess.run([cmd] + args, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return -1, "", f"{cmd} not found"
    except subprocess.TimeoutExpired:
        return -2, "", "timeout"

def extract_json(text):
    idx = text.find("{")
    if idx == -1: return None
    try: return json.loads(text[idx:])
    except json.JSONDecodeError: return None

def find_models(target):
    exts = ["*.pt","*.pth","*.pkl","*.pickle","*.h5","*.hdf5","*.onnx",
            "*.safetensors","*.gguf","*.joblib","*.npy","*.bin","*.tflite"]
    files = []
    for ext in exts:
        files.extend(glob.glob(os.path.join(target, "**", ext), recursive=True))
    return files

def hsh(d):
    return hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()[:12]

# ── Scanner result container ─────────────────────────────────────────

def make_result(scanner, installed, findings=None, detail=""):
    return {"scanner": scanner, "installed": installed,
            "findings": findings or [], "detail": detail,
            "count": len(findings) if findings else 0}

# ── Layer 1: Code SAST ───────────────────────────────────────────────

def scan_semgrep(target, out_dir, cfg_dir):
    log("L1", "Semgrep — Code SAST")
    if not tool_exists("semgrep"):
        return make_result("Semgrep", False)
    out_json = os.path.join(out_dir, "code", "semgrep.json")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    args = ["scan", "--config", "p/security-audit", "--config", "p/owasp-top-ten",
            f"--json-output={out_json}", "--quiet", target]
    custom = os.path.join(cfg_dir, "semgrep.yml")
    if os.path.isfile(custom):
        args.insert(4, "--config")
        args.insert(5, custom)
    run("semgrep", args, timeout=300)
    findings = []
    if os.path.isfile(out_json):
        try:
            data = json.load(open(out_json, errors="replace"))
            for r in data.get("results", []):
                e = r.get("extra", {})
                findings.append({
                    "scanner": "Semgrep", "category": "Code SAST",
                    "scanner_severity": e.get("severity", "INFO"),
                    "title": r.get("check_id", ""),
                    "description": e.get("message", ""),
                    "file": r.get("path", ""),
                    "line": r.get("start", {}).get("line", 0),
                    "_hash": hsh({"t": r.get("check_id"), "p": r.get("path")}),
                })
        except Exception: pass
    log("L1", f"  Semgrep: {len(findings)} finding(s)")
    return make_result("Semgrep", True, findings)

def scan_codeql(target, out_dir):
    log("L1", "CodeQL — Deep semantic analysis")
    if not tool_exists("codeql"):
        return make_result("CodeQL", False)
    db = os.path.join(out_dir, "code", "codeql-db")
    sarif = os.path.join(out_dir, "code", "codeql.sarif")
    os.makedirs(os.path.dirname(sarif), exist_ok=True)
    run("codeql", ["database", "create", db, "--language=python",
                    f"--source-root={target}", "--overwrite"], 300)
    findings = []
    if os.path.isdir(db):
        run("codeql", ["database", "analyze", db, "--format=sarifv2.1.0",
                        f"--output={sarif}",
                        "codeql/python-queries:codeql-suites/python-security-extended.qls"], 300)
    if os.path.isfile(sarif):
        try:
            data = json.load(open(sarif, errors="replace"))
            for rn in data.get("runs", []):
                for r in rn.get("results", []):
                    findings.append({
                        "scanner": "CodeQL", "category": "Code SAST",
                        "scanner_severity": "HIGH",
                        "title": r.get("ruleId", ""),
                        "description": r.get("message", {}).get("text", ""),
                        "_hash": hsh({"t": r.get("ruleId"), "m": r.get("message",{}).get("text","")}),
                    })
        except Exception: pass
    log("L1", f"  CodeQL: {len(findings)} finding(s)")
    return make_result("CodeQL", True, findings)

# ── Layer 1b: Agent Architecture ─────────────────────────────────────

def scan_agentic_radar(target, out_dir):
    log("L1b", "Agentic Radar — Agent architecture")
    if not tool_exists("agentic-radar"):
        return make_result("Agentic Radar", False)
    out = os.path.join(out_dir, "agents", "agentic-radar.txt")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    rc, stdout, stderr = run("agentic-radar", ["scan", target])
    combined = stdout + stderr
    with open(out, "w", errors="replace") as f: f.write(combined)
    findings = []
    for line in combined.split("\n"):
        if any(k in line.lower() for k in ["warning","risk","vuln","issue","finding"]):
            findings.append({"scanner": "Agentic Radar", "category": "Agent Architecture",
                             "scanner_severity": "MEDIUM", "title": line.strip()[:100],
                             "description": line.strip(),
                             "_hash": hsh({"t": "ar", "l": line.strip()[:60]})})
    log("L1b", f"  Agentic Radar: {len(findings)} finding(s)")
    return make_result("Agentic Radar", True, findings)

def scan_mcp(target, out_dir):
    log("L1b", "MCP-Scan — MCP protocol security")
    if not tool_exists("mcp-scan"):
        return make_result("MCP-Scan", False)
    out = os.path.join(out_dir, "agents", "mcp-scan.txt")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    rc, stdout, stderr = run("mcp-scan", [target])
    combined = stdout + stderr
    with open(out, "w", errors="replace") as f: f.write(combined)
    findings = []
    for line in combined.split("\n"):
        if any(k in line.lower() for k in ["warning","risk","vuln","unsafe","finding"]):
            findings.append({"scanner": "MCP-Scan", "category": "Agent Architecture",
                             "scanner_severity": "MEDIUM", "title": line.strip()[:100],
                             "description": line.strip(),
                             "_hash": hsh({"t": "mcp", "l": line.strip()[:60]})})
    log("L1b", f"  MCP-Scan: {len(findings)} finding(s)")
    return make_result("MCP-Scan", True, findings)

# ── Layer 2: Model Artifact Scanners ─────────────────────────────────

def _scan_model_tool(name, cmd, args_fn, parse_fn, target, out_dir):
    if not tool_exists(cmd):
        return make_result(name, False)
    model_files = find_models(target)
    if not model_files:
        log("L2", f"  {name}: no model files found")
        return make_result(name, True)
    findings = []
    for fpath in model_files:
        rc, out, err = run(cmd, args_fn(fpath))
        findings.extend(parse_fn(fpath, rc, out + err))
    log("L2", f"  {name}: {len(findings)} finding(s) across {len(model_files)} files")
    return make_result(name, True, findings)

def scan_modelscan(target, out_dir):
    log("L2", "ModelScan — Baseline model scanning")
    def args(f): return ["-p", f, "-r", "json"]
    def parse(f, rc, txt):
        hits = []
        data = extract_json(txt)
        if data and data.get("summary", {}).get("total_issues", 0) > 0:
            for iss in data.get("issues", []):
                hits.append({"scanner": "ModelScan", "category": "Model Artifact",
                             "scanner_severity": iss.get("severity", "HIGH"),
                             "title": iss.get("description", "Model issue"),
                             "description": iss.get("description", ""), "file": f,
                             "_hash": hsh({"t": "ms", "f": f, "d": iss.get("description","")})})
        return hits
    return _scan_model_tool("ModelScan", "modelscan", args, parse, target, out_dir)

def scan_picklescan(target, out_dir):
    log("L2", "Picklescan — Pickle-specific scanning")
    def args(f): return ["--path", f]
    def parse(f, rc, txt):
        hits = []
        if "dangerous import" in txt.lower() and "FOUND" in txt:
            for line in txt.split("\n"):
                if "dangerous import" in line.lower():
                    hits.append({"scanner": "Picklescan", "category": "Model Artifact — Pickle",
                                 "scanner_severity": "CRITICAL", "title": "Dangerous Import in Pickle",
                                 "description": line.strip(), "file": f,
                                 "_hash": hsh({"t": "ps", "f": f, "l": line.strip()[:50]})})
        return hits
    return _scan_model_tool("Picklescan", "picklescan", args, parse, target, out_dir)

def scan_fickling(target, out_dir):
    log("L2", "Fickling — Forensic pickle analysis")
    def args(f): return ["--check-safety", "-p", f]
    def parse(f, rc, txt):
        hits = []
        if any(k in txt.lower() for k in ["unsafe","malicious","dangerous","overtly"]):
            for line in txt.split("\n"):
                if any(k in line.lower() for k in ["unsafe","malicious","dangerous","overtly","call"]):
                    hits.append({"scanner": "Fickling", "category": "Model Artifact — Pickle",
                                 "scanner_severity": "CRITICAL",
                                 "title": f"Fickling: {line.strip()[:80]}",
                                 "description": line.strip(), "file": f,
                                 "_hash": hsh({"t": "fk", "f": f, "l": line.strip()[:50]})})
        return hits
    return _scan_model_tool("Fickling", "fickling", args, parse, target, out_dir)

def scan_modelaudit(target, out_dir):
    log("L2", "ModelAudit — Wide format coverage")
    def args(f): return [f, "--format", "json"]
    def parse(f, rc, txt):
        hits = []
        if rc != -1 and any(k in txt.lower() for k in ['"severity"','"issues"','"findings"']):
            hits.append({"scanner": "ModelAudit", "category": "Model Artifact",
                         "scanner_severity": "HIGH", "title": f"ModelAudit finding in {os.path.basename(f)}",
                         "description": txt.strip()[:300], "file": f,
                         "_hash": hsh({"t": "ma", "f": f})})
        return hits
    return _scan_model_tool("ModelAudit", "modelaudit", args, parse, target, out_dir)

def scan_veritensor(target, out_dir):
    log("L2", "Veritensor — Supply chain + datasets")
    def args(f): return ["scan", f]
    def parse(f, rc, txt):
        hits = []
        if rc != -1 and any(k in txt.lower() for k in ["unsafe","malicious","suspicious","warning"]):
            hits.append({"scanner": "Veritensor", "category": "Model Artifact — Supply Chain",
                         "scanner_severity": "HIGH", "title": f"Veritensor finding in {os.path.basename(f)}",
                         "description": txt.strip()[:300], "file": f,
                         "_hash": hsh({"t": "vt", "f": f})})
        return hits
    return _scan_model_tool("Veritensor", "veritensor", args, parse, target, out_dir)

# ── Layer 3: Prompt Testing ──────────────────────────────────────────

def scan_promptfoo(target, out_dir, cfg_dir):
    log("L3", "Promptfoo — Prompt regression testing")
    if not tool_exists("promptfoo"):
        return make_result("Promptfoo", False)
    config = None
    for c in [os.path.join(target, "promptfooconfig.yaml"),
              os.path.join(target, "promptfooconfig.yml"),
              os.path.join(cfg_dir, "promptfoo.yml")]:
        if os.path.isfile(c):
            config = c; break
    if not config:
        log("L3", "  No promptfoo config found")
        return make_result("Promptfoo", True, detail="No config found")
    out_json = os.path.join(out_dir, "prompts", "promptfoo-results.json")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    run("promptfoo", ["eval", "--config", config, "--output", out_json, "--no-progress-bar"], 300)
    findings = []
    if os.path.isfile(out_json):
        try:
            data = json.load(open(out_json, errors="replace"))
            for r in data.get("results", []):
                if not r.get("success", True):
                    findings.append({"scanner": "Promptfoo", "category": "Prompt Regression",
                                     "scanner_severity": "HIGH", "title": f"Failed: {r.get('description','')}",
                                     "description": str(r.get("error", r.get("output","")))[:300],
                                     "_hash": hsh({"t": "pf", "d": r.get("description","")})})
        except Exception: pass
    log("L3", f"  Promptfoo: {len(findings)} failure(s)")
    return make_result("Promptfoo", True, findings)

# ── Layer 4: Dependency Scanning ─────────────────────────────────────

def scan_osv(target, out_dir):
    log("L4", "OSV-Scanner — Dependency CVEs")
    if not tool_exists("osv-scanner"):
        return make_result("OSV-Scanner", False)
    out_json = os.path.join(out_dir, "deps", "osv-scanner.json")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    run("osv-scanner", ["scan", "--format", "json", "--output", out_json, target], 300)
    findings = []
    if os.path.isfile(out_json):
        try:
            data = json.load(open(out_json, errors="replace"))
            for res in data.get("results", []):
                for pkg in res.get("packages", []):
                    pi = pkg.get("package", {})
                    for v in pkg.get("vulnerabilities", []):
                        findings.append({"scanner": "OSV-Scanner", "category": "Dependency CVE",
                                         "scanner_severity": "HIGH",
                                         "title": f"{v.get('id','')}: {v.get('summary','')}",
                                         "description": v.get("details", v.get("summary",""))[:300],
                                         "indicators": {"package": pi.get("name",""), "version": pi.get("version","")},
                                         "_hash": hsh({"t":"osv","v":v.get("id","")})})
        except Exception: pass
    log("L4", f"  OSV-Scanner: {len(findings)} vulnerability(ies)")
    return make_result("OSV-Scanner", True, findings)

def scan_vet(target, out_dir, cfg_dir):
    log("L4", "SafeDep vet — Malware + reachability")
    if not tool_exists("vet"):
        return make_result("SafeDep vet", False)
    out_json = os.path.join(out_dir, "deps", "vet.json")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    args = ["scan", "--report-json", out_json, target]
    policy = os.path.join(cfg_dir, "vet-policy.yml")
    if os.path.isfile(policy):
        args = ["scan", "--policy", policy, "--report-json", out_json, target]
    env = os.environ.copy(); env["VET_DISABLE_TELEMETRY"] = "true"
    try:
        subprocess.run(["vet"] + args, capture_output=True, text=True, timeout=300, env=env, errors="replace")
    except Exception: pass
    findings = []
    if os.path.isfile(out_json):
        try:
            data = json.load(open(out_json, errors="replace"))
            for item in data.get("findings", data.get("results", [])):
                if isinstance(item, dict):
                    findings.append({"scanner": "SafeDep vet", "category": "Dependency Policy",
                                     "scanner_severity": item.get("severity", "MEDIUM"),
                                     "title": item.get("title", item.get("rule", "Policy violation")),
                                     "description": item.get("description", "")[:300],
                                     "_hash": hsh({"t":"vet","r":item.get("rule","")})})
        except Exception: pass
    log("L4", f"  SafeDep vet: {len(findings)} finding(s)")
    return make_result("SafeDep vet", True, findings)

def scan_cve_bin(target, out_dir):
    log("L4", "CVE Binary Tool — Binary-level scanning")
    if not tool_exists("cve-bin-tool"):
        return make_result("CVE Binary Tool", False)
    out_json = os.path.join(out_dir, "deps", "cve-bin-tool.json")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    run("cve-bin-tool", ["--format", "json", "--output-file", out_json, target], 300)
    findings = []
    if os.path.isfile(out_json):
        try:
            data = json.load(open(out_json, errors="replace"))
            items = data if isinstance(data, list) else data.get("results", [])
            for item in items:
                if isinstance(item, dict):
                    findings.append({"scanner": "CVE Binary Tool", "category": "Binary CVE",
                                     "scanner_severity": item.get("severity", "MEDIUM"),
                                     "title": item.get("cve_number", item.get("id", "CVE")),
                                     "description": item.get("description", "")[:300],
                                     "_hash": hsh({"t":"cbt","c":item.get("cve_number","")})})
        except Exception: pass
    log("L4", f"  CVE Binary Tool: {len(findings)} finding(s)")
    return make_result("CVE Binary Tool", True, findings)

# ── Layer 5: SBOM Generation ────────────────────────────────────────

def scan_aisbom(target, out_dir):
    log("L5", "AIsbom — Model SBOM")
    if not tool_exists("aisbom"):
        return make_result("AIsbom", False)
    out_json = os.path.join(out_dir, "sbom", "aisbom-models.json")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    rc, out, err = run("aisbom", ["scan", target, "--lint"])
    with open(out_json, "w", errors="replace") as f: f.write(out)
    log("L5", "  AIsbom: SBOM generated")
    return make_result("AIsbom", True, detail="SBOM generated")

def scan_syft(target, out_dir):
    log("L5", "Syft — Environment SBOM")
    if not tool_exists("syft"):
        return make_result("Syft", False)
    out_json = os.path.join(out_dir, "sbom", "syft-env.json")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    run("syft", ["scan", target, "-o", f"cyclonedx-json={out_json}"], 180)
    count = 0
    if os.path.isfile(out_json):
        try:
            count = len(json.load(open(out_json, errors="replace")).get("components", []))
        except Exception: pass
    log("L5", f"  Syft: {count} components catalogued")
    return make_result("Syft", True, detail=f"{count} components")

def scan_cyclonedx_merge(out_dir):
    log("L5", "CycloneDX — SBOM merge")
    has_cli = tool_exists("cyclonedx-cli")
    if not has_cli:
        return make_result("CycloneDX Merge", False)
    inputs = [os.path.join(out_dir, "sbom", n) for n in ["aisbom-models.json", "syft-env.json"]
              if os.path.isfile(os.path.join(out_dir, "sbom", n))]
    if not inputs:
        return make_result("CycloneDX Merge", True, detail="No SBOMs to merge")
    merged = os.path.join(out_dir, "sbom", "merged-sbom.json")
    cli_args = []
    for f in inputs: cli_args.extend(["--input-files", f])
    run("cyclonedx-cli", ["merge"] + cli_args + ["--output-file", merged, "--output-format", "json"], 60)
    log("L5", f"  CycloneDX: merged {len(inputs)} SBOMs")
    return make_result("CycloneDX Merge", True, detail=f"Merged {len(inputs)} SBOMs")


# ═══════════════════════════════════════════════════════════════════════
# Orchestrator — runs all 16 tools
# ═══════════════════════════════════════════════════════════════════════

def run_full_scan(target, out_dir, cfg_dir):
    """Execute all 6 layers and return combined results."""
    ts = datetime.now(timezone.utc)
    results = {}

    # Layer 1: Code SAST
    print("\n" + "=" * 60)
    print("  LAYER 1: Code SAST")
    print("=" * 60)
    results["semgrep"] = scan_semgrep(target, out_dir, cfg_dir)
    results["codeql"] = scan_codeql(target, out_dir)

    # Layer 1b: Agent Architecture
    print("\n" + "=" * 60)
    print("  LAYER 1b: Agent Architecture")
    print("=" * 60)
    results["agentic_radar"] = scan_agentic_radar(target, out_dir)
    results["mcp_scan"] = scan_mcp(target, out_dir)

    # Layer 2: Model Artifacts
    print("\n" + "=" * 60)
    print("  LAYER 2: Model Artifact Scanning")
    print("=" * 60)
    results["modelscan"] = scan_modelscan(target, out_dir)
    results["picklescan"] = scan_picklescan(target, out_dir)
    results["fickling"] = scan_fickling(target, out_dir)
    results["modelaudit"] = scan_modelaudit(target, out_dir)
    results["veritensor"] = scan_veritensor(target, out_dir)

    # Layer 3: Prompt Testing
    print("\n" + "=" * 60)
    print("  LAYER 3: Prompt Regression Testing")
    print("=" * 60)
    results["promptfoo"] = scan_promptfoo(target, out_dir, cfg_dir)

    # Layer 4: Dependencies
    print("\n" + "=" * 60)
    print("  LAYER 4: Dependency Scanning")
    print("=" * 60)
    results["osv_scanner"] = scan_osv(target, out_dir)
    results["safedep_vet"] = scan_vet(target, out_dir, cfg_dir)
    results["cve_bin_tool"] = scan_cve_bin(target, out_dir)

    # Layer 5: SBOM
    print("\n" + "=" * 60)
    print("  LAYER 5: SBOM Generation")
    print("=" * 60)
    results["aisbom"] = scan_aisbom(target, out_dir)
    results["syft"] = scan_syft(target, out_dir)
    results["cyclonedx_merge"] = scan_cyclonedx_merge(out_dir)

    elapsed = (datetime.now(timezone.utc) - ts).total_seconds()
    return results, elapsed


# ═══════════════════════════════════════════════════════════════════════
# Report Generator — Markdown
# ═══════════════════════════════════════════════════════════════════════

def generate_markdown_report(results, out_dir, target, elapsed):
    """Build a unified Markdown report from all scanner results."""
    report = os.path.join(out_dir, "REPORT.md")
    installed = [r["scanner"] for r in results.values() if r["installed"]]
    missing = [r["scanner"] for r in results.values() if not r["installed"]]
    all_findings = []
    for r in results.values():
        all_findings.extend(r.get("findings", []))

    sev_counts = {}
    for f in all_findings:
        s = f.get("scanner_severity", "UNKNOWN")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    lines = [
        "# AI Sentinel — Full Scan Report\n",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Target:** `{os.path.abspath(target)}`  ",
        f"**Duration:** {elapsed:.1f}s  ",
        f"**Results:** `{os.path.abspath(out_dir)}`\n",
        f"## Tool Inventory\n",
        f"**Installed ({len(installed)}):** {', '.join(sorted(installed)) or 'None'}  ",
    ]
    if missing:
        lines.append(f"**Not installed ({len(missing)}):** {', '.join(sorted(missing))}\n")

    lines.append(f"\n## Summary\n")
    lines.append(f"**Total findings:** {len(all_findings)}  ")
    if sev_counts:
        parts = [f"{k}: {v}" for k, v in sorted(sev_counts.items(), key=lambda x: -x[1])]
        lines.append(f"**By severity:** {', '.join(parts)}\n")

    lines.append("\n| Scanner | Status | Findings |")
    lines.append("|---------|--------|----------|")
    for key, r in results.items():
        status = "✅ Installed" if r["installed"] else "❌ Not installed"
        count = r["count"] if r["installed"] else "—"
        if r.get("detail") and r["installed"]:
            count = r["detail"]
        lines.append(f"| {r['scanner']} | {status} | {count} |")

    layers = [
        ("Layer 1: Code SAST", ["semgrep", "codeql"]),
        ("Layer 1b: Agent Architecture", ["agentic_radar", "mcp_scan"]),
        ("Layer 2: Model Artifacts", ["modelscan", "picklescan", "fickling", "modelaudit", "veritensor"]),
        ("Layer 3: Prompt Testing", ["promptfoo"]),
        ("Layer 4: Dependencies", ["osv_scanner", "safedep_vet", "cve_bin_tool"]),
        ("Layer 5: SBOM", ["aisbom", "syft", "cyclonedx_merge"]),
    ]
    for layer_name, keys in layers:
        layer_findings = []
        for k in keys:
            if k in results:
                layer_findings.extend(results[k].get("findings", []))
        if layer_findings:
            lines.append(f"\n## {layer_name} — {len(layer_findings)} Finding(s)\n")
            for i, f in enumerate(layer_findings[:25], 1):
                sev = f.get("scanner_severity", "INFO")
                title = f.get("title", "N/A")[:80]
                loc = f.get("file", "")
                if f.get("line"): loc += f":{f['line']}"
                lines.append(f"{i}. **[{sev}]** {title}")
                if loc: lines.append(f"   - Location: `{loc}`")
            if len(layer_findings) > 25:
                lines.append(f"\n*... and {len(layer_findings)-25} more findings*\n")

    lines.append("\n---")
    lines.append("*Report generated by AI Sentinel — sentinel-scan.py*\n")

    with open(report, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n  Report → {os.path.abspath(report)}")
    return report


# ═══════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="AI Sentinel — Unified 6-Layer Security Scanner")
    parser.add_argument("--target", default=".", help="Project directory to scan")
    parser.add_argument("--output-dir", "-o", default=None, help="Results directory")
    parser.add_argument("--configs-dir", default=None, help="Configs directory")
    parser.add_argument("--prioritize", action="store_true",
                        help="Use OpenAI to AI-prioritize findings")
    parser.add_argument("--model", default="gpt-4o", help="OpenAI model for prioritization")
    parser.add_argument("--pdf", action="store_true", help="Also generate PDF report")
    parser.add_argument("--pdf-output", default="sentinel-report.pdf", help="PDF output path")
    
    # Azure Integration
    parser.add_argument("--azure-storage-url", default=None, help="Azure Storage Account URL to fetch models from")
    parser.add_argument("--azure-container", default=None, help="Azure Blob Container containing models")
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    cfg_dir = args.configs_dir or os.path.join(project_root, "configs")
    out_dir = args.output_dir or os.path.join(
        project_root, "sentinel-results", datetime.now().strftime("%Y%m%d-%H%M%S"))

    for sub in ["code", "agents", "models", "prompts", "deps", "sbom"]:
        os.makedirs(os.path.join(out_dir, sub), exist_ok=True)

    # ── Fetch from Azure if requested ──
    if args.azure_storage_url and args.azure_container:
        try:
            sys.path.insert(0, script_dir)
            from azure_fetch import fetch_azure_models
            cache_dir = os.path.join(out_dir, "azure_models_cache")
            success = fetch_azure_models(args.azure_storage_url, args.azure_container, cache_dir)
            if success:
                # Override target to scan the downloaded models
                target = cache_dir
        except Exception as e:
            print(f"  [ERROR] Azure integration failed: {e}")

    print("=" * 60)
    print("  AI Sentinel — Full 6-Layer Security Scan")
    print("=" * 60)
    print(f"  Target:   {target}")
    print(f"  Results:  {out_dir}")
    print(f"  Configs:  {cfg_dir}")

    # Run all 16 tools
    results, elapsed = run_full_scan(target, out_dir, cfg_dir)

    # Collect all findings
    all_findings = []
    for r in results.values():
        all_findings.extend(r.get("findings", []))

    # Save raw JSON
    raw_json = os.path.join(out_dir, "all-findings.json")
    with open(raw_json, "w") as f:
        json.dump({"findings": all_findings, "tool_results": {
            k: {**v, "findings": []} for k, v in results.items()
        }}, f, indent=2, default=str)

    # Generate Markdown report
    generate_markdown_report(results, out_dir, target, elapsed)

    # Optional: AI prioritization
    if args.prioritize and all_findings:
        print("\n" + "=" * 60)
        print("  AI PRIORITIZATION (OpenAI)")
        print("=" * 60)
        try:
            sys.path.insert(0, script_dir)
            from prioritize_vulnerabilities import prioritize_with_openai
            prioritized = prioritize_with_openai(all_findings, model=args.model)
            pri_path = os.path.join(out_dir, "prioritized-findings.json")
            with open(pri_path, "w") as f:
                json.dump(prioritized, f, indent=2, default=str)
            print(f"  Prioritized → {os.path.abspath(pri_path)}")
        except Exception as e:
            print(f"  Prioritization failed: {e}")

    # Optional: PDF report
    if args.pdf:
        print("\n" + "=" * 60)
        print("  GENERATING PDF REPORT")
        print("=" * 60)
        try:
            sys.path.insert(0, script_dir)
            import generate_pdf_report as pdf_mod
        except ImportError:
            try:
                # Python doesn't like hyphens in module names, let's use importlib
                import importlib.util
                spec = importlib.util.spec_from_file_location("pdf_mod", os.path.join(script_dir, "generate-pdf-report.py"))
                pdf_mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(pdf_mod)
            except Exception as e:
                print(f"  PDF generation failed to load generator module: {e}")
                pdf_mod = None

        if pdf_mod:
            try:
                pdf = pdf_mod.SentinelPDF(orientation="P", unit="mm", format="A4")
                pdf.alias_nb_pages()
                pdf.set_auto_page_break(auto=True, margin=20)
                pdf.add_page()

                # Title
                pdf.set_font("Helvetica", "B", 24)
                pdf.set_text_color(*pdf_mod.COLOR_HEADER)
                pdf.ln(10)
                pdf.cell(0, 15, "AI Sentinel", new_x="LMARGIN", new_y="NEXT", align="C")
                pdf.set_font("Helvetica", "", 14)
                pdf.set_text_color(*pdf_mod.COLOR_MUTED)
                pdf.cell(0, 10, "Unified Security Scan & AI Prioritization Report", new_x="LMARGIN", new_y="NEXT", align="C")
                pdf.ln(5)

                pdf.set_font("Helvetica", "", 10)
                pdf.set_text_color(*pdf_mod.COLOR_TEXT)
                pdf.cell(0, 7, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", new_x="LMARGIN", new_y="NEXT", align="C")
                pdf.cell(0, 7, f"Target: {os.path.abspath(target)}", new_x="LMARGIN", new_y="NEXT", align="C")
                pdf.cell(0, 7, f"Duration: {elapsed:.1f} seconds", new_x="LMARGIN", new_y="NEXT", align="C")
                pdf.ln(10)

                # Tool Status Summary
                pdf.section_title("Tool Execution Summary")
                pdf.table_header(["Scanner", "Status", "Findings/Details"], [50, 40, 100])
                fill = False
                for key, r in results.items():
                    status_text = "INSTALLED" if r["installed"] else "MISSING"
                    pdf.set_font("Helvetica", "", 9)
                    if fill: pdf.set_fill_color(*pdf_mod.COLOR_BG_LIGHT)
                    pdf.cell(50, 7, pdf_mod.sanitize(r["scanner"]), border=1, fill=fill, align="L")
                    
                    if r["installed"]:
                        pdf.set_text_color(*pdf_mod.COLOR_PASS)
                    else:
                        pdf.set_text_color(*pdf_mod.COLOR_SKIP)
                    pdf.cell(40, 7, status_text, border=1, fill=fill, align="C")
                    pdf.set_text_color(*pdf_mod.COLOR_TEXT)
                    
                    count_txt = str(r["count"]) if r["installed"] else "--"
                    if r.get("detail") and r["installed"]:
                        count_txt = str(r["detail"])
                    pdf.cell(100, 7, pdf_mod.sanitize(count_txt), border=1, fill=fill, align="L")
                    pdf.ln()
                    fill = not fill
                pdf.ln(5)

                # Prioritized Findings
                prioritized_data = locals().get("prioritized")
                if prioritized_data and isinstance(prioritized_data, dict) and "prioritized_vulnerabilities" in prioritized_data:
                    vulns = prioritized_data["prioritized_vulnerabilities"]
                    pdf.section_title("Top Prioritized Vulnerabilities (AI Analyzed)")
                    pdf.body_text(f"OpenAI analysis prioritized {len(vulns)} vulnerabilities based on exploitability, blast radius, and CVSS impact.")
                    pdf.ln(3)

                    for i, v in enumerate(vulns[:25]): # Show top 25
                        pdf.set_font("Helvetica", "B", 10)
                        pdf.set_fill_color(*pdf_mod.COLOR_HEADER)
                        pdf.set_text_color(255, 255, 255)
                        title = pdf_mod.sanitize(v.get('title', 'Unknown Issue'))[:80]
                        pdf.cell(0, 8, f" #{v.get('priority_rank', i+1)}: {title}", fill=True, new_x="LMARGIN", new_y="NEXT")
                        
                        pdf.set_text_color(*pdf_mod.COLOR_TEXT)
                        pdf.set_font("Helvetica", "B", 9)
                        sev = str(v.get("ai_severity", v.get("scanner_severity", "UNKNOWN"))).upper()
                        cvss = v.get("cvss_estimate", "N/A")
                        scanner = v.get("scanner", "Unknown")
                        pdf.cell(0, 6, f" Severity: {sev}  |  CVSS: {cvss}  |  Scanner: {scanner}", new_x="LMARGIN", new_y="NEXT")
                        
                        pdf.set_font("Helvetica", "", 9)
                        desc = v.get("description", "")
                        if len(desc) > 400: desc = desc[:397] + "..."
                        pdf.multi_cell(0, 5, pdf_mod.sanitize(f"Description: {desc}"))
                        
                        rem = v.get("remediation", "")
                        if rem:
                            pdf.set_font("Helvetica", "I", 9)
                            pdf.multi_cell(0, 5, pdf_mod.sanitize(f"Remediation: {rem}"))
                        pdf.ln(3)
                else:
                    pdf.section_title("Security Findings")
                    if not all_findings:
                        pdf.body_text("No vulnerabilities detected across any layer. System is clean.")
                    else:
                        for i, f in enumerate(all_findings[:50]):
                            pdf.set_font("Helvetica", "B", 10)
                            pdf.cell(0, 6, f"{i+1}. [{f.get('scanner_severity', 'INFO')}] {pdf_mod.sanitize(f.get('title', ''))}", new_x="LMARGIN", new_y="NEXT")
                            pdf.set_font("Helvetica", "", 9)
                            pdf.cell(5)
                            pdf.cell(0, 5, pdf_mod.sanitize(f"Scanner: {f.get('scanner', '')} | Category: {f.get('category', '')}"), new_x="LMARGIN", new_y="NEXT")
                            pdf.cell(5)
                            desc = f.get('description', '')
                            if len(desc) > 200: desc = desc[:197] + "..."
                            pdf.multi_cell(0, 5, pdf_mod.sanitize(f"Details: {desc}"))
                            pdf.ln(2)

                out_file = os.path.join(out_dir, args.pdf_output)
                pdf.output(out_file)
                print(f"  PDF Report → {os.path.abspath(out_file)}")
            except Exception as e:
                print(f"  Failed to generate PDF: {e}")

    # Print summary
    print("\n" + "=" * 60)
    print("  SCAN COMPLETE")
    print("=" * 60)
    installed = sum(1 for r in results.values() if r["installed"])
    total = len(results)
    print(f"  Tools: {installed}/{total} installed")
    print(f"  Total findings: {len(all_findings)}")
    print(f"  Duration: {elapsed:.1f}s")

    for key, r in results.items():
        status = "✅" if r["installed"] else "❌"
        count = str(r["count"]) if r["installed"] else "—"
        if r.get("detail") and r["installed"]:
            count = r["detail"]
        print(f"  {status} {r['scanner']:20s} {count}")

    print(f"\n  Results → {os.path.abspath(out_dir)}")
    print(f"  Report  → {os.path.abspath(os.path.join(out_dir, 'REPORT.md'))}")
    if all_findings:
        print(f"  JSON    → {os.path.abspath(raw_json)}")
    print()


if __name__ == "__main__":
    main()

