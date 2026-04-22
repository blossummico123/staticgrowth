#!/usr/bin/env python3
"""
AI Sentinel -- PDF Report Generator (Full 6-Layer Pipeline)

Generates a comprehensive PDF report covering all scan layers:
  Layer 1:  Code SAST (Semgrep + CodeQL)
  Layer 1b: Agent Architecture (Agentic Radar + Snyk Agent Scan)
  Layer 2:  Model Artifacts (ModelScan + Picklescan + Fickling + ModelAudit + Veritensor)
  Layer 3:  Prompt Regression Testing (Promptfoo)
  Layer 4:  Dependencies (OSV-Scanner + SafeDep vet + CVE Binary Tool)
  Layer 5:  SBOM (AIsbom + Syft + CycloneDX merge)

Usage:
    python scripts/generate-pdf-report.py --scan-fixtures -o sentinel-report.pdf
    python scripts/generate-pdf-report.py --results-dir sentinel-results/ -o report.pdf
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

# Ensure Unicode output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

try:
    from fpdf import FPDF
except ImportError:
    print("ERROR: fpdf2 is required. Install with: pip install fpdf2")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
COLOR_HEADER = (30, 58, 95)       # dark navy
COLOR_PASS = (34, 139, 34)        # green
COLOR_FAIL = (200, 30, 30)        # red
COLOR_WARN = (200, 140, 0)        # amber
COLOR_SKIP = (130, 130, 130)      # grey
COLOR_BG_LIGHT = (240, 244, 248)  # light blue-grey
COLOR_BG_WHITE = (255, 255, 255)
COLOR_TEXT = (30, 30, 30)
COLOR_MUTED = (100, 100, 100)


def sanitize(text):
    """Replace Unicode chars that core PDF fonts can't render."""
    replacements = {
        "\u2014": "--",   # em-dash
        "\u2013": "-",    # en-dash
        "\u2018": "'",    # left single quote
        "\u2019": "'",    # right single quote
        "\u201c": '"',    # left double quote
        "\u201d": '"',    # right double quote
        "\u2192": "->",   # right arrow
        "\u2022": "*",    # bullet
        "\u2026": "...",  # ellipsis
        "\u00a0": " ",    # non-breaking space
        "\u2713": "[Y]",  # check mark
        "\u2717": "[X]",  # cross mark
        "\u2714": "[Y]",  # heavy check
        "\u2718": "[X]",  # heavy cross
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text.encode("latin-1", errors="replace").decode("latin-1")


class SentinelPDF(FPDF):
    """Custom PDF with header/footer branding."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.report_title = "AI Sentinel Scan Report"
        self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*COLOR_HEADER)
        self.cell(0, 8, self.report_title, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*COLOR_HEADER)
        self.set_line_width(0.5)
        self.line(10, self.get_y(), self.w - 10, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(*COLOR_MUTED)
        self.cell(0, 10, f"AI Sentinel  |  {self.timestamp}  |  Page {self.page_no()}/{{nb}}", align="C")

    def section_title(self, title):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(*COLOR_HEADER)
        self.ln(4)
        self.cell(0, 10, sanitize(title), new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*COLOR_HEADER)
        self.set_line_width(0.3)
        self.line(10, self.get_y(), self.w - 10, self.get_y())
        self.ln(3)

    def sub_title(self, title):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*COLOR_TEXT)
        self.ln(2)
        self.cell(0, 8, sanitize(title), new_x="LMARGIN", new_y="NEXT")

    def body_text(self, text):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(*COLOR_TEXT)
        self.multi_cell(0, 6, sanitize(text))
        self.ln(1)

    def status_badge(self, status):
        colors = {
            "PASS": COLOR_PASS, "FAIL": COLOR_FAIL,
            "SKIP": COLOR_SKIP, "WARN": COLOR_WARN,
        }
        c = colors.get(status, COLOR_TEXT)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*c)
        self.cell(16, 6, status)
        self.set_text_color(*COLOR_TEXT)
        self.set_font("Helvetica", "", 10)

    def table_header(self, cols, widths):
        self.set_fill_color(*COLOR_HEADER)
        self.set_text_color(*COLOR_BG_WHITE)
        self.set_font("Helvetica", "B", 9)
        for col, w in zip(cols, widths):
            self.cell(w, 7, col, border=1, fill=True, align="C")
        self.ln()
        self.set_text_color(*COLOR_TEXT)

    def table_row(self, cells, widths, fill=False):
        self.set_font("Helvetica", "", 9)
        if fill:
            self.set_fill_color(*COLOR_BG_LIGHT)
        for cell, w in zip(cells, widths):
            self.cell(w, 6, sanitize(str(cell)), border=1, fill=fill, align="C")
        self.ln()

    def tool_status_row(self, name, installed, findings, detail, fill=False):
        """Write a single-tool status row: Name | Status | Findings | Detail."""
        col_w = [40, 25, 25, 100]
        self.set_font("Helvetica", "", 9)
        if fill:
            self.set_fill_color(*COLOR_BG_LIGHT)
        self.cell(col_w[0], 6, sanitize(name), border=1, fill=fill, align="L")
        # status colour
        if not installed:
            self.set_text_color(*COLOR_SKIP)
            status = "NOT INSTALLED"
        elif findings > 0:
            self.set_text_color(*COLOR_FAIL)
            status = "FINDINGS"
        else:
            self.set_text_color(*COLOR_PASS)
            status = "CLEAN"
        self.set_font("Helvetica", "B", 9)
        self.cell(col_w[1], 6, status, border=1, fill=fill, align="C")
        self.set_text_color(*COLOR_TEXT)
        self.set_font("Helvetica", "", 9)
        self.cell(col_w[2], 6, str(findings) if installed else "--", border=1, fill=fill, align="C")
        self.set_font("Helvetica", "", 8)
        self.cell(col_w[3], 6, sanitize(detail[:80]) if detail else "", border=1, fill=fill, align="L")
        self.ln()


# ---------------------------------------------------------------------------
# Utility: run a command and capture output
# ---------------------------------------------------------------------------

def run_scanner(cmd, args, timeout=120):
    try:
        r = subprocess.run(
            [cmd] + args,
            capture_output=True, text=True, timeout=timeout,
            errors="replace",
        )
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return -1, "", f"{cmd} not found"
    except subprocess.TimeoutExpired:
        return -2, "", "timeout"


def _expand_path():
    """Add known tool directories to PATH so shutil.which can find them."""
    extra_dirs = [
        os.path.join(os.path.expanduser("~"), "bin"),
        os.path.join(os.path.expanduser("~"), "bin", "codeql-install", "codeql"),
    ]
    current = os.environ.get("PATH", "")
    for d in extra_dirs:
        if os.path.isdir(d) and d not in current:
            os.environ["PATH"] = d + os.pathsep + current
            current = os.environ["PATH"]

_expand_path()


def tool_installed(name):
    return shutil.which(name) is not None


def _extract_json(text):
    """Extract the first JSON object from text that may have non-JSON preamble."""
    idx = text.find("{")
    if idx == -1:
        return None
    candidate = text[idx:]
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass
    fixed = re.sub(r'\n(?=\s*[a-zA-Z"\'])', " ", candidate)
    try:
        return json.loads(fixed)
    except json.JSONDecodeError:
        pass
    fixed = candidate.replace("\n", " ")
    try:
        return json.loads(fixed)
    except json.JSONDecodeError:
        pass
    return None


def _count_json_findings(filepath):
    """Count findings in a JSON result file."""
    if not os.path.isfile(filepath):
        return 0
    try:
        with open(filepath, "r", errors="replace") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for key in ("results", "findings", "vulnerabilities", "issues"):
                v = data.get(key)
                if isinstance(v, list):
                    return len(v)
            return 0
        if isinstance(data, list):
            return len(data)
    except (json.JSONDecodeError, OSError):
        pass
    return 0


# ---------------------------------------------------------------------------
# Layer 1: Code SAST scanners
# ---------------------------------------------------------------------------

def run_semgrep(target, results_dir, configs_dir):
    """Run Semgrep SAST scan."""
    info = {"scanner": "Semgrep", "installed": tool_installed("semgrep"),
            "findings": 0, "issues": [], "output_file": None}
    if not info["installed"]:
        return info
    out_json = os.path.join(results_dir, "code", "semgrep.json")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    args = ["scan", "--config", "p/security-audit", "--config", "p/owasp-top-ten",
            f"--json-output={out_json}", "--quiet", target]
    custom = os.path.join(configs_dir, "semgrep.yml")
    if os.path.isfile(custom):
        args = ["scan", "--config", "p/security-audit", "--config", "p/owasp-top-ten",
                "--config", custom, f"--json-output={out_json}", "--quiet", target]
    print("  Running Semgrep...")
    run_scanner("semgrep", args, timeout=300)
    info["output_file"] = out_json
    if os.path.isfile(out_json):
        try:
            with open(out_json, "r", errors="replace") as f:
                data = json.load(f)
            results_list = data.get("results", [])
            info["findings"] = len(results_list)
            for r in results_list[:20]:
                sev = r.get("extra", {}).get("severity", "INFO")
                msg = r.get("extra", {}).get("message", r.get("check_id", ""))
                path = r.get("path", "")
                line = r.get("start", {}).get("line", "?")
                info["issues"].append(f"[{sev}] {path}:{line} - {msg}")
        except (json.JSONDecodeError, OSError):
            pass
    return info


def run_codeql(target, results_dir):
    info = {"scanner": "CodeQL", "installed": tool_installed("codeql"),
            "findings": 0, "issues": [], "output_file": None}
    if not info["installed"]:
        return info
    out_sarif = os.path.join(results_dir, "code", "codeql.sarif")
    db_path = os.path.join(results_dir, "code", "codeql-db")
    os.makedirs(os.path.dirname(out_sarif), exist_ok=True)
    print("  Running CodeQL...")
    run_scanner("codeql", ["database", "create", db_path, "--language=python",
                           f"--source-root={target}", "--overwrite"], timeout=300)
    if os.path.isdir(db_path):
        run_scanner("codeql", ["database", "analyze", db_path,
                                "--format=sarifv2.1.0", f"--output={out_sarif}",
                                "codeql/python-queries:codeql-suites/python-security-extended.qls"],
                    timeout=300)
    info["output_file"] = out_sarif
    if os.path.isfile(out_sarif):
        try:
            with open(out_sarif, "r", errors="replace") as f:
                data = json.load(f)
            for run_obj in data.get("runs", []):
                for r in run_obj.get("results", []):
                    info["findings"] += 1
                    msg = r.get("message", {}).get("text", "")
                    info["issues"].append(msg[:120])
        except (json.JSONDecodeError, OSError):
            pass
    return info


# ---------------------------------------------------------------------------
# Layer 1b: Agent Architecture scanners
# ---------------------------------------------------------------------------

def run_agentic_radar(target, results_dir):
    info = {"scanner": "Agentic Radar", "installed": tool_installed("agentic-radar"),
            "findings": 0, "issues": [], "output_file": None}
    if not info["installed"]:
        return info
    out_file = os.path.join(results_dir, "agents", "agentic-radar.txt")
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    print("  Running Agentic Radar...")
    rc, out, err = run_scanner("agentic-radar", ["scan", target], timeout=120)
    combined = out + err
    with open(out_file, "w", errors="replace") as f:
        f.write(combined)
    info["output_file"] = out_file
    for line in combined.split("\n"):
        line = line.strip()
        if line and any(k in line.lower() for k in ["warning", "risk", "vuln", "issue", "finding"]):
            info["findings"] += 1
            info["issues"].append(line[:120])
    return info


def run_snyk_agent_scan(target, results_dir):
    # Try new binary name first, fall back to legacy mcp-scan
    cmd = "snyk-agent-scan" if tool_installed("snyk-agent-scan") else "mcp-scan"
    info = {"scanner": "Snyk Agent Scan", "installed": tool_installed(cmd),
            "findings": 0, "issues": [], "output_file": None}
    if not info["installed"]:
        return info
    out_file = os.path.join(results_dir, "agents", "snyk-agent-scan.txt")
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    print(f"  Running Snyk Agent Scan ({cmd})...")
    rc, out, err = run_scanner(cmd, [target], timeout=120)
    combined = out + err
    with open(out_file, "w", errors="replace") as f:
        f.write(combined)
    info["output_file"] = out_file
    for line in combined.split("\n"):
        line = line.strip()
        if line and any(k in line.lower() for k in ["warning", "risk", "vuln", "issue", "finding", "unsafe"]):
            info["findings"] += 1
            info["issues"].append(line[:120])
    return info


# ---------------------------------------------------------------------------
# Layer 2: Model Artifact scanners (per-fixture)
# ---------------------------------------------------------------------------

def scan_with_modelscan(filepath):
    rc, out, err = run_scanner("modelscan", ["-p", filepath, "-r", "json"])
    combined = out + err
    flagged = False
    issues = []
    try:
        data = _extract_json(combined)
        if data:
            total = data.get("summary", {}).get("total_issues", 0)
            if total > 0:
                flagged = True
                for iss in data.get("issues", []):
                    issues.append(f"{iss.get('severity', 'UNKNOWN')}: {iss.get('description', 'N/A')}")
            for e in data.get("errors", []):
                if e.get("category") == "PICKLE_GENOPS":
                    flagged = True
                    issues.append(f"PARSE_ERROR: {e.get('description', 'Pickle parsing error')}")
    except (json.JSONDecodeError, AttributeError):
        pass
    return {"scanner": "ModelScan", "flagged": flagged, "issues": issues, "installed": rc != -1}


def scan_with_picklescan(filepath):
    rc, out, err = run_scanner("picklescan", ["--path", filepath])
    combined = out + err
    flagged = False
    issues = []
    if "dangerous import" in combined.lower() and "FOUND" in combined:
        flagged = True
        for line in combined.split("\n"):
            if "dangerous import" in line.lower():
                issues.append(line.strip())
    elif "Infected files:" in combined:
        for line in combined.split("\n"):
            if "Infected files:" in line:
                count = line.split(":")[-1].strip()
                if count.isdigit() and int(count) > 0:
                    flagged = True
                    issues.append(line.strip())
    return {"scanner": "Picklescan", "flagged": flagged, "issues": issues, "installed": rc != -1}


def scan_with_fickling(filepath):
    rc, out, err = run_scanner("fickling", ["--check-safety", "-p", filepath])
    combined = out + err
    flagged = False
    issues = []
    for keyword in ["unsafe", "malicious", "dangerous", "overtly"]:
        if keyword in combined.lower():
            flagged = True
            break
    if flagged:
        for line in combined.split("\n"):
            line = line.strip()
            if line and any(k in line.lower() for k in ["unsafe", "malicious", "dangerous", "overtly", "call"]):
                issues.append(line)
    return {"scanner": "Fickling", "flagged": flagged, "issues": issues, "installed": rc != -1}


def scan_with_modelaudit(filepath):
    rc, out, err = run_scanner("modelaudit", [filepath, "--format", "json"])
    combined = out + err
    flagged = False
    issues = []
    if rc != -1 and combined.strip():
        if any(k in combined.lower() for k in ['"severity"', '"issues"', '"findings"']):
            flagged = True
            for line in combined.split("\n"):
                line = line.strip()
                if line and any(k in line.lower() for k in ["severity", "issue", "finding"]):
                    issues.append(line[:120])
    return {"scanner": "ModelAudit", "flagged": flagged, "issues": issues, "installed": rc != -1}


def scan_with_veritensor(filepath):
    rc, out, err = run_scanner("veritensor", ["scan", filepath])
    combined = out + err
    flagged = False
    issues = []
    if rc != -1 and combined.strip():
        for keyword in ["unsafe", "malicious", "suspicious", "dangerous", "warning"]:
            if keyword in combined.lower():
                flagged = True
                break
        if flagged:
            for line in combined.split("\n"):
                line = line.strip()
                if line:
                    issues.append(line[:120])
    return {"scanner": "Veritensor", "flagged": flagged, "issues": issues, "installed": rc != -1}


FIXTURE_SCANNERS = [
    scan_with_modelscan, scan_with_picklescan, scan_with_fickling,
    scan_with_modelaudit, scan_with_veritensor,
]

PICKLE_ONLY_SCANNERS = {"scan_with_picklescan", "scan_with_fickling"}


# ---------------------------------------------------------------------------
# Layer 3: Prompt Testing
# ---------------------------------------------------------------------------

def run_promptfoo(target, results_dir, configs_dir):
    info = {"scanner": "Promptfoo", "installed": tool_installed("promptfoo"),
            "findings": 0, "issues": [], "output_file": None}
    if not info["installed"]:
        return info
    config = None
    for candidate in [
        os.path.join(target, "promptfooconfig.yaml"),
        os.path.join(target, "promptfooconfig.yml"),
        os.path.join(configs_dir, "promptfoo.yml"),
    ]:
        if os.path.isfile(candidate):
            config = candidate
            break
    if not config:
        info["issues"].append("No promptfoo config found -- skipping")
        return info
    out_json = os.path.join(results_dir, "prompts", "promptfoo-results.json")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    print(f"  Running Promptfoo (config: {os.path.basename(config)})...")
    run_scanner("promptfoo", ["eval", "--config", config, "--output", out_json,
                               "--no-progress-bar"], timeout=300)
    info["output_file"] = out_json
    if os.path.isfile(out_json):
        info["findings"] = _count_json_findings(out_json)
    return info


# ---------------------------------------------------------------------------
# Layer 4: Dependency scanners
# ---------------------------------------------------------------------------

def run_osv_scanner(target, results_dir):
    info = {"scanner": "OSV-Scanner", "installed": tool_installed("osv-scanner"),
            "findings": 0, "issues": [], "output_file": None}
    if not info["installed"]:
        return info
    out_json = os.path.join(results_dir, "deps", "osv-scanner.json")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    print("  Running OSV-Scanner...")
    run_scanner("osv-scanner", ["scan", "--format", "json", "--output", out_json, target],
                timeout=300)
    info["output_file"] = out_json
    if os.path.isfile(out_json):
        try:
            with open(out_json, "r", errors="replace") as f:
                data = json.load(f)
            vulns = data.get("results", data.get("vulnerabilities", []))
            if isinstance(vulns, list):
                info["findings"] = len(vulns)
                for v in vulns[:20]:
                    if isinstance(v, dict):
                        pkg = v.get("package", {}).get("name", "unknown")
                        vid = v.get("vulnerability", {}).get("id",
                              v.get("id", "?"))
                        info["issues"].append(f"{vid}: {pkg}")
        except (json.JSONDecodeError, OSError):
            pass
    return info


def run_safedep_vet(target, results_dir, configs_dir):
    info = {"scanner": "SafeDep vet", "installed": tool_installed("vet"),
            "findings": 0, "issues": [], "output_file": None}
    if not info["installed"]:
        return info
    out_json = os.path.join(results_dir, "deps", "vet.json")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    args = ["scan", "--report-json", out_json, target]
    policy = os.path.join(configs_dir, "vet-policy.yml")
    if os.path.isfile(policy):
        args = ["scan", "--policy", policy, "--report-json", out_json, target]
    env = os.environ.copy()
    env["VET_DISABLE_TELEMETRY"] = "true"
    print("  Running SafeDep vet...")
    try:
        subprocess.run(["vet"] + args, capture_output=True, text=True,
                        timeout=300, env=env, errors="replace")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    info["output_file"] = out_json
    if os.path.isfile(out_json):
        info["findings"] = _count_json_findings(out_json)
    return info


def run_cve_bin_tool(target, results_dir):
    info = {"scanner": "CVE Binary Tool", "installed": tool_installed("cve-bin-tool"),
            "findings": 0, "issues": [], "output_file": None}
    if not info["installed"]:
        return info
    out_json = os.path.join(results_dir, "deps", "cve-bin-tool.json")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    print("  Running CVE Binary Tool...")
    run_scanner("cve-bin-tool", ["--format", "json", "--output-file", out_json, target],
                timeout=300)
    info["output_file"] = out_json
    if os.path.isfile(out_json):
        info["findings"] = _count_json_findings(out_json)
    return info


# ---------------------------------------------------------------------------
# Layer 5: SBOM
# ---------------------------------------------------------------------------

def run_aisbom(target, results_dir):
    info = {"scanner": "AIsbom", "installed": tool_installed("aisbom"),
            "findings": 0, "issues": [], "output_file": None}
    if not info["installed"]:
        return info
    out_json = os.path.join(results_dir, "sbom", "aisbom-models.json")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    print("  Running AIsbom...")
    rc, out, err = run_scanner("aisbom", ["scan", target, "--lint"], timeout=120)
    with open(out_json, "w", errors="replace") as f:
        f.write(out)
    info["output_file"] = out_json
    info["issues"].append("SBOM generated" if out.strip() else "No model components found")
    return info


def run_syft(target, results_dir):
    info = {"scanner": "Syft", "installed": tool_installed("syft"),
            "findings": 0, "issues": [], "output_file": None}
    if not info["installed"]:
        return info
    out_json = os.path.join(results_dir, "sbom", "syft-env.json")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    print("  Running Syft...")
    run_scanner("syft", ["scan", target, "-o", f"cyclonedx-json={out_json}"], timeout=180)
    info["output_file"] = out_json
    if os.path.isfile(out_json):
        try:
            with open(out_json, "r", errors="replace") as f:
                data = json.load(f)
            comps = data.get("components", [])
            info["findings"] = len(comps)
            info["issues"].append(f"SBOM: {len(comps)} components catalogued")
        except (json.JSONDecodeError, OSError):
            pass
    return info


def run_cyclonedx_merge(results_dir):
    """Merge SBOMs using cyclonedx-cli (.NET) or Python-based merge as fallback."""
    has_cli = tool_installed("cyclonedx-cli")
    has_py = tool_installed("cyclonedx-py")
    info = {"scanner": "CycloneDX Merge", "installed": has_cli or has_py,
            "findings": 0, "issues": [], "output_file": None}
    if not info["installed"]:
        return info
    input_files = []
    for name in ["aisbom-models.json", "syft-env.json"]:
        p = os.path.join(results_dir, "sbom", name)
        if os.path.isfile(p):
            input_files.append(p)
    if not input_files:
        info["issues"].append("No SBOMs to merge")
        return info
    merged = os.path.join(results_dir, "sbom", "merged-sbom.json")
    print("  Merging SBOMs...")
    if has_cli:
        cli_args = []
        for f in input_files:
            cli_args.extend(["--input-files", f])
        run_scanner("cyclonedx-cli", ["merge"] + cli_args +
                    ["--output-file", merged, "--output-format", "json"], timeout=60)
    else:
        # Python merge: combine components from all input SBOMs
        all_components = []
        base_bom = {}
        for f in input_files:
            try:
                with open(f, "r", errors="replace") as fh:
                    data = json.load(fh)
                if not base_bom:
                    base_bom = data
                all_components.extend(data.get("components", []))
            except (json.JSONDecodeError, OSError):
                pass
        if base_bom:
            base_bom["components"] = all_components
            with open(merged, "w") as fh:
                json.dump(base_bom, fh, indent=2)
    info["output_file"] = merged
    if os.path.isfile(merged):
        try:
            with open(merged, "r", errors="replace") as fh:
                data = json.load(fh)
            comp_count = len(data.get("components", []))
            info["findings"] = comp_count
            info["issues"].append(f"Merged SBOM: {comp_count} total components")
        except (json.JSONDecodeError, OSError):
            info["issues"].append("Merged SBOM generated")
    return info


# ---------------------------------------------------------------------------
# Fixture scanning (model scanners against ground truth)
# ---------------------------------------------------------------------------

def load_manifest(fixtures_dir):
    manifest_path = os.path.join(fixtures_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        return []
    with open(manifest_path, "r") as f:
        return json.load(f)


def scan_all_fixtures(fixtures_dir, manifest):
    """Scan every fixture file with every installed model scanner."""
    results = {}
    for entry in manifest:
        fname = entry["file"]
        fpath = os.path.join(fixtures_dir, fname)
        if not os.path.exists(fpath):
            continue
        results[fname] = {"meta": entry}
        for scanner_fn in FIXTURE_SCANNERS:
            if scanner_fn.__name__ in PICKLE_ONLY_SCANNERS:
                if fname.endswith((".safetensors", ".onnx", ".h5")):
                    results[fname][scanner_fn.__name__] = {
                        "scanner": scanner_fn.__name__.replace("scan_with_", "").capitalize(),
                        "flagged": None, "issues": [], "installed": True, "skipped": True,
                    }
                    continue
            res = scanner_fn(fpath)
            results[fname][scanner_fn.__name__] = res
            status = "FLAGGED" if res["flagged"] else "clean"
            icon = "!" if res["flagged"] else "."
            print(f"  {icon} {res['scanner']:12s}  {fname:40s}  {status}")
    return results


# ---------------------------------------------------------------------------
# Full pipeline runner
# ---------------------------------------------------------------------------

def run_all_project_scans(target, results_dir, configs_dir):
    """Run all 6 scan layers against the project and return layer results."""
    layers = {}

    # Layer 1: Code SAST
    print("\n" + "=" * 60)
    print("  Layer 1: Code SAST")
    print("=" * 60)
    layers["semgrep"] = run_semgrep(target, results_dir, configs_dir)
    layers["codeql"] = run_codeql(target, results_dir)

    # Layer 1b: Agent Architecture
    print("\n" + "=" * 60)
    print("  Layer 1b: Agent Architecture")
    print("=" * 60)
    layers["agentic_radar"] = run_agentic_radar(target, results_dir)
    layers["snyk_agent_scan"] = run_snyk_agent_scan(target, results_dir)

    # Layer 3: Prompt Testing
    print("\n" + "=" * 60)
    print("  Layer 3: Prompt Regression Testing")
    print("=" * 60)
    layers["promptfoo"] = run_promptfoo(target, results_dir, configs_dir)

    # Layer 4: Dependencies
    print("\n" + "=" * 60)
    print("  Layer 4: Dependency Scanning")
    print("=" * 60)
    layers["osv_scanner"] = run_osv_scanner(target, results_dir)
    layers["safedep_vet"] = run_safedep_vet(target, results_dir, configs_dir)
    layers["cve_bin_tool"] = run_cve_bin_tool(target, results_dir)

    # Layer 5: SBOM
    print("\n" + "=" * 60)
    print("  Layer 5: SBOM Generation")
    print("=" * 60)
    layers["aisbom"] = run_aisbom(target, results_dir)
    layers["syft"] = run_syft(target, results_dir)
    layers["cyclonedx_merge"] = run_cyclonedx_merge(results_dir)

    return layers


# ---------------------------------------------------------------------------
# PDF assembly
# ---------------------------------------------------------------------------

def _pdf_layer_tool_table(pdf, tools):
    """Write a standard tool-status table for a list of layer result dicts."""
    col_w = [40, 25, 25, 100]
    pdf.table_header(["Tool", "Status", "Findings", "Details"], col_w)
    fill = False
    for t in tools:
        detail = "; ".join(t["issues"][:3]) if t["issues"] else ""
        pdf.tool_status_row(t["scanner"], t["installed"], t["findings"], detail, fill=fill)
        fill = not fill
    pdf.ln(3)


def build_pdf(fixture_results, manifest, layer_results, output_path, fixtures_dir, target):
    pdf = SentinelPDF(orientation="P", unit="mm", format="A4")
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # ── Title page ────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(*COLOR_HEADER)
    pdf.ln(10)
    pdf.cell(0, 15, "AI Sentinel", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(*COLOR_MUTED)
    pdf.cell(0, 10, "Full Security Scan Report", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(5)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*COLOR_TEXT)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    pdf.cell(0, 7, f"Generated: {ts}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(0, 7, f"Target: {target}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(0, 7, f"Fixtures: {fixtures_dir}", new_x="LMARGIN", new_y="NEXT", align="C")
    malicious = sum(1 for m in manifest if m.get("malicious"))
    safe = sum(1 for m in manifest if not m.get("malicious"))
    pdf.cell(0, 7, f"Test fixtures: {len(manifest)} ({malicious} malicious, {safe} safe)",
             new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(4)

    # ── Tool inventory ────────────────────────────────────────────
    all_tools = list(layer_results.values())
    installed = [t["scanner"] for t in all_tools if t["installed"]]
    missing = [t["scanner"] for t in all_tools if not t["installed"]]
    # Add fixture scanners
    fixture_scanner_names = set()
    for fname, fdata in fixture_results.items():
        for key, val in fdata.items():
            if key == "meta":
                continue
            sn = val.get("scanner", key)
            if val.get("installed"):
                fixture_scanner_names.add(sn)
                if sn not in installed:
                    installed.append(sn)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 7, f"Tools installed: {', '.join(sorted(set(installed))) or 'None'}",
             new_x="LMARGIN", new_y="NEXT", align="C")
    if missing:
        pdf.set_text_color(*COLOR_WARN)
        pdf.cell(0, 7, f"Not installed: {', '.join(sorted(set(missing)))}",
                 new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.set_text_color(*COLOR_TEXT)
    pdf.ln(6)

    # ── Executive Summary ─────────────────────────────────────────
    pdf.section_title("Executive Summary")

    total_project_findings = sum(t["findings"] for t in all_tools if t["installed"])
    project_tools_run = sum(1 for t in all_tools if t["installed"])
    project_tools_total = len(all_tools)
    pdf.body_text(
        f"Project scans: {project_tools_run}/{project_tools_total} tools ran, "
        f"{total_project_findings} total finding(s) across all layers."
    )

    # Fixture summary
    total_pass = total_fail = total_skip = 0
    scanner_stats = {}
    for fname, fdata in fixture_results.items():
        meta = fdata["meta"]
        is_malicious = meta.get("malicious", False)
        for key, val in fdata.items():
            if key == "meta":
                continue
            sname = val.get("scanner", key)
            if sname not in scanner_stats:
                scanner_stats[sname] = {"pass": 0, "fail": 0, "skip": 0}
            if val.get("skipped") or not val.get("installed"):
                total_skip += 1
                scanner_stats[sname]["skip"] += 1
                continue
            flagged = val.get("flagged", False)
            correct = (is_malicious and flagged) or (not is_malicious and not flagged)
            if correct:
                total_pass += 1
                scanner_stats[sname]["pass"] += 1
            else:
                total_fail += 1
                scanner_stats[sname]["fail"] += 1

    pdf.body_text(
        f"Model scanner validation: {total_pass} correct, "
        f"{total_fail} incorrect, {total_skip} skipped across {len(manifest)} fixtures."
    )
    pdf.ln(2)

    # ── Legend ─────────────────────────────────────────────────────
    pdf.section_title("Legend")
    pdf.body_text("Terminology and colour codes used throughout this report:")
    pdf.ln(1)

    legend_items = [
        ("Project Scan Statuses", [
            ("CLEAN", COLOR_PASS, "Tool ran and found no security issues."),
            ("FINDINGS", COLOR_FAIL, "Tool ran and detected one or more security issues requiring review."),
            ("NOT INSTALLED", COLOR_SKIP, "Tool is not available on this system; layer was skipped."),
        ]),
        ("Model Scanner Verdicts", [
            ("PASS", COLOR_PASS, "Scanner correctly classified the file (flagged malicious OR cleared safe)."),
            ("FN (False Negative)", COLOR_FAIL,
             "Scanner failed to detect a known-malicious file. High risk -- the payload evaded detection."),
            ("FP (False Positive)", COLOR_WARN,
             "Scanner incorrectly flagged a known-safe file. Low risk -- causes alert fatigue."),
            ("SKIP", COLOR_SKIP, "File format not applicable to this scanner (e.g. safetensors for Picklescan)."),
            ("N/A", COLOR_SKIP, "Scanner not installed; no result available."),
        ]),
        ("Fixture Classifications", [
            ("MAL (Malicious)", COLOR_FAIL,
             "File contains an embedded exploit payload (e.g. os.system, eval, subprocess via __reduce__)."),
            ("SAFE", COLOR_PASS,
             "File contains only benign data structures with no executable content."),
        ]),
        ("Severity Levels (Code/Dependency Scans)", [
            ("CRITICAL / HIGH", COLOR_FAIL, "Exploitable vulnerability or dangerous code pattern. Requires immediate action."),
            ("MEDIUM", COLOR_WARN, "Potential security issue. Should be reviewed and addressed."),
            ("LOW / INFO", COLOR_MUTED, "Informational finding or minor concern. Address as time permits."),
        ]),
    ]

    for group_title, entries in legend_items:
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*COLOR_TEXT)
        pdf.cell(0, 7, sanitize(group_title), new_x="LMARGIN", new_y="NEXT")
        for label, color, description in entries:
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*color)
            pdf.cell(4)
            pdf.cell(36, 5, sanitize(label))
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*COLOR_TEXT)
            pdf.cell(0, 5, sanitize(f"-- {description}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    # ── Layer 1: Code SAST ────────────────────────────────────────
    pdf.section_title("Layer 1: Code SAST (Semgrep + CodeQL)")
    pdf.body_text("Static Application Security Testing identifies vulnerabilities in source code.")
    _pdf_layer_tool_table(pdf, [layer_results["semgrep"], layer_results["codeql"]])

    # Detail semgrep findings
    sg = layer_results["semgrep"]
    if sg["installed"] and sg["findings"] > 0 and sg["issues"]:
        pdf.sub_title(f"Semgrep Findings Detail ({sg['findings']} issue(s))")
        pdf.body_text("Each finding shows [SEVERITY] file:line - rule description.")
        col_w_sg = [20, 60, 110]
        pdf.table_header(["Severity", "Location", "Description"], col_w_sg)
        fill = False
        for issue in sg["issues"][:40]:
            parts = issue.split(" - ", 1)
            sev_loc = parts[0] if parts else issue
            desc = parts[1] if len(parts) > 1 else ""
            sev_parts = sev_loc.split("] ", 1)
            sev = sev_parts[0].strip("[") if len(sev_parts) > 1 else "INFO"
            loc = sev_parts[1] if len(sev_parts) > 1 else sev_loc
            pdf.set_font("Helvetica", "B", 8)
            if fill:
                pdf.set_fill_color(*COLOR_BG_LIGHT)
            if sev in ("ERROR", "CRITICAL", "HIGH"):
                pdf.set_text_color(*COLOR_FAIL)
            elif sev in ("WARNING", "MEDIUM"):
                pdf.set_text_color(*COLOR_WARN)
            else:
                pdf.set_text_color(*COLOR_MUTED)
            pdf.cell(col_w_sg[0], 5, sanitize(sev), border=1, fill=fill, align="C")
            pdf.set_text_color(*COLOR_TEXT)
            pdf.set_font("Helvetica", "", 7)
            pdf.cell(col_w_sg[1], 5, sanitize(loc[:45]), border=1, fill=fill, align="L")
            pdf.cell(col_w_sg[2], 5, sanitize(desc[:85]), border=1, fill=fill, align="L")
            pdf.ln()
            fill = not fill
        if sg["findings"] > 40:
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(*COLOR_MUTED)
            pdf.cell(0, 5, sanitize(f"... and {sg['findings'] - 40} more findings (see semgrep.json for full details)"),
                     new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*COLOR_TEXT)
        pdf.ln(2)
    elif sg["installed"] and sg["findings"] == 0:
        pdf.body_text("Semgrep: No security issues found in source code. All rules passed.")
        pdf.ln(2)

    # ── Layer 1b: Agent Architecture ──────────────────────────────
    pdf.section_title("Layer 1b: Agent Architecture (Agentic Radar + Snyk Agent Scan)")
    pdf.body_text("Analyses agent frameworks and MCP configurations for security risks.")
    _pdf_layer_tool_table(pdf, [layer_results["agentic_radar"], layer_results["snyk_agent_scan"]])

    for key in ["agentic_radar", "snyk_agent_scan"]:
        t = layer_results[key]
        if t["installed"] and t["issues"]:
            pdf.sub_title(f"{t['scanner']} Findings")
            for issue in t["issues"][:15]:
                pdf.set_font("Helvetica", "", 8)
                pdf.cell(4)
                pdf.cell(0, 5, sanitize(f"- {issue}"), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

    # ── Layer 2: Model Artifacts ──────────────────────────────────
    pdf.section_title("Layer 2: Model Artifact Scanning")
    pdf.body_text(
        "Scans model files (pickle, ONNX, safetensors, HDF5, etc.) for embedded "
        "malicious payloads. Results below show per-scanner accuracy against ground truth fixtures."
    )

    # Summary table per model scanner
    col_widths = [40, 25, 25, 25, 35, 40]
    pdf.table_header(["Scanner", "Tested", "Correct", "Incorrect", "Skipped", "Accuracy"], col_widths)
    fill = False
    for sname in sorted(scanner_stats.keys()):
        s = scanner_stats[sname]
        tested = s["pass"] + s["fail"]
        acc = f"{s['pass']*100//tested}%" if tested > 0 else "N/A"
        pdf.table_row([sname, str(tested), str(s["pass"]), str(s["fail"]),
                        str(s["skip"]), acc], col_widths, fill=fill)
        fill = not fill
    pdf.ln(4)

    # Per-scanner detailed fixture results
    for sname in sorted(scanner_stats.keys()):
        pdf.sub_title(f"{sname} -- Per-File Results")
        col_w = [55, 15, 20, 20, 80]
        pdf.table_header(["File", "Type", "Expected", "Result", "Details"], col_w)
        fill = False

        for fname, fdata in fixture_results.items():
            meta = fdata["meta"]
            is_malicious = meta.get("malicious", False)
            expected = "MAL" if is_malicious else "SAFE"

            for key, val in fdata.items():
                if key == "meta":
                    continue
                if val.get("scanner", key) != sname:
                    continue
                if val.get("skipped"):
                    pdf.table_row([fname, meta.get("category", "")[:12], expected, "SKIP",
                                    "Format not applicable"], col_w, fill=fill)
                    fill = not fill
                    continue
                if not val.get("installed"):
                    pdf.table_row([fname, meta.get("category", "")[:12], expected, "N/A",
                                    "Not installed"], col_w, fill=fill)
                    fill = not fill
                    continue

                flagged = val.get("flagged", False)
                correct = (is_malicious and flagged) or (not is_malicious and not flagged)
                if correct:
                    verdict = "PASS"
                elif is_malicious and not flagged:
                    verdict = "FN"
                else:
                    verdict = "FP"

                detail = ""
                if val.get("issues"):
                    # Show the most informative issue line
                    raw = val["issues"][0]
                    detail = raw[:70]
                elif correct and is_malicious:
                    techs = ", ".join(meta.get("techniques", [])[:3])
                    detail = f"Detected: {techs}" if techs else "Correctly flagged as malicious"
                elif correct:
                    detail = "Correctly verified as safe"
                elif verdict == "FN":
                    techs = ", ".join(meta.get("techniques", [])[:2])
                    detail = f"MISSED: {meta.get('description', 'malicious payload')[:50]}"
                else:
                    detail = f"FALSE POSITIVE on {meta.get('category', 'safe file')}"

                pdf.set_font("Helvetica", "", 9)
                if fill:
                    pdf.set_fill_color(*COLOR_BG_LIGHT)
                pdf.cell(col_w[0], 6, sanitize(fname), border=1, fill=fill, align="C")
                pdf.cell(col_w[1], 6, sanitize(meta.get("category", "")[:12]), border=1, fill=fill, align="C")
                pdf.cell(col_w[2], 6, sanitize(expected), border=1, fill=fill, align="C")
                if verdict == "PASS":
                    pdf.set_text_color(*COLOR_PASS)
                elif verdict == "FN":
                    pdf.set_text_color(*COLOR_FAIL)
                else:
                    pdf.set_text_color(*COLOR_WARN)
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(col_w[3], 6, sanitize(verdict), border=1, fill=fill, align="C")
                pdf.set_text_color(*COLOR_TEXT)
                pdf.set_font("Helvetica", "", 8)
                pdf.cell(col_w[4], 6, sanitize(detail), border=1, fill=fill, align="L")
                pdf.ln()
                fill = not fill
        pdf.ln(3)

    # ── Layer 3: Prompt Testing ───────────────────────────────────
    pdf.section_title("Layer 3: Prompt Regression Testing (Promptfoo)")
    pdf.body_text("Tests LLM prompts for regressions, jailbreaks, and safety violations.")
    _pdf_layer_tool_table(pdf, [layer_results["promptfoo"]])

    pf = layer_results["promptfoo"]
    if pf["installed"] and pf["issues"]:
        pdf.sub_title("Promptfoo Details")
        for issue in pf["issues"][:15]:
            pdf.set_font("Helvetica", "", 8)
            pdf.cell(4)
            pdf.cell(0, 5, sanitize(f"- {issue}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    # ── Layer 4: Dependencies ─────────────────────────────────────
    pdf.section_title("Layer 4: Dependency Vulnerability Scanning")
    pdf.body_text("Scans project dependencies for known CVEs and supply-chain risks.")
    _pdf_layer_tool_table(pdf, [
        layer_results["osv_scanner"], layer_results["safedep_vet"],
        layer_results["cve_bin_tool"],
    ])

    for key in ["osv_scanner", "safedep_vet", "cve_bin_tool"]:
        t = layer_results[key]
        if t["installed"] and t["findings"] > 0 and t["issues"]:
            pdf.sub_title(f"{t['scanner']} -- {t['findings']} Vulnerability(ies) Found")
            pdf.body_text(f"Identified vulnerabilities in project dependencies. Review and update affected packages.")
            col_w_dep = [50, 140]
            pdf.table_header(["CVE / Advisory", "Details"], col_w_dep)
            fill = False
            for issue in t["issues"][:25]:
                parts = issue.split(": ", 1)
                cve = parts[0] if parts else "?"
                desc = parts[1] if len(parts) > 1 else issue
                pdf.set_font("Helvetica", "B", 8)
                if fill:
                    pdf.set_fill_color(*COLOR_BG_LIGHT)
                pdf.set_text_color(*COLOR_FAIL)
                pdf.cell(col_w_dep[0], 5, sanitize(cve[:38]), border=1, fill=fill, align="L")
                pdf.set_text_color(*COLOR_TEXT)
                pdf.set_font("Helvetica", "", 8)
                pdf.cell(col_w_dep[1], 5, sanitize(desc[:110]), border=1, fill=fill, align="L")
                pdf.ln()
                fill = not fill
            if t["findings"] > 25:
                pdf.set_font("Helvetica", "I", 8)
                pdf.set_text_color(*COLOR_MUTED)
                pdf.cell(0, 5, sanitize(f"... and {t['findings'] - 25} more (see full JSON output for details)"),
                         new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(*COLOR_TEXT)
            pdf.ln(3)
        elif t["installed"] and t["findings"] == 0:
            pdf.body_text(f"{t['scanner']}: No known vulnerabilities found in project dependencies.")

    # ── Layer 5: SBOM ─────────────────────────────────────────────
    pdf.section_title("Layer 5: SBOM Generation & Governance")
    pdf.body_text(
        "Generates Software Bill of Materials for AI model and infrastructure components. "
        "AIsbom catalogues ML model assets; Syft catalogues Python/system packages; "
        "CycloneDX merges both into a unified SBOM for governance and Dependency-Track upload."
    )
    _pdf_layer_tool_table(pdf, [
        layer_results["aisbom"], layer_results["syft"],
        layer_results["cyclonedx_merge"],
    ])

    # Show Syft component breakdown if available
    syft_info = layer_results["syft"]
    if syft_info["installed"] and syft_info["output_file"] and os.path.isfile(syft_info["output_file"]):
        try:
            with open(syft_info["output_file"], "r", errors="replace") as fh:
                sbom_data = json.load(fh)
            components = sbom_data.get("components", [])
            if components:
                pdf.sub_title(f"Syft -- {len(components)} Components Catalogued")
                type_counts = {}
                for c in components:
                    ctype = c.get("type", "unknown")
                    type_counts[ctype] = type_counts.get(ctype, 0) + 1
                pdf.body_text("Component breakdown by type: " +
                              ", ".join(f"{t}: {n}" for t, n in sorted(type_counts.items(), key=lambda x: -x[1])))
                col_w_sbom = [60, 30, 40, 60]
                pdf.table_header(["Package", "Version", "Type", "PURL"], col_w_sbom)
                fill = False
                for c in components[:30]:
                    name = c.get("name", "?")
                    ver = c.get("version", "?")
                    ctype = c.get("type", "?")
                    purl = c.get("purl", "")
                    if len(purl) > 45:
                        purl = purl[:42] + "..."
                    pdf.table_row([name[:45], ver[:20], ctype, purl], col_w_sbom, fill=fill)
                    fill = not fill
                if len(components) > 30:
                    pdf.set_font("Helvetica", "I", 8)
                    pdf.set_text_color(*COLOR_MUTED)
                    pdf.cell(0, 5, sanitize(f"... and {len(components) - 30} more (see syft-env.json)"),
                             new_x="LMARGIN", new_y="NEXT")
                    pdf.set_text_color(*COLOR_TEXT)
                pdf.ln(3)
        except (json.JSONDecodeError, OSError):
            pass

    # ── Fixture Inventory ─────────────────────────────────────────
    pdf.section_title("Fixture Inventory")
    pdf.body_text("Complete list of test fixtures with expected classifications.")
    pdf.ln(2)

    col_w = [50, 18, 30, 92]
    pdf.table_header(["File", "Malicious?", "Category", "Description"], col_w)
    fill = False
    for entry in manifest:
        mal = "YES" if entry["malicious"] else "NO"
        pdf.set_font("Helvetica", "", 8)
        if fill:
            pdf.set_fill_color(*COLOR_BG_LIGHT)
        pdf.cell(col_w[0], 6, sanitize(entry["file"]), border=1, fill=fill, align="L")
        if entry["malicious"]:
            pdf.set_text_color(*COLOR_FAIL)
        else:
            pdf.set_text_color(*COLOR_PASS)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(col_w[1], 6, mal, border=1, fill=fill, align="C")
        pdf.set_text_color(*COLOR_TEXT)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(col_w[2], 6, sanitize(entry.get("category", "")), border=1, fill=fill, align="C")
        desc = entry.get("description", "")
        if len(desc) > 70:
            desc = desc[:67] + "..."
        pdf.cell(col_w[3], 6, sanitize(desc), border=1, fill=fill, align="L")
        pdf.ln()
        fill = not fill

    # ── Detailed Findings (model scanner raw issues) ──────────────
    has_issues = any(
        val.get("issues")
        for fdata in fixture_results.values()
        for key, val in fdata.items() if key != "meta"
    )
    if has_issues:
        pdf.section_title("Detailed Model Scanner Findings")
        pdf.body_text(
            "Full issue details reported by each scanner. For malicious files, these show the "
            "specific dangerous import or opcode detected. For false positives, they explain "
            "what triggered the incorrect flag."
        )
        pdf.ln(2)

        for fname, fdata in fixture_results.items():
            file_has_issues = any(
                val.get("issues")
                for key, val in fdata.items() if key != "meta"
            )
            if not file_has_issues:
                continue
            meta = fdata["meta"]
            cat = meta.get("category", "unknown")
            mal = "MALICIOUS" if meta.get("malicious") else "SAFE"
            techs = ", ".join(meta.get("techniques", [])) or "none"

            # File header with coloured malicious/safe badge
            pdf.sub_title(fname)
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(4)
            pdf.set_font("Helvetica", "B", 9)
            if meta.get("malicious"):
                pdf.set_text_color(*COLOR_FAIL)
                pdf.cell(20, 5, "MAL")
            else:
                pdf.set_text_color(*COLOR_PASS)
                pdf.cell(20, 5, "SAFE")
            pdf.set_text_color(*COLOR_MUTED)
            pdf.set_font("Helvetica", "I", 9)
            pdf.cell(0, 5, sanitize(f"Category: {cat}  |  Techniques: {techs}"),
                     new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*COLOR_TEXT)
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(4)
            pdf.cell(0, 5, sanitize(f"Description: {meta.get('description', 'N/A')}"),
                     new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)

            for key, val in fdata.items():
                if key == "meta" or not val.get("issues"):
                    continue
                sname = val.get("scanner", key)
                flagged = val.get("flagged", False)
                is_mal = meta.get("malicious", False)
                # Determine verdict for this scanner+file
                if is_mal and flagged:
                    v_label = "DETECTED"
                    v_color = COLOR_PASS
                elif is_mal and not flagged:
                    v_label = "MISSED"
                    v_color = COLOR_FAIL
                elif not is_mal and flagged:
                    v_label = "FALSE POSITIVE"
                    v_color = COLOR_WARN
                else:
                    v_label = "CLEAN"
                    v_color = COLOR_PASS

                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(4)
                pdf.cell(25, 5, f"{sname}:")
                pdf.set_text_color(*v_color)
                pdf.cell(30, 5, f"[{v_label}]")
                pdf.set_text_color(*COLOR_TEXT)
                pdf.set_font("Helvetica", "", 9)
                pdf.ln()
                for issue in val["issues"]:
                    if len(issue) > 140:
                        issue = issue[:137] + "..."
                    pdf.set_font("Helvetica", "", 8)
                    pdf.cell(12)
                    pdf.cell(0, 5, sanitize(f"- {issue}"), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

    # ── Save ──────────────────────────────────────────────────────
    pdf.output(output_path)
    return output_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="AI Sentinel PDF Report Generator (Full Pipeline)")
    parser.add_argument("--results-dir", default=None,
                        help="Directory with existing scan results (reads instead of running scans)")
    parser.add_argument("--output", "-o", default="sentinel-report.pdf", help="Output PDF path")
    parser.add_argument("--scan-fixtures", action="store_true",
                        help="Run full scan pipeline + fixture validation and generate report")
    parser.add_argument("--fixtures-dir", default=None, help="Path to fixtures directory")
    parser.add_argument("--target", default=None, help="Project directory to scan (default: project root)")
    parser.add_argument("--configs-dir", default=None, help="Config directory")
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    fixtures_dir = args.fixtures_dir or os.path.join(project_root, "tests", "fixtures")
    target = args.target or project_root
    configs_dir = args.configs_dir or os.path.join(project_root, "configs")
    results_dir = args.results_dir or os.path.join(project_root, "sentinel-results",
                                                    datetime.now().strftime("%Y%m%d-%H%M%S"))

    # Ensure results directories exist
    for subdir in ["code", "agents", "models", "prompts", "deps", "sbom"]:
        os.makedirs(os.path.join(results_dir, subdir), exist_ok=True)

    # Load manifest
    manifest = load_manifest(fixtures_dir)
    if not manifest:
        print(f"ERROR: No manifest.json found in {fixtures_dir}")
        print("Run: python tests/fixtures/generate-fixtures.py")
        sys.exit(1)

    print("=" * 60)
    print("  AI Sentinel -- Full 6-Layer Security Scan")
    print("=" * 60)
    print(f"  Target:     {target}")
    print(f"  Fixtures:   {fixtures_dir}")
    print(f"  Results:    {results_dir}")
    print(f"  Configs:    {configs_dir}")
    print(f"  Fixtures:   {len(manifest)} ({sum(1 for m in manifest if m['malicious'])} malicious, "
          f"{sum(1 for m in manifest if not m['malicious'])} safe)")

    # ── Phase 1: Project-level scans (Layers 1, 1b, 3, 4, 5) ────
    print("\n\nPHASE 1: Project-Level Scans")
    print("=" * 60)
    layer_results = run_all_project_scans(target, results_dir, configs_dir)

    # ── Phase 2: Fixture-level model scans (Layer 2) ─────────────
    print("\n\n" + "=" * 60)
    print("  PHASE 2: Layer 2 -- Model Scanner Validation")
    print("=" * 60)
    print(f"  Scanning {len(manifest)} fixtures with {len(FIXTURE_SCANNERS)} model scanners...\n")
    fixture_results = scan_all_fixtures(fixtures_dir, manifest)

    # ── Phase 3: Generate PDF ────────────────────────────────────
    print(f"\n\nGenerating PDF report -> {args.output}")
    path = build_pdf(fixture_results, manifest, layer_results, args.output,
                     fixtures_dir, target)
    print(f"Done! Report saved to: {os.path.abspath(path)}")

    # ── Summary ──────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  SCAN SUMMARY")
    print("=" * 60)
    for key, t in layer_results.items():
        status = "INSTALLED" if t["installed"] else "NOT INSTALLED"
        findings = t["findings"] if t["installed"] else "--"
        print(f"  {t['scanner']:20s}  {status:15s}  findings: {findings}")
    print()
    total_pass = sum(
        1 for fdata in fixture_results.values()
        for k, v in fdata.items()
        if k != "meta" and v.get("installed") and not v.get("skipped")
        and ((fdata["meta"]["malicious"] and v.get("flagged"))
             or (not fdata["meta"]["malicious"] and not v.get("flagged")))
    )
    total_fail = sum(
        1 for fdata in fixture_results.values()
        for k, v in fdata.items()
        if k != "meta" and v.get("installed") and not v.get("skipped")
        and not ((fdata["meta"]["malicious"] and v.get("flagged"))
                 or (not fdata["meta"]["malicious"] and not v.get("flagged")))
    )
    print(f"  Model validation: {total_pass} correct, {total_fail} incorrect")


if __name__ == "__main__":
    main()
