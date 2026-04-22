#!/usr/bin/env python3
"""
AI Sentinel — AI-Powered Vulnerability Prioritizer

Parses findings from all open-source scanners (Fickling, ModelScan, Picklescan,
Semgrep, OSV-Scanner, etc.), deduplicates them, and uses OpenAI GPT to
intelligently prioritize vulnerabilities from most critical to least critical.

Outputs structured JSON ready for website consumption.

Usage:
    # Prioritize from existing scan results
    python scripts/prioritize_vulnerabilities.py --results-dir sentinel-results/20260324-180522

    # Prioritize from safety_results.json (Fickling output)
    python scripts/prioritize_vulnerabilities.py --safety-results safety_results.json

    # Scan fixtures in current directory + prioritize
    python scripts/prioritize_vulnerabilities.py --scan-dir .

    # Custom OpenAI model
    python scripts/prioritize_vulnerabilities.py --safety-results safety_results.json --model gpt-4o
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

try:
    from openai import OpenAI
except ImportError:
    print("ERROR: openai package required. Install with: pip install openai")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Finding parsers — one per scanner output format
# ---------------------------------------------------------------------------

def parse_fickling_safety_results(filepath):
    """Parse the concatenated JSON objects from Fickling's safety_results.json."""
    findings = []
    if not os.path.isfile(filepath):
        return findings

    with open(filepath, "r", errors="replace") as f:
        raw = f.read()

    # Parse concatenated JSON objects using depth-tracking
    objs = []
    depth = 0
    start = 0
    for i, c in enumerate(raw):
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                try:
                    objs.append(json.loads(raw[start:i + 1]))
                except json.JSONDecodeError:
                    pass
                start = i + 1

    for obj in objs:
        severity = obj.get("severity", "UNKNOWN")
        analysis = obj.get("analysis", "")
        details = obj.get("detailed_results", {})

        if severity == "LIKELY_SAFE":
            continue  # Skip clean files

        # Extract key indicators
        ar = details.get("AnalysisResult", {})
        unsafe_imports = ar.get("UnsafeImports", "")
        unsafe_ml = ar.get("UnsafeImportsML", "")
        bad_eval = ar.get("OvertlyBadEval", "")
        unused_vars = ar.get("UnusedVariables", "")

        finding = {
            "scanner": "Fickling",
            "scanner_severity": severity,
            "title": _fickling_title(severity, unsafe_imports, bad_eval),
            "description": analysis.replace("\\n", "\n").strip(),
            "category": "Model Artifact — Pickle Deserialization",
            "indicators": {
                k: v for k, v in {
                    "unsafe_imports": unsafe_imports,
                    "unsafe_ml_imports": unsafe_ml,
                    "overtly_bad_eval": bad_eval,
                    "unused_variables": unused_vars,
                }.items() if v
            },
        }
        finding["_hash"] = _hash_finding(finding)
        findings.append(finding)

    return findings


def _fickling_title(severity, imports, bad_eval):
    if bad_eval:
        return f"Malicious Code Execution: {bad_eval[:60]}"
    if imports:
        return f"Dangerous Import in Pickle: {imports}"
    return f"Suspicious Pickle File ({severity})"


def parse_semgrep_json(filepath):
    """Parse Semgrep JSON output."""
    findings = []
    if not os.path.isfile(filepath):
        return findings
    try:
        with open(filepath, "r", errors="replace") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return findings

    for r in data.get("results", []):
        extra = r.get("extra", {})
        finding = {
            "scanner": "Semgrep",
            "scanner_severity": extra.get("severity", "INFO"),
            "title": r.get("check_id", "Unknown rule"),
            "description": extra.get("message", ""),
            "category": "Code SAST",
            "file": r.get("path", ""),
            "line": r.get("start", {}).get("line", 0),
            "indicators": {
                "cwe": extra.get("metadata", {}).get("cwe", ""),
                "owasp": extra.get("metadata", {}).get("owasp", ""),
            },
        }
        finding["_hash"] = _hash_finding(finding)
        findings.append(finding)

    # Also report config errors as findings
    for err in data.get("errors", []):
        findings.append({
            "scanner": "Semgrep",
            "scanner_severity": "WARNING",
            "title": "Semgrep Configuration Error",
            "description": err.get("message", "Unknown error"),
            "category": "Pipeline — Broken Scanner",
            "indicators": {"error_code": err.get("code", 0)},
            "_hash": _hash_finding({"t": "semgrep-err", "m": err.get("message", "")}),
        })

    return findings


def parse_modelscan_json(filepath):
    """Parse ModelScan JSON output."""
    findings = []
    if not os.path.isfile(filepath):
        return findings
    try:
        with open(filepath, "r", errors="replace") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return findings

    for issue in data.get("issues", []):
        finding = {
            "scanner": "ModelScan",
            "scanner_severity": issue.get("severity", "UNKNOWN"),
            "title": issue.get("description", "Model artifact issue"),
            "description": issue.get("description", ""),
            "category": "Model Artifact",
            "file": issue.get("source", ""),
            "indicators": {
                "operator": issue.get("operator", ""),
                "module": issue.get("module", ""),
            },
        }
        finding["_hash"] = _hash_finding(finding)
        findings.append(finding)
    return findings


def parse_picklescan_txt(filepath):
    """Parse Picklescan text output."""
    findings = []
    if not os.path.isfile(filepath):
        return findings
    with open(filepath, "r", errors="replace") as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if "dangerous import" in line.lower() and "FOUND" in line:
            finding = {
                "scanner": "Picklescan",
                "scanner_severity": "CRITICAL",
                "title": "Dangerous Import in Pickle File",
                "description": line,
                "category": "Model Artifact — Pickle Deserialization",
                "indicators": {},
            }
            finding["_hash"] = _hash_finding(finding)
            findings.append(finding)
    return findings


def parse_osv_scanner_json(filepath):
    """Parse OSV-Scanner JSON output."""
    findings = []
    if not os.path.isfile(filepath):
        return findings
    try:
        with open(filepath, "r", errors="replace") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return findings

    for result in data.get("results", []):
        for pkg in result.get("packages", []):
            pkg_info = pkg.get("package", {})
            for vuln in pkg.get("vulnerabilities", []):
                finding = {
                    "scanner": "OSV-Scanner",
                    "scanner_severity": _osv_severity(vuln),
                    "title": f"{vuln.get('id', 'Unknown')}: {vuln.get('summary', '')}",
                    "description": vuln.get("details", vuln.get("summary", "")),
                    "category": "Dependency Vulnerability (CVE)",
                    "indicators": {
                        "vuln_id": vuln.get("id", ""),
                        "package": pkg_info.get("name", ""),
                        "version": pkg_info.get("version", ""),
                        "aliases": vuln.get("aliases", []),
                    },
                }
                finding["_hash"] = _hash_finding(finding)
                findings.append(finding)
    return findings


def _osv_severity(vuln):
    for sev in vuln.get("severity", []):
        score = sev.get("score", "")
        if "CVSS" in sev.get("type", ""):
            try:
                val = float(score.split("/")[0].split(":")[-1])
                if val >= 9.0:
                    return "CRITICAL"
                if val >= 7.0:
                    return "HIGH"
                if val >= 4.0:
                    return "MEDIUM"
                return "LOW"
            except (ValueError, IndexError):
                pass
    return "MEDIUM"


def parse_vet_json(filepath):
    """Parse SafeDep vet JSON output."""
    findings = []
    if not os.path.isfile(filepath):
        return findings
    try:
        with open(filepath, "r", errors="replace") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return findings

    for item in data.get("findings", data.get("results", [])):
        if isinstance(item, dict):
            finding = {
                "scanner": "SafeDep vet",
                "scanner_severity": item.get("severity", "MEDIUM"),
                "title": item.get("title", item.get("rule", "Dependency policy violation")),
                "description": item.get("description", item.get("message", "")),
                "category": "Dependency Policy",
                "indicators": {
                    "package": item.get("package", ""),
                    "rule": item.get("rule", ""),
                },
            }
            finding["_hash"] = _hash_finding(finding)
            findings.append(finding)
    return findings


def parse_cve_bin_tool_json(filepath):
    """Parse CVE Binary Tool JSON output."""
    findings = []
    if not os.path.isfile(filepath):
        return findings
    try:
        with open(filepath, "r", errors="replace") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return findings

    for item in data if isinstance(data, list) else data.get("results", []):
        if isinstance(item, dict):
            finding = {
                "scanner": "CVE Binary Tool",
                "scanner_severity": item.get("severity", "MEDIUM"),
                "title": item.get("cve_number", item.get("id", "CVE finding")),
                "description": item.get("description", ""),
                "category": "Binary Vulnerability (CVE)",
                "indicators": {
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                },
            }
            finding["_hash"] = _hash_finding(finding)
            findings.append(finding)
    return findings


def parse_scanner_errors(results_dir):
    """Detect broken/crashed scanners from their output files — these are findings too."""
    findings = []
    error_files = {
        "agents/agentic-radar.txt": "Agentic Radar",
        "agents/snyk-agent-scan.txt": "Snyk Agent Scan",
    }
    for rel_path, scanner_name in error_files.items():
        fpath = os.path.join(results_dir, rel_path)
        if not os.path.isfile(fpath):
            continue
        with open(fpath, "r", errors="replace") as f:
            content = f.read()
        if "Traceback" in content or "Error" in content:
            findings.append({
                "scanner": scanner_name,
                "scanner_severity": "WARNING",
                "title": f"{scanner_name} Failed to Execute",
                "description": content.strip()[:300],
                "category": "Pipeline — Broken Scanner (Coverage Gap)",
                "indicators": {"error_type": "crash"},
                "_hash": _hash_finding({"t": f"{scanner_name}-crash"}),
            })
    return findings


# ---------------------------------------------------------------------------
# Deduplication & aggregation
# ---------------------------------------------------------------------------

def _hash_finding(finding):
    """Create a content hash for deduplication."""
    key = json.dumps({
        "title": finding.get("title", ""),
        "description": finding.get("description", "")[:200],
        "category": finding.get("category", ""),
    }, sort_keys=True)
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def collect_all_findings(args):
    """Collect and deduplicate findings from all available sources."""
    all_findings = []

    # 1. Fickling safety_results.json
    if args.safety_results:
        all_findings.extend(parse_fickling_safety_results(args.safety_results))

    # 2. Results directory (structured scanner outputs)
    if args.results_dir and os.path.isdir(args.results_dir):
        rd = args.results_dir
        all_findings.extend(parse_semgrep_json(os.path.join(rd, "code", "semgrep.json")))
        all_findings.extend(parse_modelscan_json(os.path.join(rd, "models", "modelscan.json")))
        all_findings.extend(parse_picklescan_txt(os.path.join(rd, "models", "picklescan.txt")))
        all_findings.extend(parse_osv_scanner_json(os.path.join(rd, "deps", "osv-scanner.json")))
        all_findings.extend(parse_vet_json(os.path.join(rd, "deps", "vet.json")))
        all_findings.extend(parse_cve_bin_tool_json(os.path.join(rd, "deps", "cve-bin-tool.json")))
        all_findings.extend(parse_scanner_errors(rd))

    # 3. Scan directory for standalone files
    if args.scan_dir and os.path.isdir(args.scan_dir):
        sd = args.scan_dir
        for name in os.listdir(sd):
            fp = os.path.join(sd, name)
            if name == "safety_results.json":
                all_findings.extend(parse_fickling_safety_results(fp))
            elif name.endswith(".json"):
                # Try each parser
                all_findings.extend(parse_semgrep_json(fp))
                all_findings.extend(parse_modelscan_json(fp))
                all_findings.extend(parse_osv_scanner_json(fp))

    # Deduplicate by hash
    seen = set()
    unique = []
    for f in all_findings:
        h = f.get("_hash", "")
        if h and h not in seen:
            seen.add(h)
            unique.append(f)
        elif not h:
            unique.append(f)

    return unique


# ---------------------------------------------------------------------------
# OpenAI prioritization
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an expert AI/ML security analyst. You will receive a JSON array of 
vulnerability findings from open-source security scanners (Fickling, ModelScan, Picklescan, 
Semgrep, OSV-Scanner, SafeDep vet, CVE Binary Tool, etc.).

Your task is to PRIORITIZE these vulnerabilities from most critical to least critical, 
using your expert knowledge of:
- CVSS scoring methodology
- OWASP Top 10 for LLM Applications
- Real-world exploit likelihood
- Blast radius (what gets compromised if exploited)
- Whether the vulnerability enables remote code execution, data exfiltration, or lateral movement

For EACH vulnerability, you must return:
1. "priority_rank" — integer, 1 = most critical
2. "ai_severity" — one of: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
3. "cvss_estimate" — float 0.0-10.0 (your best estimate)
4. "exploit_likelihood" — one of: CONFIRMED, HIGH, MEDIUM, LOW, THEORETICAL
5. "blast_radius" — one of: FULL_SYSTEM, SERVICE, COMPONENT, MINIMAL
6. "attack_vector" — brief description of how this could be exploited
7. "remediation" — specific actionable fix
8. "justification" — 1-2 sentences explaining your priority ranking

Return ONLY valid JSON — an array of objects. Each object must include an "id" field 
matching the input finding's "id" field, plus all the fields above.

Important rules:
- Remote Code Execution (RCE) vulnerabilities are always CRITICAL
- Arbitrary code execution via pickle deserialization is CRITICAL  
- exec()/eval() of untrusted input is CRITICAL
- Broken scanners (coverage gaps) are HIGH because they create blind spots
- Known CVEs with public exploits are higher priority than theoretical risks
- Supply chain attacks (malicious dependencies) are CRITICAL
"""


def prioritize_with_openai(findings, model="gpt-4o", api_key=None):
    """Send findings to OpenAI and get back prioritized results."""
    if not findings:
        return {"prioritized_vulnerabilities": [], "metadata": {"total": 0}}

    client = OpenAI(api_key=api_key or os.environ.get("OPENAI_API_KEY"))

    # Prepare findings for the LLM (strip internal hashes, add IDs)
    prepared = []
    for i, f in enumerate(findings):
        entry = {
            "id": f.get("_hash", f"finding-{i}"),
            "scanner": f.get("scanner", "Unknown"),
            "scanner_severity": f.get("scanner_severity", "UNKNOWN"),
            "title": f.get("title", ""),
            "description": f.get("description", "")[:500],
            "category": f.get("category", ""),
            "indicators": f.get("indicators", {}),
        }
        if f.get("file"):
            entry["file"] = f["file"]
        if f.get("line"):
            entry["line"] = f["line"]
        prepared.append(entry)

    # Chunk if too many findings (token limits)
    MAX_PER_CALL = 40
    all_prioritized = []

    for chunk_start in range(0, len(prepared), MAX_PER_CALL):
        chunk = prepared[chunk_start:chunk_start + MAX_PER_CALL]

        user_msg = (
            f"Prioritize these {len(chunk)} security findings from most critical to least critical.\n\n"
            f"```json\n{json.dumps(chunk, indent=2)}\n```"
        )

        print(f"  Sending {len(chunk)} findings to OpenAI ({model})...")
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.1,
            response_format={"type": "json_object"},
        )

        raw = response.choices[0].message.content
        try:
            parsed = json.loads(raw)
            # Handle both {results: [...]} and [...] formats
            items = parsed if isinstance(parsed, list) else parsed.get(
                "prioritized_vulnerabilities", parsed.get("results",
                parsed.get("vulnerabilities", [])))
            all_prioritized.extend(items)
        except json.JSONDecodeError:
            print(f"  WARNING: Failed to parse OpenAI response, returning raw")
            all_prioritized.append({"error": "parse_failed", "raw": raw[:500]})

    # Re-sort by priority_rank across chunks
    all_prioritized.sort(key=lambda x: x.get("priority_rank", 999))
    # Re-number
    for i, item in enumerate(all_prioritized):
        item["priority_rank"] = i + 1

    # Merge AI results back with original finding data
    id_to_finding = {f.get("_hash", f"finding-{i}"): f for i, f in enumerate(findings)}
    merged = []
    for ai_result in all_prioritized:
        fid = ai_result.get("id", "")
        original = id_to_finding.get(fid, {})
        merged_entry = {
            **{k: v for k, v in original.items() if k != "_hash"},
            **ai_result,
        }
        merged_entry.pop("_hash", None)
        merged.append(merged_entry)

    # Build severity summary
    severity_counts = {}
    for item in merged:
        sev = item.get("ai_severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model_used": model,
            "total_findings": len(merged),
            "severity_summary": severity_counts,
            "scanners_represented": list(set(
                f.get("scanner", "Unknown") for f in findings
            )),
        },
        "prioritized_vulnerabilities": merged,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="AI-powered vulnerability prioritization using OpenAI"
    )
    parser.add_argument("--safety-results", "-s",
                        help="Path to Fickling safety_results.json")
    parser.add_argument("--results-dir", "-r",
                        help="Path to sentinel-results/<timestamp>/ directory")
    parser.add_argument("--scan-dir", "-d",
                        help="Directory to scan for any JSON result files")
    parser.add_argument("--model", "-m", default="gpt-4o",
                        help="OpenAI model to use (default: gpt-4o)")
    parser.add_argument("--api-key", "-k",
                        help="OpenAI API key (or set OPENAI_API_KEY env var)")
    parser.add_argument("--output", "-o", default="prioritized_vulnerabilities.json",
                        help="Output JSON file path")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse findings without calling OpenAI")
    args = parser.parse_args()

    if not any([args.safety_results, args.results_dir, args.scan_dir]):
        parser.error("Provide at least one of: --safety-results, --results-dir, --scan-dir")

    # Step 1: Collect & deduplicate
    print("\n==> Collecting findings from all scanners...")
    findings = collect_all_findings(args)
    print(f"    Found {len(findings)} unique findings")

    if not findings:
        print("    No findings to prioritize.")
        result = {"metadata": {"total_findings": 0}, "prioritized_vulnerabilities": []}
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"    Empty results written to {args.output}")
        return

    # Show summary before API call
    scanners = set(f.get("scanner", "?") for f in findings)
    print(f"    Scanners: {', '.join(scanners)}")
    sevs = {}
    for f in findings:
        s = f.get("scanner_severity", "?")
        sevs[s] = sevs.get(s, 0) + 1
    print(f"    Severity breakdown: {sevs}")

    if args.dry_run:
        print("\n==> DRY RUN — skipping OpenAI call")
        result = {
            "metadata": {"total_findings": len(findings), "mode": "dry_run"},
            "unprioritized_findings": [
                {k: v for k, v in f.items() if k != "_hash"} for f in findings
            ],
        }
    else:
        # Step 2: Prioritize with AI
        print("\n==> Sending to OpenAI for AI-powered prioritization...")
        api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
        if not api_key:
            print("ERROR: Set OPENAI_API_KEY environment variable or pass --api-key")
            sys.exit(1)
        result = prioritize_with_openai(findings, model=args.model, api_key=api_key)

    # Step 3: Write output
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n==> Prioritized results written to {args.output}")

    # Print top findings
    vulns = result.get("prioritized_vulnerabilities", [])
    if vulns:
        print(f"\n{'='*70}")
        print(f"  TOP VULNERABILITIES (AI-PRIORITIZED)")
        print(f"{'='*70}")
        for v in vulns[:10]:
            rank = v.get("priority_rank", "?")
            sev = v.get("ai_severity", v.get("scanner_severity", "?"))
            title = v.get("title", "Unknown")[:65]
            cvss = v.get("cvss_estimate", "?")
            print(f"  #{rank:<3} [{sev:<12}] CVSS:{cvss:<4}  {title}")


if __name__ == "__main__":
    main()
