#!/usr/bin/env python3
"""
AI Sentinel — Main End-to-End Pipeline

This is the primary entrypoint for the application. It automatically connects:
1. Fetching models from Azure AI Foundry
2. Running the native Python security scanners (Sentinel Engine)
3. Prioritizing vulnerabilities via OpenAI
4. Generating a final Markdown report
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

# Add scripts directory to path to import our modules
SCRIPT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
sys.path.insert(0, SCRIPT_DIR)

from azure_fetch import fetch_azure_models
import importlib.util
spec = importlib.util.spec_from_file_location("sentinel_scan", os.path.join(SCRIPT_DIR, "sentinel-scan.py"))
sentinel_scan = importlib.util.module_from_spec(spec)
sys.modules["sentinel_scan"] = sentinel_scan
spec.loader.exec_module(sentinel_scan)
SentinelEngine = sentinel_scan.SentinelEngine
try:
    from prioritize_vulnerabilities import prioritize_with_openai
except ImportError:
    prioritize_with_openai = None


def generate_markdown_report(results: dict, out_dir: str, target: str):
    """Generate a final Markdown report from unified results."""
    report_path = os.path.join(out_dir, "REPORT.md")
    findings = results.get("prioritized", results).get("findings", results.get("findings", []))
    
    # If prioritized format
    if "prioritized_vulnerabilities" in results.get("prioritized", {}):
        findings = results["prioritized"]["prioritized_vulnerabilities"]
        
    lines = [
        "# AI Sentinel — Full Scan Report\n",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Target:** `{os.path.abspath(target)}`  ",
        f"**Duration:** {results['metadata'].get('duration_seconds', 0):.1f}s  \n",
        f"## Summary\n",
        f"**Total Findings:** {len(findings)}\n"
    ]
    
    for i, f in enumerate(findings[:50], 1):
        sev = f.get("ai_severity", f.get("scanner_severity", f.get("severity", "INFO")))
        title = f.get("title", "Unknown")
        scanner = f.get("scanner", "Unknown")
        lines.append(f"{i}. **[{sev}]** {title} (Source: {scanner})")
        if f.get("file"):
            lines.append(f"   - File: `{f.get('file')}`")
        if f.get("description"):
            desc = str(f.get("description")).replace('\n', ' ')[:200]
            lines.append(f"   - Details: {desc}...")
            
    if len(findings) > 50:
        lines.append(f"\n*... and {len(findings)-50} more findings*")
        
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return report_path


def run_pipeline(target_dir: str, config_dir: str = None, prioritize: bool = False, model: str = "gpt-4o", azure_config: dict = None):
    """Executes the complete pipeline end-to-end."""
    print("\n" + "=" * 60)
    print("  AI SENTINEL — END-TO-END PIPELINE")
    print("=" * 60)
    
    scan_target = os.path.abspath(target_dir)

    # ---------------------------------------------------------
    # Phase 1: Fetching
    # ---------------------------------------------------------
    if azure_config and all(azure_config.values()):
        try:
            cache_dir = os.path.join(os.path.dirname(SCRIPT_DIR), "azure_models_cache")
            success = fetch_azure_models(
                subscription_id=azure_config["subscription_id"], 
                resource_group=azure_config["resource_group"], 
                workspace_name=azure_config["workspace_name"], 
                model_name=azure_config["model_name"], 
                model_version=azure_config["model_version"], 
                cache_dir=cache_dir
            )
            if success:
                scan_target = cache_dir
            else:
                print("  [WARNING] Azure fetch failed or returned no models. Scanning original target.")
        except Exception as e:
            print(f"  [ERROR] Azure AI Foundry fetch crashed: {e}")

    # ---------------------------------------------------------
    # Phase 2: Scanning
    # ---------------------------------------------------------
    engine = SentinelEngine(scan_target, config_dir)
    results = engine.run_all()
    
    # ---------------------------------------------------------
    # Phase 3: AI Prioritization
    # ---------------------------------------------------------
    if prioritize and prioritize_with_openai and results["findings"]:
        print("\n==> Running AI Prioritization...")
        try:
            prioritized = prioritize_with_openai(results["findings"], model=model)
            results["prioritized"] = prioritized
        except Exception as e:
            print(f"  [ERROR] Prioritization failed: {e}")

    # ---------------------------------------------------------
    # Phase 4: Reporting
    # ---------------------------------------------------------
    out_dir = os.path.join(os.path.dirname(SCRIPT_DIR), "sentinel-results", datetime.now().strftime('%Y%m%d-%H%M%S'))
    os.makedirs(out_dir, exist_ok=True)
    
    json_path = os.path.join(out_dir, "all-findings.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)
        
    report_path = generate_markdown_report(results, out_dir, scan_target)

    print("\n" + "=" * 60)
    print("  PIPELINE COMPLETE")
    print("=" * 60)
    print(f"  Total unique findings: {results['metadata']['total_findings']}")
    print(f"  Duration: {results['metadata'].get('duration_seconds', 0):.1f}s")
    print(f"  JSON Artifact: {os.path.abspath(json_path)}")
    print(f"  Report Generated: {os.path.abspath(report_path)}")
    
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Sentinel End-to-End Pipeline")
    parser.add_argument("--target", default=".", help="Project directory to scan")
    parser.add_argument("--configs-dir", default=None, help="Configs directory")
    parser.add_argument("--prioritize", action="store_true", help="Use OpenAI to prioritize findings")
    parser.add_argument("--model", default="gpt-4o", help="OpenAI model for prioritization")
    
    # Azure AI Foundry Integration
    parser.add_argument("--azure-subscription-id", default=None, help="Azure Subscription ID")
    parser.add_argument("--azure-resource-group", default=None, help="Azure Resource Group")
    parser.add_argument("--azure-workspace-name", default=None, help="Azure AI Foundry Workspace")
    parser.add_argument("--azure-model-name", default=None, help="Registered Model Name")
    parser.add_argument("--azure-model-version", default="1", help="Registered Model Version")
    
    args = parser.parse_args()

    azure_config = None
    if args.azure_subscription_id and args.azure_workspace_name and args.azure_model_name:
        azure_config = {
            "subscription_id": args.azure_subscription_id,
            "resource_group": args.azure_resource_group,
            "workspace_name": args.azure_workspace_name,
            "model_name": args.azure_model_name,
            "model_version": args.azure_model_version
        }

    run_pipeline(
        target_dir=args.target,
        config_dir=args.configs_dir,
        prioritize=args.prioritize,
        model=args.model,
        azure_config=azure_config
    )
