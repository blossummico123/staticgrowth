#!/usr/bin/env python3
"""
AI Sentinel — Azure AI Foundry Model Discovery & Fetcher

Connects to Azure AI Foundry (Azure Machine Learning Workspaces),
discovers all registered models, lets the user select which ones to scan
(interactively or via CLI filters), and downloads them to a local cache.

Modes:
  --discover          Interactive mode: list models, prompt for selection
  --scan-all          Headless: download every model (latest version)
  --filter-name       Headless: glob pattern on model name
  --filter-tag        Headless: key=value tag match
  --filter-type       Headless: model type match (custom_model, mlflow_model, etc.)
  --model-name        Legacy: fetch a single specific model

Uses DefaultAzureCredential for seamless local/cloud auth.
"""

import fnmatch
import os
import shutil
import sys

from azure.identity import DefaultAzureCredential

try:
    from azure.ai.ml import MLClient
except ImportError:
    MLClient = None


# ── Constants ────────────────────────────────────────────────────────

_SEPARATOR = "=" * 70
_THIN_SEP = "─" * 70


# ── Model Discovery ─────────────────────────────────────────────────

def _create_ml_client(subscription_id, resource_group, workspace_name):
    """Authenticate and return an MLClient instance."""
    if MLClient is None:
        print("  [ERROR] azure-ai-ml package is not installed.")
        print("          Run: pip install azure-ai-ml azure-identity")
        return None

    credential = DefaultAzureCredential()
    return MLClient(
        credential=credential,
        subscription_id=subscription_id,
        resource_group_name=resource_group,
        workspace_name=workspace_name,
    )


def list_workspace_models(subscription_id, resource_group, workspace_name):
    """
    Discover all registered models in an Azure ML workspace.

    Returns a flat list of dicts — one entry per (model, version) pair:
      [
        {"name": "bert-base", "version": "2", "type": "mlflow_model",
         "description": "...", "tags": {...}, "stage": "Production"},
        ...
      ]

    The list is sorted by model name (ascending), then version (descending).
    """
    print(f"\n{_SEPARATOR}")
    print("  AZURE MODEL DISCOVERY")
    print(_SEPARATOR)
    print(f"  Workspace:     {workspace_name}")
    print(f"  Resource Group: {resource_group}")
    print(f"  Subscription:  {subscription_id}")
    print(f"  Connecting...")

    ml_client = _create_ml_client(subscription_id, resource_group, workspace_name)
    if ml_client is None:
        return []

    try:
        raw_models = ml_client.models.list()
    except Exception as e:
        print(f"  [ERROR] Failed to list models: {e}")
        _print_auth_hint(e)
        return []

    # Build flat list: one entry per (name, version)
    models = []
    for m in raw_models:
        models.append({
            "name": m.name,
            "version": str(m.version),
            "type": getattr(m, "type", None) or "custom_model",
            "description": (getattr(m, "description", None) or "")[:120],
            "tags": dict(m.tags) if m.tags else {},
            "stage": getattr(m, "stage", "") or "",
        })

    # Sort: name ascending, then version descending (newest first)
    models.sort(key=lambda x: (x["name"], -_version_key(x["version"])))

    print(f"  Found {len(models)} model version(s) across {len(set(m['name'] for m in models))} model(s).\n")
    return models


# ── Display ──────────────────────────────────────────────────────────

def display_model_table(models):
    """
    Print a formatted table of discovered models to stdout.

    Each row is a unique (model, version) pair. Columns:
      #  |  Model Name  |  Version  |  Type  |  Stage  |  Tags  |  Description
    """
    if not models:
        print("  No models found in this workspace.\n")
        return

    # Column headers
    header = (
        f"  {'#':>4}  "
        f"{'Model Name':<32}  "
        f"{'Ver':>5}  "
        f"{'Type':<16}  "
        f"{'Stage':<12}  "
        f"{'Tags':<24}  "
        f"{'Description'}"
    )
    print(header)
    print(f"  {_THIN_SEP}")

    for idx, m in enumerate(models, 1):
        tags_str = ", ".join(f"{k}={v}" for k, v in list(m["tags"].items())[:2])
        if len(m["tags"]) > 2:
            tags_str += "…"

        row = (
            f"  {idx:>4}  "
            f"{m['name']:<32}  "
            f"v{m['version']:>4}  "
            f"{m['type']:<16}  "
            f"{m['stage'] or '—':<12}  "
            f"{tags_str:<24}  "
            f"{m['description'][:35]}"
        )
        print(row)

    # Summary
    unique_names = set(m["name"] for m in models)
    print(f"  {_THIN_SEP}")
    print(f"  {len(models)} version(s) across {len(unique_names)} model(s)\n")


# ── Interactive Selection ────────────────────────────────────────────

def prompt_model_selection(models):
    """
    Interactively prompt the user to select models from the table.

    Supports:
      - Individual indices:  1,3,5
      - Ranges:              1-5
      - Mixed:               1,3-7,10
      - 'all' to select everything
      - 'q' to abort

    Returns a list of selected model dicts.
    """
    if not models:
        return []

    display_model_table(models)

    while True:
        try:
            raw = input("  Select models to scan (e.g. 1,3,5 | 1-5 | all | q): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Aborted.")
            return []

        if raw == "q":
            print("  Scan cancelled.")
            return []

        if raw == "all":
            print(f"  Selected all {len(models)} model version(s).")
            return list(models)

        selected = _parse_selection(raw, len(models))
        if selected is None:
            print("  Invalid input. Use numbers like 1,3,5 or 1-5 or 'all' or 'q'.")
            continue

        chosen = [models[i] for i in selected]
        print(f"  Selected {len(chosen)} model version(s):")
        for m in chosen:
            print(f"    • {m['name']} v{m['version']}")
        print()
        return chosen


def _parse_selection(raw, max_idx):
    """
    Parse a comma-separated selection string with optional ranges.
    Returns a sorted list of 0-based indices, or None if invalid.
    """
    indices = set()
    parts = [p.strip() for p in raw.split(",") if p.strip()]

    for part in parts:
        if "-" in part:
            bounds = part.split("-", 1)
            try:
                start, end = int(bounds[0]), int(bounds[1])
            except ValueError:
                return None
            if start < 1 or end > max_idx or start > end:
                return None
            indices.update(range(start - 1, end))  # convert to 0-based
        else:
            try:
                val = int(part)
            except ValueError:
                return None
            if val < 1 or val > max_idx:
                return None
            indices.add(val - 1)

    return sorted(indices) if indices else None


# ── Headless Filtering ───────────────────────────────────────────────

def filter_models(models, name_pattern=None, tag_filter=None, type_filter=None):
    """
    Filter a model list in headless/CI mode.

    Args:
        name_pattern: Glob pattern matched against model name (e.g. "bert*").
        tag_filter:   "key=value" string matched against model tags.
        type_filter:  Exact match on model type (e.g. "mlflow_model").

    Returns a filtered list of model dicts.
    """
    result = list(models)

    if name_pattern:
        result = [m for m in result if fnmatch.fnmatch(m["name"], name_pattern)]

    if tag_filter and "=" in tag_filter:
        key, val = tag_filter.split("=", 1)
        result = [m for m in result if m["tags"].get(key.strip()) == val.strip()]

    if type_filter:
        result = [m for m in result if m["type"] == type_filter]

    return result


# ── Model Downloading ────────────────────────────────────────────────

def fetch_azure_models(
    subscription_id,
    resource_group,
    workspace_name,
    models_to_fetch=None,
    model_name=None,
    model_version="1",
    cache_dir="./azure_models_cache",
):
    """
    Download one or more registered models from Azure AI Foundry.

    Supports two calling conventions:
      1. Batch mode (new): pass `models_to_fetch` as a list of
         {"name": ..., "version": ...} dicts.
      2. Legacy mode: pass `model_name` and `model_version` directly.

    Models are downloaded sequentially. Existing cache entries for a model
    are wiped and re-downloaded every time (no incremental caching).

    Returns:
        dict: {"success": [list of downloaded models], "failed": [list of failed models]}
        bool: (legacy mode only) True if the single model was fetched successfully.
    """
    # Normalise to batch format
    if models_to_fetch is None:
        if model_name is None:
            print("  [ERROR] No models specified for download.")
            return False
        # Legacy single-model mode
        models_to_fetch = [{"name": model_name, "version": str(model_version)}]
        legacy_mode = True
    else:
        legacy_mode = False

    print(f"\n{_SEPARATOR}")
    print("  AZURE AI FOUNDRY MODEL FETCH")
    print(_SEPARATOR)
    print(f"  Workspace:  {workspace_name}")
    print(f"  Models:     {len(models_to_fetch)} to download")
    print(f"  Cache Dir:  {os.path.abspath(cache_dir)}")
    print(f"  Mode:       Sequential | Always re-download")

    ml_client = _create_ml_client(subscription_id, resource_group, workspace_name)
    if ml_client is None:
        return False if legacy_mode else {"success": [], "failed": models_to_fetch}

    success = []
    failed = []

    for idx, entry in enumerate(models_to_fetch, 1):
        name = entry["name"]
        version = str(entry["version"])
        model_dir = os.path.join(cache_dir, name, f"v{version}")

        print(f"\n  [{idx}/{len(models_to_fetch)}] {name} v{version}")

        # Always wipe and re-download
        if os.path.exists(model_dir):
            print(f"    Clearing existing cache: {model_dir}")
            shutil.rmtree(model_dir, ignore_errors=True)

        os.makedirs(model_dir, exist_ok=True)

        try:
            ml_client.models.download(
                name=name,
                version=version,
                download_path=model_dir,
            )
            print(f"    ✓ Downloaded to {model_dir}")
            success.append(entry)
        except Exception as e:
            print(f"    ✗ Failed: {e}")
            _print_auth_hint(e)
            failed.append({**entry, "error": str(e)})

    # Summary
    print(f"\n{_THIN_SEP}")
    print(f"  Download complete: {len(success)} succeeded, {len(failed)} failed")
    if failed:
        for f in failed:
            print(f"    ✗ {f['name']} v{f['version']}: {f.get('error', 'unknown')[:80]}")
    print()

    if legacy_mode:
        return len(success) > 0

    return {"success": success, "failed": failed}


# ── Orchestration (combines discovery + selection + fetch) ───────────

def discover_and_fetch(
    subscription_id,
    resource_group,
    workspace_name,
    cache_dir="./azure_models_cache",
    scan_all=False,
    filter_name=None,
    filter_tag=None,
    filter_type=None,
):
    """
    High-level orchestrator: discover models, select, and download.

    In interactive mode (TTY + no filters), shows the table and prompts.
    In headless mode (--scan-all or --filter-*), selects automatically.

    Returns:
        tuple: (bool success, str scan_target_path)
    """
    # Step 1: Discover
    models = list_workspace_models(subscription_id, resource_group, workspace_name)
    if not models:
        print("  No models found. Nothing to fetch.")
        return False, None

    # Step 2: Select
    if scan_all:
        selected = models
        print(f"  --scan-all: selecting all {len(selected)} model version(s).")
    elif filter_name or filter_tag or filter_type:
        selected = filter_models(models, filter_name, filter_tag, filter_type)
        print(f"  Filters applied: {len(selected)} of {len(models)} version(s) matched.")
        if selected:
            display_model_table(selected)
        else:
            print("  No models matched the filters.")
            return False, None
    elif sys.stdin.isatty():
        selected = prompt_model_selection(models)
        if not selected:
            return False, None
    else:
        # Non-interactive, no filters — default to listing only
        print("  [INFO] Non-interactive terminal detected. Use --scan-all or --filter-* flags.")
        display_model_table(models)
        return False, None

    # Step 3: Fetch sequentially
    result = fetch_azure_models(
        subscription_id=subscription_id,
        resource_group=resource_group,
        workspace_name=workspace_name,
        models_to_fetch=[{"name": m["name"], "version": m["version"]} for m in selected],
        cache_dir=cache_dir,
    )

    if isinstance(result, dict) and result["success"]:
        return True, os.path.abspath(cache_dir)
    return False, None


# ── Helpers ──────────────────────────────────────────────────────────

def _version_key(version_str):
    """Convert a version string to a sortable integer. Non-numeric → 0."""
    try:
        return int(version_str)
    except (ValueError, TypeError):
        return 0


def _print_auth_hint(exception):
    """Print helpful auth hints if the error looks like an authentication failure."""
    err_str = str(exception)
    if "AuthenticationFailed" in err_str or "ClientAuthenticationError" in err_str:
        print("          If running locally, ensure you have run 'az login'.")
        print("          If in the cloud, ensure Managed Identity has AzureML permissions.")


# ── CLI Entrypoint ───────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Discover and fetch registered models from Azure AI Foundry",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive discovery — list all models, pick which to scan
  python azure_fetch.py --subscription-id X --resource-group Y --workspace-name Z --discover

  # Headless — scan every model in the workspace
  python azure_fetch.py --subscription-id X --resource-group Y --workspace-name Z --scan-all

  # Headless — filter by name glob and tag
  python azure_fetch.py --subscription-id X --resource-group Y --workspace-name Z \\
      --filter-name "bert*" --filter-tag "env=production"

  # Legacy — fetch a single model by name and version
  python azure_fetch.py --subscription-id X --resource-group Y --workspace-name Z \\
      --model-name my-model --model-version 2
        """,
    )

    # Required Azure connection params
    parser.add_argument("--subscription-id", required=True, help="Azure Subscription ID")
    parser.add_argument("--resource-group", required=True, help="Azure Resource Group")
    parser.add_argument("--workspace-name", required=True, help="Azure ML Workspace / AI Studio Project Name")
    parser.add_argument("--cache-dir", default="./azure_models_cache", help="Local directory to save models")

    # Discovery mode
    mode_group = parser.add_argument_group("Discovery Mode")
    mode_group.add_argument("--discover", action="store_true", help="Interactive: list all models and prompt for selection")
    mode_group.add_argument("--scan-all", action="store_true", help="Headless: download every model version")
    mode_group.add_argument("--filter-name", default=None, help="Headless: glob pattern to match model names (e.g. 'bert*')")
    mode_group.add_argument("--filter-tag", default=None, help="Headless: filter by tag as 'key=value'")
    mode_group.add_argument("--filter-type", default=None, help="Headless: filter by model type (e.g. 'mlflow_model')")

    # Legacy single-model mode
    legacy_group = parser.add_argument_group("Legacy Mode (single model)")
    legacy_group.add_argument("--model-name", default=None, help="Registered Model Name")
    legacy_group.add_argument("--model-version", default="1", help="Registered Model Version")

    args = parser.parse_args()

    # Determine which mode to run
    is_discovery = args.discover or args.scan_all or args.filter_name or args.filter_tag or args.filter_type
    is_legacy = args.model_name is not None

    if is_discovery:
        success, target = discover_and_fetch(
            subscription_id=args.subscription_id,
            resource_group=args.resource_group,
            workspace_name=args.workspace_name,
            cache_dir=args.cache_dir,
            scan_all=args.scan_all,
            filter_name=args.filter_name,
            filter_tag=args.filter_tag,
            filter_type=args.filter_type,
        )
        sys.exit(0 if success else 1)

    elif is_legacy:
        success = fetch_azure_models(
            subscription_id=args.subscription_id,
            resource_group=args.resource_group,
            workspace_name=args.workspace_name,
            model_name=args.model_name,
            model_version=args.model_version,
            cache_dir=args.cache_dir,
        )
        sys.exit(0 if success else 1)

    else:
        # No mode specified — default to interactive discovery
        success, target = discover_and_fetch(
            subscription_id=args.subscription_id,
            resource_group=args.resource_group,
            workspace_name=args.workspace_name,
            cache_dir=args.cache_dir,
        )
        sys.exit(0 if success else 1)
