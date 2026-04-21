#!/usr/bin/env python3
"""
AI Sentinel — Azure AI Foundry Model Fetcher

Connects to Azure AI Foundry (Azure Machine Learning Workspaces)
and downloads registered model artifacts to a local cache for scanning.
Uses DefaultAzureCredential for seamless local/cloud auth.
"""

import os
from azure.identity import DefaultAzureCredential
try:
    from azure.ai.ml import MLClient
except ImportError:
    MLClient = None


def fetch_azure_models(subscription_id, resource_group, workspace_name, model_name, model_version="1", cache_dir="./azure_models_cache"):
    """
    Connects to Azure AI Foundry and downloads a specific registered model.
    """
    print("\n" + "=" * 60)
    print("  AZURE AI FOUNDRY MODEL FETCH")
    print("=" * 60)
    print(f"  Workspace:  {workspace_name}")
    print(f"  Model:      {model_name} (v{model_version})")
    print(f"  Cache Dir:  {cache_dir}")
    
    if MLClient is None:
        print("  [ERROR] azure-ai-ml package is not installed.")
        print("          Please run: pip install azure-ai-ml azure-identity")
        return False

    os.makedirs(cache_dir, exist_ok=True)
    
    try:
        # DefaultAzureCredential supports az login, environment variables, and managed identities
        credential = DefaultAzureCredential()
        ml_client = MLClient(
            credential=credential,
            subscription_id=subscription_id,
            resource_group_name=resource_group,
            workspace_name=workspace_name
        )
        
        print(f"  Authenticating to {workspace_name} and downloading model artifacts...")
        
        # Download the model to the cache directory
        ml_client.models.download(
            name=model_name,
            version=str(model_version),
            download_path=cache_dir
        )
                
        print("-" * 60)
        print(f"  Successfully fetched model '{model_name}' (v{model_version}) from Azure AI Foundry.")
        return True
        
    except Exception as e:
        print(f"  [ERROR] Failed to fetch model from Azure AI Foundry: {e}")
        if "AuthenticationFailed" in str(e) or "ClientAuthenticationError" in str(e):
            print("          If running locally, ensure you have run 'az login'.")
            print("          If in the cloud, ensure Managed Identity has AzureML permissions.")
        return False

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Fetch registered models from Azure AI Foundry")
    parser.add_argument("--subscription-id", required=True, help="Azure Subscription ID")
    parser.add_argument("--resource-group", required=True, help="Azure Resource Group")
    parser.add_argument("--workspace-name", required=True, help="Azure ML Workspace / AI Studio Project Name")
    parser.add_argument("--model-name", required=True, help="Registered Model Name")
    parser.add_argument("--model-version", default="1", help="Registered Model Version")
    parser.add_argument("--cache-dir", default="./azure_models_cache", help="Local directory to save models")
    args = parser.parse_args()
    
    fetch_azure_models(
        args.subscription_id, 
        args.resource_group, 
        args.workspace_name, 
        args.model_name, 
        args.model_version, 
        args.cache_dir
    )
