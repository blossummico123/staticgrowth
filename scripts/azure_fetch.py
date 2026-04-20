#!/usr/bin/env python3
"""
AI Sentinel — Azure Model Fetcher

Connects to Azure Blob Storage (where Azure ML stores models)
and downloads model artifacts to a local cache for scanning.
Uses DefaultAzureCredential for seamless local/cloud auth.
"""

import os
import sys
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError, ClientAuthenticationError

# Known model extensions to look for in the blob container
MODEL_EXTENSIONS = (
    ".pt", ".pth", ".pkl", ".pickle", ".h5", ".hdf5",
    ".onnx", ".safetensors", ".gguf", ".joblib", ".npy", ".bin", ".tflite", ".dill"
)

def fetch_azure_models(storage_url, container_name, cache_dir):
    """
    Connects to Azure Blob Storage and downloads model files.
    """
    print("\n" + "=" * 60)
    print("  AZURE MODEL FETCH")
    print("=" * 60)
    print(f"  Storage:   {storage_url}")
    print(f"  Container: {container_name}")
    print(f"  Cache Dir: {cache_dir}")
    
    os.makedirs(cache_dir, exist_ok=True)
    
    try:
        # DefaultAzureCredential supports az login, environment variables, and managed identities
        credential = DefaultAzureCredential()
        blob_service_client = BlobServiceClient(account_url=storage_url, credential=credential)
        container_client = blob_service_client.get_container_client(container_name)
        
        print("  Authenticating and listing blobs...")
        blob_list = container_client.list_blobs()
        
        downloaded = 0
        for blob in blob_list:
            if blob.name.lower().endswith(MODEL_EXTENSIONS):
                # Handle nested directories inside the blob container
                local_path = os.path.join(cache_dir, os.path.normpath(blob.name))
                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                
                print(f"  Downloading: {blob.name} ({(blob.size or 0) / 1024 / 1024:.2f} MB)")
                
                # Download the blob
                blob_client = container_client.get_blob_client(blob)
                with open(local_path, "wb") as f:
                    data = blob_client.download_blob()
                    data.readinto(f)
                downloaded += 1
                
        print("-" * 60)
        print(f"  Successfully fetched {downloaded} model(s) from Azure.")
        return downloaded > 0
        
    except ClientAuthenticationError:
        print("  [ERROR] Azure Authentication failed.")
        print("          If running locally, ensure you have run 'az login'.")
        print("          If in the cloud, ensure Managed Identity is assigned.")
        return False
    except ResourceNotFoundError:
        print(f"  [ERROR] Container '{container_name}' not found.")
        return False
    except Exception as e:
        print(f"  [ERROR] Failed to fetch models from Azure: {e}")
        return False

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Fetch models from Azure Blob Storage")
    parser.add_argument("--url", required=True, help="Azure Storage Account URL")
    parser.add_argument("--container", required=True, help="Container name")
    parser.add_argument("--cache-dir", default="./azure_models_cache", help="Local directory to save models")
    args = parser.parse_args()
    
    fetch_azure_models(args.url, args.container, args.cache_dir)
