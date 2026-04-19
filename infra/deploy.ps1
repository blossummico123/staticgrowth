<#
.SYNOPSIS
    AI Sentinel - One-command Azure deployment
.DESCRIPTION
    Builds Docker image, pushes to ACR, and runs Terraform to deploy.
.EXAMPLE
    .\infra\deploy.ps1 -OpenAIApiKey "sk-your-key"
    .\infra\deploy.ps1 -OpenAIApiKey "sk-your-key" -Destroy
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$OpenAIApiKey,

    [string]$Location = "eastus",
    [string]$ImageTag = "latest",
    [switch]$Destroy,
    [switch]$PlanOnly
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$InfraDir = Join-Path $ProjectRoot "infra"

# Ensure terraform is on PATH
if (-not (Get-Command terraform -ErrorAction SilentlyContinue)) {
    if (Test-Path "C:\terraform\terraform.exe") {
        $env:Path = "C:\terraform;" + $env:Path
    }
}

Write-Host ""
Write-Host "========================================"
Write-Host "  AI Sentinel - Azure Deployment"
Write-Host "========================================"
Write-Host ""

# -- Step 0: Validate tools --
$requiredTools = @("az", "terraform", "docker")
foreach ($tool in $requiredTools) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Host "ERROR: $tool is required but not installed."
        Write-Host "Install from:"
        Write-Host "  az:        https://learn.microsoft.com/en-us/cli/azure/install-azure-cli"
        Write-Host "  terraform: https://developer.hashicorp.com/terraform/downloads"
        Write-Host "  docker:    https://docs.docker.com/desktop/install/windows-install/"
        exit 1
    }
}

# -- Step 1: Azure login check --
Write-Host "[1/6] Checking Azure login..."
$account = az account show 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Host "  Logging in to Azure..."
    az login
    $account = az account show | ConvertFrom-Json
}
Write-Host "  Logged in as: $($account.user.name)"
Write-Host "  Subscription: $($account.id)"

# -- Step 2: Terraform init --
Write-Host ""
Write-Host "[2/6] Initializing Terraform..."
Push-Location $InfraDir
terraform init -upgrade
Pop-Location

# -- Handle destroy --
if ($Destroy) {
    Write-Host ""
    Write-Host "[DESTROY] Destroying all resources..."
    Push-Location $InfraDir
    terraform destroy `
        -var "openai_api_key=$OpenAIApiKey" `
        -var "location=$Location"
    Pop-Location
    Write-Host "  Resources destroyed."
    exit 0
}

# -- Step 3: Terraform plan --
if ($PlanOnly) {
    Write-Host ""
    Write-Host "[3/6] Planning infrastructure..."
    Push-Location $InfraDir
    terraform plan `
        -var "openai_api_key=$OpenAIApiKey" `
        -var "location=$Location" `
        -var "container_image_tag=$ImageTag"
    Pop-Location
    Write-Host "  Plan complete. Remove -PlanOnly to apply."
    exit 0
}

# -- Step 4: Terraform apply (creates ACR first) --
Write-Host ""
Write-Host "[4/6] Creating Azure resources..."
Push-Location $InfraDir
terraform apply `
    "-target=azurerm_resource_group.main" `
    "-target=azurerm_container_registry.acr" `
    "-target=azurerm_user_assigned_identity.api_identity" `
    "-target=azurerm_role_assignment.acr_pull" `
    "-target=azurerm_log_analytics_workspace.logs" `
    "-target=azurerm_storage_account.storage" `
    "-target=azurerm_key_vault.kv" `
    "-target=azurerm_container_app_environment.env" `
    -var "openai_api_key=$OpenAIApiKey" `
    -var "location=$Location" `
    -var "container_image_tag=$ImageTag" `
    -auto-approve
Pop-Location

# -- Step 5: Build and push Docker image --
Write-Host ""
Write-Host "[5/6] Building and pushing Docker image..."

# Get ACR name from Terraform output
Push-Location $InfraDir
$acrServer = (terraform output -raw acr_login_server)
Pop-Location

Write-Host "  ACR: $acrServer"

# Login to ACR
az acr login --name ($acrServer -replace '\.azurecr\.io$','')

# Build and push
Push-Location $ProjectRoot
docker build -t "${acrServer}/ai-sentinel-api:${ImageTag}" .
docker push "${acrServer}/ai-sentinel-api:${ImageTag}"
Pop-Location

Write-Host "  Image pushed: ${acrServer}/ai-sentinel-api:${ImageTag}"

# -- Step 6: Update Container App to pull new image --
Write-Host ""
Write-Host "[6/6] Updating Container App..."
Push-Location $InfraDir
terraform apply `
    -var "openai_api_key=$OpenAIApiKey" `
    -var "location=$Location" `
    -var "container_image_tag=$ImageTag" `
    -auto-approve
Pop-Location

# -- Done --
Write-Host ""
Write-Host "========================================"
Write-Host "  Deployment complete!"
Write-Host "========================================"

Push-Location $InfraDir
$apiUrl = terraform output -raw api_url
$docsUrl = terraform output -raw swagger_ui_url
Pop-Location

Write-Host ""
Write-Host "  API URL:     $apiUrl"
Write-Host "  Swagger UI:  $docsUrl"
Write-Host ""
Write-Host "  Test with:"
Write-Host "    curl ${apiUrl}/api/v1/health"
Write-Host ""
