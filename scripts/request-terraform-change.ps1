<#
.SYNOPSIS
  Opens a multi-party approved Terraform change (destroy, or an apply that deletes/replaces resources).

.DESCRIPTION
  Optionally zips and uploads a local Terraform root module, then starts the
  DeletionGuard-TerraformChange runbook. The gate produces a plan with a read-only
  role, approvers review that plan, and exactly that plan is applied after approval.

.EXAMPLE
  .\request-terraform-change.ps1 -SourceDirectory ..\examples\terraform-sample -SourceBucket my-tf-sources `
      -Operation destroy -Justification 'Remove the sample stack after the PoC - CHG-1235'

.EXAMPLE
  .\request-terraform-change.ps1 -SourceBucket my-tf-sources -SourceKey apps/billing/v42.zip `
      -Operation apply -Justification 'Replace the billing DB with the encrypted one - CHG-1300'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$SourceBucket,
    [string]$SourceKey,
    [string]$SourceDirectory,
    [string]$WorkingDirectory = '.',
    [Parameter(Mandatory)] [ValidateSet('destroy', 'apply')] [string]$Operation,
    [Parameter(Mandatory)] [ValidateLength(20, 1000)] [string]$Justification,
    [string]$HomeRegion
)
$ErrorActionPreference = 'Stop'
if (-not $HomeRegion) { $HomeRegion = $env:AWS_REGION }
if (-not $HomeRegion) { $HomeRegion = (aws configure get region) }
if (-not $HomeRegion) { throw 'Specify -HomeRegion or configure a default region.' }
if (-not $SourceKey -and -not $SourceDirectory) { throw 'Specify -SourceKey (existing zip) or -SourceDirectory (to upload).' }

if ($SourceDirectory) {
    $dir = (Resolve-Path $SourceDirectory).Path
    $name = Split-Path $dir -Leaf
    $SourceKey = "deletion-guard-sources/$name-$(Get-Date -Format 'yyyyMMddHHmmss').zip"
    $zip = Join-Path ([System.IO.Path]::GetTempPath()) "$name-$([guid]::NewGuid()).zip"
    . (Join-Path $PSScriptRoot 'zip-utils.ps1')
    # Exclude local state and provider caches.
    New-PortableZip -SourceDirectory $dir -DestinationPath $zip `
        -Exclude @('.terraform', 'terraform.tfstate', 'terraform.tfstate.backup', 'tfplan')
    aws s3 cp $zip "s3://$SourceBucket/$SourceKey" --only-show-errors --no-cli-pager
    if ($LASTEXITCODE -ne 0) { throw 'Upload of the Terraform source failed.' }
    Remove-Item $zip -Force
    Write-Host "Uploaded $dir to s3://$SourceBucket/$SourceKey"
}

$request = @{
    DocumentName = 'DeletionGuard-TerraformChange'
    Parameters   = @{
        SourceBucket     = @($SourceBucket)
        SourceKey        = @($SourceKey)
        WorkingDirectory = @($WorkingDirectory)
        Operation        = @($Operation)
        Justification    = @($Justification)
    }
}
$tmp = New-TemporaryFile
try {
    $request | ConvertTo-Json -Depth 5 | Set-Content -Path $tmp -Encoding ascii
    $executionId = aws ssm start-automation-execution --cli-input-json "file://$tmp" --region $HomeRegion `
        --query AutomationExecutionId --output text --no-cli-pager
    if ($LASTEXITCODE -ne 0) { throw 'Could not start the Terraform change request.' }
}
finally {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}

$account = aws sts get-caller-identity --query Account --output text --no-cli-pager
Write-Host ''
Write-Host 'Terraform change request submitted' -ForegroundColor Green
Write-Host "  Execution ID : $executionId"
Write-Host "  Source       : s3://$SourceBucket/$SourceKey ($Operation)"
Write-Host "  Plan (after the plan step): s3://deletion-guard-plans-$account-$HomeRegion/plans/$executionId/plan.txt"
Write-Host "  Track it     : https://$HomeRegion.console.aws.amazon.com/systems-manager/automation/execution/$executionId`?region=$HomeRegion"
