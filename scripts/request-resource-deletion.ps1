<#
.SYNOPSIS
  Opens a multi-party approved deletion request for one protected resource.

.DESCRIPTION
  Starts the DeletionGuard-DeleteResource runbook in the current member account, in
  the guard's home region. Approvers are notified; after both approval levels pass,
  the DeletionGuard gate verifies the approvals and deletes the resource.

.EXAMPLE
  .\request-resource-deletion.ps1 -ResourceType AWS::DynamoDB::Table -ResourceIdentifier orders `
      -TargetRegion eu-west-1 -Justification 'Decommission legacy orders service - CHG-1234'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceType,
    [Parameter(Mandatory)] [string]$ResourceIdentifier,
    [Parameter(Mandatory)] [string]$TargetRegion,
    [Parameter(Mandatory)] [ValidateLength(20, 1000)] [string]$Justification,
    [switch]$DisableDeletionProtection,
    # Region where DeletionGuard is installed (defaults to the configured CLI region).
    [string]$HomeRegion
)
$ErrorActionPreference = 'Stop'
if (-not $HomeRegion) { $HomeRegion = $env:AWS_REGION }
if (-not $HomeRegion) { $HomeRegion = (aws configure get region) }
if (-not $HomeRegion) { throw 'Specify -HomeRegion or configure a default region.' }

$account = aws sts get-caller-identity --query Account --output text --no-cli-pager
if ($LASTEXITCODE -ne 0) { throw 'AWS credentials are not configured.' }

$request = @{
    DocumentName = 'DeletionGuard-DeleteResource'
    Parameters   = @{
        ResourceType              = @($ResourceType)
        ResourceIdentifier        = @($ResourceIdentifier)
        TargetRegion              = @($TargetRegion)
        Justification             = @($Justification)
        DisableDeletionProtection = @($DisableDeletionProtection.IsPresent.ToString().ToLower())
    }
}
# Pass the request as a file to avoid shell quoting issues with free-text justifications.
$tmp = New-TemporaryFile
try {
    $request | ConvertTo-Json -Depth 5 | Set-Content -Path $tmp -Encoding ascii
    $executionId = aws ssm start-automation-execution --cli-input-json "file://$tmp" --region $HomeRegion `
        --query AutomationExecutionId --output text --no-cli-pager
    if ($LASTEXITCODE -ne 0) { throw 'Could not start the deletion request.' }
}
finally {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host 'Deletion request submitted' -ForegroundColor Green
Write-Host "  Execution ID : $executionId"
Write-Host "  Account      : $account"
Write-Host "  Resource     : $ResourceType $ResourceIdentifier ($TargetRegion)"
Write-Host "  Track it     : https://$HomeRegion.console.aws.amazon.com/systems-manager/automation/execution/$executionId`?region=$HomeRegion"
Write-Host ''
Write-Host 'Approvers can approve with:'
Write-Host "  aws ssm send-automation-signal --automation-execution-id $executionId --signal-type Approve --payload Comment='<reason>' --region $HomeRegion"
