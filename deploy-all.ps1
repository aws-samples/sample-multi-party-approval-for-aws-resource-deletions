<#
.SYNOPSIS
  Deploys DeletionGuard to an AWS Organization.

.DESCRIPTION
  Run with credentials for the management account (or a delegated administrator
  for StackSets and Organizations policies), in the guard's home region.

  1. Checks prerequisites and shows what will be deployed.
  2. Deploys the central artifacts bucket (DeletionGuardArtifacts-<region>).
  3. Packages and uploads the gate Lambda and the member-account template.
  4. Deploys DeletionGuardOrg-<region>: the service-managed StackSet that installs the
     guard in every account of the target OUs, and (if attachScps=true) the two SCPs.

.PARAMETER ConfigPath
  Path to the guard configuration. Defaults to guard-config.json next to this script.

.PARAMETER Yes
  Skip the confirmation prompt.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'guard-config.json'),
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Root = $PSScriptRoot
$CdkDir = Join-Path $Root 'infrastructure/cdk'
$BuildDir = Join-Path $Root 'build'

function Write-Step([string]$Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Invoke-Checked([scriptblock]$Command, [string]$What) {
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$What failed (exit code $LASTEXITCODE)" }
}
function Get-ContentHash([string[]]$Files) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = New-Object System.IO.MemoryStream
    foreach ($f in ($Files | Sort-Object)) {
        $rel = [System.Text.Encoding]::UTF8.GetBytes($f.Substring($Root.Length))
        $stream.Write($rel, 0, $rel.Length)
        $bytes = [System.IO.File]::ReadAllBytes($f)
        $stream.Write($bytes, 0, $bytes.Length)
    }
    $hash = $sha.ComputeHash($stream.ToArray())
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 16)
}

# ---------------------------------------------------------------------------- prerequisites
Write-Step 'Checking prerequisites'
foreach ($cmd in @('aws', 'node', 'npm')) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "'$cmd' is required but was not found in PATH." }
}
if (-not (Test-Path $ConfigPath)) {
    throw "Configuration not found: $ConfigPath. Copy guard-config.example.json to guard-config.json and edit it."
}
$ConfigPath = (Resolve-Path $ConfigPath).Path
$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

$identityJson = aws sts get-caller-identity --output json --no-cli-pager
if ($LASTEXITCODE -ne 0) { throw 'AWS credentials are not configured (aws sts get-caller-identity failed).' }
$identity = $identityJson | ConvertFrom-Json

$region = $env:AWS_REGION
if (-not $region) { $region = $env:AWS_DEFAULT_REGION }
if (-not $region) { $region = (aws configure get region) }
if (-not $region) { throw 'No AWS region configured. Set AWS_REGION or run: aws configure set region <region>' }
$env:AWS_REGION = $region

$orgId = aws organizations describe-organization --query 'Organization.Id' --output text --no-cli-pager
if ($LASTEXITCODE -ne 0 -or -not $orgId) { throw 'Could not read the AWS Organization. Run this from the management or a delegated administrator account.' }

Write-Host ''
Write-Host "  Account        : $($identity.Account)  ($($identity.Arn))"
Write-Host "  Home region    : $region"
Write-Host "  Organization   : $orgId"
Write-Host "  Target OUs     : $($config.organizationalUnitIds -join ', ')"
Write-Host "  Target regions : $($config.allowedTargetRegions -join ', ')"
Write-Host "  Attach SCPs    : $($config.attachScps)" -ForegroundColor $(if ($config.attachScps) { 'Yellow' } else { 'Gray' })
if ($config.attachScps) {
    Write-Host ''
    Write-Host '  The SCPs will block destructive actions for EVERY identity in the target OUs' -ForegroundColor Yellow
    Write-Host '  except the DeletionGuard executor roles. Test on a sandbox OU first.' -ForegroundColor Yellow
}
if (-not $Yes) {
    $answer = Read-Host "`nProceed? (y/N)"
    if ($answer -notin @('y', 'Y', 'yes')) { Write-Host 'Aborted.'; exit 1 }
}

# ---------------------------------------------------------------------------- CDK dependencies & bootstrap
Write-Step 'Installing CDK dependencies'
Push-Location $CdkDir
try {
    Invoke-Checked { npm ci --no-fund --no-audit } 'npm ci'

    $null = aws cloudformation describe-stacks --stack-name CDKToolkit --region $region --no-cli-pager 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Step "Bootstrapping CDK in $($identity.Account)/$region"
        Invoke-Checked { npx cdk bootstrap "aws://$($identity.Account)/$region" } 'cdk bootstrap'
    }

    # ------------------------------------------------------------------------ artifacts bucket
    $artifactsStack = "DeletionGuardArtifacts-$region"
    Write-Step "Deploying $artifactsStack"
    Invoke-Checked {
        npx cdk deploy $artifactsStack -c "organizationId=$orgId" -c "configPath=$ConfigPath" --require-approval never
    } 'cdk deploy (artifacts)'
    $bucket = aws cloudformation describe-stacks --stack-name $artifactsStack --region $region `
        --query "Stacks[0].Outputs[?OutputKey=='ArtifactsBucketName'].OutputValue" --output text --no-cli-pager

    # ------------------------------------------------------------------------ gate package
    Write-Step 'Packaging the gate Lambda'
    $gateSrc = Join-Path $Root 'src/deletion_gate'
    $resolverSrc = Join-Path $Root 'src/approver_resolver'
    $gateFiles = Get-ChildItem $gateSrc, $resolverSrc -Recurse -File -Filter '*.py' | ForEach-Object { $_.FullName }
    $gateHash = Get-ContentHash $gateFiles
    $staging = Join-Path $BuildDir 'gate'
    if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
    New-Item -ItemType Directory -Path (Join-Path $staging 'deletion_gate') -Force | Out-Null
    Get-ChildItem $gateSrc -File -Filter '*.py' | Copy-Item -Destination (Join-Path $staging 'deletion_gate')
    New-Item -ItemType Directory -Path (Join-Path $staging 'approver_resolver') -Force | Out-Null
    Get-ChildItem $resolverSrc -File -Filter '*.py' | Copy-Item -Destination (Join-Path $staging 'approver_resolver')
    $zip = Join-Path $BuildDir "gate-$gateHash.zip"
    . (Join-Path $Root 'scripts/zip-utils.ps1')
    New-PortableZip -SourceDirectory $staging -DestinationPath $zip
    $gateKey = "lambda/gate-$gateHash.zip"
    Invoke-Checked { aws s3 cp $zip "s3://$bucket/$gateKey" --only-show-errors --no-cli-pager } 'upload gate package'

    # ------------------------------------------------------------------------ member template
    Write-Step 'Synthesizing the member-account template'
    Invoke-Checked { npx cdk synth DeletionGuardMember -c "configPath=$ConfigPath" --quiet } 'cdk synth (member)'
    $template = Join-Path $CdkDir 'cdk.out/DeletionGuardMember.template.json'
    $templateHash = Get-ContentHash @($template)
    $templateKey = "templates/member-$templateHash.json"
    Invoke-Checked { aws s3 cp $template "s3://$bucket/$templateKey" --only-show-errors --no-cli-pager } 'upload member template'

    # ------------------------------------------------------------------------ org stack
    $orgStack = "DeletionGuardOrg-$region"
    Write-Step "Deploying $orgStack (StackSet rollout can take several minutes)"
    Invoke-Checked {
        npx cdk deploy $orgStack `
            -c "organizationId=$orgId" -c "configPath=$ConfigPath" -c "artifactsBucket=$bucket" `
            -c "gateCodeKey=$gateKey" -c "memberTemplateKey=$templateKey" `
            --require-approval never
    } 'cdk deploy (org)'
}
finally {
    Pop-Location
}

# ---------------------------------------------------------------------------- summary
$instances = aws cloudformation list-stack-instances --stack-set-name 'DeletionGuard-Member' --call-as $config.stackSetCallAs `
    --region $region --query 'Summaries[].[Account,StackInstanceStatus.DetailedStatus]' --output text --no-cli-pager

Write-Host ''
Write-Host '========================================' -ForegroundColor Green
Write-Host '  DeletionGuard deployment complete' -ForegroundColor Green
Write-Host '========================================' -ForegroundColor Green
Write-Host ''
Write-Host "  Home region       : $region" -ForegroundColor Cyan
Write-Host "  Artifacts bucket  : $bucket" -ForegroundColor Cyan
Write-Host "  StackSet          : DeletionGuard-Member" -ForegroundColor Cyan
Write-Host "  SCPs attached     : $($config.attachScps)" -ForegroundColor Cyan
Write-Host '  Stack instances   :' -ForegroundColor Cyan
if ($instances) { $instances -split "`n" | ForEach-Object { Write-Host "    $_" } } else { Write-Host '    (none yet)' }
Write-Host ''
Write-Host '  Request a deletion from a member account (home region):' -ForegroundColor Cyan
Write-Host "    .\scripts\request-resource-deletion.ps1 -ResourceType AWS::DynamoDB::Table -ResourceIdentifier <table> -TargetRegion <region> -Justification '<why>'"
$tfImage = if ($config.terraform.PSObject.Properties.Name -contains 'buildImage') { $config.terraform.buildImage } else { '' }
if ($tfImage) {
    Write-Host '  Request a Terraform destroy:' -ForegroundColor Cyan
    Write-Host "    .\scripts\request-terraform-change.ps1 -SourceDirectory .\examples\terraform-sample -SourceBucket <bucket> -Operation destroy -Justification '<why>'"
} else {
    Write-Host '  Terraform approval path: not deployed (set terraform.buildImage to enable it)' -ForegroundColor Yellow
}
Write-Host ''
