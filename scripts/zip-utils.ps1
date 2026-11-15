# Cross-platform zip helper. Compress-Archive on Windows PowerShell 5.1 writes entry names
# with backslashes, which Linux (Lambda, CodeBuild) treats as part of the file name.
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function New-PortableZip {
    param(
        [Parameter(Mandatory)] [string]$SourceDirectory,
        [Parameter(Mandatory)] [string]$DestinationPath,
        [string[]]$Exclude = @()
    )
    $src = (Resolve-Path $SourceDirectory).Path.TrimEnd('\', '/')
    if (Test-Path $DestinationPath) { Remove-Item $DestinationPath -Force }
    $zip = [System.IO.Compression.ZipFile]::Open($DestinationPath, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        Get-ChildItem $src -Recurse -File -Force | ForEach-Object {
            $relative = $_.FullName.Substring($src.Length + 1).Replace('\', '/')
            $parts = $relative.Split('/')
            if ($parts | Where-Object { $Exclude -contains $_ }) { return }
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $zip, $_.FullName, $relative, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
        }
    }
    finally {
        $zip.Dispose()
    }
}
