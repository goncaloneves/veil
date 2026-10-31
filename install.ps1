& {
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue'

  $repo = 'goncaloneves/veil'
  $version = if ($env:VEIL_VERSION) { $env:VEIL_VERSION } else { 'latest' }
  $dir = if ($env:VEIL_INSTALL_DIR) { $env:VEIL_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\veil' }
  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { 'arm64' } else { 'x64' }
  $asset = "veil-windows-$arch.exe"
  $base = if ($version -eq 'latest') { "https://github.com/$repo/releases/latest/download" } else { "https://github.com/$repo/releases/download/$version" }

  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ('veil-' + [Guid]::NewGuid())
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    $download = Join-Path $tmp 'veil.exe'
    $sums = Join-Path $tmp 'SHA256SUMS'
    Write-Host "Downloading $asset ($version)"
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $download
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile $sums
    $expected = Get-Content $sums | ForEach-Object {
      $parts = $_ -split '\s+'
      if ($parts.Count -ge 2 -and $parts[1].TrimStart('*') -eq $asset) { $parts[0].ToLowerInvariant() }
    } | Select-Object -First 1
    $actual = (Get-FileHash -Algorithm SHA256 -Path $download).Hash.ToLowerInvariant()
    if (-not $expected -or $expected -ne $actual) {
      throw 'veil: the download does not match its published checksum; nothing was installed'
    }
    $installed = & $download version
    if ($LASTEXITCODE -ne 0) {
      throw 'veil: the downloaded build does not run on this system; nothing was installed'
    }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $target = Join-Path $dir 'veil.exe'
    Move-Item -Force -Path $download -Destination $target
    Write-Host "Installed veil $installed to $target"
    if (-not (($env:Path -split ';') -contains $dir)) {
      Write-Host "Add $dir to your PATH to run veil from anywhere."
    }
  } finally {
    Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
  }
}
