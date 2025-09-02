param(
    [string]$component_dir,
    [string]$cfg # driver configuration (free/checked)
)

echo "Building PV drivers ($cfg)..."

if (! (Test-Path -Path "env:QB_SCRIPTS")) {
  echo "[!] QB_SCRIPTS variable not set"
  exit 1
}

if (! (Test-Path -Path "env:EnterpriseWDK")) {
  . $env:QB_SCRIPTS\common.ps1
  $env:EWDK_PATH = Find-EWDK
  Launch-EWDK
}

foreach ($driver in @("xenbus", "xeniface", "xenvbd", "xenvif", "xennet")) {
  echo "Building $driver"
  cd "$component_dir\$driver"
  if (! (Test-Path "$driver\x64")) {
    New-Item -Path "$driver\x64" -ItemType Directory -Force
  }
  & .\build.ps1 $cfg x64 Off # no signing
}
