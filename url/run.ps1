$ErrorActionPreference = "Stop"

function Assert-Command($name) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    throw "Komut bulunamadi: $name. Python'u kurup PATH'e ekleyin veya Windows Python Launcher (py) kurulu olsun."
  }
}

Assert-Command "py"

Write-Host 
if (-not (Test-Path ".\.venv")) {
  py -m venv .venv
}

$python = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
  throw ".venv icinde python.exe bulunamadi. .venv klasorunu silip tekrar deneyin."
}

Write-Host 
& $python -m pip install -U pip
& $python -m pip install -r requirements.txt

if (-not (Test-Path ".\model.pkl")) {
  Write-Host 
  & $python .\main.py
}

Write-Host 
& $python .\gui.py
