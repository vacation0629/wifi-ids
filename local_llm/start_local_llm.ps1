param (
    [int]$Port = 1234,
    [int]$GpuLayers = 99
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ServerExe = Join-Path $ScriptDir "bin\llama-server.exe"
$ModelPath = Join-Path $ScriptDir "models\Nemotron-Mini-4B-Instruct-Q4_K_M.gguf"

if (-not (Test-Path $ServerExe)) {
    Write-Error "llama-server.exe not found at $ServerExe"
    exit 1
}

if (-not (Test-Path $ModelPath)) {
    Write-Error "Model file not found at $ModelPath"
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting Nemotron-Mini-4B with Vulkan on AMD RX 6700 XT " -ForegroundColor Cyan
Write-Host " Server Address: http://0.0.0.0:$Port                     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

& $ServerExe `
    -m $ModelPath `
    -ngl $GpuLayers `
    --port $Port `
    --host 0.0.0.0 `
    --ctx-size 4096 `
    --alias "nvidia/nemotron-mini-4b-instruct"
