<#
.SYNOPSIS
Installs and starts QN-Sentry with one command (#18), on Windows.

.DESCRIPTION
1. Checks that Docker is installed and running, with Docker Compose 2.24 or newer
2. Creates .env from .env.example with a generated database password and domain
   verification secret. An existing .env is kept: only the example values are replaced
3. Builds and starts every service, and waits until the API answers

Running it again is safe: it keeps .env and updates the containers. install.sh does the
same on Linux, macOS and Git Bash.

Windows blocks scripts by default; run it like this to allow it once:

    powershell -ExecutionPolicy Bypass -File .\install.ps1

.PARAMETER DomainVerificationSecret
The secret the team already uses, so the TXT records that were added keep working.
Only used when .env has no secret of its own yet.
#>
[CmdletBinding()]
param(
    [string]$DomainVerificationSecret = $env:DOMAIN_VERIFICATION_SECRET
)

# Native commands report errors through their exit code, not through PowerShell errors
$ErrorActionPreference = 'Continue'
Set-Location -LiteralPath $PSScriptRoot

$MinComposeMinor = 24 # 2.24: the version docs/installation.md requires
$ExamplePassword = 'change-me'
$ExampleSecret = 'change-me-to-at-least-32-random-characters'
$HealthUrl = 'http://127.0.0.1:8000/api/health'
$WaitSeconds = 180
$EnvFile = Join-Path $PSScriptRoot '.env'

# Compose must not see it: .env is the only source
Remove-Item Env:DOMAIN_VERIFICATION_SECRET -ErrorAction SilentlyContinue

function Write-Step([string]$Text) { Write-Host "`n==> $Text" -ForegroundColor Cyan }
function Write-Note([string]$Text) { Write-Host "    $Text" }
function Stop-Install([string]$Text) {
    Write-Host "`nError: $Text" -ForegroundColor Red
    exit 1
}

# Runs a native command without showing its output; true when it succeeded
function Test-Command([scriptblock]$Command) {
    & $Command 2>&1 | Out-Null
    return $LASTEXITCODE -eq 0
}

# ---------- 1. Requirements ----------

Write-Step 'Checking the requirements'
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Stop-Install 'Docker is not installed. Install Docker Desktop: https://docs.docker.com/desktop/setup/install/windows-install/'
}
if (-not (Test-Command { docker info })) {
    Stop-Install 'Docker is installed but not running. Start Docker Desktop, wait until it says it is running, and try again.'
}
$compose = (& docker compose version --short 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $compose) {
    Stop-Install 'The Docker Compose plugin is missing: update Docker Desktop.'
}
# e.g. "2.29.7", "v2.24.0" or "2.30.3-desktop.1"
$parts = $compose.TrimStart('v').Split('.')
$major = [int]($parts[0] -replace '\D.*$', '')
$minor = if ($parts.Count -gt 1) { [int]('0' + ($parts[1] -replace '\D.*$', '')) } else { 0 }
if ($major -lt 2 -or ($major -eq 2 -and $minor -lt $MinComposeMinor)) {
    Stop-Install "Docker Compose $compose is too old: 2.$MinComposeMinor or newer is needed (update Docker Desktop)."
}
$server = (& docker version --format '{{.Server.Version}}' 2>$null | Out-String).Trim()
Write-Note "Docker $server, Docker Compose $compose"
# Checked before .env is touched. Spaces, quotes or # would be read differently from .env
if ($DomainVerificationSecret -and $DomainVerificationSecret -notmatch '^[^\s#"'']{32,}$') {
    Stop-Install 'The secret must be at least 32 characters, without spaces, quotes or #.'
}

# ---------- 2. Configuration ----------

function New-RandomHex([int]$Bytes) {
    # The operating system's cryptographic random generator (Get-Random is not meant for secrets)
    $buffer = New-Object byte[] $Bytes
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($buffer) } finally { $generator.Dispose() }
    return -join ($buffer | ForEach-Object { $_.ToString('x2') })
}

function Get-EnvValue([string]$Key) {
    foreach ($line in [IO.File]::ReadAllLines($EnvFile)) {
        if ($line.StartsWith("$Key=")) { return $line.Substring($Key.Length + 1) }
    }
    return ''
}

function Set-EnvValue([string]$Key, [string]$Value) {
    $lines = @([IO.File]::ReadAllLines($EnvFile))
    $found = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i].StartsWith("$Key=")) {
            $lines[$i] = "$Key=$Value"
            $found = $true
        }
    }
    if (-not $found) { $lines += "$Key=$Value" }
    # Without a BOM: Docker Compose would read it as part of the first variable's name
    [IO.File]::WriteAllLines($EnvFile, [string[]]$lines, (New-Object Text.UTF8Encoding $false))
}

# The database volume of an earlier installation: its password is the one in that .env.
# The project name is the folder name, as Docker Compose makes it
$project = if ($env:COMPOSE_PROJECT_NAME) { $env:COMPOSE_PROJECT_NAME } else {
    (Split-Path -Leaf $PSScriptRoot).ToLower() -replace '[^a-z0-9_-]', ''
}
function Test-Database {
    $volumes = & docker volume ls -q `
        --filter "label=com.docker.compose.project=$project" `
        --filter 'label=com.docker.compose.volume=db-data' 2>$null
    return [bool]$volumes
}

Write-Step 'Preparing the configuration (.env)'
if (-not (Test-Path -LiteralPath $EnvFile)) {
    if (Test-Database) {
        Stop-Install ("There is no .env, but the database of an earlier installation still exists, and it only " +
            "accepts the password of that .env. Put the old .env back, or delete all clients, scans and findings " +
            "with 'docker compose down -v' and run this script again.")
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '.env.example') -Destination $EnvFile
    Write-Note 'Created .env from .env.example'
} else {
    Write-Note 'Keeping the existing .env'
}

$password = Get-EnvValue 'POSTGRES_PASSWORD'
if (-not $password -or $password -eq $ExamplePassword) {
    if (Test-Database) {
        # The database was made with this password: a new one would lock the services out
        Write-Note 'Warning: the database still uses the example password. Leaving it, since a new one would not match the existing database.'
    } else {
        Set-EnvValue 'POSTGRES_PASSWORD' (New-RandomHex 24)
        Write-Note 'Generated a database password'
    }
}

$secret = Get-EnvValue 'DOMAIN_VERIFICATION_SECRET'
if (-not $secret -or $secret -eq $ExampleSecret) {
    if ($DomainVerificationSecret) {
        Set-EnvValue 'DOMAIN_VERIFICATION_SECRET' $DomainVerificationSecret
        Write-Note 'Using the DOMAIN_VERIFICATION_SECRET that was given'
    } else {
        Set-EnvValue 'DOMAIN_VERIFICATION_SECRET' (New-RandomHex 32)
        Write-Note 'Generated a new DOMAIN_VERIFICATION_SECRET: every domain needs the TXT record the'
        Write-Note "dashboard shows for it. To keep the records the team already added, put the team's"
        Write-Note 'secret in .env instead and run this script again.'
    }
} elseif ($DomainVerificationSecret -and $DomainVerificationSecret -ne $secret) {
    Write-Note 'Warning: .env already has another DOMAIN_VERIFICATION_SECRET. Keeping it: changing it'
    Write-Note 'would invalidate every TXT record. Edit .env yourself if you really want to replace it.'
}

# ---------- 3. Start ----------

Write-Step 'Building and starting QN-Sentry (the first build takes a few minutes)'
& docker compose up -d --build
if ($LASTEXITCODE -ne 0) {
    & docker compose logs --tail 20 migrate api
    Stop-Install ("Not everything could be started; the last lines of the logs are above. A port already in use " +
        "is the most common cause, on Windows also a port that Windows reserved: see 'Ports already in use' in " +
        "docs/installation.md.")
}

Write-Step 'Waiting for the API'
$deadline = (Get-Date).AddSeconds($WaitSeconds)
while ($true) {
    try {
        $health = Invoke-RestMethod -Uri $HealthUrl -TimeoutSec 5
        if ($health.database -eq 'ok') { break }
    } catch {
        # Not answering yet
    }
    if ((Get-Date) -gt $deadline) {
        & docker compose logs --tail 20 api
        Stop-Install "The API did not answer within $WaitSeconds seconds; the last lines of its log are above."
    }
    Start-Sleep -Seconds 3
}

Write-Step 'QN-Sentry is running'
Write-Note 'Dashboard: http://localhost:8080'
Write-Note 'API:       http://localhost:8000/api/health'
Write-Note ''
Write-Note '.env holds the database password and the verification secret: keep a copy in a'
Write-Note 'password manager and never commit it. Next: docs/user-guide.md'
Write-Note "Stop with 'docker compose down'; your data is kept."
