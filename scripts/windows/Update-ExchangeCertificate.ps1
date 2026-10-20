<#
.SYNOPSIS
    Keep an Exchange server's certificate in step with Certifi.

.DESCRIPTION
    Runs `certifi-cli request` for the given names, and when Certifi hands
    back a certificate that Exchange isn't using yet, imports it and enables
    it for the chosen services. The certificate it replaces can be removed
    afterwards with -RemoveOld.

    Safe to run as often as you like (it's meant for a daily scheduled task):
    when nothing changed it checks Exchange already has the current
    certificate enabled and exits without touching anything.

    Works with Exchange 2010 SP3 through Exchange 2019 / SE. Written for
    Windows PowerShell 2.0 so Exchange 2010's snap-in can be loaded with
    `powershell.exe -Version 2.0`; newer Exchange runs it on the default
    PowerShell. See docs/exchange.md.

.PARAMETER Domain
    Names on the certificate. The first is the subject (CN); the rest are
    SANs. Accepts an array or one comma-separated string — the latter is what
    a scheduled task's `-File` arguments deliver.

.PARAMETER Services
    Exchange services to enable the certificate for. Default: IIS,SMTP.

.EXAMPLE
    .\Update-ExchangeCertificate.ps1 -Domain mail.contoso.com,autodiscover.contoso.com -RemoveOld
#>
param(
    [Parameter(Mandatory = $true)]
    [string[]] $Domain,

    [string] $Services = 'IIS,SMTP',

    [string] $CertifiCli = "$env:ProgramFiles\Certifi\certifi-cli.exe",

    [string] $Config = "$env:ProgramData\Certifi\certifi.json",

    # Where the PFX, its password and the state file live. Keep it under the
    # locked-down %ProgramData%\Certifi folder — these files hold the key.
    [string] $WorkDir = "$env:ProgramData\Certifi\exchange",

    [string] $LogFile = "$env:ProgramData\Certifi\logs\exchange.log",

    # Remove the certificate this script installed last time, once the new
    # one is enabled. Only ever touches a thumbprint this script recorded.
    [switch] $RemoveOld,

    # Mark the imported private key exportable (e.g. to copy the cert to
    # another server). Off by default.
    [switch] $Exportable
)

$ErrorActionPreference = 'Stop'

function Write-Log([string] $Message) {
    $line = '{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $Message
    Write-Output $line
    Add-Content -Path $LogFile -Value $line
}

function Import-ExchangeShell {
    if (Get-Command Enable-ExchangeCertificate -ErrorAction SilentlyContinue) {
        return
    }
    # 2013 and later register "SnapIn"; 2010 registers "E2010". The snap-in
    # runs locally, so it works from a scheduled task with no remoting setup.
    $names = @(
        'Microsoft.Exchange.Management.PowerShell.SnapIn',
        'Microsoft.Exchange.Management.PowerShell.E2010'
    )
    foreach ($name in $names) {
        if (Get-PSSnapin -Registered -Name $name -ErrorAction SilentlyContinue) {
            Add-PSSnapin $name
            return
        }
    }
    throw 'No Exchange Management Shell snap-in found. Run this on the Exchange server (for Exchange 2010, start it with powershell.exe -Version 2.0).'
}

# Look a certificate up by thumbprint. Filtering the full list rather than
# using -Thumbprint, which fails differently on different Exchange versions
# when there's no match.
function Find-ExchangeCertificate([string] $Thumbprint) {
    Get-ExchangeCertificate | Where-Object { $_.Thumbprint -eq $Thumbprint } | Select-Object -First 1
}

foreach ($dir in @($WorkDir, (Split-Path -Parent $LogFile))) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

try {
    # A scheduled task passes "-Domain a,b" as a single string.
    $names = @($Domain | ForEach-Object { $_ -split ',' } |
        ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($names.Count -eq 0) {
        throw 'No -Domain given.'
    }

    $pfx = Join-Path $WorkDir 'exchange.pfx'
    $pwFile = Join-Path $WorkDir 'exchange.pfx.password'
    $leaf = "$pfx.crt"
    $stateFile = Join-Path $WorkDir 'installed.thumbprint'

    # ── 1. Ask Certifi for the cert ──────────────────────────────────────────
    $cliArgs = @('--config', $Config, 'request')
    foreach ($n in $names) { $cliArgs += @('-d', $n) }
    $cliArgs += @('--key-algo', 'rsa-2048', '--pfx', $pfx, '--pfx-password-file', $pwFile)

    Write-Log "Requesting certificate for $($names -join ', ')"
    if (-not (Test-Path $CertifiCli)) {
        throw "certifi-cli not found at $CertifiCli"
    }
    # certifi-cli reports progress on stderr. Windows PowerShell turns each
    # redirected stderr line into an error record, which 'Stop' would make
    # fatal — so relax it for this one call and judge by the exit code.
    $ErrorActionPreference = 'Continue'
    & $CertifiCli @cliArgs 2>&1 | ForEach-Object { Write-Log "  certifi-cli: $_" }
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    switch ($code) {
        0 { Write-Log 'Certifi: certificate unchanged.' }
        2 { Write-Log 'Certifi: new certificate written.' }
        3 { Write-Log 'Certifi: still issuing; the next run will pick it up.'; exit 0 }
        default { throw "certifi-cli exited with $code" }
    }

    # ── 2. Is Exchange already using it? ─────────────────────────────────────
    # Decided from Exchange itself, not the exit code, so a run that failed
    # halfway through is finished off by the next one.
    # The .crt is PEM; decode it to DER ourselves rather than rely on every
    # .NET version parsing PEM.
    $pem = [IO.File]::ReadAllText($leaf)
    $b64 = ($pem -replace '-----[A-Z ]+-----', '') -replace '\s', ''
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,[Convert]::FromBase64String($b64))
    $thumb = $cert.Thumbprint
    Write-Log "Current certificate: $thumb (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))"

    Import-ExchangeShell

    $wanted = @($Services -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $existing = Find-ExchangeCertificate $thumb
    if ($existing) {
        $enabled = "$($existing.Services)" -split ',\s*'
        $missing = @($wanted | Where-Object { $enabled -notcontains $_ })
        if ($missing.Count -eq 0) {
            Write-Log "Exchange already uses $thumb for $($wanted -join ', '). Nothing to do."
            exit 0
        }
    } else {
        # ── 3. Import ────────────────────────────────────────────────────────
        $password = ConvertTo-SecureString -String ([IO.File]::ReadAllText($pwFile).Trim()) -AsPlainText -Force
        $bytes = [IO.File]::ReadAllBytes($pfx)
        Import-ExchangeCertificate -FileData $bytes -Password $password `
            -PrivateKeyExportable $Exportable.IsPresent | Out-Null
        Write-Log "Imported $thumb into the local computer's certificate store."
    }

    # ── 4. Enable ────────────────────────────────────────────────────────────
    # -Force answers "overwrite the default SMTP certificate?" with yes.
    Enable-ExchangeCertificate -Thumbprint $thumb -Services ($wanted -join ',') -Force
    Write-Log "Enabled $thumb for $($wanted -join ', ')."

    # ── 5. Tidy up the one this replaced ─────────────────────────────────────
    $previous = $null
    if (Test-Path $stateFile) {
        $previous = ([IO.File]::ReadAllText($stateFile)).Trim()
    }
    Set-Content -Path $stateFile -Value $thumb
    if ($RemoveOld -and $previous -and $previous -ne $thumb) {
        if (Find-ExchangeCertificate $previous) {
            Remove-ExchangeCertificate -Thumbprint $previous -Confirm:$false
            Write-Log "Removed previous certificate $previous."
        }
    }

    exit 0
} catch {
    Write-Log "ERROR: $_ (line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim()))"
    exit 1
}
