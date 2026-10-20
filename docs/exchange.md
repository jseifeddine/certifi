# Exchange

Replace the certificate on an on-premises Exchange server (OWA, ActiveSync, Autodiscover, EWS, Outlook Anywhere and SMTP/TLS) with one from Certifi, and keep it renewed without anyone touching it again.

It works on **Exchange 2010 SP3 through Exchange 2019 / Subscription Edition**, on **Windows Server 2012 R2 and newer** (2008 R2 also works with the legacy CLI).

How it fits together:

```
Certifi server ──(daily renewal, DNS-01)──► always holds a current cert
       ▲
       │ certifi-cli request --pfx …        (scheduled task on the Exchange server, daily)
       │
Update-ExchangeCertificate.ps1 ──► Import-ExchangeCertificate ──► Enable-ExchangeCertificate -Services IIS,SMTP
```

The Exchange server never needs to be reachable from the internet for this. Certifi validates with DNS-01, and the Exchange box only makes outbound HTTPS calls to your Certifi server.

Follow [Windows](windows.md) first for the folder permissions, the binary and the machine-wide config. This page only covers what's specific to Exchange.

## Before you start

- **Names.** List every name clients use: usually the external URL host (`mail.contoso.com`) and `autodiscover.contoso.com`, plus any internal host names that differ. Public CAs can't issue for `.local` or other private suffixes. If your internal URLs use one, point them at the public name first (split-DNS) with `Set-OwaVirtualDirectory -InternalUrl` and its siblings.
- **RSA key.** Exchange 2010 and 2013 can't use ECDSA certificates, and on 2016/2019 ECC is an opt-in feature. The script always requests `--key-algo rsa-2048`. **The Certifi server must be 1.4.2 or later:** earlier versions fail to issue RSA certificates with more than one name ("CSR does not specify same identifiers as Order"). If a certificate for the same names already exists in Certifi with an EC key, re-issue it first: `certifi-cli renew mail.contoso.com --key-algo rsa-2048`.
- **Which CLI build.** Use `certifi-cli-<version>-windows-amd64-legacy.exe` on Server 2012 R2 (so Exchange 2010, 2013, and 2016 on 2012 R2) and the plain `-windows-amd64.exe` on 2016 and newer. [Windows → Downloads](windows.md#downloads) explains why.
- **API token.** Its role needs `certificate.create` and `certificate.download` for those names.
- **Root certificate.** Let's Encrypt chains to *ISRG Root X1*. Servers with automatic root updates (the default) already have it. On a server that's cut off from Windows Update, import it into *Trusted Root Certification Authorities* first, or Exchange marks the certificate as invalid.

## Install the script

The script is [`scripts/windows/Update-ExchangeCertificate.ps1`](../scripts/windows/Update-ExchangeCertificate.ps1) in the repository. Copy it next to the CLI's data:

```powershell
Copy-Item .\Update-ExchangeCertificate.ps1 "$env:ProgramData\Certifi\Update-ExchangeCertificate.ps1"
```

On each run it:

1. Runs `certifi-cli request -d <names> --key-algo rsa-2048 --pfx … --pfx-password-file …`. The CLI creates the certificate in Certifi the first time; after that it only writes a new PFX once Certifi has renewed the certificate.
2. Reads the certificate's thumbprint and asks Exchange whether that certificate is installed and enabled for the services you chose. If it is, it stops there. This check goes by Exchange's actual state, not the CLI's exit code, so a run that failed halfway is finished by the next one.
3. Otherwise imports the PFX with `Import-ExchangeCertificate` and runs `Enable-ExchangeCertificate -Services IIS,SMTP -Force`, which also binds it to the *Default Web Site* in IIS.
4. With `-RemoveOld`, removes the certificate the script installed last time. It only ever removes a thumbprint it recorded itself, never a certificate you installed by hand, and never the self-signed *Microsoft Exchange* certificate that the back end and hybrid/OAuth need.

Files it keeps under `C:\ProgramData\Certifi\exchange\`: `exchange.pfx`, `exchange.pfx.password`, `exchange.pfx.crt` (the leaf certificate, PEM) and `installed.thumbprint`. It logs to `C:\ProgramData\Certifi\logs\exchange.log`.

| Parameter | Default | |
|---|---|---|
| `-Domain` | *(required)* | Names; the first is the subject. An array, or one comma-separated string. |
| `-Services` | `IIS,SMTP` | Add `IMAP,POP` if clients use them over TLS. |
| `-RemoveOld` | off | Remove the previous certificate once the new one is enabled. |
| `-Exportable` | off | Import the private key as exportable. |
| `-CertifiCli` | `C:\Program Files\Certifi\certifi-cli.exe` | |
| `-Config` | `C:\ProgramData\Certifi\certifi.json` | |
| `-WorkDir`, `-LogFile` | under `C:\ProgramData\Certifi` | |

## First run, by hand

Do it interactively once, so any problem shows up on screen rather than in a task result. Use an elevated PowerShell on the Exchange server.

Not sure which Exchange you have? `Get-ChildItem HKLM:\SOFTWARE\Microsoft\ExchangeServer` lists `v14` for 2010 and `v15` for 2013 and later.

**All versions.** Run it on the default PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:ProgramData\Certifi\Update-ExchangeCertificate.ps1" -Domain mail.contoso.com,autodiscover.contoso.com
```

**Exchange 2010, only if that fails** with `No Exchange Management Shell snap-in found` or errors from the Exchange cmdlets: its snap-in sometimes needs the PowerShell 2.0 engine. First check that the engine can start at all:

```powershell
powershell.exe -Version 2.0 -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'   # expect 2.0
```

If that prints `2.0`, run the script the same way with `-Version 2.0` added after `powershell.exe`, and add it to the task below too. If it errors, the engine isn't installed: `Install-WindowsFeature PowerShell-V2`. Don't put `-Version 2.0` in a task without this check. When the engine is missing, powershell.exe exits immediately with `0xFFFF0000` and the script never runs.

Then check:

```powershell
Get-ExchangeCertificate | Format-Table Thumbprint, Services, NotAfter, Subject -AutoSize
```

The new certificate should list `IIS, SMTP`. Browse to `https://mail.contoso.com/owa` and look at the certificate. Exchange 2010 sometimes keeps serving the old certificate until IIS restarts; if so, run `iisreset /noforce` once. Later renewals update the binding in place.

Once you're happy with it, remove the certificate you replaced by hand, *after* checking that nothing else uses it (`Get-ExchangeCertificate -Thumbprint <old> | fl Services`):

```powershell
Remove-ExchangeCertificate -Thumbprint <old thumbprint>
```

## Schedule it

The same account options as in [Windows → scheduled task](windows.md#4-create-the-scheduled-task) apply, with one extra for Exchange:

- **SYSTEM** (recommended). The local snap-in acts as the Exchange server's own computer account, which already has the rights `Enable-ExchangeCertificate` needs.
- **A service account** needs everything listed on the Windows page (local Administrators, Log on as a batch job, access to `C:\ProgramData\Certifi`) **plus** membership of the Exchange **Organization Management** role group. Enabling a certificate for SMTP writes to the server's object in Active Directory.

```powershell
$script = "$env:ProgramData\Certifi\Update-ExchangeCertificate.ps1"
$names  = 'mail.contoso.com,autodiscover.contoso.com'

# Only for Exchange 2010 that needed it above: put "-Version 2.0 " at the start.
$arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass " +
             "-File `"$script`" -Domain $names -RemoveOld"

$action   = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
$trigger  = New-ScheduledTaskTrigger -Daily -At 3:17am -RandomDelay (New-TimeSpan -Minutes 30)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
              -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName 'Certifi Exchange certificate' `
  -Action $action -Trigger $trigger -Settings $settings `
  -User 'NT AUTHORITY\SYSTEM' -RunLevel Highest
```

For a service account, register with `-User`/`-Password` (or `-Principal` for a gMSA) as shown on the [Windows](windows.md#4-create-the-scheduled-task) page.

Test it under the task's account straight away:

```powershell
Start-ScheduledTask -TaskName 'Certifi Exchange certificate'
Start-Sleep 60
Get-ScheduledTaskInfo -TaskName 'Certifi Exchange certificate' | Select LastRunTime, LastTaskResult
Get-Content "$env:ProgramData\Certifi\logs\exchange.log" -Tail 20
```

The script exits `0` when the certificate is in place (whether or not anything changed) and `1` on any error, with the reason in the log.

## Several Exchange servers

Run the task on **each** server, with the same `-Domain` list. Certifi recognises the same set of names and returns the same certificate to all of them (its `request` is idempotent), so every server behind the load balancer serves an identical certificate and they all switch within a day of a renewal.

## Edge Transport

An Edge server isn't domain-joined and has no IIS. Install the CLI the same way, run the script with `-Services SMTP`, and afterwards **re-create the Edge subscription** (`New-EdgeSubscription` on the Edge server, then import it on a Mailbox server). Exchange requires that whenever the Edge server's SMTP certificate changes. That step isn't automated, so leave the Edge server on a manually renewed certificate unless you're prepared to handle it every renewal.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| CLI exits immediately; "entry point not found" in the event log | Plain `-windows-amd64.exe` on Server 2012 R2 or older; use the `-legacy` build. |
| "VCRUNTIME140.dll is missing" | A 1.4.0 build; those needed the Visual C++ Redistributable. Use 1.4.1 or later. |
| `No Exchange Management Shell snap-in found` | Not on an Exchange server, or an Exchange 2010 snap-in that needs `-Version 2.0`; see [First run](#first-run-by-hand). |
| Task "completes" at once; result `0xFFFF0000` (4294901760), no log written | powershell.exe couldn't start the requested engine, almost always `-Version 2.0` without the 2.0 engine or .NET 3.5. Remove `-Version 2.0` from the task's arguments. |
| `CSR does not specify same identifiers as Order` | Certifi server older than 1.4.2: RSA certificates with several names fail. Upgrade the server (`docker compose pull && docker compose up -d`), then run the script again. |
| `certifi-cli exited with 1` and `401`/`403` in the log | The token is wrong or its role lacks `certificate.create` / `certificate.download` for one of the names. |
| `No URL/token available` when run as the task | The task's account can't read `C:\ProgramData\Certifi\certifi.json`. Check the folder permissions. |
| Exchange shows the certificate as *Invalid* | The chain doesn't build: import *ISRG Root X1* into Trusted Root, then `Get-ExchangeCertificate` again. |
| OWA still shows the old certificate | `iisreset /noforce`, or check the *Default Web Site* binding in IIS Manager. Leave the *Exchange Back End* site's binding on the self-signed certificate. |
| Outlook prompts about a name mismatch | A client-facing URL uses a name that isn't on the certificate. Compare `Get-ClientAccessServer \| fl AutoDiscoverServiceInternalUri` (`Get-ClientAccessService` on 2016 and later) and each virtual directory's `InternalUrl`/`ExternalUrl` with your `-Domain` list. |
