# Windows

`certifi-cli.exe` keeps certificates on a Windows server up to date: a scheduled task runs it daily, it fetches the current certificate from your Certifi server, and only when that changed does it write new files and run your reload step. This page covers installing it, where its configuration lives, and the scheduled task, including which account it runs as.

Running Exchange? [Exchange](exchange.md) builds on this page with a ready-made script.

## Downloads

Each [release](https://github.com/jseifeddine/certifi/releases/latest) attaches:

| File | Runs on |
|---|---|
| `certifi-cli-<version>-windows-amd64.exe` | Windows 10 / Server 2016 and newer |
| `certifi-cli-<version>-windows-amd64-legacy.exe` | Windows 7 / Server 2008 R2, 2012, **2012 R2** |
| `certifi-<version>-windows-amd64.exe` | The server itself, Windows 10 / Server 2016 and newer |

Rust's standard Windows target dropped Windows 7, 8.1 and Server 2012 R2 in Rust 1.78. On those systems the normal `.exe` exits straight away with an "entry point not found" error. The `-legacy` build targets `x86_64-win7-windows-msvc` instead, so use it on 2012 R2. Check `SHA256SUMS-<version>-windows-amd64.txt` before installing.

The `.exe` files are self-contained: the C runtime is linked in, so they don't need the Visual C++ Redistributable. **1.4.0 was the exception.** Its Windows builds fail to start with "VCRUNTIME140.dll is missing" on a machine without the redistributable, so use 1.4.1 or later. Compatibility mode in the file's properties doesn't help and isn't needed.

Every CI run on a pull request also uploads the three `.exe` files as the `certifi-windows-amd64` artifact (Actions → the run → Artifacts), for testing a change before it's released.

## Layout

| Path | What |
|---|---|
| `C:\Program Files\Certifi\certifi-cli.exe` | The binary. Rename the downloaded file to `certifi-cli.exe`. |
| `C:\ProgramData\Certifi\certifi.json` | Machine-wide CLI config (server URL + API token). |
| `C:\ProgramData\Certifi\…` | Certificates, keys and logs the task writes. |

`%ProgramData%` is the right home for this: it's machine-wide, it's the same folder whichever account the task runs as, and it isn't a user profile that can be deleted or roam.

### Which config file the CLI reads

1. `--config <path>` or `CERTIFI_CONFIG`, when given.
2. `%APPDATA%\certifi.json`, the current user's own config, when it exists.
3. `%ProgramData%\Certifi\certifi.json` otherwise.

So a task running as **SYSTEM** or a service account, neither of which has a per-user config, picks up the machine-wide file without any flags. `CERTIFI_URL` / `CERTIFI_TOKEN` still override whichever file is used. `certifi-cli init` writes `%APPDATA%\certifi.json` unless you pass `--config`.

## Set up

Run these in an **elevated** PowerShell on the server.

### 1. Lock down the folder first

By default every user on the machine can read new folders under `C:\ProgramData`. This folder will hold an API token and private keys, so cut it down to SYSTEM and Administrators *before* putting anything in it. Files created later inherit these permissions.

```powershell
$dir = "$env:ProgramData\Certifi"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
# SYSTEM (S-1-5-18) and Administrators (S-1-5-32-544), nobody else.
# SIDs rather than names so this works on non-English Windows.
icacls $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
```

If the task will run as a service account rather than SYSTEM (step 4), give it access too:

```powershell
icacls $dir /grant 'CONTOSO\svc-certifi:(OI)(CI)M'
```

### 2. Install the binary

```powershell
New-Item -ItemType Directory -Force -Path "$env:ProgramFiles\Certifi" | Out-Null
# The -legacy build on Server 2012 R2 and older; the plain one on 2016+.
Copy-Item .\certifi-cli-<version>-windows-amd64-legacy.exe "$env:ProgramFiles\Certifi\certifi-cli.exe"
& "$env:ProgramFiles\Certifi\certifi-cli.exe" --version
```

### 3. Write the machine-wide config

Create an API token in the web admin (Settings → API Tokens) for a role that can **create** and **download** certificates for the names this server needs, and nothing more. Then:

```powershell
& "$env:ProgramFiles\Certifi\certifi-cli.exe" --config "$env:ProgramData\Certifi\certifi.json" init
& "$env:ProgramFiles\Certifi\certifi-cli.exe" list     # proves the config and token work
```

### 4. Create the scheduled task

Choose the account the task runs as:

- **SYSTEM** (`NT AUTHORITY\SYSTEM`). The simplest option: no password to manage or expire, full access to the local machine's certificate store, and it can restart services. Use it unless your policy says otherwise.
- **A dedicated service account**, e.g. `CONTOSO\svc-certifi`. It needs:
  - membership of the server's local **Administrators** group, to write the local machine's certificate store and private keys and to restart IIS or other services;
  - **Log on as a batch job**. Task Scheduler grants this when you register the task with the account's password; a Group Policy that sets "Log on as a batch job" overrides that, so the account must be listed there too;
  - Modify access to `C:\ProgramData\Certifi` (the second `icacls` in step 1);
  - a password that doesn't expire, or a reminder to update the task when it does. A [group managed service account](https://learn.microsoft.com/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview) (gMSA) avoids passwords entirely (option c below).

Either way the task runs **whether or not anyone is logged on**, with highest privileges.

The action below writes PEM files and recycles IIS when they change. Swap the `request` arguments for what your service needs: `--pfx` / `--pfx-password-file` for a PKCS#12 archive, `--fullchain` / `--privkey` for PEM. See [CLI](cli.md).

```powershell
$cli  = "$env:ProgramFiles\Certifi\certifi-cli.exe"
$arguments = 'request -d app.contoso.com ' +
        "--fullchain `"$env:ProgramData\Certifi\app\fullchain.pem`" " +
        "--privkey `"$env:ProgramData\Certifi\app\privkey.pem`" " +
        '--reload-cmd "iisreset /noforce"'

$action   = New-ScheduledTaskAction -Execute $cli -Argument $arguments
# A random delay spreads many servers' requests out.
$trigger  = New-ScheduledTaskTrigger -Daily -At 3:17am -RandomDelay (New-TimeSpan -Minutes 30)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
              -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew
```

Then register it as **one** of:

```powershell
# a) SYSTEM
Register-ScheduledTask -TaskName 'Certifi certificate refresh' `
  -Action $action -Trigger $trigger -Settings $settings `
  -User 'NT AUTHORITY\SYSTEM' -RunLevel Highest
```

```powershell
# b) a service account. The password is stored by Task Scheduler, not in the task definition.
$cred = Get-Credential 'CONTOSO\svc-certifi'
Register-ScheduledTask -TaskName 'Certifi certificate refresh' `
  -Action $action -Trigger $trigger -Settings $settings `
  -User $cred.UserName -Password $cred.GetNetworkCredential().Password -RunLevel Highest
```

```powershell
# c) a gMSA (note the trailing $). No password; the domain rotates it.
$principal = New-ScheduledTaskPrincipal -UserId 'CONTOSO\svc-certifi$' -LogonType Password -RunLevel Highest
Register-ScheduledTask -TaskName 'Certifi certificate refresh' `
  -Action $action -Trigger $trigger -Settings $settings -Principal $principal
```

Prefer the GUI? In Task Scheduler → *Create Task…*: on **General**, *Change User or Group…* → `SYSTEM` (or the service account), tick *Run whether user is logged on or not* and *Run with highest privileges*; add a daily trigger on **Triggers**; on **Actions**, set *Program* to `C:\Program Files\Certifi\certifi-cli.exe` and *Arguments* to the `request …` line.

### 5. Test it as that account

Don't wait for 3am:

```powershell
Start-ScheduledTask -TaskName 'Certifi certificate refresh'
Start-Sleep 30
Get-ScheduledTaskInfo -TaskName 'Certifi certificate refresh' | Select LastRunTime, LastTaskResult
```

`LastTaskResult` is the CLI's exit code: `0` = nothing changed, `2` = new files written and reload ran, `3` = still issuing (the next run picks it up), `1` = error. Task Scheduler shows a `2` as a non-zero result; that's expected the first time.

Task Scheduler doesn't keep the CLI's output. To see it, run the same command interactively *as SYSTEM* with [PsExec](https://learn.microsoft.com/sysinternals/downloads/psexec) (`psexec -s -i powershell.exe`). For a permanent log, point the task at a one-line `C:\ProgramData\Certifi\refresh.cmd` instead:

```bat
"C:\Program Files\Certifi\certifi-cli.exe" request -d app.contoso.com --fullchain "C:\ProgramData\Certifi\app\fullchain.pem" --privkey "C:\ProgramData\Certifi\app\privkey.pem" --reload-cmd "iisreset /noforce" >> "C:\ProgramData\Certifi\refresh.log" 2>&1
```

A `.cmd` file passes the CLI's exit code back to Task Scheduler as its own.

## Running the server on Windows

`certifi-<version>-windows-amd64.exe` is the full server. With no `DATA_DIR` set it keeps its database in `%ProgramData%\Certifi\data`, and it reads environment variables from `%ProgramData%\Certifi\certifi.env` (same format as `.env`) as well as from the environment and a `.env` in the working directory. Lock the folder down as in step 1: the database holds every certificate's private key.

There's no Windows service wrapper. Run it at startup with a scheduled task (trigger *At startup*, account SYSTEM, no execution time limit), or under a service wrapper such as [WinSW](https://github.com/winsw/winsw) or NSSM. The Docker image is still the main supported way to run the server; see [Installation](installation.md).
