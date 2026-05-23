//! certifi-cli — command-line client for the Certifi server.
//!
//! Designed for cron use: the `request` subcommand is idempotent on the
//! server side and writes output files atomically. Exit codes signal what
//! the caller's reload-on-change wrapper should do.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use certifi_client::{Auth, Client, IntegrationKind};
use certifi_types::{
    normalize_host, CreateIntegrationRequest, IssueCertRequest, UpdateIntegrationRequest,
};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ── Exit codes (acme.sh / cron convention) ───────────────────────────────────
// Picked so cron wrappers can branch on $? without parsing stdout.
const EXIT_OK_UNCHANGED: u8 = 0;
const EXIT_ERROR: u8 = 1;
const EXIT_OK_CHANGED: u8 = 2;
const EXIT_TIMEOUT: u8 = 3;

#[derive(Parser, Debug)]
#[command(
    name = "certifi-cli",
    version,
    about = "Client for the Certifi cert manager"
)]
struct Cli {
    /// Path to the config file. Defaults to platform user-config location.
    #[arg(short, long, env = "CERTIFI_CONFIG", global = true)]
    config: Option<PathBuf>,

    /// Override the server URL (or set CERTIFI_URL).
    #[arg(short = 'u', long, env = "CERTIFI_URL", global = true)]
    url: Option<String>,

    /// Override the API token (or set CERTIFI_TOKEN).
    #[arg(short = 't', long, env = "CERTIFI_TOKEN", global = true)]
    token: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Interactively prompt for URL + token and write the config file.
    Init,
    /// List all certificates.
    List,
    /// Show one certificate by id or common name.
    Get { target: String },
    /// Force-renew a certificate.
    Renew { target: String },
    /// Delete a certificate.
    Delete { target: String },
    /// Request a cert (idempotent) and optionally write its files to disk.
    Request(RequestArgs),
    /// Fetch documentation served by the connected Certifi server.
    ///
    /// `docs` with no slug prints the table of contents; `docs <slug>`
    /// prints the raw markdown of that topic. The server bakes the
    /// contents of `/docs` into its binary at compile time, so what you
    /// see here is what's pinned to that server's version — no drift
    /// from what shipped.
    Docs {
        /// Doc slug (e.g. `api`, `cli`). Omit to list available topics.
        slug: Option<String>,
    },

    /// Manage DNS integrations. Indispensable for headless deployments
    /// where the web admin isn't running.
    #[command(subcommand)]
    Integrations(IntegrationsCmd),
}

#[derive(Subcommand, Debug)]
enum IntegrationsCmd {
    /// List configured integrations.
    #[command(alias = "ls")]
    List,
    /// Show the available integration kinds (PowerDNS, Cloudflare, ...).
    /// With `--kind`, print the full field list for that one kind.
    Kinds {
        /// Kind id to drill into (e.g. `pdns`). Omit for the overview.
        #[arg(long)]
        kind: Option<String>,
    },
    /// Show one configured integration.
    Show { id: String },
    /// Create a new integration. With every `--kind`/`--name`/`--config`
    /// flag supplied, this is fully non-interactive; otherwise it falls
    /// back to a prompt for each missing piece.
    Add(AddIntegrationArgs),
    /// Update an existing integration. Each `--config k=v` overrides one
    /// field; pass an empty value to clear (e.g. `--config pdns_server=`).
    /// Pass `--enable` / `--disable` to flip the enabled flag.
    Update(UpdateIntegrationArgs),
    /// Delete an integration. The cert renewal scheduler will skip any
    /// remaining cert whose domains aren't covered by another integration.
    #[command(alias = "rm")]
    Delete { id: String },
    /// Probe the integration by listing zones. Returns whatever the
    /// configured credentials can see; non-2xx if the upstream rejects.
    Test { id: String },
}

#[derive(Args, Debug)]
struct AddIntegrationArgs {
    /// One of the kinds shown by `certifi-cli integrations kinds`.
    #[arg(long)]
    kind: Option<String>,
    /// Display name (free-text).
    #[arg(long)]
    name: Option<String>,
    /// Repeated `key=value` config entries. Omit to be prompted for each
    /// required field. Use the kind's field id (e.g. `pdns_url`, `cf_api_token`).
    #[arg(long = "config", value_name = "key=value", num_args = 0..)]
    config: Vec<String>,
    /// Start the integration disabled (default: enabled).
    #[arg(long, default_value_t = false)]
    disabled: bool,
}

#[derive(Args, Debug)]
struct UpdateIntegrationArgs {
    id: String,
    /// New display name.
    #[arg(long)]
    name: Option<String>,
    /// Repeated `key=value` config entries to merge.
    #[arg(long = "config", value_name = "key=value", num_args = 0..)]
    config: Vec<String>,
    #[arg(long, conflicts_with = "disable")]
    enable: bool,
    #[arg(long, conflicts_with = "enable")]
    disable: bool,
}

#[derive(Args, Debug)]
struct RequestArgs {
    /// First value is the Subject CN; subsequent values are SANs. May be
    /// repeated (-d a -d b) or space-separated (-d a b).
    #[arg(short = 'd', long = "domain", required = true, num_args = 1..)]
    domains: Vec<String>,

    /// Write the issuer chain + leaf to this path.
    #[arg(long)]
    fullchain: Option<PathBuf>,
    /// Write the leaf certificate (no chain) to this path.
    #[arg(long)]
    cert: Option<PathBuf>,
    /// Write the issuer chain only to this path.
    #[arg(long)]
    chain: Option<PathBuf>,
    /// Write the private key to this path. On Unix this file is created 0600.
    #[arg(long)]
    privkey: Option<PathBuf>,

    /// Seconds to wait for the server to issue a new cert.
    #[arg(long, default_value_t = 300)]
    timeout: u64,

    /// Polling interval (seconds) while waiting for issuance.
    #[arg(long, default_value_t = 1)]
    poll_interval: u64,

    /// Shell command to run if any output file was written. Useful for
    /// `--reload-cmd "systemctl reload nginx"` in a cron job.
    #[arg(long)]
    reload_cmd: Option<String>,

    /// Enable / disable auto-renewal on the server when a new cert is created.
    /// Ignored on dedup hits — existing cert's setting is preserved.
    #[arg(long)]
    auto_renew: Option<bool>,

    /// Override the server's default key algorithm for a new cert.
    #[arg(long)]
    key_algo: Option<String>,

    /// Optional free-text description stored on the cert. Ignored on dedup
    /// hits (existing cert's description is preserved).
    #[arg(long)]
    description: Option<String>,
}

// ── Config file ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfigFile {
    url: String,
    token: String,
}

fn default_config_path() -> Result<PathBuf> {
    // Match the user-facing convention of ~/.config/certifi.json on Unix-likes
    // (including macOS), and %APPDATA%\certifi.json on Windows.
    #[cfg(windows)]
    {
        Ok(dirs::config_dir()
            .ok_or_else(|| anyhow!("could not locate %APPDATA%"))?
            .join("certifi.json"))
    }
    #[cfg(not(windows))]
    {
        Ok(dirs::home_dir()
            .ok_or_else(|| anyhow!("could not locate home directory"))?
            .join(".config")
            .join("certifi.json"))
    }
}

fn load_config(path: &Path) -> Result<Option<ConfigFile>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(
            serde_json::from_str(&s).context("config file is not valid JSON")?,
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context(format!("reading config at {}", path.display())),
    }
}

fn save_config(path: &Path, cfg: &ConfigFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(cfg)? + "\n";
    write_file_secure(path, body.as_bytes(), /* private = */ true)?;
    Ok(())
}

/// Resolve effective (url, token) by precedence:
///   1. explicit --url / --token flags (which clap maps from CERTIFI_URL / CERTIFI_TOKEN)
///   2. the config file (if present)
///
/// If neither is available, returns an error pointing the user to `init`.
fn resolve_creds(cli: &Cli, config_path: &Path) -> Result<(String, String)> {
    if let (Some(u), Some(t)) = (cli.url.as_deref(), cli.token.as_deref()) {
        return Ok((u.to_string(), t.to_string()));
    }
    if let Some(cfg) = load_config(config_path)? {
        let url = cli.url.clone().unwrap_or(cfg.url);
        let token = cli.token.clone().unwrap_or(cfg.token);
        return Ok((url, token));
    }
    Err(anyhow!(
        "No URL/token available. Set CERTIFI_URL + CERTIFI_TOKEN, or run `certifi-cli init`."
    ))
}

// ── Interactive init ─────────────────────────────────────────────────────────

async fn run_init(config_path: &Path) -> Result<()> {
    println!("Certifi CLI setup");
    println!("─────────────────");
    println!("The URL can point to either the web admin (e.g. https://certifi.example.com)");
    println!("or the backend API directly (e.g. http://localhost:8080). Both work.");
    println!();

    let default_url = match load_config(config_path)? {
        Some(c) => c.url,
        None => "http://localhost:8080".to_string(),
    };
    let url = prompt(&format!("Server URL [{}]: ", default_url))?;
    let url = if url.is_empty() { default_url } else { url };

    let token = rpassword::prompt_password("API token: ")
        .context("reading token from stdin")?
        .trim()
        .to_string();
    if token.is_empty() {
        return Err(anyhow!("token must not be empty"));
    }

    // Validate against the server before saving. health doesn't need auth, so
    // it tests URL reachability; list_certificates tests auth.
    let client = Client::new(&url, Auth::Token(token.clone()))?;
    let _ = client
        .health()
        .await
        .with_context(|| format!("could not reach {}", url))?;
    let _ = client
        .list_certificates()
        .await
        .context("auth check failed — is the token correct?")?;

    save_config(config_path, &ConfigFile { url, token })?;
    println!("Saved {}", config_path.display());
    Ok(())
}

fn prompt(label: &str) -> Result<String> {
    print!("{}", label);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Accept either a UUID-shaped id or a common name. CN lookup is normalized
/// (lowercase + trailing-dot strip) for forgiveness.
async fn resolve_id(client: &Client, target: &str) -> Result<String> {
    if looks_like_uuid(target) {
        return Ok(target.to_string());
    }
    let needle = normalize_host(target);
    let certs = client.list_certificates().await?;
    certs
        .into_iter()
        .find(|c| normalize_host(&c.common_name) == needle)
        .map(|c| c.id)
        .ok_or_else(|| anyhow!("no certificate with id or CN '{}'", target))
}

fn looks_like_uuid(s: &str) -> bool {
    s.len() == 36 && s.chars().filter(|c| *c == '-').count() == 4
}

/// Returns true if the file was written (i.e. either didn't exist or had
/// different contents). The write is atomic — we stage in the same directory
/// and rename into place.
fn write_if_changed(path: &Path, content: &[u8], private: bool) -> Result<bool> {
    if let Ok(existing) = std::fs::read(path) {
        if existing == content {
            return Ok(false);
        }
    }
    write_file_secure(path, content, private)?;
    Ok(true)
}

fn write_file_secure(path: &Path, content: &[u8], private: bool) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&parent).with_context(|| format!("creating {}", parent.display()))?;

    let mut tmp = tempfile::Builder::new()
        .prefix(".certifi-")
        .suffix(".tmp")
        .tempfile_in(&parent)
        .with_context(|| format!("creating temp file in {}", parent.display()))?;
    tmp.write_all(content)?;
    tmp.flush()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if private { 0o600 } else { 0o644 };
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = private; // Windows: rely on parent-directory ACLs
    }

    tmp.persist(path)
        .with_context(|| format!("renaming temp file into {}", path.display()))?;
    Ok(())
}

// ── Subcommand impls ─────────────────────────────────────────────────────────

async fn run_list(client: &Client) -> Result<()> {
    let certs = client.list_certificates().await?;
    if certs.is_empty() {
        println!("No certificates.");
        return Ok(());
    }
    println!(
        "{:<38} {:<32} {:<8} {:<20} SANs",
        "ID", "COMMON NAME", "STATUS", "EXPIRES"
    );
    for c in certs {
        println!(
            "{:<38} {:<32} {:<8} {:<20} {}",
            c.id,
            truncate(&c.common_name, 32),
            c.status,
            c.expires_at.as_deref().unwrap_or("-"),
            c.sans.join(", ")
        );
    }
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}

async fn run_get(client: &Client, target: &str) -> Result<()> {
    let id = resolve_id(client, target).await?;
    let c = client.get_certificate(&id).await?;
    println!("{}", serde_json::to_string_pretty(&c)?);
    Ok(())
}

async fn run_renew(client: &Client, target: &str) -> Result<()> {
    let id = resolve_id(client, target).await?;
    let resp = client.renew_certificate(&id).await?;
    println!(
        "Renewal queued for {} (id {}). Status: {}",
        resp.common_name, resp.id, resp.status
    );
    Ok(())
}

async fn run_delete(client: &Client, target: &str) -> Result<()> {
    let id = resolve_id(client, target).await?;
    client.delete_certificate(&id).await?;
    println!("Deleted {}", id);
    Ok(())
}

async fn run_integrations(client: &Client, cmd: IntegrationsCmd) -> Result<()> {
    match cmd {
        IntegrationsCmd::List => integrations_list(client).await,
        IntegrationsCmd::Kinds { kind } => integrations_kinds(client, kind.as_deref()).await,
        IntegrationsCmd::Show { id } => integrations_show(client, &id).await,
        IntegrationsCmd::Add(args) => integrations_add(client, args).await,
        IntegrationsCmd::Update(args) => integrations_update(client, args).await,
        IntegrationsCmd::Delete { id } => integrations_delete(client, &id).await,
        IntegrationsCmd::Test { id } => integrations_test(client, &id).await,
    }
}

async fn integrations_list(client: &Client) -> Result<()> {
    let listing = client.list_integrations().await?;
    if listing.integrations.is_empty() {
        println!("No integrations configured.");
        println!("Run `certifi-cli integrations kinds` to see what's available, then `certifi-cli integrations add --kind <kind>`.");
        return Ok(());
    }
    println!("{:<38} {:<12} {:<25} ENABLED", "ID", "KIND", "NAME",);
    for i in listing.integrations {
        println!(
            "{:<38} {:<12} {:<25} {}",
            i.id,
            i.kind,
            truncate(&i.name, 25),
            if i.enabled { "yes" } else { "no" },
        );
    }
    Ok(())
}

async fn integrations_kinds(client: &Client, kind: Option<&str>) -> Result<()> {
    let listing = client.list_integrations().await?;
    let kinds = listing.available_kinds;

    if let Some(k) = kind {
        let meta = kinds.iter().find(|m| m.id == k).ok_or_else(|| {
            anyhow!(
                "unknown kind '{}'. Known: {}",
                k,
                kinds
                    .iter()
                    .map(|m| m.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
        println!("{} ({})\n", meta.name, meta.id);
        let key_w = meta.fields.iter().map(|f| f.key.len()).max().unwrap_or(0);
        for f in &meta.fields {
            let bits: Vec<&str> = vec![
                f.field_type.as_str(),
                if f.required { "required" } else { "optional" },
            ];
            print!(
                "  {:<width$}  {:<14}  {}",
                f.key,
                format!("({})", bits.join(", ")),
                f.label,
                width = key_w
            );
            if !f.default.is_empty() {
                print!("  [default: {}]", f.default);
            }
            println!();
            if !f.hint.is_empty() {
                println!("  {:<width$}  {:<14}  {}", "", "", f.hint, width = key_w);
            }
        }
        return Ok(());
    }

    if kinds.is_empty() {
        println!("(server reported no available kinds)");
        return Ok(());
    }
    println!("{:<14} NAME", "KIND");
    for k in kinds {
        println!("{:<14} {}", k.id, k.name);
    }
    println!("\nDetails: certifi-cli integrations kinds --kind <kind>");
    Ok(())
}

async fn integrations_show(client: &Client, id: &str) -> Result<()> {
    let i = client.get_integration(id).await?;
    println!("{}", serde_json::to_string_pretty(&i)?);
    Ok(())
}

async fn integrations_add(client: &Client, args: AddIntegrationArgs) -> Result<()> {
    // Resolve kind metadata (drives interactive prompts).
    let kinds = client.list_integrations().await?.available_kinds;
    let kind_id = match args.kind.clone() {
        Some(k) => k,
        None => {
            let known: Vec<&str> = kinds.iter().map(|m| m.id.as_str()).collect();
            let val = prompt(&format!("Kind ({}): ", known.join(" / ")))?;
            if val.is_empty() {
                return Err(anyhow!("kind is required"));
            }
            val
        }
    };
    let meta: &IntegrationKind = kinds.iter().find(|m| m.id == kind_id).ok_or_else(|| {
        anyhow!(
            "unknown kind '{}'. Known: {}",
            kind_id,
            kinds
                .iter()
                .map(|m| m.id.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        )
    })?;

    let name = match args.name {
        Some(n) => n,
        None => {
            let val = prompt("Name: ")?;
            if val.is_empty() {
                return Err(anyhow!("name is required"));
            }
            val
        }
    };

    // Parse the supplied --config k=v pairs once; fall back to a prompt for
    // any required field that wasn't given.
    let mut config = parse_kv_pairs(&args.config)?;
    for f in &meta.fields {
        if config.contains_key(&f.key) {
            continue;
        }
        if !f.required && std::env::var("CERTIFI_NONINTERACTIVE").is_ok() {
            continue;
        }
        let value = prompt_for_field(f)?;
        // Empty + optional → skip; empty + required → reject.
        if value.is_empty() {
            if f.required {
                return Err(anyhow!("field '{}' is required", f.key));
            }
            continue;
        }
        config.insert(f.key.clone(), value);
    }

    let req = CreateIntegrationRequest {
        kind: kind_id,
        name,
        config,
        enabled: !args.disabled,
    };
    let created = client.create_integration(&req).await?;
    println!("Created integration {} ({})", created.id, created.name);
    Ok(())
}

async fn integrations_update(client: &Client, args: UpdateIntegrationArgs) -> Result<()> {
    let config = if args.config.is_empty() {
        None
    } else {
        Some(parse_kv_pairs(&args.config)?)
    };
    let enabled = if args.enable {
        Some(true)
    } else if args.disable {
        Some(false)
    } else {
        None
    };
    let req = UpdateIntegrationRequest {
        name: args.name,
        config,
        enabled,
    };
    let updated = client.update_integration(&args.id, &req).await?;
    println!("Updated integration {} ({})", updated.id, updated.name);
    Ok(())
}

async fn integrations_delete(client: &Client, id: &str) -> Result<()> {
    client.delete_integration(id).await?;
    println!("Deleted integration {}", id);
    Ok(())
}

async fn integrations_test(client: &Client, id: &str) -> Result<()> {
    let r = client.test_integration(id).await?;
    println!(
        "{} via {}: {} zone{} visible",
        if r.ok { "OK" } else { "FAILED" },
        r.provider,
        r.zone_count,
        if r.zone_count == 1 { "" } else { "s" },
    );
    for z in r.zones.iter().take(20) {
        println!("  {}", z);
    }
    if r.zones.len() > 20 {
        println!("  ... and {} more", r.zones.len() - 20);
    }
    Ok(())
}

/// Parse `key=value` strings into a map. Rejects empty keys; an empty value
/// is allowed (carries "clear this field" semantics on update).
fn parse_kv_pairs(pairs: &[String]) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for p in pairs {
        let (k, v) = p
            .split_once('=')
            .ok_or_else(|| anyhow!("config must be key=value (got '{}')", p))?;
        let k = k.trim();
        if k.is_empty() {
            return Err(anyhow!("config key may not be empty (got '{}')", p));
        }
        out.insert(k.to_string(), v.to_string());
    }
    Ok(out)
}

/// Ask the user for one field's value. Passwords are read without echo.
fn prompt_for_field(f: &certifi_client::IntegrationField) -> Result<String> {
    let label = if f.required {
        format!("{} ({}): ", f.label, f.key)
    } else if !f.default.is_empty() {
        format!("{} ({}) [{}]: ", f.label, f.key, f.default)
    } else {
        format!("{} ({}, optional): ", f.label, f.key)
    };
    let raw = if f.field_type == "password" {
        rpassword::prompt_password(&label).context("reading from stdin")?
    } else {
        prompt(&label)?
    };
    let trimmed = raw.trim().to_string();
    // Apply default if the user accepted by pressing enter.
    Ok(
        if trimmed.is_empty() && !f.default.is_empty() && !f.required {
            f.default.clone()
        } else {
            trimmed
        },
    )
}

async fn run_docs(client: &Client, slug: Option<&str>) -> Result<()> {
    use std::io::IsTerminal;
    match slug {
        Some(s) => {
            let body = client.get_doc(s).await?;
            // Pretty-print only when the user is actually looking at a
            // terminal. Pipes / redirects / `less` see raw markdown so the
            // ANSI escapes don't end up in their files / pagers.
            if std::io::stdout().is_terminal() {
                let skin = termimad::MadSkin::default();
                skin.print_text(&body);
            } else {
                print!("{}", body);
                if !body.ends_with('\n') {
                    println!();
                }
            }
        }
        None => {
            let toc = client.list_docs().await?;
            if toc.is_empty() {
                println!("(server returned no docs)");
                return Ok(());
            }
            println!("Available topics — run `certifi-cli docs <slug>`:");
            let width = toc.iter().map(|d| d.slug.len()).max().unwrap_or(0);
            for d in toc {
                println!("  {:<width$}  {}", d.slug, d.title, width = width);
            }
        }
    }
    Ok(())
}

async fn run_request(client: &Client, args: &RequestArgs) -> Result<u8> {
    if args.domains.is_empty() {
        return Err(anyhow!("at least one -d/--domain required"));
    }
    let cn = args.domains[0].clone();
    let sans: Vec<String> = args.domains[1..].to_vec();

    let req = IssueCertRequest {
        common_name: cn.clone(),
        sans: Some(sans.clone()),
        auto_renew: args.auto_renew,
        key_algo: args.key_algo.clone(),
        description: args.description.clone(),
    };

    let initial = client.create_certificate(&req).await?;
    if initial.deduplicated {
        eprintln!(
            "Server returned existing cert (id {}, status {}).",
            initial.id, initial.status
        );
    } else {
        eprintln!(
            "Server queued issuance for {} (id {}, status {}).",
            cn, initial.id, initial.status
        );
    }

    // If the server gave us a non-active status, wait for it.
    let cert = if initial.status == "active" {
        client.get_certificate(&initial.id).await?
    } else {
        match client
            .wait_until_ready(
                &initial.id,
                Duration::from_secs(args.timeout),
                Duration::from_secs(args.poll_interval),
            )
            .await
        {
            Ok(c) => c,
            Err(certifi_client::Error::Timeout) => {
                eprintln!("Timed out after {}s waiting for issuance.", args.timeout);
                return Ok(EXIT_TIMEOUT);
            }
            Err(e) => return Err(e.into()),
        }
    };

    // Now download whatever the caller asked for and write atomically.
    let mut changed = false;
    if let Some(p) = &args.fullchain {
        let bytes = client.download_fullchain(&cert.id).await?;
        changed |= write_if_changed(p, &bytes, false)
            .with_context(|| format!("writing fullchain to {}", p.display()))?;
    }
    if let Some(p) = &args.cert {
        let bytes = client.download_cert(&cert.id).await?;
        changed |= write_if_changed(p, &bytes, false)
            .with_context(|| format!("writing cert to {}", p.display()))?;
    }
    if let Some(p) = &args.chain {
        let bytes = client.download_chain(&cert.id).await?;
        changed |= write_if_changed(p, &bytes, false)
            .with_context(|| format!("writing chain to {}", p.display()))?;
    }
    if let Some(p) = &args.privkey {
        let bytes = client.download_privkey(&cert.id).await?;
        changed |= write_if_changed(p, &bytes, /* private = */ true)
            .with_context(|| format!("writing privkey to {}", p.display()))?;
    }

    eprintln!(
        "Cert {} is valid (expires {}). Files {}.",
        cert.id,
        cert.expires_at.as_deref().unwrap_or("unknown"),
        if changed { "updated" } else { "unchanged" }
    );

    if changed {
        if let Some(cmd) = &args.reload_cmd {
            eprintln!("Running reload command: {}", cmd);
            let status = run_shell(cmd)?;
            if !status.success() {
                return Err(anyhow!(
                    "reload command exited with {}",
                    status
                        .code()
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "signal".into())
                ));
            }
        }
        Ok(EXIT_OK_CHANGED)
    } else {
        Ok(EXIT_OK_UNCHANGED)
    }
}

fn run_shell(cmd: &str) -> Result<std::process::ExitStatus> {
    // Use the platform's shell so users can write pipes / && etc. naturally.
    let status = if cfg!(windows) {
        std::process::Command::new("cmd").args(["/C", cmd]).status()
    } else {
        std::process::Command::new("sh").args(["-c", cmd]).status()
    }
    .context("failed to launch reload command")?;
    Ok(status)
}

// ── main ─────────────────────────────────────────────────────────────────────

async fn dispatch(cli: Cli) -> Result<u8> {
    let config_path = match &cli.config {
        Some(p) => p.clone(),
        None => default_config_path()?,
    };

    if matches!(cli.cmd, Cmd::Init) {
        run_init(&config_path).await?;
        return Ok(EXIT_OK_UNCHANGED);
    }

    let (url, token) = resolve_creds(&cli, &config_path)?;
    let client = Client::new(&url, Auth::Token(token))?;

    match cli.cmd {
        Cmd::Init => unreachable!(),
        Cmd::List => run_list(&client).await?,
        Cmd::Get { target } => run_get(&client, &target).await?,
        Cmd::Renew { target } => run_renew(&client, &target).await?,
        Cmd::Delete { target } => run_delete(&client, &target).await?,
        Cmd::Request(args) => return run_request(&client, &args).await,
        Cmd::Docs { slug } => run_docs(&client, slug.as_deref()).await?,
        Cmd::Integrations(sub) => run_integrations(&client, sub).await?,
    }
    Ok(EXIT_OK_UNCHANGED)
}

fn init_tracing() {
    // Default to silent; enable per-target verbosity via RUST_LOG, e.g.:
    //   RUST_LOG=hyper=trace,reqwest=trace certifi-cli list
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    let cli = Cli::parse();
    match dispatch(cli).await {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("Error: {:#}", e);
            ExitCode::from(EXIT_ERROR)
        }
    }
}
