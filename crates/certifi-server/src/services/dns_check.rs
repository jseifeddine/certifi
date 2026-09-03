//! Authoritative-nameserver propagation checks for DNS-01 challenges.
//!
//! Publishing a TXT record through a provider API only means the *primary*
//! has it. Let's Encrypt resolves the challenge from the internet, hitting
//! whichever authoritative server answers first — so on a hidden-primary /
//! multi-secondary setup (PowerDNS with AXFR/NOTIFY to ns1, ns2, …) a
//! validation fired too early sees the old contents of the RRset and the
//! order dies with "Incorrect TXT record ... found".
//!
//! The historical workaround was a fixed `propagation_delay` sleep, which is
//! both too short when a secondary is slow and wasted time when it isn't.
//! Instead we ask every authoritative nameserver for the zone directly and
//! wait until all of them serve every value we deployed.

use anyhow::{Context, Result};
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// How long a single query to one nameserver may take before we treat that
/// server as "not answering yet" and retry on the next pass.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Poll interval between propagation passes.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// One challenge RRset: the FQDN and every TXT value that must be visible on
/// it before ACME is told to validate. A cert covering both `example.com` and
/// `*.example.com` produces two different values on the *same* name, and both
/// must be live simultaneously.
#[derive(Debug, Clone)]
pub struct ExpectedTxt {
    pub fqdn: String,
    pub values: BTreeSet<String>,
}

/// Wait until every authoritative nameserver for each challenge name serves
/// all of the expected TXT values.
///
/// Returns `Ok(true)` once everything agrees, `Ok(false)` if `timeout` ran out
/// first (caller decides whether to push on), and `Err` only when the zone's
/// nameservers can't be discovered at all — the caller then falls back to the
/// provider's fixed propagation delay.
pub async fn wait_for_propagation(expected: &[ExpectedTxt], timeout: Duration) -> Result<bool> {
    if expected.is_empty() {
        return Ok(true);
    }

    let recursive = system_resolver();

    // Resolve the authoritative server IPs once — they don't change mid-issuance,
    // and re-resolving them every second would just add noise and latency.
    let mut targets: Vec<(&ExpectedTxt, Vec<(String, IpAddr)>)> = Vec::new();
    for exp in expected {
        let servers = authoritative_servers(&recursive, &exp.fqdn)
            .await
            .with_context(|| format!("locating authoritative nameservers for {}", exp.fqdn))?;
        if servers.is_empty() {
            anyhow::bail!("no authoritative nameservers resolved for {}", exp.fqdn);
        }
        tracing::info!(
            "DNS check: {} is served by {}",
            exp.fqdn,
            servers
                .iter()
                .map(|(n, ip)| format!("{} ({})", n, ip))
                .collect::<Vec<_>>()
                .join(", ")
        );
        targets.push((exp, servers));
    }

    let deadline = Instant::now() + timeout;
    let mut last_report = String::new();

    loop {
        let mut all_ready = true;
        let mut report: Vec<String> = Vec::new();

        for (exp, servers) in &targets {
            for (ns_name, ip) in servers {
                let seen = query_txt(*ip, &exp.fqdn).await;
                let missing: Vec<&String> =
                    exp.values.iter().filter(|v| !seen.contains(*v)).collect();
                if !missing.is_empty() {
                    all_ready = false;
                    report.push(format!(
                        "{} @ {}: {} of {} value(s) missing",
                        exp.fqdn,
                        ns_name,
                        missing.len(),
                        exp.values.len()
                    ));
                }
            }
        }

        if all_ready {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            tracing::warn!(
                "DNS check: gave up after {}s — still waiting on: {}",
                timeout.as_secs(),
                report.join("; ")
            );
            return Ok(false);
        }

        // Only log when the picture changes, so a 3-minute wait doesn't write
        // 180 identical lines.
        let joined = report.join("; ");
        if joined != last_report {
            tracing::info!("DNS check: waiting on {}", joined);
            last_report = joined;
        }
        sleep(POLL_INTERVAL).await;
    }
}

/// Recursive resolver used to discover NS records and resolve their addresses.
/// Prefers the host's configured resolvers, falling back to a public one when
/// there's no usable resolv.conf (common in scratch containers).
fn system_resolver() -> TokioAsyncResolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = QUERY_TIMEOUT;
    opts.attempts = 2;
    match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(
                "DNS check: no system resolver config ({}), using defaults",
                e
            );
            TokioAsyncResolver::tokio(ResolverConfig::default(), opts)
        }
    }
}

/// Names to try as the zone cut, nearest first: `_acme-challenge.a.b.c.tld`
/// yields `a.b.c.tld`, `b.c.tld`, `c.tld`. The `_acme-challenge` label is never
/// a zone of its own, and the TLD is not worth querying — if the delegation
/// isn't found by then, something else is wrong.
fn zone_candidates(fqdn: &str) -> Vec<String> {
    let labels: Vec<&str> = fqdn.trim_end_matches('.').split('.').collect();
    (1..labels.len().saturating_sub(1))
        .map(|i| labels[i..].join("."))
        .collect()
}

/// Walk up the label hierarchy from the challenge name until an NS RRset turns
/// up (`_acme-challenge.pbx.hb.com.au` → `pbx.hb.com.au` → `hb.com.au` → …),
/// then resolve each nameserver to an address. Returns `(ns_name, ip)` pairs.
async fn authoritative_servers(
    resolver: &TokioAsyncResolver,
    fqdn: &str,
) -> Result<Vec<(String, IpAddr)>> {
    let base = fqdn.trim_end_matches('.');

    for candidate in zone_candidates(base) {
        let ns_names: Vec<String> = match resolver.ns_lookup(format!("{}.", candidate)).await {
            Ok(lookup) => lookup
                .iter()
                .map(|ns| ns.0.to_utf8().trim_end_matches('.').to_string())
                .collect(),
            // NXDOMAIN / no NS at this level — keep climbing.
            Err(_) => continue,
        };
        if ns_names.is_empty() {
            continue;
        }

        let mut out: Vec<(String, IpAddr)> = Vec::new();
        for ns in ns_names {
            match resolver.lookup_ip(format!("{}.", ns)).await {
                Ok(ips) => {
                    for ip in ips.iter() {
                        out.push((ns.clone(), ip));
                    }
                }
                Err(e) => tracing::warn!("DNS check: cannot resolve nameserver {}: {}", ns, e),
            }
        }
        if !out.is_empty() {
            return Ok(out);
        }
    }

    anyhow::bail!("no NS records found for any parent of {}", base)
}

/// Query one nameserver directly (no recursion, no cache) for the TXT values
/// at `fqdn`. Errors and empty answers both come back as an empty set — the
/// caller just retries until the deadline.
async fn query_txt(ip: IpAddr, fqdn: &str) -> BTreeSet<String> {
    let cfg = ResolverConfig::from_parts(
        None,
        vec![],
        NameServerConfigGroup::from_ips_clear(&[ip], 53, true),
    );
    let mut opts = ResolverOpts::default();
    opts.timeout = QUERY_TIMEOUT;
    opts.attempts = 1;
    opts.cache_size = 0;

    let resolver = TokioAsyncResolver::tokio(cfg, opts);
    let mut out = BTreeSet::new();
    if let Ok(lookup) = resolver.txt_lookup(format!("{}.", fqdn)).await {
        for txt in lookup.iter() {
            // A TXT record is a list of character-strings; a >255-byte value
            // arrives split, and the wire value is their concatenation.
            let joined: String = txt
                .txt_data()
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk).to_string())
                .collect();
            out.insert(joined);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_expectation_is_immediately_satisfied() {
        let ok = wait_for_propagation(&[], Duration::from_secs(1))
            .await
            .unwrap();
        assert!(ok);
    }

    #[test]
    fn zone_candidates_walk_upwards_from_the_challenge_name() {
        assert_eq!(
            zone_candidates("_acme-challenge.pbx.hb.com.au"),
            vec!["pbx.hb.com.au", "hb.com.au", "com.au"]
        );
    }

    #[test]
    fn zone_candidates_skip_the_challenge_label_and_the_tld() {
        // The `_acme-challenge` label is never a zone cut, and stopping before
        // the bare TLD avoids a pointless query to the root servers' delegation.
        let c = zone_candidates("_acme-challenge.example.com");
        assert_eq!(c, vec!["example.com"]);
    }

    #[test]
    fn zone_candidates_tolerates_a_trailing_dot_and_short_names() {
        assert_eq!(
            zone_candidates("_acme-challenge.example.com."),
            vec!["example.com"]
        );
        assert!(zone_candidates("localhost").is_empty());
    }

    #[test]
    fn expected_txt_dedupes_identical_values() {
        let mut values = BTreeSet::new();
        values.insert("abc".to_string());
        values.insert("abc".to_string());
        let e = ExpectedTxt {
            fqdn: "_acme-challenge.example.com".into(),
            values,
        };
        assert_eq!(e.values.len(), 1);
    }
}
