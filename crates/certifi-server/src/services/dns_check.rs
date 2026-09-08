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
//!
//! **This never consults a recursive resolver or a cache — least of all the
//! host's own.** Let's Encrypt validates DNS-01 by walking the delegation from
//! the root against authoritative servers; a certifi box inside a split-horizon
//! network whose `/etc/resolv.conf` points at an internal recursor would
//! otherwise be told about internal-only nameservers serving an internal-only
//! copy of the zone, and a record correctly published to the real public
//! backend looks "missing" until the check times out. So we do the same
//! iterative walk here: root hints → TLD → the zone's authoritative NS, every
//! query with recursion disabled and answers taken only from the servers that
//! are authoritative for the name in question.

use anyhow::{Context, Result};
use hickory_resolver::proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

/// How long a single query to one nameserver may take before we treat that
/// server as "not answering yet" and move on to the next.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Poll interval between propagation passes.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// EDNS0 UDP payload we advertise (DNS flag-day 2020 value). Referrals with a
/// full NS set plus glue can still exceed this — the `TC` bit then sends us to
/// TCP.
const EDNS_UDP_PAYLOAD: u16 = 1232;

/// Ceiling on referral hops (`. → tld → zone → …`) and on how deep the
/// resolver will recurse to look up a nameserver's own address. Real
/// delegations are 2–4 deep; anything past this is a loop or misconfiguration.
const MAX_DEPTH: usize = 12;

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

    // Resolve the authoritative server IPs once — they don't change mid-issuance,
    // and re-resolving them every second would just add noise and latency.
    let mut targets: Vec<(&ExpectedTxt, Vec<(String, IpAddr)>)> = Vec::new();
    for exp in expected {
        let servers = authoritative_servers(&exp.fqdn)
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

// ---------------------------------------------------------------------------
// Iterative resolution — root hints down to the zone's authoritative servers.
// ---------------------------------------------------------------------------

/// IANA root nameserver addresses (both families). Every recursive resolver
/// ships a list like this; it changes maybe once a decade. The walk starts
/// here so the delegation we follow is the real public one — not whatever a
/// local recursor claims.
fn root_hints() -> Vec<IpAddr> {
    const V4: [[u8; 4]; 13] = [
        [198, 41, 0, 4],     // a.root-servers.net
        [170, 247, 170, 2],  // b
        [192, 33, 4, 12],    // c
        [199, 7, 91, 13],    // d
        [192, 203, 230, 10], // e
        [192, 5, 5, 241],    // f
        [192, 112, 36, 4],   // g
        [198, 97, 190, 53],  // h
        [192, 36, 148, 17],  // i
        [192, 58, 128, 30],  // j
        [193, 0, 14, 129],   // k
        [199, 7, 83, 42],    // l
        [202, 12, 27, 33],   // m
    ];
    const V6: [&str; 13] = [
        "2001:503:ba3e::2:30", // a
        "2801:1b8:10::b",      // b
        "2001:500:2::c",       // c
        "2001:500:2d::d",      // d
        "2001:500:a8::e",      // e
        "2001:500:2f::f",      // f
        "2001:500:12::d0d",    // g
        "2001:500:1::53",      // h
        "2001:7fe::53",        // i
        "2001:503:c27::2:30",  // j
        "2001:7fd::1",         // k
        "2001:500:9f::42",     // l
        "2001:dc3::35",        // m
    ];
    V4.iter()
        .map(|o| IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])))
        .chain(
            V6.iter()
                .filter_map(|s| s.parse::<Ipv6Addr>().ok().map(IpAddr::V6)),
        )
        .collect()
}

/// The delegation for a name: which zone is cut, the NS names authoritative for
/// it, and any glue addresses learned on the way down.
struct Delegation {
    zone: Name,
    ns_names: Vec<Name>,
    glue: Vec<(Name, IpAddr)>,
}

/// Discover the nameservers actually authoritative for `fqdn`'s zone and
/// resolve each to an address. Returns `(ns_name, ip)` pairs — the same shape
/// the propagation loop then queries directly for the TXT value.
async fn authoritative_servers(fqdn: &str) -> Result<Vec<(String, IpAddr)>> {
    let name = to_name(fqdn)?;
    let deleg = delegation_for(&name, 0)
        .await
        .with_context(|| format!("walking the delegation for {name}"))?;

    let mut out: Vec<(String, IpAddr)> = Vec::new();
    for ns in &deleg.ns_names {
        let glued: Vec<IpAddr> = deleg
            .glue
            .iter()
            .filter(|(n, _)| n == ns)
            .map(|(_, ip)| *ip)
            .collect();
        let ips = if !glued.is_empty() {
            glued
        } else {
            // Out-of-bailiwick NS with no glue in the referral — resolve it the
            // same way, from the root.
            resolve_host(ns, 1).await.unwrap_or_default()
        };
        let label = ns.to_utf8();
        let label = label.trim_end_matches('.');
        for ip in ips {
            if !out.iter().any(|(_, existing)| *existing == ip) {
                out.push((label.to_string(), ip));
            }
        }
    }

    if out.is_empty() {
        anyhow::bail!("no addresses for any nameserver of {}", deleg.zone);
    }
    Ok(out)
}

/// Walk from the root hints towards `name`, following referrals, until a server
/// stops delegating. The last delegation seen is the zone's own.
async fn delegation_for(name: &Name, depth: usize) -> Result<Delegation> {
    if depth > MAX_DEPTH {
        anyhow::bail!("delegation walk for {} exceeded {} hops", name, MAX_DEPTH);
    }

    let mut servers: Vec<IpAddr> = root_hints();
    let mut best: Option<Delegation> = None;

    for _ in 0..MAX_DEPTH {
        let resp = match query_any(&servers, name, RecordType::NS).await {
            Ok(r) => r,
            // Whole level unreachable: stop with whatever delegation we have.
            Err(e) => {
                if best.is_some() {
                    break;
                }
                return Err(e);
            }
        };

        let Some((owner, ns_names)) = ns_rrset(&resp, name) else {
            // NODATA / NXDOMAIN / no NS anywhere below here — the zone we're
            // already standing on is the authoritative one.
            break;
        };

        // The RRset must belong to a zone at or below the one we last saw, and
        // still be a parent of the name we're chasing. Anything else is a
        // lame or lying server — stop rather than follow it sideways/up.
        let deeper_than_best = best
            .as_ref()
            .map(|b| b.zone.zone_of(&owner))
            .unwrap_or(true);
        if !owner.zone_of(name) || !deeper_than_best {
            break;
        }

        let glue = glue_for(&resp, &ns_names);
        let same_zone_as_best = best.as_ref().map(|b| b.zone == owner).unwrap_or(false);
        best = Some(Delegation {
            zone: owner.clone(),
            ns_names: ns_names.clone(),
            glue: glue.clone(),
        });
        // Answer-section NS for the zone we're already at: that's the apex's
        // own RRset, authoritative and final.
        if same_zone_as_best || resp.authoritative() && !resp.answers().is_empty() {
            break;
        }

        // Descend: prefer glue, fall back to resolving one NS from the root.
        let mut next: Vec<IpAddr> = glue.iter().map(|(_, ip)| *ip).collect();
        if next.is_empty() {
            for ns in &ns_names {
                if let Ok(ips) = Box::pin(resolve_host(ns, depth + 1)).await {
                    next.extend(ips);
                    if !next.is_empty() {
                        break;
                    }
                }
            }
        }
        if next.is_empty() {
            break;
        }
        servers = next;
    }

    best.ok_or_else(|| anyhow::anyhow!("no NS delegation found for {}", name))
}

/// Resolve a hostname's A/AAAA the same way — from the root, authoritative
/// answers only. Used for nameservers whose referral carried no glue.
async fn resolve_host(name: &Name, depth: usize) -> Result<Vec<IpAddr>> {
    if depth > MAX_DEPTH {
        anyhow::bail!("address lookup for {} recursed too deep", name);
    }
    let deleg = Box::pin(delegation_for(name, depth)).await?;

    let mut servers: Vec<IpAddr> = deleg.glue.iter().map(|(_, ip)| *ip).collect();
    if servers.is_empty() {
        for ns in &deleg.ns_names {
            if let Ok(ips) = Box::pin(resolve_host(ns, depth + 1)).await {
                servers.extend(ips);
                if !servers.is_empty() {
                    break;
                }
            }
        }
    }
    if servers.is_empty() {
        anyhow::bail!("no reachable nameserver for {}", deleg.zone);
    }

    let mut out: Vec<IpAddr> = Vec::new();
    for rtype in [RecordType::A, RecordType::AAAA] {
        if let Ok(resp) = query_any(&servers, name, rtype).await {
            for rec in resp.answers() {
                match rec.data() {
                    Some(RData::A(a)) => out.push(IpAddr::V4(a.0)),
                    Some(RData::AAAA(a)) => out.push(IpAddr::V6(a.0)),
                    _ => {}
                }
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Pull the NS RRset from a response: the answer section if the server was
/// authoritative for it, otherwise the authority section (a referral). Returns
/// the owner name and the NS target names.
fn ns_rrset(resp: &Message, name: &Name) -> Option<(Name, Vec<Name>)> {
    for section in [resp.answers(), resp.name_servers()] {
        let ns: Vec<&Record> = section
            .iter()
            .filter(|r| r.record_type() == RecordType::NS)
            .collect();
        if ns.is_empty() {
            continue;
        }
        let owner = ns[0].name().clone();
        // A well-formed RRset shares one owner; ignore stragglers.
        let names: Vec<Name> = ns
            .iter()
            .filter(|r| r.name() == &owner)
            .filter_map(|r| match r.data() {
                Some(RData::NS(target)) => Some(target.0.clone()),
                _ => None,
            })
            .collect();
        if !names.is_empty() && owner.zone_of(name) {
            return Some((owner, names));
        }
    }
    None
}

/// Glue (A/AAAA in the additional section) for the given NS names.
fn glue_for(resp: &Message, ns_names: &[Name]) -> Vec<(Name, IpAddr)> {
    resp.additionals()
        .iter()
        .filter(|r| ns_names.iter().any(|n| n == r.name()))
        .filter_map(|r| match r.data() {
            Some(RData::A(a)) => Some((r.name().clone(), IpAddr::V4(a.0))),
            Some(RData::AAAA(a)) => Some((r.name().clone(), IpAddr::V6(a.0))),
            _ => None,
        })
        .collect()
}

/// Try each server in turn; return the first real response (NoError/NXDomain).
/// SERVFAIL, timeouts and transport errors move to the next server.
async fn query_any(servers: &[IpAddr], name: &Name, rtype: RecordType) -> Result<Message> {
    let mut ordered = servers.to_vec();
    // Spread load / avoid always hammering a.root-servers.net first.
    let n = ordered.len();
    if n > 0 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as usize)
            .unwrap_or(0);
        ordered.rotate_left(nanos % n);
    }

    let mut last_err: Option<anyhow::Error> = None;
    for ip in ordered {
        match query_one(ip, name, rtype).await {
            Ok(msg) => return Ok(msg),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no nameservers to query for {}", name)))
}

/// A single non-recursive query to one server. UDP first; if the answer is
/// truncated, retry over TCP. An empty/refused/failed answer is an error so the
/// caller falls through to the next server.
async fn query_one(server: IpAddr, name: &Name, rtype: RecordType) -> Result<Message> {
    let mut msg = Message::new();
    msg.set_id(rand_id())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(false)
        .add_query(Query::query(name.clone(), rtype));
    let mut edns = Edns::new();
    edns.set_version(0);
    edns.set_max_payload(EDNS_UDP_PAYLOAD);
    msg.set_edns(edns);
    let wire = msg.to_vec().context("encode DNS query")?;

    let bind: SocketAddr = if server.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let target = SocketAddr::new(server, 53);

    let udp = async {
        let sock = UdpSocket::bind(bind).await.context("bind UDP")?;
        sock.connect(target).await.context("connect UDP")?;
        sock.send(&wire).await.context("send UDP query")?;
        let mut buf = vec![0u8; EDNS_UDP_PAYLOAD as usize + 64];
        let n = sock.recv(&mut buf).await.context("recv UDP answer")?;
        Message::from_vec(&buf[..n]).context("decode UDP answer")
    };

    let resp = match timeout(QUERY_TIMEOUT, udp).await {
        Ok(Ok(m)) => m,
        Ok(Err(e)) => return Err(e),
        Err(_) => anyhow::bail!("{} timed out", server),
    };

    let resp = if resp.truncated() {
        timeout(QUERY_TIMEOUT, query_tcp(target, &wire))
            .await
            .map_err(|_| anyhow::anyhow!("{} TCP timed out", server))??
    } else {
        resp
    };

    use hickory_resolver::proto::op::ResponseCode;
    match resp.response_code() {
        ResponseCode::NoError | ResponseCode::NXDomain => Ok(resp),
        other => anyhow::bail!("{} answered {:?}", server, other),
    }
}

/// DNS-over-TCP: 2-byte length prefix both ways.
async fn query_tcp(target: SocketAddr, wire: &[u8]) -> Result<Message> {
    let mut stream = TcpStream::connect(target).await.context("connect TCP")?;
    let len = u16::try_from(wire.len()).context("query too large for TCP")?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(wire).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("read TCP len")?;
    let mut body = vec![0u8; u16::from_be_bytes(len_buf) as usize];
    stream
        .read_exact(&mut body)
        .await
        .context("read TCP body")?;
    Message::from_vec(&body).context("decode TCP answer")
}

/// Query one nameserver directly for the TXT values at `fqdn`. Errors and empty
/// answers both come back as an empty set — the caller just retries until the
/// deadline.
async fn query_txt(ip: IpAddr, fqdn: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(name) = to_name(fqdn) else {
        return out;
    };
    let Ok(resp) = query_one(ip, &name, RecordType::TXT).await else {
        return out;
    };
    for rec in resp.answers() {
        if let Some(RData::TXT(txt)) = rec.data() {
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

/// Parse an FQDN into an absolute `Name`.
fn to_name(fqdn: &str) -> Result<Name> {
    let trimmed = fqdn.trim_end_matches('.');
    Name::from_ascii(format!("{trimmed}.")).with_context(|| format!("invalid DNS name {fqdn:?}"))
}

/// Cheap query ID. These queries go to a single connected socket and are
/// matched by that, not by guessing resistance, but a varying ID is still
/// correct form.
fn rand_id() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos ^ (nanos >> 16)) as u16
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

    /// End-to-end walk against the live DNS root. Ignored by default (needs
    /// outbound UDP/53); run with `cargo test -- --ignored dns_check::tests::walks`.
    #[tokio::test]
    #[ignore]
    async fn walks_the_real_delegation_to_a_zones_nameservers() {
        // A zone whose nameservers are out-of-bailiwick (example.com is served
        // by *.ns.cloudflare.com), so the walk also has to resolve those NS
        // hostnames from the root — the glue-less path.
        let got = authoritative_servers("_acme-challenge.example.com")
            .await
            .expect("delegation walk");
        assert!(!got.is_empty());
        for (ns, ip) in &got {
            assert!(ns.contains('.'), "not a hostname: {ns}");
            let private = match ip {
                IpAddr::V4(v4) => {
                    v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
                }
                IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
            };
            assert!(
                !private,
                "walk returned a non-public address {ip} for {ns} — did it hit a recursor?"
            );
        }

        // A name a few labels deep still lands on real authoritative servers.
        let deep = authoritative_servers("_acme-challenge.www.iana.org")
            .await
            .expect("deep delegation walk");
        assert!(!deep.is_empty());
    }

    #[test]
    fn root_hints_cover_both_families() {
        let hints = root_hints();
        assert_eq!(hints.iter().filter(|ip| ip.is_ipv4()).count(), 13);
        assert_eq!(hints.iter().filter(|ip| ip.is_ipv6()).count(), 13);
        assert!(hints.contains(&"198.41.0.4".parse().unwrap()));
    }

    #[test]
    fn to_name_absolutises_and_rejects_garbage() {
        assert_eq!(
            to_name("_acme-challenge.example.com").unwrap().to_ascii(),
            "_acme-challenge.example.com."
        );
        assert_eq!(
            to_name("_acme-challenge.example.com.").unwrap().to_ascii(),
            "_acme-challenge.example.com."
        );
        assert!(to_name("not a hostname").is_err());
    }

    #[test]
    fn ns_rrset_prefers_answer_then_authority_and_checks_bailiwick() {
        use hickory_resolver::proto::rr::rdata::NS;
        use hickory_resolver::proto::rr::DNSClass;

        let name = to_name("_acme-challenge.sub.example.com").unwrap();
        let zone = Name::from_ascii("example.com.").unwrap();
        let ns_target = Name::from_ascii("ns1.example.com.").unwrap();

        let mut referral = Message::new();
        referral.add_name_server(Record::from_rdata(
            zone.clone(),
            3600,
            RData::NS(NS(ns_target.clone())),
        ));
        // An unrelated NS in the authority section must not be picked.
        referral.add_name_server(
            Record::from_rdata(
                Name::from_ascii("other.test.").unwrap(),
                3600,
                RData::NS(NS(Name::from_ascii("ns.other.test.").unwrap())),
            )
            .set_dns_class(DNSClass::IN)
            .clone(),
        );

        let (owner, names) = ns_rrset(&referral, &name).expect("referral NS found");
        assert_eq!(owner, zone);
        assert_eq!(names, vec![ns_target]);

        // Out-of-bailiwick only → nothing usable.
        let mut lame = Message::new();
        lame.add_name_server(Record::from_rdata(
            Name::from_ascii("elsewhere.net.").unwrap(),
            3600,
            RData::NS(NS(Name::from_ascii("ns.elsewhere.net.").unwrap())),
        ));
        assert!(ns_rrset(&lame, &name).is_none());
    }

    #[test]
    fn glue_for_matches_only_named_servers() {
        use hickory_resolver::proto::rr::rdata::{A, AAAA};

        let ns1 = Name::from_ascii("ns1.example.com.").unwrap();
        let ns2 = Name::from_ascii("ns2.example.com.").unwrap();
        let mut resp = Message::new();
        resp.add_additional(Record::from_rdata(
            ns1.clone(),
            3600,
            RData::A(A("192.0.2.1".parse().unwrap())),
        ));
        resp.add_additional(Record::from_rdata(
            ns1.clone(),
            3600,
            RData::AAAA(AAAA("2001:db8::1".parse().unwrap())),
        ));
        resp.add_additional(Record::from_rdata(
            Name::from_ascii("unrelated.example.com.").unwrap(),
            3600,
            RData::A(A("192.0.2.9".parse().unwrap())),
        ));

        let glue = glue_for(&resp, &[ns1.clone(), ns2]);
        assert_eq!(glue.len(), 2);
        assert!(glue.iter().all(|(n, _)| n == &ns1));
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
