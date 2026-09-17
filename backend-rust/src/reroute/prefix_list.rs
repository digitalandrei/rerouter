//! IOS prefix-list reading and sequence placement — the pure half of the
//! sequenced `bgp_advertise_add` / `bgp_advertise_remove` templates.
//!
//! # Why this module exists
//!
//! Every outbound prefix-list on a real edge router ends with a terminating
//! deny:
//!
//! ```text
//! ip prefix-list pfx-to-viva seq  5 permit 194.105.142.0/24
//! ip prefix-list pfx-to-viva seq 10 deny 0.0.0.0/0 le 32
//! ```
//!
//! `ip prefix-list <name> permit <cidr>` with NO sequence number makes IOS
//! auto-assign `highest + 5`, which lands the new permit *after* that deny,
//! where it is never reached. The CLI reports success, the router advertises
//! nothing, and only the post-apply verification catches it. Fail-safe, but the
//! feature does not work. So the controller must place the entry itself, with an
//! explicit sequence, strictly before the first entry that would shadow it.
//!
//! # Why the list is read fresh, in-session, at apply time
//!
//! On IOS, reusing an existing sequence number with different content REPLACES
//! that entry. Acting on an hour-old picture of the list therefore risks
//! silently overwriting a live filter entry — a data-plane change nobody asked
//! for. Cached inventory is not acceptable for this decision; only a read taken
//! moments before the write is.
//!
//! That read is ONE extra `show` inside the SSH session the executor already
//! opens to push the config. It is deliberately **not**
//! [`crate::ssh::discover_prefixes_and_store`] and it does **not** run the drift
//! audit: no new connection, no database reconcile, no audit pass, nothing that
//! could stall a mitigation behind a second SSH handshake during a flood. That
//! prohibition (and the lint in [`crate::reroute::inventory_audit`] that
//! enforces it) stands unchanged.
//!
//! Everything in this module is pure: it takes the raw `show ip prefix-list
//! <name>` text and returns a decision. It never panics — malformed, denied,
//! truncated or empty output yields [`SequencePlan::Refuse`], never a guess.

use std::net::Ipv4Addr;

/// IOS accepts prefix-list sequence numbers in 1..=4294967294.
pub const MIN_SEQ: u32 = 1;
pub const MAX_SEQ: u32 = 4_294_967_294;

/// The gap IOS itself leaves between auto-assigned entries. Reused when we
/// append past the end of a list so a hand-edited list keeps its usual shape.
const APPEND_STEP: u32 = 5;

/// One parsed `seq N permit|deny A.B.C.D/L [ge X] [le Y]` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixListEntry {
    pub sequence: u32,
    pub permit: bool,
    pub network: Ipv4Addr,
    pub length: u8,
    pub ge: Option<u8>,
    pub le: Option<u8>,
}

impl PrefixListEntry {
    /// Render the entry's match clause exactly as IOS prints (and accepts) it.
    fn clause(&self) -> String {
        let mut s = format!(
            "{} {}/{}",
            if self.permit { "permit" } else { "deny" },
            self.network,
            self.length
        );
        if let Some(ge) = self.ge {
            s.push_str(&format!(" ge {ge}"));
        }
        if let Some(le) = self.le {
            s.push_str(&format!(" le {le}"));
        }
        s
    }

    /// Does this entry match the route `network/length`?
    ///
    /// IOS semantics: the entry's first `self.length` bits must equal the
    /// route's, and the route's length must fall in the entry's length range.
    /// With neither `ge` nor `le` the range is exactly `self.length`; `ge`
    /// alone opens the top to /32; `le` alone opens the bottom to `self.length`.
    fn matches(&self, network: Ipv4Addr, length: u8) -> bool {
        if !same_network(self.network, network, self.length) {
            return false;
        }
        let low = self.ge.unwrap_or(self.length);
        let high = self
            .le
            .unwrap_or(if self.ge.is_some() { 32 } else { self.length });
        low <= length && length <= high
    }

    /// True when this entry is *exactly* the route, with no range qualifiers —
    /// i.e. removing it withdraws that prefix and nothing else.
    fn is_exactly(&self, network: Ipv4Addr, length: u8) -> bool {
        self.network == network && self.length == length && self.ge.is_none() && self.le.is_none()
    }
}

/// What the executor should do with the list it just read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequencePlan {
    /// Write the template's command at this sequence number. Guaranteed free in
    /// the list that was just read.
    Use(u32),
    /// The router is already in the requested state. Push no config; go straight
    /// to verification.
    ///
    /// `sequence` is set ONLY when a later rollback may name that entry exactly
    /// — i.e. an entry whose match clause is precisely this prefix. It is `None`
    /// for a broader covering entry or for a deny, because rendering a rollback
    /// against such a sequence would have IOS delete (or REPLACE) an entry that
    /// means something else. With `None` the rollback simply resolves from its
    /// own fresh read, which is always safe.
    AlreadySatisfied { sequence: Option<u32>, note: String },
    /// Fail closed. Nothing is pushed and nothing may be guessed.
    Refuse(String),
}

/// Cisco markers that mean the read itself was rejected. Mirrors
/// `ssh::cisco_denied`, kept local so this module stays pure and dependency-free.
fn denied(output: &str) -> Option<String> {
    const MARKERS: [&str; 6] = [
        "% Invalid input",
        "ommand authorization failed",
        "not authorized",
        "% Incomplete command",
        "% Ambiguous command",
        "% Permission denied",
    ];
    output
        .lines()
        .map(str::trim)
        .find(|l| MARKERS.iter().any(|m| l.contains(m)))
        .map(str::to_string)
}

/// Parse `show ip prefix-list <name>` output into the entries of THAT list,
/// sorted by sequence.
///
/// Fail-closed by construction:
///   * a denied / error read is an error;
///   * output with no `ip prefix-list <name>:` header for the requested list is
///     an error (an empty read is indistinguishable from a truncated one, and a
///     wrong "the list is empty" conclusion is what puts an entry in the wrong
///     place);
///   * a `seq` line that does not parse completely is an error — silently
///     skipping it could skip the very deny we must insert in front of;
///   * duplicate sequence numbers are an error.
pub fn parse_prefix_list(output: &str, name: &str) -> Result<Vec<PrefixListEntry>, String> {
    if let Some(marker) = denied(output) {
        return Err(format!(
            "the router rejected the prefix-list read: {marker}"
        ));
    }
    let mut entries: Vec<PrefixListEntry> = Vec::new();
    let mut header_seen = false;
    let mut expected_entries: Option<usize> = None;
    let mut in_target = false;

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((header, count)) = parse_header(line) {
            in_target = header == name;
            if in_target {
                if header_seen {
                    return Err(format!(
                        "prefix-list '{name}' was reported more than once; refusing an ambiguous read"
                    ));
                }
                header_seen = true;
                expected_entries = Some(count);
            }
            continue;
        }
        if !line.starts_with("seq ") {
            // `Count: 2, range entries: 1` and similar preamble lines from the
            // `detail` form, plus anything else the image prints, are ignored —
            // they carry no entry. Entry lines always start with `seq`.
            continue;
        }
        if !in_target {
            continue;
        }
        let entry = parse_entry(line)?;
        if entries.iter().any(|e| e.sequence == entry.sequence) {
            return Err(format!(
                "prefix-list '{name}' reported sequence {} twice; refusing to act on an \
                 unreadable list",
                entry.sequence
            ));
        }
        entries.push(entry);
    }

    if !header_seen {
        return Err(format!(
            "the fresh read did not show prefix-list '{name}' on the device; refusing to \
             guess its contents"
        ));
    }
    if expected_entries != Some(entries.len()) {
        return Err(format!(
            "prefix-list '{name}' declared {} entr{} but the completed read contained {}; refusing a truncated read",
            expected_entries.unwrap_or(0),
            if expected_entries == Some(1) { "y" } else { "ies" },
            entries.len()
        ));
    }
    entries.sort_by_key(|e| e.sequence);
    Ok(entries)
}

/// `ip prefix-list NAME: 2 entries` -> (`NAME`, 2).
fn parse_header(line: &str) -> Option<(&str, usize)> {
    let rest = line.strip_prefix("ip prefix-list ")?;
    let (name, count) = rest.split_once(':')?;
    let name = name.trim();
    let mut words = count.split_whitespace();
    let count = words.next()?.parse().ok()?;
    if !matches!(words.next(), Some("entry" | "entries")) || words.next().is_some() {
        return None;
    }
    (!name.is_empty()).then_some((name, count))
}

/// `seq 10 deny 0.0.0.0/0 le 32` -> a typed entry. Anything unexpected errors.
fn parse_entry(line: &str) -> Result<PrefixListEntry, String> {
    // The `detail` form appends `(hit count: 0, refcount: 0)`; drop it.
    let body = match line.split_once('(') {
        Some((head, _)) => head.trim(),
        None => line,
    };
    let mut toks = body.split_whitespace();
    let bad = || format!("could not parse prefix-list entry {line:?}");

    if toks.next() != Some("seq") {
        return Err(bad());
    }
    let sequence: u32 = toks.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    if !(MIN_SEQ..=MAX_SEQ).contains(&sequence) {
        return Err(bad());
    }
    let permit = match toks.next() {
        Some("permit") => true,
        Some("deny") => false,
        _ => return Err(bad()),
    };
    let (net_s, len_s) = toks
        .next()
        .ok_or_else(bad)?
        .split_once('/')
        .ok_or_else(bad)?;
    let network: Ipv4Addr = net_s.parse().map_err(|_| bad())?;
    let length: u8 = len_s.parse().map_err(|_| bad())?;
    if length > 32 {
        return Err(bad());
    }

    let mut ge = None;
    let mut le = None;
    while let Some(tok) = toks.next() {
        let value: u8 = toks.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
        if value > 32 {
            return Err(bad());
        }
        match tok {
            "ge" if ge.is_none() => ge = Some(value),
            "le" if le.is_none() => le = Some(value),
            _ => return Err(bad()),
        }
    }
    Ok(PrefixListEntry {
        sequence,
        permit,
        network,
        length,
        ge,
        le,
    })
}

/// Parse `a.b.c.d/len` (already normalized by the template's `cidr` validator).
fn parse_prefix(prefix: &str) -> Result<(Ipv4Addr, u8), String> {
    let (net, len) = prefix
        .split_once('/')
        .ok_or_else(|| format!("invalid prefix {prefix:?}"))?;
    let network: Ipv4Addr = net
        .trim()
        .parse()
        .map_err(|_| format!("invalid prefix {prefix:?}"))?;
    let length: u8 = len
        .trim()
        .parse()
        .map_err(|_| format!("invalid prefix {prefix:?}"))?;
    if length > 32 {
        return Err(format!("invalid prefix {prefix:?}"));
    }
    Ok((network, length))
}

/// True when `a` and `b` agree on their first `len` bits.
fn same_network(a: Ipv4Addr, b: Ipv4Addr, len: u8) -> bool {
    let mask: u32 = if len == 0 {
        0
    } else {
        u32::MAX
            .checked_shl(32 - u32::from(len.min(32)))
            .unwrap_or(0)
    };
    (u32::from(a) & mask) == (u32::from(b) & mask)
}

/// Where to insert a `permit <prefix>` so it is actually REACHED.
///
/// Walks the list in sequence order and stops at the first entry that matches
/// the prefix:
///   * a matching **permit** means the prefix is already advertised through this
///     list — nothing to push ([`SequencePlan::AlreadySatisfied`], carrying that
///     entry's sequence so a rollback can still remove exactly it);
///   * a matching **deny** is the shadowing entry: the new permit must land
///     strictly between the entry before it and that deny.
///
/// With no matching entry at all the permit still gets an EXPLICIT sequence
/// (`last + 5`), never IOS auto-assignment — the rollback has to be able to name
/// the exact entry it removes.
///
/// Refuses, rather than guessing, when the gap holds no free integer. It never
/// renumbers the router's list and never falls back to the bare append that
/// caused the original silent no-op.
pub fn plan_add(output: &str, list: &str, prefix: &str) -> SequencePlan {
    let entries = match parse_prefix_list(output, list) {
        Ok(entries) => entries,
        Err(e) => return SequencePlan::Refuse(e),
    };
    let (network, length) = match parse_prefix(prefix) {
        Ok(v) => v,
        Err(e) => return SequencePlan::Refuse(e),
    };

    let shadow = entries.iter().find(|e| e.matches(network, length));
    let Some(shadow) = shadow else {
        // Nothing reaches this prefix today: append past the end, explicitly.
        let last = entries.last().map(|e| e.sequence).unwrap_or(0);
        let candidate = last.saturating_add(APPEND_STEP).min(MAX_SEQ);
        if candidate <= last {
            return SequencePlan::Refuse(format!(
                "prefix-list '{list}' already uses sequence {last}, the highest IOS accepts \
                 ({MAX_SEQ}); renumber the prefix-list before advertising {prefix}"
            ));
        }
        return free_or_refuse(candidate, &entries, list, prefix);
    };

    if shadow.permit {
        return SequencePlan::AlreadySatisfied {
            // Only an entry that IS this prefix may be named by a rollback.
            sequence: shadow
                .is_exactly(network, length)
                .then_some(shadow.sequence),
            note: format!(
                "{prefix} is already permitted by prefix-list '{list}' seq {} ({}); no \
                 configuration change was needed",
                shadow.sequence,
                shadow.clause()
            ),
        };
    }

    // The shadowing deny. Insert strictly between it and whatever precedes it.
    let previous = entries
        .iter()
        .filter(|e| e.sequence < shadow.sequence)
        .map(|e| e.sequence)
        .next_back()
        .unwrap_or(0);
    match midpoint(previous, shadow.sequence) {
        Some(candidate) => free_or_refuse(candidate, &entries, list, prefix),
        None => SequencePlan::Refuse(format!(
            "prefix-list '{list}' has no free sequence number between {previous} and {} \
             (the entry '{}' that would shadow {prefix}), so the permit cannot be placed \
             where it would be reached. Renumber the prefix-list on the router (leave a \
             gap before seq {}) and retry; Rerouter will not renumber it or append past \
             the deny.",
            shadow.sequence,
            shadow.clause(),
            shadow.sequence
        )),
    }
}

/// Which entry to remove so `prefix` stops being advertised through `list`.
///
/// Mirrors [`plan_add`]: walk to the first entry that matches the prefix.
///   * a matching **deny** (or no match at all) means the prefix is already not
///     advertised through this list — nothing to push;
///   * a matching **permit** for exactly this prefix is the entry to remove;
///   * a matching permit that is BROADER (a different network/length, or one
///     carrying `ge`/`le`) is refused: removing it would withdraw prefixes the
///     operator did not ask about.
pub fn plan_remove(output: &str, list: &str, prefix: &str) -> SequencePlan {
    let entries = match parse_prefix_list(output, list) {
        Ok(entries) => entries,
        Err(e) => return SequencePlan::Refuse(e),
    };
    let (network, length) = match parse_prefix(prefix) {
        Ok(v) => v,
        Err(e) => return SequencePlan::Refuse(e),
    };

    let Some(reached) = entries.iter().find(|e| e.matches(network, length)) else {
        return SequencePlan::AlreadySatisfied {
            sequence: None,
            note: format!(
                "no entry in prefix-list '{list}' reaches {prefix}, so it is already not \
                 advertised through it; no configuration change was needed"
            ),
        };
    };
    if !reached.permit {
        return SequencePlan::AlreadySatisfied {
            // Never hand a DENY's sequence to a rollback: re-adding a permit at
            // that sequence would REPLACE the deny.
            sequence: None,
            note: format!(
                "{prefix} is already denied by prefix-list '{list}' seq {} ({}); no \
                 configuration change was needed",
                reached.sequence,
                reached.clause()
            ),
        };
    }
    if !reached.is_exactly(network, length) {
        return SequencePlan::Refuse(format!(
            "{prefix} is advertised through prefix-list '{list}' by the BROADER entry seq \
             {} ('{}'), not by an entry of its own. Removing that entry would withdraw more \
             than {prefix}, so Rerouter refuses it — adjust the prefix-list on the router by \
             hand if that is really the intent.",
            reached.sequence,
            reached.clause()
        ));
    }
    SequencePlan::Use(reached.sequence)
}

/// A sequence strictly between `low` and `high`, or `None` when the gap is
/// empty. The midpoint (not `low + 1`) so repeated insertions into the same gap
/// keep halving the room instead of exhausting one end immediately.
fn midpoint(low: u32, high: u32) -> Option<u32> {
    if high <= low + 1 {
        return None;
    }
    let mid = low + (high - low) / 2;
    (mid > low && mid < high).then_some(mid)
}

/// Last line of defence: never emit a sequence the fresh read shows as occupied.
/// Reusing an occupied sequence would REPLACE that entry on IOS.
fn free_or_refuse(
    candidate: u32,
    entries: &[PrefixListEntry],
    list: &str,
    prefix: &str,
) -> SequencePlan {
    if !(MIN_SEQ..=MAX_SEQ).contains(&candidate) {
        return SequencePlan::Refuse(format!(
            "computed sequence {candidate} for {prefix} is outside the range IOS accepts \
             ({MIN_SEQ}..={MAX_SEQ}); renumber prefix-list '{list}' on the router"
        ));
    }
    if let Some(occupied) = entries.iter().find(|e| e.sequence == candidate) {
        return SequencePlan::Refuse(format!(
            "refusing to write prefix-list '{list}' seq {candidate} for {prefix}: that \
             sequence is already occupied by '{}' and IOS would REPLACE it",
            occupied.clause()
        ));
    }
    SequencePlan::Use(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real shape read off the routers this fix came from.
    const VIVA: &str = "\
ip prefix-list pfx-to-viva: 2 entries
   seq 5 permit 194.105.142.0/24
   seq 10 deny 0.0.0.0/0 le 32";

    /// AKAMAI peers: the whole list is one terminating deny.
    const NO_EXPORT: &str = "\
ip prefix-list no-export: 1 entries
   seq 10 deny 0.0.0.0/0 le 32";

    fn used(plan: &SequencePlan) -> u32 {
        match plan {
            SequencePlan::Use(n) => *n,
            other => panic!("expected an insertion, got {other:?}"),
        }
    }

    fn refusal(plan: &SequencePlan) -> &str {
        match plan {
            SequencePlan::Refuse(reason) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    // ---- parsing -------------------------------------------------------------

    #[test]
    fn parses_a_real_list() {
        let entries = parse_prefix_list(VIVA, "pfx-to-viva").expect("parse");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sequence, 5);
        assert!(entries[0].permit);
        assert_eq!(entries[0].length, 24);
        assert_eq!(entries[1].sequence, 10);
        assert!(!entries[1].permit);
        assert_eq!(entries[1].le, Some(32));
        assert_eq!(entries[1].ge, None);
    }

    #[test]
    fn parses_ge_and_le_in_either_order_and_the_detail_suffix() {
        let out = "ip prefix-list x: 2 entries\n\
                   seq 5 permit 10.0.0.0/8 ge 16 le 24 (hit count: 3, refcount: 1)\n\
                   seq 10 permit 172.16.0.0/12 le 20 ge 14";
        let entries = parse_prefix_list(out, "x").expect("parse");
        assert_eq!((entries[0].ge, entries[0].le), (Some(16), Some(24)));
        assert_eq!((entries[1].ge, entries[1].le), (Some(14), Some(20)));
    }

    #[test]
    fn entries_of_other_lists_are_not_mixed_in() {
        let out = "ip prefix-list other: 1 entries\n\
                   seq 5 permit 8.8.8.0/24\n\
                   ip prefix-list mine: 1 entries\n\
                   seq 7 deny 0.0.0.0/0 le 32";
        let entries = parse_prefix_list(out, "mine").expect("parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sequence, 7);
    }

    #[test]
    fn empty_output_is_refused_never_treated_as_an_empty_list() {
        let err = parse_prefix_list("", "pfx-to-viva").expect_err("must refuse");
        assert!(err.contains("did not show prefix-list"), "{err}");
        // Same for whitespace-only and for output about a DIFFERENT list.
        assert!(parse_prefix_list("   \n\n  ", "pfx-to-viva").is_err());
        assert!(parse_prefix_list(NO_EXPORT, "pfx-to-viva").is_err());
    }

    #[test]
    fn a_denied_read_is_refused() {
        let out = "% Invalid input detected at '^' marker.";
        let err = parse_prefix_list(out, "pfx-to-viva").expect_err("must refuse");
        assert!(err.contains("rejected the prefix-list read"), "{err}");
    }

    #[test]
    fn a_malformed_entry_is_refused_not_skipped() {
        // If this deny were silently skipped we would append after it.
        let out = "ip prefix-list x: 2 entries\n\
                   seq 5 permit 194.105.142.0/24\n\
                   seq 10 deny 0.0.0.0/0 lt 32";
        assert!(parse_prefix_list(out, "x").is_err());
        for bad in [
            "ip prefix-list x: 1 entries\nseq deny 0.0.0.0/0",
            "ip prefix-list x: 1 entries\nseq 10 block 0.0.0.0/0",
            "ip prefix-list x: 1 entries\nseq 10 deny 0.0.0.0",
            "ip prefix-list x: 1 entries\nseq 10 deny 0.0.0.0/33",
            "ip prefix-list x: 1 entries\nseq 10 deny 0.0.0.0/0 le",
            "ip prefix-list x: 1 entries\nseq 10 deny 0.0.0.0/0 le 99",
            "ip prefix-list x: 1 entries\nseq 0 deny 0.0.0.0/0",
            "ip prefix-list x: 1 entries\nseq 99999999999 deny 0.0.0.0/0",
        ] {
            assert!(parse_prefix_list(bad, "x").is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn duplicate_sequences_are_refused() {
        let out = "ip prefix-list x: 2 entries\nseq 5 permit 1.0.0.0/8\nseq 5 deny 2.0.0.0/8";
        assert!(parse_prefix_list(out, "x").is_err());
    }

    #[test]
    fn declared_entry_count_must_match_the_complete_body() {
        let truncated = "ip prefix-list x: 2 entries\nseq 5 permit 192.0.2.0/24";
        let err = parse_prefix_list(truncated, "x").unwrap_err();
        assert!(err.contains("declared 2 entries"), "{err}");
        assert!(matches!(
            plan_add(truncated, "x", "198.51.100.0/24"),
            SequencePlan::Refuse(_)
        ));

        let header_only = "ip prefix-list x: 1 entry";
        assert!(parse_prefix_list(header_only, "x").is_err());
    }

    #[test]
    fn an_empty_list_requires_an_explicit_zero_count() {
        assert!(parse_prefix_list("ip prefix-list x: 0 entries", "x")
            .expect("complete empty list")
            .is_empty());
    }

    #[test]
    fn nothing_here_panics_on_arbitrary_text() {
        for junk in [
            "",
            "\u{0}\u{1}",
            "ip prefix-list : 0 entries",
            "ip prefix-list x:",
            "seq 5 permit 1.2.3.0/24",
            "ip prefix-list x: 1 entries\nseq",
            "ip prefix-list x: 1 entries\nseq 5 permit /",
            "ip prefix-list x: 1 entries\nseq 4294967295 permit 1.2.3.0/24",
            "é\nseq 1 permit 1.2.3.4/32\nip prefix-list é: 1 entries",
        ] {
            let _ = parse_prefix_list(junk, "x");
            let _ = plan_add(junk, "x", "1.2.3.0/24");
            let _ = plan_remove(junk, "x", "1.2.3.0/24");
            let _ = plan_add(junk, "x", "not-a-prefix");
        }
    }

    // ---- matching semantics --------------------------------------------------

    #[test]
    fn a_terminating_deny_with_le_shadows_everything() {
        let plan = plan_add(NO_EXPORT, "no-export", "194.105.142.0/24");
        // Only 1..9 are free before seq 10, and nothing precedes it.
        assert_eq!(used(&plan), 5);
    }

    #[test]
    fn a_ge_range_deny_shadows_only_lengths_inside_it() {
        // deny 10.0.0.0/8 ge 25 catches /25../32 inside 10/8, not a /24.
        let out = "ip prefix-list x: 2 entries\n\
                   seq 10 deny 10.0.0.0/8 ge 25\n\
                   seq 20 deny 0.0.0.0/0 le 32";
        // The /24 is NOT shadowed by seq 10; the catch-all at 20 is.
        assert_eq!(used(&plan_add(out, "x", "10.1.2.0/24")), 15);
        // A /26 inside 10/8 IS shadowed by seq 10, so it goes before it.
        assert_eq!(used(&plan_add(out, "x", "10.1.2.64/26")), 5);
    }

    #[test]
    fn an_le_range_deny_shadows_lengths_between_its_own_and_le() {
        // deny 10.0.0.0/8 le 24 catches /8../24 inside 10/8.
        let out = "ip prefix-list x: 1 entries\nseq 20 deny 10.0.0.0/8 le 24";
        assert_eq!(used(&plan_add(out, "x", "10.1.2.0/24")), 10);
        // A /25 falls outside the le range and past the end of the list.
        assert_eq!(used(&plan_add(out, "x", "10.1.2.0/25")), 25);
    }

    #[test]
    fn an_exact_deny_shadows_only_that_exact_prefix() {
        let out = "ip prefix-list x: 1 entries\nseq 20 deny 10.1.2.0/24";
        assert_eq!(used(&plan_add(out, "x", "10.1.2.0/24")), 10);
        // A more specific prefix is not matched by an entry with no ge/le.
        assert_eq!(used(&plan_add(out, "x", "10.1.2.128/25")), 25);
    }

    #[test]
    fn a_deny_of_a_different_network_does_not_shadow() {
        let out = "ip prefix-list x: 1 entries\nseq 20 deny 172.16.0.0/12 le 32";
        assert_eq!(used(&plan_add(out, "x", "194.105.142.0/24")), 25);
    }

    // ---- placement -----------------------------------------------------------

    #[test]
    fn inserts_between_the_preceding_entry_and_the_shadowing_deny() {
        // seq 5 permit, seq 10 deny-all: the only room is 6..9, midpoint 7.
        assert_eq!(used(&plan_add(VIVA, "pfx-to-viva", "194.105.143.0/24")), 7);
    }

    #[test]
    fn appends_with_an_explicit_sequence_when_nothing_shadows() {
        let out = "ip prefix-list x: 2 entries\n\
                   seq 5 permit 194.105.142.0/24\n\
                   seq 10 permit 194.105.143.0/24";
        // No deny at all — still explicit, never IOS auto-assignment.
        assert_eq!(used(&plan_add(out, "x", "194.105.144.0/24")), 15);
    }

    #[test]
    fn a_full_gap_is_refused_and_names_both_sequences() {
        let out = "ip prefix-list x: 2 entries\n\
                   seq 5 permit 194.105.142.0/24\n\
                   seq 6 deny 0.0.0.0/0 le 32";
        let reason = refusal(&plan_add(out, "x", "194.105.143.0/24")).to_string();
        assert!(reason.contains("between 5 and 6"), "{reason}");
        assert!(reason.contains("Renumber the prefix-list"), "{reason}");
        assert!(!reason.contains("seq 11"), "must not suggest an append");
    }

    #[test]
    fn a_shadowing_deny_at_sequence_one_leaves_no_room_and_is_refused() {
        let out = "ip prefix-list x: 1 entries\nseq 1 deny 0.0.0.0/0 le 32";
        let reason = refusal(&plan_add(out, "x", "194.105.142.0/24")).to_string();
        assert!(reason.contains("between 0 and 1"), "{reason}");
    }

    #[test]
    fn the_chosen_sequence_is_never_one_the_fresh_read_shows_as_occupied() {
        // Every placement over a spread of shapes must miss every live sequence:
        // reusing one would REPLACE that entry on IOS.
        let shapes = [
            VIVA,
            NO_EXPORT,
            "ip prefix-list x: 3 entries\nseq 1 permit 10.0.0.0/8\nseq 4 permit 11.0.0.0/8\nseq 9 deny 0.0.0.0/0 le 32",
            "ip prefix-list x: 2 entries\nseq 100 permit 10.0.0.0/8\nseq 200 deny 0.0.0.0/0 le 32",
        ];
        for shape in shapes {
            let name = if shape == VIVA {
                "pfx-to-viva"
            } else if shape == NO_EXPORT {
                "no-export"
            } else {
                "x"
            };
            let entries = parse_prefix_list(shape, name).expect("parse");
            if let SequencePlan::Use(n) = plan_add(shape, name, "194.105.143.0/24") {
                assert!(
                    !entries.iter().any(|e| e.sequence == n),
                    "chose occupied seq {n} in {shape:?}"
                );
            }
        }
    }

    #[test]
    fn free_or_refuse_rejects_a_collision_even_if_a_caller_computed_one() {
        let entries = parse_prefix_list(VIVA, "pfx-to-viva").expect("parse");
        let reason = refusal(&free_or_refuse(5, &entries, "pfx-to-viva", "1.2.3.0/24")).to_string();
        assert!(reason.contains("already occupied"), "{reason}");
        assert!(reason.contains("REPLACE"), "{reason}");
        assert!(free_or_refuse(0, &entries, "x", "1.2.3.0/24") != SequencePlan::Use(0));
    }

    #[test]
    fn appending_past_the_top_of_the_ios_range_is_refused() {
        let out = format!("ip prefix-list x: 1 entries\nseq {MAX_SEQ} permit 10.0.0.0/8");
        let reason = refusal(&plan_add(&out, "x", "194.105.142.0/24")).to_string();
        assert!(reason.contains("highest IOS accepts"), "{reason}");
    }

    // ---- already-satisfied ---------------------------------------------------

    #[test]
    fn an_already_permitted_prefix_is_a_no_op_that_still_names_its_entry() {
        match plan_add(VIVA, "pfx-to-viva", "194.105.142.0/24") {
            SequencePlan::AlreadySatisfied { sequence, note } => {
                assert_eq!(sequence, Some(5));
                assert!(note.contains("already permitted"), "{note}");
            }
            other => panic!("expected a no-op, got {other:?}"),
        }
    }

    #[test]
    fn a_prefix_covered_by_a_broader_reachable_permit_is_a_no_op_with_no_rollback_sequence() {
        let out = "ip prefix-list x: 2 entries\n\
                   seq 5 permit 194.105.0.0/16 le 24\n\
                   seq 10 deny 0.0.0.0/0 le 32";
        match plan_add(out, "x", "194.105.142.0/24") {
            SequencePlan::AlreadySatisfied { sequence, note } => {
                // A rollback must NOT be handed seq 5: removing it would withdraw
                // the whole /16, not the /24 the operator asked about.
                assert_eq!(sequence, None);
                assert!(note.contains("seq 5"), "{note}");
            }
            other => panic!("expected a no-op, got {other:?}"),
        }
    }

    #[test]
    fn a_permit_that_sits_behind_a_shadowing_deny_does_not_count_as_applied() {
        // The permit at seq 20 is unreachable; the deny at 10 wins.
        let out = "ip prefix-list x: 2 entries\n\
                   seq 10 deny 0.0.0.0/0 le 32\n\
                   seq 20 permit 194.105.142.0/24";
        assert_eq!(used(&plan_add(out, "x", "194.105.142.0/24")), 5);
    }

    // ---- removal -------------------------------------------------------------

    #[test]
    fn removal_targets_the_exact_reachable_permit() {
        assert_eq!(
            used(&plan_remove(VIVA, "pfx-to-viva", "194.105.142.0/24")),
            5
        );
    }

    #[test]
    fn removing_a_prefix_nothing_reaches_is_a_no_op() {
        match plan_remove(VIVA, "pfx-to-viva", "10.9.9.0/24") {
            SequencePlan::AlreadySatisfied { sequence, note } => {
                // The catch-all deny reaches it, so the note names that entry —
                // but a rollback must never be handed a DENY's sequence, or
                // re-adding a permit there would REPLACE the deny.
                assert_eq!(sequence, None);
                assert!(note.contains("already denied"), "{note}");
                assert!(note.contains("seq 10"), "{note}");
            }
            other => panic!("expected a no-op, got {other:?}"),
        }
        // A list with no catch-all at all: nothing reaches the prefix.
        let out = "ip prefix-list x: 1 entries\nseq 5 permit 194.105.142.0/24";
        match plan_remove(out, "x", "10.9.9.0/24") {
            SequencePlan::AlreadySatisfied { sequence, note } => {
                assert_eq!(sequence, None);
                assert!(note.contains("already not advertised"), "{note}");
            }
            other => panic!("expected a no-op, got {other:?}"),
        }
    }

    #[test]
    fn removing_a_prefix_carried_by_a_broader_permit_is_refused() {
        let out = "ip prefix-list x: 2 entries\n\
                   seq 5 permit 194.105.0.0/16 le 24\n\
                   seq 10 deny 0.0.0.0/0 le 32";
        let reason = refusal(&plan_remove(out, "x", "194.105.142.0/24")).to_string();
        assert!(reason.contains("BROADER"), "{reason}");
        assert!(reason.contains("seq 5"), "{reason}");
    }

    #[test]
    fn removal_refuses_the_same_unreadable_output_add_does() {
        assert!(matches!(
            plan_remove("", "x", "1.2.3.0/24"),
            SequencePlan::Refuse(_)
        ));
    }

    // ---- midpoint ------------------------------------------------------------

    #[test]
    fn midpoint_is_strictly_inside_the_gap_or_none() {
        assert_eq!(midpoint(0, 5), Some(2));
        assert_eq!(midpoint(5, 10), Some(7));
        assert_eq!(midpoint(5, 7), Some(6));
        assert_eq!(midpoint(5, 6), None);
        assert_eq!(midpoint(0, 1), None);
        assert_eq!(midpoint(7, 7), None);
        assert_eq!(midpoint(MAX_SEQ, MAX_SEQ), None);
        for (low, high) in [(0u32, 2u32), (1, 4), (10, 4_294_967_294)] {
            let mid = midpoint(low, high).expect("gap has room");
            assert!(mid > low && mid < high, "{mid} not inside ({low},{high})");
        }
    }
}
