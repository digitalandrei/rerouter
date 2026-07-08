// Display-layer helpers: turn stable machine identifiers (snake_case template
// names, event types, enums) into natural Title-cased labels. The backend keeps
// the machine names as identifiers; this is purely how we render them.

const ACRONYMS: Record<string, string> = {
  bgp: "BGP", rtbh: "RTBH", mss: "MSS", tcp: "TCP", udp: "UDP",
  ip: "IP", ipv4: "IPv4", ipv6: "IPv6", as: "AS", asn: "ASN",
  snmp: "SNMP", ssh: "SSH", totp: "TOTP", ddos: "DDoS", mtu: "MTU",
  acl: "ACL", cli: "CLI", rx: "Rx", tx: "Tx", id: "ID", url: "URL", api: "API",
};
const WORDS: Record<string, string> = { iface: "Interface" };

/** snake_case / kebab / space token -> human Title Case, respecting acronyms
 *  (bgp -> BGP, mss -> MSS, iface -> Interface). Empty input -> "". */
export function humanizeToken(raw: string | null | undefined): string {
  if (!raw) return "";
  return raw
    .trim()
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((w) => {
      const lw = w.toLowerCase();
      if (ACRONYMS[lw]) return ACRONYMS[lw];
      if (WORDS[lw]) return WORDS[lw];
      return lw.charAt(0).toUpperCase() + lw.slice(1);
    })
    .join(" ");
}

/** Friendly template label: curated display_name, else humanized machine name. */
export function templateLabel(t: { display_name?: string | null; name: string }): string {
  return t.display_name?.trim() || humanizeToken(t.name);
}

/** Same, from separate fields (reroute rows / rule actions). Falls back to "—". */
export function templateLabelFrom(
  displayName: string | null | undefined,
  name: string | null | undefined,
): string {
  return displayName?.trim() || (name ? humanizeToken(name) : "—");
}

/** Tone + label for a device's SSH reachability status (devices.ssh_status).
 *  "no_privilege" means SSH works but the account lacks privilege 15 — an
 *  actionable config fix, so it's a warning, not a hard failure. */
export function sshStatusBadge(status: string): {
  tone: "good" | "warn" | "bad" | "neutral";
  label: string;
} {
  switch (status) {
    case "reachable":
      return { tone: "good", label: "reachable" };
    case "no_privilege":
      return { tone: "warn", label: "no privilege" };
    case "unreachable":
      return { tone: "bad", label: "unreachable" };
    default:
      return { tone: "neutral", label: "unknown" };
  }
}

/** A device's AUTOMATION status derived from SSH health + stability. Returns a
 *  badge (tone+label) when automatic mitigations targeting the device are held, or
 *  null when automation is active (device stable). Manual reroutes are still
 *  allowed once ssh_status='reachable' (the gate blocks a genuinely unreachable
 *  device). */
export function automationStatus(d: {
  ssh_status: string;
  automation_stable: boolean;
}): { tone: "warn" | "bad"; label: string } | null {
  if (d.ssh_status === "reachable") {
    return d.automation_stable ? null : { tone: "warn", label: "auto held (stabilizing)" };
  }
  // no_privilege / unreachable / unknown -> automatic mitigations suspended.
  return { tone: "bad", label: "auto suspended" };
}

// Thin aliases so call sites read intently (all just humanizeToken today).
export const eventTypeLabel = humanizeToken;
export const providerTypeLabel = humanizeToken;
export const samplingSourceLabel = humanizeToken;
export const triggerTypeLabel = humanizeToken;
