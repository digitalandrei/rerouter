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
const TEMPLATE_LABELS: Record<string, string> = {
  bgp_advertise_add: "Add prefix-list entry (legacy)",
  bgp_advertise_remove: "Remove prefix-list entry (legacy)",
};
const TEMPLATE_GUIDANCE: Record<string, string> = {
  bgp_advertise_add: "Edits entries inside the peer’s attached prefix list. For new work, use Change BGP export policy to change the peer attachment.",
  bgp_advertise_remove: "Removes entries inside the peer’s attached prefix list. For new work, use Change BGP export policy to change the peer attachment.",
  bgp_export_policy_set: "Changes which existing prefix list or route map is attached outbound to the selected peer; it does not edit policy contents.",
};

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
  return TEMPLATE_LABELS[t.name] ?? t.display_name?.trim() ?? humanizeToken(t.name);
}

/** Same, from separate fields (reroute rows / rule actions). Falls back to "—". */
export function templateLabelFrom(
  displayName: string | null | undefined,
  name: string | null | undefined,
): string {
  return (name ? TEMPLATE_LABELS[name] : undefined) ?? displayName?.trim() ?? (name ? humanizeToken(name) : "—");
}

export function templateGuidance(name: string): string | null { return TEMPLATE_GUIDANCE[name] ?? null; }

export function orderTemplatesForChoice<T extends { name: string }>(templates: T[]): T[] {
  const rank = (name: string) => name === "bgp_export_policy_set" ? 0 : name === "bgp_advertise_add" || name === "bgp_advertise_remove" ? 2 : 1;
  return [...templates].sort((a, b) => rank(a.name) - rank(b.name));
}

/** Tone + label for a device's SSH reachability status (devices.ssh_status).
 *  "reachable" = SSH answered at enable ('#') AND the account can run every command
 *  a reroute needs. "no_privilege" = SSH works but the account can't do the work —
 *  either it's not privilege 15, or a parser view denies a required command — an
 *  actionable config fix, so it's a warning, not a hard failure. */
export function sshStatusBadge(status: string): {
  tone: "good" | "warn" | "bad" | "neutral";
  label: string;
} {
  switch (status) {
    case "reachable":
      return { tone: "good", label: "reachable" };
    case "no_privilege":
      return { tone: "warn", label: "insufficient access" };
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

/** Compact "3h ago" for a server timestamp. undefined = the API build has no
 *  such field, so we say nothing rather than invent a time; null = never. */
export function timeAgo(iso: string | null | undefined): string {
  if (iso === undefined) return "";
  if (iso === null) return "never";
  const ms = Date.now() - new Date(iso).getTime();
  if (!Number.isFinite(ms)) return "never";
  if (ms < 0) return "just now";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

// Thin aliases so call sites read intently (all just humanizeToken today).
export const eventTypeLabel = humanizeToken;
export const providerTypeLabel = humanizeToken;
export const samplingSourceLabel = humanizeToken;
export const triggerTypeLabel = humanizeToken;
