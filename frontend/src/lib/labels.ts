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

// Thin aliases so call sites read intently (all just humanizeToken today).
export const eventTypeLabel = humanizeToken;
export const providerTypeLabel = humanizeToken;
export const samplingSourceLabel = humanizeToken;
export const triggerTypeLabel = humanizeToken;
