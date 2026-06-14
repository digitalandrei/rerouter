/** Shared rule vocab, reused by the Rules page + the edit dialog. */
export const METRICS = [
  { value: "rx_bps", label: "Rx bps (SNMP)" },
  { value: "tx_bps", label: "Tx bps (SNMP)" },
  { value: "rx_pps", label: "Rx pps (SNMP)" },
  { value: "tx_pps", label: "Tx pps (SNMP)" },
  { value: "rx_util_percent", label: "Rx utilization % (SNMP)" },
  { value: "tx_util_percent", label: "Tx utilization % (SNMP)" },
  { value: "flow_pps", label: "Flow pps (NetFlow)" },
  { value: "flow_bps", label: "Flow bps (NetFlow)" },
];

export const SEVERITIES = ["info", "warning", "critical"];

/** Comparison operators — must match the backend rules API (rules.rs). */
export const OPERATORS: { value: string; label: string }[] = [
  { value: ">", label: "above (>)" },
  { value: ">=", label: "at or above (>=)" },
  { value: "<", label: "below (<)" },
  { value: "<=", label: "at or below (<=)" },
  { value: "==", label: "equals (==)" },
  { value: "!=", label: "not equal (!=)" },
];

/** Flow metrics are evaluated against flow buckets and carry a selector. */
export function isFlowMetric(value: string): boolean {
  return value === "flow_pps" || value === "flow_bps";
}

/** Common IP protocols for the flow selector (empty = any). */
export const FLOW_PROTOCOLS = [
  { value: "", label: "Any protocol" },
  { value: "6", label: "TCP" },
  { value: "17", label: "UDP" },
  { value: "1", label: "ICMP" },
  { value: "132", label: "SCTP" },
];

export function metricLabel(value: string): string {
  return METRICS.find((m) => m.value === value)?.label ?? value;
}

/** Recovery policy: how a firing rule clears. */
export const RECOVERY_MODES = [
  { value: "auto", label: "Auto — clear after settle window" },
  { value: "threshold", label: "Threshold — clear below a recovery value" },
  { value: "manual", label: "Manual — operator clears it" },
];

/** A unit-appropriate placeholder for the threshold input, by metric. */
export function thresholdHint(metric: string): string {
  if (metric === "flow_pps" || metric === "rx_pps" || metric === "tx_pps") {
    return "packets/sec — e.g. 500000 for 500 Kpps";
  }
  if (metric === "flow_bps" || metric === "rx_bps" || metric === "tx_bps") {
    return "bits/sec — e.g. 1000000000 for 1 Gbps";
  }
  if (metric === "rx_util_percent" || metric === "tx_util_percent") {
    return "percent — e.g. 90";
  }
  if (metric === "oper_status") {
    return "1 = up, 0 = down";
  }
  return "threshold value";
}
