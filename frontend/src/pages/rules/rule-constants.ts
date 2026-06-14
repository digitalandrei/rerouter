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
