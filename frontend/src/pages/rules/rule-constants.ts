/** Shared rule vocab, reused by the Rules page + the edit dialog. */
export const METRICS = [
  { value: "rx_bps", label: "Rx bps" },
  { value: "tx_bps", label: "Tx bps" },
  { value: "rx_pps", label: "Rx pps" },
  { value: "tx_pps", label: "Tx pps" },
  { value: "rx_util_percent", label: "Rx utilization %" },
  { value: "tx_util_percent", label: "Tx utilization %" },
];

export const SEVERITIES = ["info", "warning", "critical"];

export function metricLabel(value: string): string {
  return METRICS.find((m) => m.value === value)?.label ?? value;
}
