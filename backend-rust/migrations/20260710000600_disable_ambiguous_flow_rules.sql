-- The collector persists protocol identity only in talker buckets that also carry
-- a port selector. A protocol-only rule could therefore be evaluated against a
-- wider bucket than its saved condition implies. New API writes reject that
-- shape; disable any legacy rows so upgrades fail closed until an operator adds
-- an explicit source/destination port or removes the protocol selector.

UPDATE rules
SET enabled = 0
WHERE metric IN ('flow_pps', 'flow_bps')
  AND flow_protocol IS NOT NULL
  AND flow_port IS NULL;
