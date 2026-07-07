-- Last SSH reachability-probe outcome, mirroring telnet_reachable. A periodic
-- probe (reachability_interval_seconds, default 5 min) opens a no-command SSH
-- liveness session and records here whether the device answered, so the UI shows
-- a definite "SSH reachable/unreachable" state instead of a time-window guess.
-- SSH remains the authoritative signal for the reroute gate (last_ssh_ok_at drives
-- the 60s recency short-circuit); this column is the display of the last probe.

ALTER TABLE devices
    ADD COLUMN ssh_reachable TINYINT(1) NOT NULL DEFAULT 0 AFTER telnet_reachable;
