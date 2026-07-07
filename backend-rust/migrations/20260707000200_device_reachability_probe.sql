-- Device control-plane reachability probe, used to decide whether a device is
-- available to receive a mitigation. Reachability for reroutes is driven by SSH
-- (a reroute pushes config over SSH), with a telnet port-open check kept as an
-- informational secondary signal.
--
--   telnet_port        the TCP port the periodic telnet probe connects to (23).
--   telnet_reachable    last telnet TCP-connect outcome (informational only).
--   last_telnet_ok_at   when telnet last accepted a TCP connection.
--   last_ssh_ok_at      when SSH last answered commands (a real reroute OR a
--                       liveness probe). Drives the 60s "responded recently"
--                       short-circuit so the reroute preflight does not re-probe
--                       (and does not trip the device's SSH connection throttle).

ALTER TABLE devices
    ADD COLUMN telnet_port       SMALLINT UNSIGNED NOT NULL DEFAULT 23 AFTER ssh_port,
    ADD COLUMN telnet_reachable  TINYINT(1)        NOT NULL DEFAULT 0  AFTER reachable,
    ADD COLUMN last_telnet_ok_at TIMESTAMP         NULL DEFAULT NULL   AFTER last_poll_at,
    ADD COLUMN last_ssh_ok_at    TIMESTAMP         NULL DEFAULT NULL   AFTER last_telnet_ok_at;
