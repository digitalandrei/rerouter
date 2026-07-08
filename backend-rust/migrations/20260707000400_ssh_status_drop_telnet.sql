-- Telnet reachability is not used operationally (the routers keep telnet closed),
-- so drop the telnet probe columns. Replace the ssh_reachable bool with a richer
-- ssh_status that distinguishes:
--   'reachable'    — answered at privileged EXEC ('#'); usable for a reroute.
--   'no_privilege' — SSH connected + authenticated but landed at user-EXEC ('>');
--                    the account just lacks privilege 15 (an actionable config fix,
--                    NOT a connectivity problem).
--   'unreachable'  — could not connect / authenticate / reach a usable prompt.
--   'unknown'      — not probed yet.
-- last_ssh_error holds the last probe's message for display. last_ssh_ok_at still
-- drives the reroute gate's 60s recency short-circuit (stamped only on 'reachable').

ALTER TABLE devices
    DROP COLUMN telnet_port,
    DROP COLUMN telnet_reachable,
    DROP COLUMN last_telnet_ok_at,
    DROP COLUMN ssh_reachable,
    ADD COLUMN ssh_status     VARCHAR(20) NOT NULL DEFAULT 'unknown' AFTER reachable,
    ADD COLUMN last_ssh_error TEXT        NULL                       AFTER last_ssh_ok_at;
