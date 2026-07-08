-- Device automation-stability clock. A device must be continuously SSH-reachable
-- (privileged EXEC) for a stability window before AUTOMATIC mitigations targeting
-- it resume — so a just-recovered or flapping device is not auto-acted upon.
--
--   ssh_reachable_since — when SSH last BECAME reachable and has stayed reachable.
--   Set (only if currently NULL) on a 'reachable' probe; cleared to NULL on any
--   'no_privilege'/'unreachable' probe and on controller startup. "Stable" =
--   ssh_status='reachable' AND now - ssh_reachable_since >= the stability window.
--
-- Automatic mitigations require stability; manual reroutes are allowed during the
-- window (with a UI warning) but still require SSH-reachable via the existing gate.

ALTER TABLE devices
    ADD COLUMN ssh_reachable_since TIMESTAMP NULL DEFAULT NULL AFTER last_ssh_ok_at;
