-- Hardening changes the prepared evidence and recovery-ownership contract.
-- Preserve consumed plans as immutable execution history; unused credentials
-- must be prepared again after the new controller starts. Both current and
-- legacy preview stores remain part of the compatibility boundary.
UPDATE execution_plans
SET expires_at = UTC_TIMESTAMP()
WHERE consumed_at IS NULL AND expires_at > UTC_TIMESTAMP();

UPDATE action_previews
SET expires_at = UTC_TIMESTAMP()
WHERE used_at IS NULL AND expires_at > UTC_TIMESTAMP();
