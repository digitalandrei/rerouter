-- Record the existing recovered-but-still-owned rule transition in the same
-- transaction as its cursor, recovery attempt, and alert. Existing event values
-- and historical rows are preserved.
ALTER TABLE rule_events
    MODIFY COLUMN event ENUM('matched','fired','cleared','recovered_awaiting_revert') NOT NULL;
