-- A recovery attempt that is durably proven to have made no write is retryable.
-- Older finalization could leave such a child labelled compensation_blocked
-- even though every source association was settled known_no_write and no
-- inverse action ever reached a write-capable state. Repair only that exact,
-- evidence-complete shape; ambiguous/changed attempts remain untouched.
UPDATE reroute_bundles child
JOIN (
    SELECT recovery_bundle_id
    FROM recovery_attempt_sources
    GROUP BY recovery_bundle_id
    HAVING SUM(settlement = 'known_no_write') > 0
       AND SUM(settlement IN ('active', 'blocked')) = 0
) settled ON settled.recovery_bundle_id = child.id
SET child.state = 'failed'
WHERE child.state = 'compensation_blocked'
  AND NOT EXISTS (
      SELECT 1
      FROM reroutes inverse
      WHERE inverse.bundle_id = child.id
        AND (
            inverse.state IN ('pending', 'running', 'verifying', 'uncertain')
            OR inverse.mutation_effect IN ('changed', 'unknown')
        )
  );
