-- Multi-source recovery ownership. The legacy recovery_bundle_id remains a
-- compatibility pointer; these rows are the authoritative association.
CREATE TABLE recovery_attempt_sources (
    recovery_bundle_id BIGINT UNSIGNED NOT NULL,
    source_bundle_id BIGINT UNSIGNED NOT NULL,
    claim_token VARCHAR(128) NOT NULL,
    settlement ENUM('active','restored','known_no_write','blocked') NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    settled_at DATETIME NULL,
    PRIMARY KEY (recovery_bundle_id, source_bundle_id),
    KEY idx_recovery_attempt_source (source_bundle_id, settlement),
    CONSTRAINT fk_recovery_attempt_child FOREIGN KEY (recovery_bundle_id)
        REFERENCES reroute_bundles(id) ON DELETE RESTRICT,
    CONSTRAINT fk_recovery_attempt_source FOREIGN KEY (source_bundle_id)
        REFERENCES reroute_bundles(id) ON DELETE RESTRICT
) ENGINE=InnoDB;

DROP TEMPORARY TABLE IF EXISTS legacy_source_proof;
CREATE TEMPORARY TABLE legacy_source_proof AS
SELECT source.id AS source_id,source.total_actions,
       source.state NOT IN ('planned','running','compensating') AS source_terminal,
       (SELECT COUNT(*) FROM reroutes root WHERE root.bundle_id=source.id AND root.rollback_of_reroute_id IS NULL) AS root_originals,
       (SELECT COUNT(*) FROM reroute_bundle_actions slot WHERE slot.bundle_id=source.id) AS ledger_slots,
       (SELECT COUNT(*) FROM reroute_bundle_actions slot WHERE slot.bundle_id=source.id AND slot.reroute_id IS NULL
          AND slot.state IN ('queued','noop','failed','compensated') AND slot.mutation_effect IN ('pending','noop')) AS unwritten_slots,
       (SELECT COUNT(*) FROM reroute_bundle_actions slot WHERE slot.bundle_id=source.id AND
          (slot.position>=source.total_actions OR NOT (
            EXISTS(SELECT 1 FROM reroutes root WHERE root.id=slot.reroute_id AND root.bundle_id=source.id
              AND root.bundle_position=slot.position AND root.rollback_of_reroute_id IS NULL)
            OR (slot.reroute_id IS NULL AND slot.state IN ('queued','noop','failed','compensated')
              AND slot.mutation_effect IN ('pending','noop'))))) AS invalid_slots,
       (SELECT COUNT(*) FROM reroute_bundle_actions slot WHERE slot.bundle_id=source.id AND
          EXISTS(SELECT 1 FROM reroutes root WHERE root.id=slot.reroute_id AND root.bundle_id=source.id
            AND root.bundle_position=slot.position AND root.rollback_of_reroute_id IS NULL)) AS linked_root_slots,
       (SELECT COUNT(*) FROM reroutes root WHERE root.bundle_id=source.id AND root.rollback_of_reroute_id IS NULL
          AND (root.state IN ('planned','pending','running','verifying','uncertain') OR root.mutation_effect IN ('pending','unknown')
            OR EXISTS(SELECT 1 FROM reroutes inverse WHERE inverse.rollback_of_reroute_id=root.id
              AND (inverse.state IN ('planned','pending','running','verifying','uncertain')
                OR inverse.mutation_effect IN ('pending','unknown','changed') AND inverse.state<>'succeeded')))) AS ambiguous_effects,
       (SELECT COUNT(*) FROM reroutes root WHERE root.bundle_id=source.id AND root.rollback_of_reroute_id IS NULL
          AND root.mutation_effect IN ('changed','unknown') AND NOT EXISTS(SELECT 1 FROM reroutes inverse
            WHERE inverse.rollback_of_reroute_id=root.id AND inverse.state='succeeded'
              AND inverse.mutation_effect IN ('changed','noop'))) AS remaining
FROM reroute_bundles source;

-- A device may quarantine mutations from several source activations even while
-- one recovery child temporarily owns its executable change w.
CREATE TABLE device_change_window_sources (
    device_id BIGINT UNSIGNED NOT NULL,
    source_bundle_id BIGINT UNSIGNED NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, source_bundle_id),
    KEY idx_window_source_bundle (source_bundle_id, device_id),
    CONSTRAINT fk_window_source_device FOREIGN KEY (device_id)
        REFERENCES devices(id) ON DELETE RESTRICT,
    CONSTRAINT fk_window_source_bundle FOREIGN KEY (source_bundle_id)
        REFERENCES reroute_bundles(id) ON DELETE RESTRICT
) ENGINE=InnoDB;

INSERT IGNORE INTO recovery_attempt_sources
    (recovery_bundle_id, source_bundle_id, claim_token, settlement, settled_at)
SELECT DISTINCT child.id, original.bundle_id,
       CASE WHEN source.recovery_bundle_id=child.id AND source.recovery_claim_token IS NOT NULL
            THEN source.recovery_claim_token ELSE CONCAT('legacy:child:', child.id) END,
       CASE WHEN source.recovery_bundle_id=child.id AND source.recovery_claim_token IS NOT NULL THEN 'active'
            WHEN proof.source_terminal=1 AND proof.ambiguous_effects=0 AND proof.remaining=0 AND proof.root_originals>0
             AND ((proof.total_actions=0) OR (proof.ledger_slots=proof.total_actions AND proof.invalid_slots=0 AND proof.linked_root_slots=proof.root_originals)
               OR (proof.ledger_slots=0 AND proof.root_originals=proof.total_actions)) THEN 'restored'
            WHEN proof.source_terminal=1 AND proof.total_actions>0 AND proof.ambiguous_effects=0
             AND proof.ledger_slots=proof.total_actions AND proof.invalid_slots=0
             AND proof.linked_root_slots=0 AND proof.root_originals=0 AND proof.unwritten_slots=proof.total_actions THEN 'known_no_write'
            ELSE 'blocked' END,
       CASE WHEN source.recovery_bundle_id=child.id AND source.recovery_claim_token IS NOT NULL THEN NULL
            ELSE COALESCE(child.finished_at,CURRENT_TIMESTAMP) END
FROM reroute_bundles child
JOIN reroute_bundle_actions ba ON ba.bundle_id = child.id
JOIN reroutes original ON original.id = ba.original_reroute_id
JOIN reroute_bundles source ON source.id = original.bundle_id
JOIN legacy_source_proof proof ON proof.source_id=source.id
WHERE child.parent_bundle_id IS NOT NULL OR source.recovery_bundle_id = child.id;

INSERT IGNORE INTO recovery_attempt_sources
    (recovery_bundle_id, source_bundle_id, claim_token, settlement, settled_at)
SELECT DISTINCT child.id, child.parent_bundle_id,
       CASE WHEN source.recovery_bundle_id=child.id AND source.recovery_claim_token IS NOT NULL
            THEN source.recovery_claim_token ELSE CONCAT('legacy:child:', child.id) END,
       CASE WHEN source.recovery_bundle_id=child.id AND source.recovery_claim_token IS NOT NULL THEN 'active'
            WHEN proof.source_terminal=1 AND proof.ambiguous_effects=0 AND proof.remaining=0 AND proof.root_originals>0
             AND ((proof.total_actions=0) OR (proof.ledger_slots=proof.total_actions AND proof.invalid_slots=0 AND proof.linked_root_slots=proof.root_originals)
               OR (proof.ledger_slots=0 AND proof.root_originals=proof.total_actions)) THEN 'restored'
            WHEN proof.source_terminal=1 AND proof.total_actions>0 AND proof.ambiguous_effects=0
             AND proof.ledger_slots=proof.total_actions AND proof.invalid_slots=0
             AND proof.linked_root_slots=0 AND proof.root_originals=0 AND proof.unwritten_slots=proof.total_actions THEN 'known_no_write'
            ELSE 'blocked' END,
       CASE WHEN source.recovery_bundle_id=child.id AND source.recovery_claim_token IS NOT NULL THEN NULL
            ELSE COALESCE(child.finished_at,CURRENT_TIMESTAMP) END
FROM reroute_bundles child
JOIN reroute_bundles source ON source.id = child.parent_bundle_id
JOIN legacy_source_proof proof ON proof.source_id=source.id
WHERE child.parent_bundle_id IS NOT NULL;

INSERT IGNORE INTO recovery_attempt_sources
    (recovery_bundle_id, source_bundle_id, claim_token, settlement, settled_at)
SELECT DISTINCT inverse.bundle_id, original.bundle_id,
       CASE WHEN source.recovery_bundle_id=inverse.bundle_id AND source.recovery_claim_token IS NOT NULL
            THEN source.recovery_claim_token ELSE CONCAT('legacy:child:', inverse.bundle_id) END,
       CASE WHEN source.recovery_bundle_id=inverse.bundle_id AND source.recovery_claim_token IS NOT NULL THEN 'active'
            WHEN proof.source_terminal=1 AND proof.ambiguous_effects=0 AND proof.remaining=0 AND proof.root_originals>0
             AND ((proof.total_actions=0) OR (proof.ledger_slots=proof.total_actions AND proof.invalid_slots=0 AND proof.linked_root_slots=proof.root_originals)
               OR (proof.ledger_slots=0 AND proof.root_originals=proof.total_actions)) THEN 'restored'
            WHEN proof.source_terminal=1 AND proof.total_actions>0 AND proof.ambiguous_effects=0
             AND proof.ledger_slots=proof.total_actions AND proof.invalid_slots=0
             AND proof.linked_root_slots=0 AND proof.root_originals=0 AND proof.unwritten_slots=proof.total_actions THEN 'known_no_write'
            ELSE 'blocked' END,
       CASE WHEN source.recovery_bundle_id=inverse.bundle_id AND source.recovery_claim_token IS NOT NULL THEN NULL
            ELSE COALESCE(child.finished_at,CURRENT_TIMESTAMP) END
FROM reroutes inverse
JOIN reroutes original ON original.id = inverse.rollback_of_reroute_id
JOIN reroute_bundles source ON source.id = original.bundle_id
JOIN reroute_bundles child ON child.id = inverse.bundle_id
JOIN legacy_source_proof proof ON proof.source_id=source.id
WHERE inverse.bundle_id IS NOT NULL AND original.bundle_id IS NOT NULL;

-- Seed membership only from a device that is actually quarantined now. A
-- recovery child holding the physical window contributes its root source(s),
-- never the child id itself.
INSERT IGNORE INTO device_change_window_sources (device_id, source_bundle_id)
SELECT w.device_id, w.bundle_id
FROM device_change_windows AS w
WHERE w.bundle_id IS NOT NULL
  AND EXISTS(SELECT 1 FROM reroutes original WHERE original.bundle_id=w.bundle_id
      AND original.rollback_of_reroute_id IS NULL AND original.mutation_effect IN ('changed','unknown')
      AND NOT EXISTS(SELECT 1 FROM reroutes inverse WHERE inverse.rollback_of_reroute_id=original.id
          AND inverse.state='succeeded' AND inverse.mutation_effect IN ('changed','noop')));

INSERT IGNORE INTO device_change_window_sources (device_id, source_bundle_id)
SELECT DISTINCT w.device_id, ras.source_bundle_id
FROM device_change_windows AS w
JOIN recovery_attempt_sources ras ON ras.recovery_bundle_id=w.bundle_id
JOIN reroute_bundle_actions action ON action.bundle_id=ras.recovery_bundle_id
JOIN reroutes original ON original.id=action.original_reroute_id
WHERE original.bundle_id=ras.source_bundle_id AND original.device_id=w.device_id
  AND ras.settlement IN ('active','blocked');

-- Legacy recovery children may have durable inverse reroutes but no immutable
-- bundle-action ledger. Preserve only the root source proved by that inverse
-- relationship and the retained physical window.
INSERT IGNORE INTO device_change_window_sources (device_id, source_bundle_id)
SELECT DISTINCT w.device_id, original.bundle_id
FROM device_change_windows AS w
JOIN reroutes inverse ON inverse.bundle_id=w.bundle_id AND inverse.rollback_of_reroute_id IS NOT NULL
JOIN reroutes original ON original.id=inverse.rollback_of_reroute_id AND original.device_id=w.device_id
JOIN recovery_attempt_sources ras ON ras.recovery_bundle_id=inverse.bundle_id
  AND ras.source_bundle_id=original.bundle_id AND ras.settlement IN ('active','blocked');

DROP TEMPORARY TABLE legacy_source_proof;
