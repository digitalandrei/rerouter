-- Global collector publication generation. Completeness readers fail closed
-- while the current in-memory flush cohort is registering contributors.
CREATE TABLE flow_publication_barrier (
    id              TINYINT UNSIGNED NOT NULL,
    generation      VARCHAR(36) NOT NULL,
    registry_ready  TINYINT(1) NOT NULL DEFAULT 0,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT chk_flow_publication_barrier_singleton CHECK (id = 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO flow_publication_barrier (id,generation,registry_ready)
VALUES (1,'bootstrap',0)
ON DUPLICATE KEY UPDATE id=VALUES(id);
