-- Deterministic legacy notification and preview evidence (valid on baseline 56).
INSERT INTO users(id,name,email,password,two_factor_enforced)
VALUES(900001,'Migration Fixture','migration-fixture@example.test','fixture',0);
INSERT INTO alert_recipients(id,user_id,email,verified_at) VALUES
 (900011,900001,'delivery@example.test',UTC_TIMESTAMP()),
 (900012,NULL,'unrouted@rerouter.local',NULL);
INSERT INTO webhook_endpoints(id,name,url_encrypted,enabled) VALUES
 (900021,'fixture-teams',X'010203',1);
INSERT INTO alerts(id,event_type,severity,dedup_key,payload_json) VALUES
 (900101,'fixture_sent','warning','fixture-sent','{"marker":"immutable-sent"}'),
 (900102,'fixture_suppressed','warning','fixture-suppressed','{"marker":"immutable-suppressed"}'),
 (900103,'fixture_rate','warning','fixture-rate','{"marker":"immutable-rate"}'),
 (900104,'fixture_failed','warning','fixture-failed','{"marker":"immutable-failed"}'),
 (900105,'fixture_unattempted','warning','fixture-unattempted','{"marker":"immutable-unattempted"}'),
 (900106,'fixture_no_audience','warning','fixture-no-audience','{"marker":"immutable-no-audience"}'),
 (900107,'fixture_teams_rate','warning','fixture-teams-rate','{"marker":"immutable-teams-rate"}');
INSERT INTO alert_deliveries(id,alert_id,recipient_id,endpoint_id,channel,status,error,sent_at,created_at) VALUES
 (900201,900101,900011,NULL,'email','sent',NULL,'2026-09-01 00:00:01','2026-09-01 00:00:01'),
 (900202,900102,900011,NULL,'email','queued','suppressed: deduplicated within window',NULL,'2026-09-01 00:00:02'),
 (900203,900103,900011,NULL,'email','queued','rate limited: deferred to digest',NULL,'2026-09-01 00:00:03'),
 (900204,900104,900011,NULL,'email','failed','connection refused',NULL,'2026-09-01 00:00:04'),
 (900205,900106,900012,NULL,'email','queued','no subscribed recipients',NULL,'2026-09-01 00:00:05'),
 (900206,900107,NULL,900021,'teams','queued','rate limited: retry https://example.invalid/webhook?sig=SYNTHETIC_SECRET',NULL,'2026-09-01 00:00:06');
INSERT INTO action_previews(token_hash,user_id,scope,scope_id,plan_hash,expires_at,used_at) VALUES
 (REPEAT('a',64),900001,'manual',NULL,REPEAT('1',64),'2036-01-01 00:00:00',NULL),
 (REPEAT('b',64),900001,'manual',NULL,REPEAT('2',64),'2036-01-01 00:00:00','2026-09-01 00:00:00');
