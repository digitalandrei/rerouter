-- Ownership and immutable plan evidence available on baseline 69.
INSERT INTO devices(id,name,hostname,enabled) VALUES
 (900301,'fixture-router','192.0.2.30',0),
 (900302,'fixture-router-legacy','192.0.2.31',0);
INSERT INTO reroute_bundles(id,trigger_type,state,total_actions,completed_actions,source_json,
 lifecycle_state,remaining_mutations,recovery_claim_token,recovery_bundle_id,finished_at) VALUES
 (900401,'manual','compensation_blocked',1,1,'{"marker":"source-restored"}','recovery_blocked',1,NULL,NULL,'2026-09-01 01:00:00'),
 (900402,'manual','succeeded',1,1,'{"marker":"child-restored"}','inactive',0,NULL,NULL,'2026-09-01 01:01:00'),
 (900403,'manual','compensation_blocked',1,0,'{"marker":"source-ambiguous"}','recovery_running',1,'current-child-token',NULL,'2026-09-01 02:00:00'),
 (900404,'manual','running',1,0,'{"marker":"child-ambiguous"}','recovery_running',0,NULL,NULL,NULL),
 (900405,'manual','compensation_blocked',0,0,'{"marker":"source-missing-evidence"}','recovery_blocked',0,NULL,NULL,'2026-09-01 03:00:00'),
 (900406,'manual','aborted',0,0,'{"marker":"child-parent-only"}','inactive',0,NULL,NULL,'2026-09-01 03:01:00'),
 (900407,'manual','compensation_blocked',1,1,'{"marker":"source-legacy-inverse"}','recovery_running',1,'legacy-inverse-token',NULL,'2026-09-01 04:00:00'),
 (900408,'manual','running',1,0,'{"marker":"child-legacy-inverse"}','recovery_running',0,NULL,NULL,NULL);
UPDATE reroute_bundles SET parent_bundle_id=900401 WHERE id=900402;
UPDATE reroute_bundles SET parent_bundle_id=900403 WHERE id=900404;
UPDATE reroute_bundles SET parent_bundle_id=900405 WHERE id=900406;
UPDATE reroute_bundles SET recovery_bundle_id=900404 WHERE id=900403;
UPDATE reroute_bundles SET recovery_bundle_id=900408 WHERE id=900407;
UPDATE reroute_bundles SET recovery_bundle_id=900404 WHERE id=900403;
INSERT INTO reroutes(id,device_id,bundle_id,bundle_position,trigger_type,state,mutation_effect,
 prior_state_json,after_state_json,rollback_snapshot_json,started_at,finished_at) VALUES
 (900501,900301,900401,0,'manual','succeeded','changed','[{"kind":"interface_admin","interface":"Gi0/0","shutdown":false}]','[{"kind":"interface_admin","interface":"Gi0/0","shutdown":true}]','{"marker":"immutable-inverse-a"}','2026-09-01 01:00:00','2026-09-01 01:00:01'),
 (900502,900301,900402,0,'rollback','succeeded','changed','[{"kind":"interface_admin","interface":"Gi0/0","shutdown":true}]','[{"kind":"interface_admin","interface":"Gi0/0","shutdown":false}]',NULL,'2026-09-01 01:00:10','2026-09-01 01:00:11'),
 (900503,900301,900403,0,'manual','succeeded','unknown','[{"kind":"interface_admin","interface":"Gi0/1","shutdown":false}]','[{"kind":"interface_admin","interface":"Gi0/1","shutdown":true}]','{"marker":"immutable-inverse-b"}','2026-09-01 02:00:00','2026-09-01 02:00:01'),
 (900504,900302,900407,0,'manual','succeeded','changed','[{"kind":"interface_admin","interface":"Gi0/2","shutdown":false}]','[{"kind":"interface_admin","interface":"Gi0/2","shutdown":true}]','{"marker":"immutable-legacy-root"}','2026-09-01 04:00:00','2026-09-01 04:00:01'),
 (900505,900302,900408,0,'rollback','failed','unknown','[{"kind":"interface_admin","interface":"Gi0/2","shutdown":true}]','[{"kind":"interface_admin","interface":"Gi0/2","shutdown":false}]',NULL,'2026-09-01 04:00:10','2026-09-01 04:00:11');
UPDATE reroutes SET rollback_of_reroute_id=900501 WHERE id=900502;
UPDATE reroutes SET rollback_of_reroute_id=900504 WHERE id=900505;
INSERT INTO reroute_bundle_actions(id,bundle_id,position,original_reroute_id,device_id,
 template_snapshot_json,rollback_snapshot_json,canonical_params_json,rendered_plan_json,
 prepared_action_json,state,mutation_effect,reroute_id) VALUES
 (900601,900402,0,900501,900301,'{"marker":"template-a"}','{"marker":"immutable-ledger-inverse-a"}','{}','{}','{"marker":"immutable-prepared-a"}','succeeded','changed',900502),
 (900602,900404,0,900503,900301,'{"marker":"template-b"}','{"marker":"immutable-ledger-inverse-b"}','{}','{}','{"marker":"immutable-prepared-b"}','queued','pending',NULL);
INSERT INTO device_change_windows(device_id,bundle_id,owner_token,phase)
VALUES(900301,900404,'current-child-token','uncertain');
INSERT INTO device_change_windows(device_id,bundle_id,owner_token,phase)
VALUES(900302,900408,'legacy-inverse-token','uncertain');
INSERT INTO execution_plans(id,user_id,scope,reason,snapshot_json,plan_hash,token_hash,expires_at,consumed_at,bundle_id) VALUES
 (900701,900001,'bundle_revert','consumed immutable','{"marker":"immutable-consumed-plan","actions":[{"original_reroute_id":900501}]}',REPEAT('3',64),REPEAT('c',64),'2036-01-01 00:00:00','2026-09-01 01:00:00',900402),
 (900702,900001,'manual_mitigation','unused expires','{"marker":"immutable-unused-plan","actions":[]}',REPEAT('4',64),REPEAT('d',64),'2036-01-01 00:00:00',NULL,NULL);
