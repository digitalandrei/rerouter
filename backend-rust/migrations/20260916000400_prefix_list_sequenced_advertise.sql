-- Sequenced prefix-list insertion for the BGP advertise templates.
--
-- THE BUG (verified against the live routers): every outbound prefix-list on
-- these boxes ends with a terminating deny —
--
--     ip prefix-list no-export   seq 10 deny 0.0.0.0/0 le 32
--     ip prefix-list pfx-to-viva seq  5 permit 194.105.142.0/24
--     ip prefix-list pfx-to-viva seq 10 deny 0.0.0.0/0 le 32
--
-- and 20260623000100 seeded `bgp_advertise_add` with
-- `ip prefix-list {prefix_list_name} permit {prefix}` — NO sequence number. IOS
-- auto-assigns `highest + 5`, so the new permit lands AFTER the terminating deny
-- and is never reached. The CLI reports success, the router advertises nothing,
-- and only the post-apply verification catches it. Fail-safe, but the feature
-- does not work.
--
-- THE FIX: render an EXPLICIT sequence, chosen by the controller from a read of
-- the target list taken inside the SAME SSH session that pushes the config
-- (src/reroute/prefix_list.rs). `{sequence}` is a `seq`-typed parameter that the
-- caller can never supply: the executor strips it from caller input and writes it
-- back only after resolving it, so the rollback can remove EXACTLY the entry that
-- was added rather than content-matching it.
--
-- Cached inventory is not acceptable for this decision: on IOS, reusing an
-- existing sequence number with different content REPLACES that entry, so acting
-- on an hour-old picture of the list risks silently overwriting a live filter.
-- The read is one extra `show` in an already-open session — NOT a discovery run
-- (no new connection, no reconcile, no drift audit).
--
-- 20260623000100 is already applied, so its seeds are UPDATEd here rather than
-- edited in place. Templates are matched by their unique `name`.
--
-- Safety posture is unchanged because this migration does not touch
-- `automatic_allowed` at all. Note what that value actually is: 20260710000200
-- (execution policy) deliberately set BOTH advertise templates to
-- `automatic_allowed = 1`, so they ARE automatic-capable. That remains gated by
-- enforce mode + the global enable + the per-rule enable, and it is a decision
-- taken in that migration, not here. Parameters, verification and the rollback
-- pairing are likewise preserved.

-- bgp_advertise_add: place the permit at a controller-chosen sequence.
UPDATE reroute_templates
SET parameter_schema_json = '{"neighbor_ip":{"type":"ip","label":"Upstream neighbor","required":true,"source":"bgp_peer"},"prefix":{"type":"cidr","label":"Prefix to advertise","required":true,"source":"announced_prefix"},"prefix_list_name":{"type":"string","label":"Outbound prefix-list","required":true,"source":"peer_out_prefix_list"},"sequence":{"type":"seq","label":"Prefix-list sequence","required":false,"deferred":true}}',
    plan_json = '{"transport":"ios_ssh","config_mode":true,"apply":["ip prefix-list {prefix_list_name} seq {sequence} permit {prefix}"],"exec_after":["clear ip bgp {neighbor_ip} soft out"]}',
    description = 'Advertise a prefix toward one upstream BGP peer: add it to the peer''s outbound route-map prefix-list at a sequence chosen from a fresh read of that list (so the entry lands BEFORE the list''s terminating deny and is actually reached), then clear ip bgp <peer> soft out. Use to shift an attacked prefix onto a less-saturated upstream. Reversible.'
WHERE name = 'bgp_advertise_add';

-- bgp_advertise_remove: remove EXACTLY one entry, by sequence.
UPDATE reroute_templates
SET parameter_schema_json = '{"neighbor_ip":{"type":"ip","label":"Upstream neighbor","required":true,"source":"bgp_peer"},"prefix":{"type":"cidr","label":"Prefix to withdraw","required":true,"source":"announced_prefix"},"prefix_list_name":{"type":"string","label":"Outbound prefix-list","required":true,"source":"peer_out_prefix_list"},"sequence":{"type":"seq","label":"Prefix-list sequence","required":false,"deferred":true}}',
    plan_json = '{"transport":"ios_ssh","config_mode":true,"apply":["no ip prefix-list {prefix_list_name} seq {sequence} permit {prefix}"],"exec_after":["clear ip bgp {neighbor_ip} soft out"]}',
    description = 'Stop advertising a prefix toward one upstream BGP peer: remove exactly its entry from the peer''s outbound route-map prefix-list (by sequence number), then clear ip bgp <peer> soft out. Rollback of bgp_advertise_add.'
WHERE name = 'bgp_advertise_remove';

-- Re-assert the rollback pairing (idempotent; unchanged by this migration, but
-- cheap insurance that the pair stays wired after a partial seed).
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'bgp_advertise_remove'
    SET t.rollback_template_id = r.id WHERE t.name = 'bgp_advertise_add';
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'bgp_advertise_add'
    SET t.rollback_template_id = r.id WHERE t.name = 'bgp_advertise_remove';
