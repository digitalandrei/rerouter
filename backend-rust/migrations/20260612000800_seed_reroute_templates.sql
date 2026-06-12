-- Starter reroute template catalog (see docs/reroute-engine.md). Idempotent:
-- INSERT IGNORE keyed on the unique template name, so operator edits survive
-- re-runs. Templates are the ONLY way a reroute can happen — parameters are
-- validated against parameter_schema_json; there is no free-text execution.

-- cloudflare_under_attack: low safety, easily reversible, auto-allowed.
INSERT IGNORE INTO reroute_templates
    (name, description, provider_type, mode, safety_level, automatic_allowed,
     manual_confirmation_required, parameter_schema_json, plan_json,
     verification_json, auto_expiry_seconds, enabled)
VALUES
    ('cloudflare_under_attack',
     'Set the Cloudflare zone security level to under_attack. Stores the prior level for exact rollback.',
     'cloudflare', 'cloudflare_api', 'low', 1, 0,
     '{"type":"object","required":["zone_id"],"properties":{"zone_id":{"type":"string"}},"additionalProperties":false}',
     '{"steps":[{"action":"set_security_level","value":"under_attack"}]}',
     '{"method":"cloudflare_api","expect":{"security_level":"under_attack"}}',
     1800, 1);

-- blackhole_prefix (RTBH): high safety, manual typed confirmation + re-auth,
-- auto-expires so a forgotten blackhole self-clears.
INSERT IGNORE INTO reroute_templates
    (name, description, provider_type, mode, safety_level, automatic_allowed,
     manual_confirmation_required, parameter_schema_json, plan_json,
     verification_json, auto_expiry_seconds, enabled)
VALUES
    ('blackhole_prefix',
     'Announce the target prefix with the upstream blackhole community (RTBH). Disruptive: drops ALL traffic to the prefix.',
     'bgp_rtbh', 'bgp_announce', 'high', 0, 1,
     '{"type":"object","required":["prefix","blackhole_community"],"properties":{"prefix":{"type":"string"},"blackhole_community":{"type":"string"}},"additionalProperties":false}',
     '{"steps":[{"action":"announce_blackhole"}]}',
     '{"method":"bgp_feed","expect":{"announcement_present":true,"community_present":true}}',
     1800, 1);

-- flowspec_drop: high safety, manual typed confirmation + re-auth.
INSERT IGNORE INTO reroute_templates
    (name, description, provider_type, mode, safety_level, automatic_allowed,
     manual_confirmation_required, parameter_schema_json, plan_json,
     verification_json, auto_expiry_seconds, enabled)
VALUES
    ('flowspec_drop',
     'Install an upstream BGP FlowSpec drop rule for a specific traffic tuple.',
     'flowspec', 'flowspec', 'high', 0, 1,
     '{"type":"object","required":["dst"],"properties":{"src":{"type":"string"},"dst":{"type":"string"},"proto":{"type":"string"},"port":{"type":"integer"}},"additionalProperties":false}',
     '{"steps":[{"action":"install_flowspec_rule"}]}',
     '{"method":"flowspec_state","expect":{"rule_installed":true}}',
     NULL, 1);
