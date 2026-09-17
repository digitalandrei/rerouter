-- Repair the immutable action catalog used by prepared/exclusive execution.
-- Forward-only: earlier migrations may already have been applied in production.

-- The IPv4 Null-Route templates moved from `target` to `prefix`, but the old
-- command placeholders survived.  Use the canonical CIDR-derived values.
UPDATE reroute_templates
SET plan_json = '{"transport":"ios_ssh","config_mode":true,"apply":["ip route {prefix_net} {prefix_mask} Null0"]}',
    verification_json = '{"method":"ios_show","command":"show running-config | include ^ip route {prefix_net} {prefix_mask} Null0$","expect":"ip route {prefix_net} {prefix_mask} Null0"}'
WHERE name = 'null_route_prefix';

UPDATE reroute_templates
SET plan_json = '{"transport":"ios_ssh","config_mode":true,"apply":["no ip route {prefix_net} {prefix_mask} Null0"]}',
    verification_json = '{"method":"ios_show","command":"show running-config | include ^ip route {prefix_net} {prefix_mask} Null0$","reject":"ip route {prefix_net} {prefix_mask} Null0"}'
WHERE name = 'null_route_withdraw';

UPDATE reroute_templates
SET plan_json = '{"transport":"ios_ssh","config_mode":true,"apply":["ipv6 route {prefix} Null0"]}',
    verification_json = '{"method":"ios_show","command":"show running-config | include ^ipv6 route {prefix} Null0$","expect":"ipv6 route {prefix} Null0"}'
WHERE name = 'null_route_prefix_v6';

UPDATE reroute_templates
SET plan_json = '{"transport":"ios_ssh","config_mode":true,"apply":["no ipv6 route {prefix} Null0"]}',
    verification_json = '{"method":"ios_show","command":"show running-config | include ^ipv6 route {prefix} Null0$","reject":"ipv6 route {prefix} Null0"}'
WHERE name = 'null_route_withdraw_v6';

-- RTBH success requires the exact configured prefix, Null0 next-hop, and tag.
-- Prepared execution adds structured BGP/community checks; these exact config
-- checks also make legacy execution refuse an untagged or differently-tagged
-- pre-existing Null0 route.
UPDATE reroute_templates
SET verification_json = '{"method":"ios_show","command":"show running-config | include ^ip route {prefix_net} {prefix_mask} Null0 tag {tag}$","expect":"ip route {prefix_net} {prefix_mask} Null0 tag {tag}"}'
WHERE name = 'blackhole_prefix';

UPDATE reroute_templates
SET verification_json = '{"method":"ios_show","command":"show running-config | include ^ip route {prefix_net} {prefix_mask} Null0 tag {tag}$","reject":"ip route {prefix_net} {prefix_mask} Null0 tag {tag}"}'
WHERE name = 'blackhole_withdraw';

UPDATE reroute_templates
SET verification_json = '{"method":"ios_show","command":"show running-config | include ^ipv6 route {prefix} Null0 tag {tag}$","expect":"ipv6 route {prefix} Null0 tag {tag}"}'
WHERE name = 'blackhole_prefix_v6';

UPDATE reroute_templates
SET verification_json = '{"method":"ios_show","command":"show running-config | include ^ipv6 route {prefix} Null0 tag {tag}$","reject":"ipv6 route {prefix} Null0 tag {tag}"}'
WHERE name = 'blackhole_withdraw_v6';

-- Match the exact NLRI including prefix length.  The structured verifier parses
-- rows; retaining the full CIDR here also closes the legacy net-only substring.
UPDATE reroute_templates
SET verification_json = '{"method":"ios_show","command":"show ip bgp neighbors {neighbor_ip} advertised-routes","expect":"{prefix}"}'
WHERE name = 'bgp_advertise_add';

UPDATE reroute_templates
SET verification_json = '{"method":"ios_show","command":"show ip bgp neighbors {neighbor_ip} advertised-routes","reject":"{prefix}"}'
WHERE name = 'bgp_advertise_remove';
