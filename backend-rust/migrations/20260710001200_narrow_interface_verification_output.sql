-- Verification evidence is persisted and exposed in reroute detail. Restrict
-- MSS checks to the one relevant line instead of retaining an entire interface
-- stanza that may contain unrelated authentication or addressing configuration.

UPDATE reroute_templates
SET verification_json =
    '{"method":"ios_show","command":"show running-config interface {interface} | include ip tcp adjust-mss","expect":"ip tcp adjust-mss {mss}"}'
WHERE name = 'iface_tcp_adjust_mss';

UPDATE reroute_templates
SET verification_json =
    '{"method":"ios_show","command":"show running-config interface {interface} | include ip tcp adjust-mss","reject":"ip tcp adjust-mss"}'
WHERE name = 'iface_tcp_adjust_mss_remove';
