-- Make `automatic_allowed` an enforced policy instead of inert metadata.
-- Route-map changes and interface shutdown/no-shutdown stay manual-only. The MSS
-- pair is allowed because it is intentionally an ordered companion action.

UPDATE reroute_templates SET automatic_allowed = 0;

UPDATE reroute_templates
   SET automatic_allowed = 1
 WHERE name IN (
    'null_route_prefix', 'null_route_withdraw',
    'null_route_prefix_v6', 'null_route_withdraw_v6',
    'blackhole_prefix', 'blackhole_withdraw',
    'blackhole_prefix_v6', 'blackhole_withdraw_v6',
    'bgp_session_enable', 'bgp_session_disable',
    'bgp_advertise_add', 'bgp_advertise_remove',
    'iface_tcp_adjust_mss', 'iface_tcp_adjust_mss_remove'
 );
