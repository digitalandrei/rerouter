# Telemetry parser fixtures

Every telemetry/provider parser must have fixtures here. Each fixture stores the
raw input, the source/version, and the expected parsed JSON. Parser failures must
return structured errors and are asserted — never panics.

Examples to add as parsers land:
  netflow_v9_template_01.bin / .json
  ipfix_data_01.bin / .json
  sflow_sample_01.bin / .json
  cloudflare_zone_analytics_01.json
  bgp_feed_blackhole_present_01.json
