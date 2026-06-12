//! NetFlow v9 / IPFIX collector. Template-based: cache templates per exporter
//! before decoding data records. Apply the per-exporter sampling rate.
//! Parsers return structured errors, never panic. See ../skills/traffic-telemetry.md.

// TODO(milestone 1): UDP listener, template cache, record decode -> flow tuples.
