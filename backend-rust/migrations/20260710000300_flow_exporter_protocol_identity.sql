-- NetFlow and sFlow may legitimately originate from the same router address and
-- reuse observation-domain/sub-agent zero. Keep their durable health rows apart.

ALTER TABLE flow_exporters
    DROP INDEX uq_flow_exporters_src_domain,
    ADD UNIQUE KEY uq_flow_exporters_src_domain_version
        (source_addr, observation_domain, version);
