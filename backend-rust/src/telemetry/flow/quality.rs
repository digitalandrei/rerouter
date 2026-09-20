//! Persisted completeness evidence for flow buckets.
//!
//! Missing evidence is deliberately unavailable. In particular, a zero-row
//! selector is a measured zero only after every enrolled contributor known for
//! the interface produced both its exact interface bucket and quality row.

use chrono::{DateTime, Utc};
use sqlx::MySqlPool;

use super::Direction;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualityDimension {
    Interface,
    Port,
    Asn,
    Talker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceAvailability {
    Available,
    Unavailable,
}

/// Evidence shared by whole-interface and selector observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketEvidence {
    pub availability: EvidenceAvailability,
    pub expected_exporters: u64,
    pub observed_exporters: u64,
    pub dropped: u64,
    pub sampling_high_confidence: bool,
    pub pkts_available: bool,
    pub bytes_available: bool,
}

impl BucketEvidence {
    fn unavailable(expected_exporters: u64, observed_exporters: u64) -> Self {
        Self {
            availability: EvidenceAvailability::Unavailable,
            expected_exporters,
            observed_exporters,
            dropped: 0,
            sampling_high_confidence: false,
            pkts_available: false,
            bytes_available: false,
        }
    }
}

type EvidenceRow = (
    Option<u64>,
    Option<bool>,
    Option<u64>,
    Option<String>,
    Option<bool>,
    Option<bool>,
);

fn evaluate(rows: &[EvidenceRow]) -> BucketEvidence {
    let expected = rows.len() as u64;
    if expected == 0 {
        return BucketEvidence::unavailable(0, 0);
    }
    let observed = rows.iter().filter(|r| r.0.is_some()).count() as u64;
    if observed != expected || rows.iter().any(|r| r.1 != Some(true)) {
        return BucketEvidence::unavailable(expected, observed);
    }
    BucketEvidence {
        availability: EvidenceAvailability::Available,
        expected_exporters: expected,
        observed_exporters: observed,
        dropped: rows
            .iter()
            .filter_map(|r| r.2)
            .fold(0u64, u64::saturating_add),
        sampling_high_confidence: rows.iter().all(|r| r.3.as_deref() == Some("high")),
        pkts_available: rows.iter().all(|r| r.4 == Some(true)),
        bytes_available: rows.iter().all(|r| r.5 == Some(true)),
    }
}

/// Load exact-bucket evidence for one device/interface/direction/dimension.
///
/// The durable membership table is the expected contributor set. Every member
/// must still belong to this device and have an exact interface aggregate plus
/// a quality row at `bucket_ts`; otherwise the result is unavailable. This is
/// intentionally conservative for historical rows created before quality was
/// persisted and for silent exporters.
pub async fn bucket_evidence(
    pool: &MySqlPool,
    device_id: u64,
    if_index: u32,
    direction: Direction,
    bucket_ts: DateTime<Utc>,
    dimension: QualityDimension,
) -> anyhow::Result<BucketEvidence> {
    let (complete_col, dropped_col) = match dimension {
        QualityDimension::Interface => ("iface_complete", "iface_dropped"),
        QualityDimension::Port => ("port_complete", "port_dropped"),
        QualityDimension::Asn => ("asn_complete", "asn_dropped"),
        QualityDimension::Talker => ("talker_complete", "talker_dropped"),
    };
    // Column names come exclusively from the enum above; values remain bound.
    let sql = format!(
        "SELECT b.id, q.{complete_col}, q.{dropped_col}, \
                b.sampling_confidence, b.pkts_available, b.bytes_available \
         FROM flow_publication_barrier publication \
         JOIN flow_exporter_interfaces m ON publication.id=1 AND publication.registry_ready=1 \
         JOIN flow_exporters e ON e.id = m.exporter_id AND e.device_id = m.device_id \
         LEFT JOIN flow_iface_buckets b ON b.exporter_id = m.exporter_id \
              AND b.device_id = m.device_id AND b.if_index = m.if_index \
              AND b.direction = m.direction AND b.bucket_ts = ? \
         LEFT JOIN flow_bucket_quality q ON q.exporter_id = m.exporter_id \
              AND q.bucket_ts = ? \
         WHERE m.device_id = ? AND m.if_index = ? AND m.direction = ? \
              AND m.first_seen_at <= ?"
    );
    let rows: Vec<EvidenceRow> = sqlx::query_as(&sql)
        .bind(bucket_ts)
        .bind(bucket_ts)
        .bind(device_id)
        .bind(if_index)
        .bind(direction.as_str())
        .bind(bucket_ts)
        .fetch_all(pool)
        .await?;

    Ok(evaluate(&rows))
}

#[cfg(test)]
mod tests {
    use super::{evaluate, EvidenceAvailability};

    fn complete(id: u64) -> super::EvidenceRow {
        (
            Some(id),
            Some(true),
            Some(0),
            Some("high".into()),
            Some(true),
            Some(true),
        )
    }

    #[test]
    fn no_persisted_membership_is_unknown() {
        let evidence = evaluate(&[]);
        assert_eq!(evidence.availability, EvidenceAvailability::Unavailable);
        assert_eq!(evidence.expected_exporters, 0);
    }

    #[test]
    fn missing_exporter_interface_row_or_quality_is_unavailable() {
        let mut rows = vec![complete(1), complete(2)];
        rows[1].0 = None;
        let missing_bucket = evaluate(&rows);
        assert_eq!(
            missing_bucket.availability,
            EvidenceAvailability::Unavailable
        );
        assert_eq!(missing_bucket.observed_exporters, 1);

        rows[1] = complete(2);
        rows[1].1 = None;
        assert_eq!(
            evaluate(&rows).availability,
            EvidenceAvailability::Unavailable
        );
    }

    #[test]
    fn complete_zero_preserves_base_counter_and_sampling_evidence() {
        let evidence = evaluate(&[complete(1), complete(2)]);
        assert_eq!(evidence.availability, EvidenceAvailability::Available);
        assert!(evidence.sampling_high_confidence);
        assert!(evidence.pkts_available);
        assert!(evidence.bytes_available);
        assert_eq!(evidence.dropped, 0);
    }
}
