//! Payload-free timing boundaries for offline operational latency reports.
use std::time::Instant;

pub(crate) struct Stage {
    name: &'static str,
    subject_id: u64,
    started: Instant,
    outcome: &'static str,
}

impl Stage {
    pub(crate) fn start(name: &'static str, subject_id: u64) -> Self {
        Self {
            name,
            subject_id,
            started: Instant::now(),
            outcome: "incomplete",
        }
    }

    pub(crate) fn complete(&mut self, outcome: &'static str) {
        self.outcome = outcome;
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        tracing::info!(
            event_type = "hardening_timing",
            stage = self.name,
            subject_id = self.subject_id,
            elapsed_us = self.started.elapsed().as_micros() as u64,
            outcome = self.outcome,
            "operational stage completed"
        );
    }
}
