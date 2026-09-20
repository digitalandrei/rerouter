//! Bounded, coalescing flow-detection wake queue.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

pub const MAX_DIRTY_INTERFACES: usize = 4096;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowWakeBatch {
    pub interface_ids: Vec<u64>,
    pub full_rescan: bool,
}

#[derive(Debug, Default)]
struct State {
    pending: BTreeSet<u64>,
    full_rescan: bool,
    in_flight: Option<FlowWakeBatch>,
}

#[derive(Debug, Clone, Default)]
pub struct FlowWakeQueue {
    state: Arc<Mutex<State>>,
    notify: Arc<Notify>,
}

impl FlowWakeQueue {
    pub fn mark_interfaces(&self, ids: impl IntoIterator<Item = u64>) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        for id in ids {
            if state.pending.len() < MAX_DIRTY_INTERFACES || state.pending.contains(&id) {
                state.pending.insert(id);
            } else {
                state.full_rescan = true;
            }
        }
        if state.full_rescan || !state.pending.is_empty() {
            self.notify.notify_one();
        }
    }

    pub async fn wait_and_take(&self) -> FlowWakeBatch {
        loop {
            {
                let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(batch) = &state.in_flight {
                    return batch.clone();
                }
                if state.full_rescan || !state.pending.is_empty() {
                    let batch = FlowWakeBatch {
                        interface_ids: std::mem::take(&mut state.pending).into_iter().collect(),
                        full_rescan: std::mem::take(&mut state.full_rescan),
                    };
                    state.in_flight = Some(batch.clone());
                    return batch;
                }
            }
            self.notify.notified().await;
        }
    }

    pub fn complete_success(&self, batch: FlowWakeBatch) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.in_flight.as_ref() == Some(&batch) {
            state.in_flight = None;
        }
        if state.full_rescan || !state.pending.is_empty() {
            self.notify.notify_one();
        }
    }

    pub fn complete_failure(&self, batch: FlowWakeBatch) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.in_flight.as_ref() == Some(&batch) {
            state.in_flight = None;
        }
        state.full_rescan |= batch.full_rescan;
        for id in batch.interface_ids {
            if state.pending.len() < MAX_DIRTY_INTERFACES || state.pending.contains(&id) {
                state.pending.insert(id);
            } else {
                state.full_rescan = true;
            }
        }
        self.notify.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn coalesces_and_requeues_failed_work() {
        let queue = FlowWakeQueue::default();
        queue.mark_interfaces([3, 1, 3]);
        let batch = queue.wait_and_take().await;
        assert_eq!(batch.interface_ids, vec![1, 3]);
        queue.complete_failure(batch);
        assert_eq!(queue.wait_and_take().await.interface_ids, vec![1, 3]);
    }

    #[tokio::test]
    async fn overflow_requires_full_rescan() {
        let queue = FlowWakeQueue::default();
        queue.mark_interfaces(0..=(MAX_DIRTY_INTERFACES as u64));
        let batch = queue.wait_and_take().await;
        assert_eq!(batch.interface_ids.len(), MAX_DIRTY_INTERFACES);
        assert!(batch.full_rescan);
    }
}
