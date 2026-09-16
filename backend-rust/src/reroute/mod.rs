//! Reroute engine — controlled, audited mitigations that move traffic.
//! THE most dangerous part of the system. See ../docs/reroute-engine.md and
//! ../agents/reroute-safety-agent.md.

pub mod bundle;
pub mod executor;
pub mod flow_target;
pub mod guard;
pub mod inventory_audit;
pub mod locks;
pub mod prefix_list;
pub mod reachability;
pub mod rollback;
pub mod state_machine;
pub mod templates;
