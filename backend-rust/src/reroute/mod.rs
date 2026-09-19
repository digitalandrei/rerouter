//! Reroute engine — controlled, audited mitigations that move traffic.
//! THE most dangerous part of the system. See ../docs/reroute-engine.md and
//! ../agents/reroute-safety-agent.md.

pub mod bundle;
pub mod device_plan;
pub mod executor;
pub mod flow_target;
pub mod guard;
pub mod inventory_audit;
pub mod locks;
pub mod policy;
pub mod prefix_list;
pub mod preparation;
pub mod projection;
pub mod reachability;
pub mod recovery;
pub mod rollback;
pub mod state_machine;
pub mod templates;
