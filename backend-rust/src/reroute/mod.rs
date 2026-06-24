//! Reroute engine — controlled, audited mitigations that move traffic.
//! THE most dangerous part of the system. See ../docs/reroute-engine.md and
//! ../agents/reroute-safety-agent.md.

pub mod executor;
pub mod guard;
pub mod locks;
pub mod rollback;
pub mod state_machine;
pub mod templates;
