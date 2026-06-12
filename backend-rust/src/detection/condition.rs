//! Rule condition operators and threshold comparison.
//! Operators: >, >=, <, <=, ==, !=, between, outside, changed, stale.
//! See ../docs/detection-engine.md.

#[derive(Debug, Clone, Copy)]
pub enum Op { Gt, Ge, Lt, Le, Eq, Ne, Between, Outside, Changed, Stale }

// TODO(milestone 2): evaluate a metric value against an operator + threshold(s).
