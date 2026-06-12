//! Rule condition operators and threshold comparison.
//! Operators: >, >=, <, <=, ==, !=, between, outside, changed, stale.
//! See ../docs/detection-engine.md.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Gt,
    Ge,
    Lt,
    Le,
    Eq,
    Ne,
    Between,
    Outside,
    Changed,
    Stale,
}

impl Op {
    /// Parse the operator string stored on a rule. Unknown strings are treated as
    /// "never matches" by returning None (the caller skips evaluation).
    pub fn parse(s: &str) -> Option<Op> {
        Some(match s {
            ">" => Op::Gt,
            ">=" => Op::Ge,
            "<" => Op::Lt,
            "<=" => Op::Le,
            "==" | "=" => Op::Eq,
            "!=" | "<>" => Op::Ne,
            "between" => Op::Between,
            "outside" => Op::Outside,
            "changed" => Op::Changed,
            "stale" => Op::Stale,
            _ => return None,
        })
    }

    /// Compare a single metric value against a threshold for the binary
    /// operators. Multi-arg operators (between/outside/changed/stale) are not
    /// handled here and return false.
    pub fn compare(self, value: f64, threshold: f64) -> bool {
        match self {
            Op::Gt => value > threshold,
            Op::Ge => value >= threshold,
            Op::Lt => value < threshold,
            Op::Le => value <= threshold,
            Op::Eq => (value - threshold).abs() < f64::EPSILON,
            Op::Ne => (value - threshold).abs() >= f64::EPSILON,
            // Operators that need more than one threshold are evaluated elsewhere.
            Op::Between | Op::Outside | Op::Changed | Op::Stale => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_operators() {
        assert_eq!(Op::parse(">"), Some(Op::Gt));
        assert_eq!(Op::parse("<="), Some(Op::Le));
        assert_eq!(Op::parse("=="), Some(Op::Eq));
        assert_eq!(Op::parse("nope"), None);
    }

    #[test]
    fn compares_binary_operators() {
        assert!(Op::Gt.compare(10.0, 5.0));
        assert!(!Op::Gt.compare(5.0, 10.0));
        assert!(Op::Lt.compare(1.0, 2.0));
        assert!(Op::Ge.compare(5.0, 5.0));
        assert!(Op::Le.compare(5.0, 5.0));
    }
}
