//! Plain-text alert rendering. Bodies must NEVER contain secrets (community
//! strings, credentials). For a fired detection rule the body states whether the
//! metric is above/below the threshold and, when a reroute template is attached,
//! the would-run plan that observe mode suppressed.

use serde_json::Value;

/// One-line subject: "[SEVERITY] event_type — context".
pub fn subject(event_type: &str, severity: &str, payload: &Value) -> String {
    let sev = severity.to_uppercase();
    match event_type {
        "rule_fired" => {
            let rule = payload
                .get("rule_name")
                .and_then(Value::as_str)
                .unwrap_or("rule");
            let iface = payload
                .get("interface")
                .and_then(Value::as_str)
                .unwrap_or("");
            if iface.is_empty() {
                format!("[{sev}] Rule fired: {rule}")
            } else {
                format!("[{sev}] Rule fired: {rule} ({iface})")
            }
        }
        other => format!("[{sev}] {other}"),
    }
}

/// Full plain-text body.
pub fn render(
    event_type: &str,
    severity: &str,
    occurrence_count: u32,
    created_at: chrono::DateTime<chrono::Utc>,
    payload: &Value,
) -> String {
    let mut s = String::new();
    s.push_str("Rerouter alert\n");
    s.push_str("==============\n\n");
    s.push_str(&format!("Event:     {event_type}\n"));
    s.push_str(&format!("Severity:  {severity}\n"));
    s.push_str(&format!(
        "Time:      {} UTC\n",
        created_at.format("%Y-%m-%d %H:%M:%S")
    ));
    if occurrence_count > 1 {
        s.push_str(&format!("Occurrences: {occurrence_count} (collapsed)\n"));
    }
    s.push('\n');

    if event_type == "rule_fired" {
        render_rule_fired(&mut s, payload);
    } else if let Some(msg) = payload.get("message").and_then(Value::as_str) {
        s.push_str(msg);
        s.push('\n');
    }

    s.push_str("\n--\nThis is an automated message from the Rerouter controller.\n");
    s
}

fn render_rule_fired(s: &mut String, payload: &Value) {
    let metric = payload
        .get("metric")
        .and_then(Value::as_str)
        .unwrap_or("metric");
    let operator = payload
        .get("operator")
        .and_then(Value::as_str)
        .unwrap_or("");
    let threshold = payload.get("threshold_value").and_then(Value::as_f64);
    let observed = payload.get("observed_value").and_then(Value::as_f64);
    let direction = payload
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("above");
    let iface = payload
        .get("interface")
        .and_then(Value::as_str)
        .unwrap_or("");

    if !iface.is_empty() {
        s.push_str(&format!("Interface: {iface}\n"));
    }
    if let (Some(obs), Some(th)) = (observed, threshold) {
        s.push_str(&format!(
            "Condition: {metric} is {direction} threshold ({metric} {operator} {th})\n"
        ));
        s.push_str(&format!("Observed:  {metric} = {obs}\n"));
        s.push_str(&format!("Threshold: {th}\n"));
    } else {
        s.push_str(&format!(
            "Condition: {metric} {operator} {}\n",
            threshold.unwrap_or(0.0)
        ));
    }

    // Would-run actions (observe mode, or a manual-only rule: nothing executed —
    // we show the exact commands each attached action WOULD have run).
    if let Some(actions) = payload.get("would_run_actions").and_then(Value::as_array) {
        if !actions.is_empty() {
            s.push('\n');
            s.push_str("Mitigations (NOT executed — observe mode):\n");
            for action in actions {
                let template = action
                    .get("template_name")
                    .and_then(Value::as_str)
                    .unwrap_or("action");
                let device = action
                    .get("device_name")
                    .and_then(Value::as_str)
                    .unwrap_or("device");
                s.push_str(&format!("  {template} on {device}:\n"));
                if let Some(cmds) = action
                    .get("rendered")
                    .and_then(|r| r.get("commands"))
                    .and_then(Value::as_array)
                {
                    for cmd in cmds {
                        if let Some(c) = cmd.as_str() {
                            s.push_str(&format!("    {c}\n"));
                        }
                    }
                }
            }
            s.push_str("  (flip operating_mode to 'enforce' to allow execution)\n");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rule_fired_body_includes_threshold_direction_and_plan() {
        let payload = json!({
            "rule_name": "High inbound",
            "interface": "GigabitEthernet0/0 on edge1",
            "metric": "rx_bps",
            "operator": ">",
            "threshold_value": 1000.0,
            "observed_value": 5000.0,
            "direction": "above",
            "would_run_actions": [{
                "template_name": "blackhole_prefix",
                "device_name": "edge1",
                "rendered": { "commands": ["configure terminal", "ip route 203.0.113.0 255.255.255.0 Null0 tag 666", "end"] }
            }]
        });
        let now = chrono::Utc::now();
        let body = render("rule_fired", "critical", 1, now, &payload);
        assert!(body.contains("above threshold"));
        assert!(body.contains("rx_bps = 5000"));
        assert!(body.contains("NOT executed"));
        assert!(body.contains("ip route 203.0.113.0 255.255.255.0 Null0 tag 666"));
        assert!(body.contains("blackhole_prefix on edge1"));
        // never leak secrets
        assert!(!body.to_lowercase().contains("community"));

        let subj = subject("rule_fired", "critical", &payload);
        assert!(subj.contains("CRITICAL"));
        assert!(subj.contains("High inbound"));
    }
}
