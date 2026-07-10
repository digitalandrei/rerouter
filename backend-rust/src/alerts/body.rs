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
        e if e.starts_with("reroute_") => {
            let state = e.strip_prefix("reroute_").unwrap_or(e);
            let template = payload
                .get("template_display_name")
                .and_then(Value::as_str)
                .or_else(|| payload.get("template").and_then(Value::as_str))
                .unwrap_or("reroute");
            let device = payload
                .get("device_name")
                .and_then(Value::as_str)
                .unwrap_or("device");
            format!("[{sev}] Reroute {state}: {template} on {device}")
        }
        "operating_mode_changed" | "automatic_actions_changed" | "global_lock_changed" => {
            let after = payload.get("after").and_then(Value::as_str).unwrap_or("");
            if after.is_empty() {
                format!("[{sev}] {event_type}")
            } else {
                format!("[{sev}] {event_type} -> {after}")
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
    } else if event_type.starts_with("reroute_") {
        render_reroute(&mut s, event_type, payload);
    } else if matches!(
        event_type,
        "operating_mode_changed" | "automatic_actions_changed" | "global_lock_changed"
    ) {
        render_mode_change(&mut s, payload);
    } else if let Some(msg) = payload.get("message").and_then(Value::as_str) {
        s.push_str(msg);
        s.push('\n');
    }

    s.push_str("\n--\nThis is an automated message from the Rerouter controller.\n");
    s
}

/// The acting user, when the payload carries an `actor` object. Manual and rollback
/// actions and mode flips are attributed here (email/name); automatic actions have
/// no actor and print nothing. Never leaks secrets — only email/display name.
fn push_actor(s: &mut String, payload: &Value) {
    let Some(actor) = payload.get("actor").filter(|a| a.is_object()) else {
        return;
    };
    let email = actor.get("email").and_then(Value::as_str).unwrap_or("");
    let name = actor.get("name").and_then(Value::as_str).unwrap_or("");
    let who = match (name.is_empty(), email.is_empty()) {
        (false, false) => format!("{name} <{email}>"),
        (true, false) => email.to_string(),
        (false, true) => name.to_string(),
        (true, true) => match actor.get("id").and_then(Value::as_u64) {
            Some(id) => format!("user #{id}"),
            None => return,
        },
    };
    s.push_str(&format!("By:        {who}\n"));
}

/// Append a labelled command block (the exact CLI a reroute ran / would run / would
/// undo). `commands` is a JSON array of strings; a missing/empty array prints nothing.
fn push_commands(s: &mut String, label: &str, commands: Option<&Value>) {
    let Some(cmds) = commands.and_then(Value::as_array).filter(|c| !c.is_empty()) else {
        return;
    };
    s.push('\n');
    s.push_str(label);
    s.push('\n');
    for c in cmds {
        if let Some(c) = c.as_str() {
            s.push_str(&format!("    {c}\n"));
        }
    }
}

/// Body for `reroute_*` events (started / succeeded / failed / uncertain, for
/// manual, automatic, and rollback triggers). States WHAT ran, on which device, WHO
/// decided (manual), the commands run, and the rollback to undo them by hand.
fn render_reroute(s: &mut String, event_type: &str, payload: &Value) {
    let state = event_type.strip_prefix("reroute_").unwrap_or(event_type);
    let template = payload
        .get("template_display_name")
        .and_then(Value::as_str)
        .or_else(|| payload.get("template").and_then(Value::as_str))
        .unwrap_or("reroute");
    let device = payload
        .get("device_name")
        .and_then(Value::as_str)
        .unwrap_or("device");
    let trigger = payload
        .get("trigger_type")
        .and_then(Value::as_str)
        .unwrap_or("manual");

    s.push_str(&format!("Action:    {template}\n"));
    s.push_str(&format!("Device:    {device}\n"));
    s.push_str(&format!("Trigger:   {trigger}\n"));
    s.push_str(&format!("State:     {state}\n"));
    push_actor(s, payload);
    if let Some(reason) = payload.get("reason").and_then(Value::as_str) {
        if !reason.is_empty() {
            s.push_str(&format!("Reason:    {reason}\n"));
        }
    }
    if let Some(detail) = payload.get("detail") {
        if let Some(fail) = detail.get("failure_reason").and_then(Value::as_str) {
            if !fail.is_empty() {
                s.push_str(&format!("Failure:   {fail}\n"));
            }
        }
        if let Some(v) = detail.get("verification").and_then(Value::as_str) {
            if !v.is_empty() {
                s.push_str(&format!("Verify:    {v}\n"));
            }
        }
    }

    push_commands(s, "Commands run:", payload.get("commands"));
    push_commands(
        s,
        "Rollback (to undo by hand):",
        payload.get("rollback_commands"),
    );
}

/// Body for arming / mode-flip events. These are the highest-consequence changes
/// (they can allow traffic-moving actions), so the email states the change and who
/// made it.
fn render_mode_change(s: &mut String, payload: &Value) {
    if let (Some(before), Some(after)) = (
        payload.get("before").and_then(Value::as_str),
        payload.get("after").and_then(Value::as_str),
    ) {
        s.push_str(&format!("Changed:   {before} -> {after}\n"));
    }
    push_actor(s, payload);
    if let Some(msg) = payload.get("message").and_then(Value::as_str) {
        if !msg.is_empty() {
            s.push_str(&format!("\n{msg}\n"));
        }
    }
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
                if let Some(rb) = action
                    .get("rollback")
                    .and_then(|r| r.get("commands"))
                    .and_then(Value::as_array)
                    .filter(|c| !c.is_empty())
                {
                    s.push_str("    rollback (to undo by hand):\n");
                    for cmd in rb {
                        if let Some(c) = cmd.as_str() {
                            s.push_str(&format!("      {c}\n"));
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
                "rendered": { "commands": ["configure terminal", "ip route 203.0.113.0 255.255.255.0 Null0 tag 666", "end"] },
                "rollback": { "commands": ["configure terminal", "no ip route 203.0.113.0 255.255.255.0 Null0 tag 666", "end"] }
            }]
        });
        let now = chrono::Utc::now();
        let body = render("rule_fired", "critical", 1, now, &payload);
        assert!(body.contains("above threshold"));
        assert!(body.contains("rx_bps = 5000"));
        assert!(body.contains("NOT executed"));
        assert!(body.contains("ip route 203.0.113.0 255.255.255.0 Null0 tag 666"));
        assert!(body.contains("blackhole_prefix on edge1"));
        // observe-mode alerts also show the rollback (undo) commands.
        assert!(body.contains("rollback (to undo by hand):"));
        assert!(body.contains("no ip route 203.0.113.0 255.255.255.0 Null0 tag 666"));
        // never leak secrets
        assert!(!body.to_lowercase().contains("community"));

        let subj = subject("rule_fired", "critical", &payload);
        assert!(subj.contains("CRITICAL"));
        assert!(subj.contains("High inbound"));
    }

    #[test]
    fn manual_reroute_body_shows_actor_commands_and_rollback() {
        let payload = json!({
            "reroute_id": 42,
            "template": "blackhole_prefix",
            "template_display_name": "Blackhole prefix",
            "device_name": "edge1",
            "trigger_type": "manual",
            "actor": { "id": 7, "email": "op@example.com", "name": "Op Erator" },
            "reason": "attack on 203.0.113.0/24",
            "commands": ["configure terminal", "ip route 203.0.113.0 255.255.255.0 Null0 tag 666", "end"],
            "rollback_commands": ["configure terminal", "no ip route 203.0.113.0 255.255.255.0 Null0 tag 666", "end"],
            "detail": { "verification": "route present" }
        });
        let body = render("reroute_succeeded", "info", 1, chrono::Utc::now(), &payload);
        // who decided
        assert!(body.contains("Op Erator <op@example.com>"));
        assert!(body.contains("Trigger:   manual"));
        assert!(body.contains("State:     succeeded"));
        assert!(body.contains("attack on 203.0.113.0/24"));
        // forward commands
        assert!(body.contains("Commands run:"));
        assert!(body.contains("ip route 203.0.113.0 255.255.255.0 Null0 tag 666"));
        // rollback commands (to undo by hand)
        assert!(body.contains("Rollback (to undo by hand):"));
        assert!(body.contains("no ip route 203.0.113.0 255.255.255.0 Null0 tag 666"));
        // never leak secrets
        let low = body.to_lowercase();
        assert!(!low.contains("community"));
        assert!(!low.contains("password"));

        let subj = subject("reroute_succeeded", "info", &payload);
        assert!(subj.contains("Reroute succeeded"));
        assert!(subj.contains("Blackhole prefix on edge1"));
    }

    #[test]
    fn automatic_reroute_body_has_no_actor_line() {
        let payload = json!({
            "template": "null_route_prefix",
            "device_name": "edge2",
            "trigger_type": "automatic",
            "actor": Value::Null,
            "commands": ["configure terminal", "ip route 198.51.100.5 255.255.255.255 Null0", "end"],
            "detail": {}
        });
        let body = render("reroute_started", "info", 1, chrono::Utc::now(), &payload);
        assert!(body.contains("Trigger:   automatic"));
        assert!(!body.contains("By:"));
    }

    #[test]
    fn mode_flip_body_shows_change_and_actor() {
        let payload = json!({
            "actor": { "id": 1, "email": "admin@example.com", "name": "Admin" },
            "before": "observe",
            "after": "enforce",
            "message": "operating_mode changed from observe to enforce"
        });
        let body = render(
            "operating_mode_changed",
            "critical",
            1,
            chrono::Utc::now(),
            &payload,
        );
        assert!(body.contains("Changed:   observe -> enforce"));
        assert!(body.contains("Admin <admin@example.com>"));
        let subj = subject("operating_mode_changed", "critical", &payload);
        assert!(subj.contains("CRITICAL"));
        assert!(subj.contains("enforce"));
    }
}
