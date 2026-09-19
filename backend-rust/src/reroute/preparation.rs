//! Shared definition validation. A saved set is not permission to execute: the
//! complete concrete plan is prepared and authorized independently for each run.

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::MySqlPool;

use super::templates::{self, Template};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ActionDraft {
    #[serde(default)]
    pub id: Option<u64>,
    pub reroute_template_id: u64,
    pub device_id: u64,
    #[serde(default)]
    pub params: Value,
    #[serde(default = "enabled_default")]
    pub enabled: bool,
    #[serde(default)]
    pub auto_target: Option<String>,
}

fn enabled_default() -> bool {
    true
}

/// Defines the actual safety order; clients never assign an action a safer class.
pub fn safety_phase(name: &str) -> u8 {
    super::bundle::safety_phase(name).1
}

/// Validate the complete definition before saving it. Flow targets are allowed
/// only with an explicit compatible rule context; they never have manual meaning.
pub async fn validate_drafts(
    pool: &MySqlPool,
    drafts: &[ActionDraft],
    flow_rule: bool,
) -> Result<Vec<(Template, ActionDraft)>> {
    ensure!(!drafts.is_empty(), "at least one action is required");
    ensure!(
        drafts.len() <= 256,
        "a mitigation may contain at most 256 actions"
    );
    ensure!(
        drafts.iter().any(|a| a.enabled),
        "at least one action must be enabled"
    );
    let mut validated = Vec::with_capacity(drafts.len());
    let mut phase = 0;
    for (position, action) in drafts.iter().enumerate() {
        let template = templates::load(pool, action.reroute_template_id)
            .await
            .with_context(|| format!("action {}: template unavailable", position + 1))?;
        ensure!(
            template.provider_type == "device_cli",
            "action {}: unsupported action template",
            position + 1
        );
        let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices WHERE id = ?")
            .bind(action.device_id)
            .fetch_one(pool)
            .await?;
        ensure!(
            exists == 1,
            "action {}: router is unavailable",
            position + 1
        );
        if action.enabled {
            ensure!(
                template.enabled,
                "action {}: template is disabled",
                position + 1
            );
            if template.name != "bgp_export_policy_set" {
                let next = safety_phase(&template.name);
                ensure!(next >= phase, "action {}: additive and preparation actions must precede withdrawals and shutdowns", position + 1);
                phase = next;
            }
        }
        let mut canonical = action.clone();
        if let Some(target) = action.auto_target.as_deref().filter(|v| !v.is_empty()) {
            ensure!(flow_rule && target == "flow_dst_host", "action {}: automatic flow targets require a flow rule; choose an explicit prefix for a manual mitigation", position + 1);
            ensure!(
                matches!(
                    template.name.as_str(),
                    "null_route_prefix" | "blackhole_prefix"
                ),
                "action {}: template does not support a flow target",
                position + 1
            );
        } else {
            canonical.auto_target = None;
            canonical.params = templates::canonicalize_inventory_params(
                pool,
                action.device_id,
                &template,
                &action.params,
            )
            .await
            .with_context(|| format!("action {}", position + 1))?;
            ensure!(
                templates::prefix_target_is_contained(
                    pool,
                    action.device_id,
                    &template,
                    &canonical.params
                )
                .await?,
                "action {}: prefix is outside the router's announced space",
                position + 1
            );
            templates::render(&template, &canonical.params)
                .with_context(|| format!("action {}", position + 1))?;
        }
        validated.push((template, canonical));
    }
    Ok(validated)
}

/// A run may change targets/parameters, but must preserve the saved operation
/// identities and order. To change those, create a new definition or run once.
pub fn validate_overrides(saved: &[ActionDraft], effective: &[ActionDraft]) -> Result<()> {
    ensure!(
        saved.len() == effective.len(),
        "saved action count changed; reload the mitigation template"
    );
    for (a, b) in saved.iter().zip(effective) {
        if a.id != b.id
            || a.reroute_template_id != b.reroute_template_id
            || a.enabled != b.enabled
            || a.auto_target != b.auto_target
        {
            bail!("run overrides may change routers and parameters only; edit or duplicate the template to change its actions or order");
        }
    }
    Ok(())
}

/// Common read-only preparation used by manual and automatic entry points.
/// All deterministic validation precedes SSH, and every snapshot is obtained
/// before returning a set that may be admitted.
pub async fn inspect_actions(
    pool: &MySqlPool,
    actions: &mut [super::bundle::BundleAction],
    automatic: bool,
) -> Result<()> {
    inspect_actions_inner(pool, actions, automatic, None::<&NoReader>).await
}

struct NoReader;
impl super::device_plan::PreparationReader for NoReader {
    fn read_one<'a>(&'a self, _: u64, _: &'a str) -> crate::ssh::BoxFuture<'a, Result<String>> {
        Box::pin(async { bail!("reader unavailable") })
    }
    fn read_many<'a>(
        &'a self,
        _: u64,
        _: &'a [String],
    ) -> crate::ssh::BoxFuture<'a, Result<Vec<String>>> {
        Box::pin(async { bail!("reader unavailable") })
    }
}

pub async fn inspect_actions_with_reader<R: super::device_plan::PreparationReader>(
    pool: &MySqlPool,
    actions: &mut [super::bundle::BundleAction],
    automatic: bool,
    reader: &R,
) -> Result<()> {
    inspect_actions_inner(pool, actions, automatic, Some(reader)).await
}

async fn inspect_actions_inner<R: super::device_plan::PreparationReader>(
    pool: &MySqlPool,
    actions: &mut [super::bundle::BundleAction],
    automatic: bool,
    reader: Option<&R>,
) -> Result<()> {
    ensure!(!actions.is_empty(), "no enabled actions to prepare");
    let mut phase = 0;
    for action in actions.iter_mut() {
        let current = templates::load(pool, action.template.id).await?;
        ensure!(
            serde_json::to_value(&current)? == serde_json::to_value(&action.template)?,
            "action template changed during preparation; retry preview"
        );
        ensure!(
            action.template.enabled,
            "action {}: template disabled",
            action.position + 1
        );
        ensure!(
            !automatic || action.template.automatic_allowed,
            "action {}: template is manual-only",
            action.position + 1
        );
        if action.template.name != "bgp_export_policy_set" {
            let next = safety_phase(&action.template.name);
            ensure!(
                next >= phase,
                "action {}: unsafe action order",
                action.position + 1
            );
            phase = next;
        }
        action.params = templates::canonicalize_inventory_params(
            pool,
            action.device_id,
            &action.template,
            &action.params,
        )
        .await?;
        ensure!(
            templates::prefix_target_is_contained(
                pool,
                action.device_id,
                &action.template,
                &action.params
            )
            .await?,
            "action {}: prefix outside announced space",
            action.position + 1
        );
        let rendered = templates::render(&action.template, &action.params)?;
        ensure!(
            rendered.verify.is_some(),
            "action {}: verification is required",
            action.position + 1
        );
    }
    let inputs: Vec<_> = actions
        .iter()
        .map(|a| super::device_plan::PrepareInput {
            device_id: a.device_id,
            template_id: a.template.id,
            template_name: a.template.name.clone(),
            canonical_params: a.params.clone(),
        })
        .collect();
    let plans = match reader {
        Some(reader) => {
            super::device_plan::prepare_actions_read_only_with_reader(pool, &inputs, reader).await?
        }
        None => {
            crate::ssh::RusshExecutor::new(pool.clone())
                .prepare_actions(&inputs)
                .await?
        }
    };
    ensure!(
        plans.len() == actions.len(),
        "device preparation did not return the complete action set"
    );
    for (index, left) in plans.iter().enumerate() {
        for right in plans.iter().skip(index + 1) {
            if left.device_id != right.device_id {
                continue;
            }
            let legacy = left
                .after
                .iter()
                .chain(right.after.iter())
                .find_map(|s| match s {
                    super::device_plan::DeviceStateSnapshot::RouteMapAssignment {
                        neighbor,
                        direction,
                        ..
                    } => Some((neighbor, direction)),
                    _ => None,
                });
            let export = left
                .after
                .iter()
                .chain(right.after.iter())
                .find_map(|s| match s {
                    super::device_plan::DeviceStateSnapshot::ExportPolicyAttachment {
                        neighbor,
                        ..
                    } => Some(neighbor),
                    _ => None,
                });
            if let (Some((legacy_peer, direction)), Some(export_peer)) = (legacy, export) {
                ensure!(legacy_peer!=export_peer||direction!="out","legacy route-map and export-policy actions overlap the same peer; combine them into one typed export-policy action");
            }
        }
    }
    phase = 0;
    for (action, plan) in actions.iter_mut().zip(plans) {
        plan.validate()?;
        let next = if action.template.name == "bgp_export_policy_set" {
            use super::device_plan::PreparedSafetyEffect::*;
            match super::device_plan::prepared_safety_effect(&plan)? {
                Additive => 0,
                Neutral => 1,
                Noop => phase,
                Destructive => 2,
                Mixed | Unproven => bail!(
                    "action {}: export policy effect is mixed or cannot be proved",
                    action.position + 1
                ),
            }
        } else {
            safety_phase(&action.template.name)
        };
        ensure!(
            next >= phase,
            "action {}: unsafe prepared action order",
            action.position + 1
        );
        phase = next;
        action.params = plan.canonical_params.clone();
        action.prepared = Some(plan);
    }
    Ok(())
}

/// Build inverses exclusively from durable mutation ownership. Mutable rule or
/// preset definitions and caller-supplied parameters are never inverse inputs.
pub async fn prepare_rollbacks(
    pool: &MySqlPool,
    originals: &[u64],
    reason: &str,
    inspect: bool,
) -> Result<Vec<super::bundle::BundleAction>> {
    use super::device_plan::{
        PreparedDeviceAction, PreparedEffect, PreparedInverse,
        PREPARED_DEVICE_ACTION_SCHEMA_VERSION,
    };
    type Original = (
        u64,
        String,
        String,
        Option<u64>,
        Option<sqlx::types::Json<Value>>,
        Option<sqlx::types::Json<Value>>,
        Option<sqlx::types::Json<Value>>,
    );
    let mut actions = Vec::new();
    for original_id in originals {
        let (device_id, effect, state, rollback_of, template, params, inverse): Original = sqlx::query_as(
            "SELECT device_id, mutation_effect, state, rollback_of_reroute_id, template_snapshot_json, parameters_json, rollback_snapshot_json FROM reroutes WHERE id = ?",
        ).bind(original_id).fetch_optional(pool).await?.with_context(||format!("original action #{original_id} not found"))?;
        ensure!(
            rollback_of.is_none(),
            "reroute #{original_id} is already an inverse and cannot be inverted again"
        );
        if effect == "noop" {
            continue;
        }
        ensure!(
            effect == "changed" && matches!(state.as_str(), "succeeded" | "failed"),
            "original action #{original_id} must be reconciled before rollback"
        );
        let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reroutes WHERE rollback_of_reroute_id = ? AND state IN ('planned','pending','running','verifying','uncertain','succeeded')")
            .bind(original_id).fetch_one(pool).await?;
        ensure!(
            existing == 0,
            "original action #{original_id} already has an active, uncertain, or verified rollback"
        );
        let mut template: Template = serde_json::from_value(
            template
                .context("legacy action has no immutable template; reconciliation is required")?
                .0,
        )?;
        let inverse: PreparedInverse = serde_json::from_value(
            inverse
                .context("original action has no proven inverse; reconciliation is required")?
                .0,
        )?;
        let params = params.map(|p| p.0).unwrap_or(Value::Null);
        template.name = format!("prepared_inverse_of_{original_id}");
        let prepared = PreparedDeviceAction {
            schema_version: PREPARED_DEVICE_ACTION_SCHEMA_VERSION,
            device_id,
            template_id: template.id,
            template_name: template.name.clone(),
            canonical_params: params.clone(),
            commands: inverse.commands,
            before: inverse.expected_current,
            after: inverse.restore,
            verify: inverse.verify,
            effect: PreparedEffect::Change,
            inverse: None,
            prepared_at: chrono::Utc::now(),
        };
        prepared.validate()?;
        actions.push(super::bundle::BundleAction {
            device_id,
            template,
            params,
            reason: reason.to_string(),
            position: actions.len() as u32,
            auto_target: None,
            auto_target_low_confidence: None,
            prepared: Some(prepared),
            original_reroute_id: Some(*original_id),
        });
    }
    if inspect {
        let mut prepared: Vec<_> = actions.iter().filter_map(|a| a.prepared.clone()).collect();
        super::device_plan::prepare_inverse_sequence_read_only(pool, &mut prepared).await?;
        for (action, plan) in actions.iter_mut().zip(prepared) {
            action.prepared = Some(plan);
        }
    }
    Ok(actions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn draft(id: u64) -> ActionDraft {
        ActionDraft {
            id: Some(id),
            reroute_template_id: id,
            device_id: 1,
            params: json!({"prefix":"192.0.2.0/24"}),
            enabled: true,
            auto_target: None,
        }
    }
    #[test]
    fn overrides_preserve_order_and_operation_identity() {
        let saved = vec![draft(1), draft(2)];
        let mut changed = saved.clone();
        changed[0].device_id = 4;
        changed[0].params = json!({"prefix":"198.51.100.0/24"});
        assert!(validate_overrides(&saved, &changed).is_ok());
        changed.swap(0, 1);
        assert!(validate_overrides(&saved, &changed).is_err());
        assert!(validate_overrides(&saved, &saved[..1]).is_err());
        let mut disabled = saved.clone();
        disabled[0].enabled = false;
        assert!(validate_overrides(&saved, &disabled).is_err());
    }
}
