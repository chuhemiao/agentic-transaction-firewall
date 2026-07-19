use std::str::FromStr;

use atf_core::Amount;
use atf_intent::TransactionIntent;
use cedar_policy::{Context, EntityId, EntityTypeName, EntityUid, Request};
use serde_json::{json, Map, Value};

use crate::error::PolicyError;

/// Maps a [`TransactionIntent`] onto a Cedar `Request`.
///
/// This MVP mapping deliberately keeps everything in `context` rather than
/// building an `Entities` store with per-entity attributes: it is simpler,
/// and every field a policy needs is available as `context.<field>`. A
/// richer entity model (e.g. an `Agent` entity with `parents` for role
/// hierarchies) is future work once `atf-identity` exists (PRD §17).
///
/// Principal is `Agent::"<agent_id>"`, action is
/// `Action::"<category>/<operation>"`, resource is
/// `Resource::"<resource_id>"`.
pub(crate) fn build_request(intent: &TransactionIntent) -> Result<Request, PolicyError> {
    let principal = entity_uid("Agent", &intent.principal.agent_id)?;
    let action_id = format!("{}/{}", intent.action.category, intent.action.operation);
    let action = entity_uid("Action", &action_id)?;
    let resource = entity_uid("Resource", &intent.resource.resource_id)?;
    let context = build_context(intent)?;

    Request::new(principal, action, resource, context, None)
        .map_err(|e| PolicyError::RequestBuild(e.to_string()))
}

fn entity_uid(type_name: &str, id: &str) -> Result<EntityUid, PolicyError> {
    let parsed_type = EntityTypeName::from_str(type_name)
        .map_err(|e| PolicyError::RequestBuild(format!("bad entity type `{type_name}`: {e}")))?;
    let parsed_id = EntityId::from_str(id)
        .map_err(|e| PolicyError::RequestBuild(format!("bad entity id `{id}`: {e}")))?;
    Ok(EntityUid::from_type_name_and_id(parsed_type, parsed_id))
}

/// Encodes an [`Amount`] as a Cedar `decimal` extension value so example
/// policies can do range comparisons (`context.amount.lessThan(decimal("..."))`)
/// instead of only string equality. Cedar's decimal extension supports up to
/// 4 fractional digits; an amount with finer precision than that will fail
/// to build a Context, which surfaces as `PolicyError::ContextBuild` — fail
/// closed rather than silently truncating a financial amount.
fn decimal_value(amount: &Amount) -> Value {
    json!({ "__extn": { "fn": "decimal", "arg": amount.to_string() } })
}

fn build_context(intent: &TransactionIntent) -> Result<Context, PolicyError> {
    let mut ctx = Map::new();

    ctx.insert(
        "organization_id".into(),
        json!(intent.principal.organization_id),
    );
    insert_opt(&mut ctx, "user_id", &intent.principal.user_id);
    insert_opt(&mut ctx, "agent_version", &intent.principal.agent_version);
    insert_opt(&mut ctx, "strategy_id", &intent.principal.strategy_id);

    ctx.insert("mandate_id".into(), json!(intent.mandate.mandate_id));
    insert_opt(&mut ctx, "task_id", &intent.mandate.task_id);
    ctx.insert("purpose".into(), json!(intent.mandate.purpose));
    insert_opt(&mut ctx, "budget_id", &intent.mandate.budget_id);
    ctx.insert(
        "human_authorized".into(),
        json!(intent.mandate.human_authorized),
    );

    ctx.insert("protocol".into(), json!(intent.resource.protocol));
    insert_opt(&mut ctx, "venue", &intent.resource.venue);
    insert_opt(&mut ctx, "resource_type", &intent.resource.resource_type);

    ctx.insert("network".into(), json!(intent.transaction.network));
    ctx.insert("asset".into(), json!(intent.transaction.asset));
    ctx.insert("amount".into(), decimal_value(&intent.transaction.amount));
    insert_opt(&mut ctx, "destination", &intent.transaction.destination);
    insert_opt(&mut ctx, "contract", &intent.transaction.contract);
    if let Some(max_fee) = &intent.transaction.max_fee {
        ctx.insert("max_fee".into(), decimal_value(max_fee));
    }
    insert_opt(&mut ctx, "slippage_bps", &intent.transaction.slippage_bps);
    if let Some(leverage) = &intent.transaction.leverage {
        ctx.insert("leverage".into(), decimal_value(leverage));
    }

    // Cedar records have no null/absent-value type, so unset fields must be
    // omitted entirely rather than encoded as `null` (PRD context is meant
    // to be a superset; policies that need a field to always be present
    // should check with `context has field` first).
    Context::from_json_value(Value::Object(ctx), None)
        .map_err(|e| PolicyError::ContextBuild(e.to_string()))
}

fn insert_opt<T: serde::Serialize>(map: &mut Map<String, Value>, key: &str, value: &Option<T>) {
    if let Some(v) = value {
        map.insert(key.to_string(), json!(v));
    }
}
