use crate::error::{SemanticErrorCode, SemanticValidationErrors, SemanticViolation};
use crate::types::TransactionIntent;

/// Validate the ATF Agent-Commerce Payment Profile v1.
///
/// CAIP syntax is implemented from the official specifications:
/// https://standards.chainagnostic.org/CAIPs/caip-2
/// https://standards.chainagnostic.org/CAIPs/caip-10
/// https://standards.chainagnostic.org/CAIPs/caip-19
///
/// ATF additionally requires percent escapes to be complete uppercase hex
/// octets. No value is canonicalized or silently rewritten.
pub(crate) fn validate(intent: &TransactionIntent) -> Result<(), SemanticValidationErrors> {
    let mut violations = Vec::new();

    if intent.resource.resource_type.is_none() {
        push(
            &mut violations,
            SemanticErrorCode::ProfileFieldRequired,
            "resource.resource_type",
        );
    }

    let network = intent.transaction.network.as_str();
    let network_is_valid = is_caip_2_chain_id(network);
    if !network_is_valid {
        push(
            &mut violations,
            SemanticErrorCode::NetworkIdInvalid,
            "transaction.network",
        );
    }

    match caip_19_chain_id(&intent.transaction.asset) {
        Some(asset_network) if network_is_valid && asset_network != network => push(
            &mut violations,
            SemanticErrorCode::AssetNetworkMismatch,
            "transaction.asset",
        ),
        Some(_) => {}
        None => push(
            &mut violations,
            SemanticErrorCode::AssetIdInvalid,
            "transaction.asset",
        ),
    }

    match intent.transaction.destination.as_deref() {
        None => push(
            &mut violations,
            SemanticErrorCode::ProfileFieldRequired,
            "transaction.destination",
        ),
        Some(destination) => match caip_10_chain_id(destination) {
            Some(destination_network) if network_is_valid && destination_network != network => {
                push(
                    &mut violations,
                    SemanticErrorCode::DestinationNetworkMismatch,
                    "transaction.destination",
                );
            }
            Some(_) => {}
            None => push(
                &mut violations,
                SemanticErrorCode::DestinationIdInvalid,
                "transaction.destination",
            ),
        },
    }

    for (field, present) in [
        (
            "transaction.contract",
            intent.transaction.contract.is_some(),
        ),
        (
            "transaction.calldata_hash",
            intent.transaction.calldata_hash.is_some(),
        ),
        (
            "transaction.slippage_bps",
            intent.transaction.slippage_bps.is_some(),
        ),
        (
            "transaction.leverage",
            intent.transaction.leverage.is_some(),
        ),
    ] {
        if present {
            push(
                &mut violations,
                SemanticErrorCode::ProfileFieldForbidden,
                field,
            );
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(SemanticValidationErrors::new(violations))
    }
}

fn is_caip_2_chain_id(value: &str) -> bool {
    let Some((namespace, reference)) = value.split_once(':') else {
        return false;
    };
    valid_namespace(namespace)
        && (1..=32).contains(&reference.len())
        && reference
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn caip_19_chain_id(value: &str) -> Option<&str> {
    let mut segments = value.split('/');
    let chain_id = segments.next()?;
    let asset_type = segments.next()?;
    let token_id = segments.next();
    if segments.next().is_some() || !is_caip_2_chain_id(chain_id) {
        return None;
    }

    let (asset_namespace, asset_reference) = asset_type.split_once(':')?;
    if !valid_namespace(asset_namespace)
        || !valid_caip_value(asset_reference, 128)
        || token_id.is_some_and(|token| !valid_caip_value(token, 78))
    {
        return None;
    }
    Some(chain_id)
}

fn caip_10_chain_id(value: &str) -> Option<&str> {
    let first_separator = value.find(':')?;
    let second_separator = value[first_separator + 1..].find(':')? + first_separator + 1;
    let chain_id = &value[..second_separator];
    let account_address = &value[second_separator + 1..];
    (is_caip_2_chain_id(chain_id) && valid_caip_value(account_address, 128)).then_some(chain_id)
}

fn valid_namespace(value: &str) -> bool {
    (3..=8).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_caip_value(value: &str, max_len: usize) -> bool {
    if value.is_empty() || value.len() > max_len {
        return false;
    }

    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            byte if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.') => {
                index += 1;
            }
            b'%' if index + 2 < bytes.len()
                && is_upper_hex(bytes[index + 1])
                && is_upper_hex(bytes[index + 2]) =>
            {
                index += 3;
            }
            _ => return false,
        }
    }
    true
}

fn is_upper_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)
}

fn push(violations: &mut Vec<SemanticViolation>, code: SemanticErrorCode, field: &'static str) {
    violations.push(SemanticViolation::new(code, field));
}
