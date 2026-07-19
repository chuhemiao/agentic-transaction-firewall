use ulid::Ulid;

/// Generate a new lexicographically-sortable identifier (ULID), used for
/// `intent_id` and similar fields (PRD §9.2 example: `"intent_id": "01J..."`).
pub fn new_ulid() -> String {
    Ulid::generate().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn generates_parseable_ulid() {
        let id = new_ulid();
        assert!(Ulid::from_str(&id).is_ok());
    }
}
