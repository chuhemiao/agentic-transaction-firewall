use std::fmt;
use std::str::FromStr;

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// A fixed-point amount (money, quantity, ratio in basis points, etc).
///
/// Backed by [`rust_decimal::Decimal`] and serialized as a JSON string only
/// (the `serde-str` feature on `rust_decimal` rejects bare JSON numbers on
/// deserialization). This is the one and only numeric type core ATF domain
/// models should use for anything that represents money — floating point is
/// banned in the core domain model (PRD §9.1.7, §35.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Amount(Decimal);

impl Amount {
    pub const ZERO: Amount = Amount(Decimal::ZERO);

    pub fn from_decimal(value: Decimal) -> Self {
        Self(value)
    }

    pub fn as_decimal(&self) -> Decimal {
        self.0
    }

    pub fn is_negative(&self) -> bool {
        self.0.is_sign_negative() && !self.0.is_zero()
    }

    pub fn checked_add(self, other: Amount) -> Option<Amount> {
        self.0.checked_add(other.0).map(Amount)
    }

    pub fn checked_sub(self, other: Amount) -> Option<Amount> {
        self.0.checked_sub(other.0).map(Amount)
    }
}

impl FromStr for Amount {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Decimal::from_str(s)
            .map(Amount)
            .map_err(|e| CoreError::InvalidAmount(format!("{s}: {e}")))
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixed_point_string() {
        let a: Amount = "12.50".parse().unwrap();
        assert_eq!(a.to_string(), "12.50");
    }

    #[test]
    fn rejects_garbage() {
        assert!("not-a-number".parse::<Amount>().is_err());
    }

    #[test]
    fn serializes_as_json_string_not_number() {
        let a: Amount = "12.50".parse().unwrap();
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, "\"12.50\"");
    }

    #[test]
    fn rejects_bare_json_float_on_deserialize() {
        assert!(serde_json::from_str::<Amount>("12.50").is_err());
        assert!(serde_json::from_str::<Amount>("\"12.50\"").is_ok());
    }

    #[test]
    fn checked_add_and_sub() {
        let a: Amount = "10".parse().unwrap();
        let b: Amount = "2.5".parse().unwrap();
        assert_eq!(a.checked_add(b).unwrap().to_string(), "12.5");
        assert_eq!(a.checked_sub(b).unwrap().to_string(), "7.5");
    }

    #[test]
    fn detects_negative() {
        let a: Amount = "-1".parse().unwrap();
        assert!(a.is_negative());
        assert!(!Amount::ZERO.is_negative());
    }
}
