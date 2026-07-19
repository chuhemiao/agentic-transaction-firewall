use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::CoreError;

/// A UTC timestamp that always serializes/deserializes as an RFC 3339 string
/// (PRD §9.1.8), never as an epoch number or chrono's internal struct form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(DateTime<Utc>);

impl Timestamp {
    pub fn now() -> Self {
        Self(Utc::now())
    }

    pub fn from_datetime(dt: DateTime<Utc>) -> Self {
        Self(dt)
    }

    pub fn as_datetime(&self) -> DateTime<Utc> {
        self.0
    }
}

impl FromStr for Timestamp {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DateTime::parse_from_rfc3339(s)
            .map(|dt| Timestamp(dt.with_timezone(&Utc)))
            .map_err(|e| CoreError::InvalidTimestamp(format!("{s}: {e}")))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_rfc3339_opts(SecondsFormat::Millis, true))
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Timestamp::from_str(&s).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_rfc3339() {
        let ts: Timestamp = "2026-07-18T08:00:00Z".parse().unwrap();
        let json = serde_json::to_string(&ts).unwrap();
        assert_eq!(json, "\"2026-07-18T08:00:00.000Z\"");
        let back: Timestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ts);
    }

    #[test]
    fn rejects_non_rfc3339() {
        assert!("2026-07-18".parse::<Timestamp>().is_err());
        assert!(serde_json::from_str::<Timestamp>("1752825600").is_err());
    }
}
