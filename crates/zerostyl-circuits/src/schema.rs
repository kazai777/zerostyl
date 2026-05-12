use serde::{Deserialize, Serialize};

/// Schema describing the witness inputs of a circuit.
///
/// Consumed by the ABI exporter, SDK code generators, and the debugger's
/// `schema` command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessSchema {
    pub fields: Vec<WitnessField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessField {
    pub name: String,
    pub kind: FieldType,
    pub visibility: FieldVisibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FieldType {
    U64,
    U128,
    Bool,
    Bytes32,
    Address,
    Fp,
    Array { kind: Box<FieldType>, len: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldVisibility {
    Private,
    Public,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicInputsSchema {
    pub fields: Vec<PublicInputField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicInputField {
    pub name: String,
    pub kind: FieldType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_schema_roundtrip() {
        let schema = WitnessSchema {
            fields: vec![
                WitnessField {
                    name: "balance".into(),
                    kind: FieldType::U64,
                    visibility: FieldVisibility::Private,
                    description: Some("user balance".into()),
                },
                WitnessField {
                    name: "merkle_siblings".into(),
                    kind: FieldType::Array { kind: Box::new(FieldType::Fp), len: 32 },
                    visibility: FieldVisibility::Private,
                    description: None,
                },
            ],
        };
        let json = serde_json::to_string(&schema).unwrap();
        let back: WitnessSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(schema, back);
    }

    #[test]
    fn field_type_array_serializes_with_named_fields() {
        let t = FieldType::Array { kind: Box::new(FieldType::Bool), len: 32 };
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains("\"len\":32"));
        assert!(json.contains("\"kind\""));
    }

    #[test]
    fn description_omitted_when_none() {
        let f = WitnessField {
            name: "x".into(),
            kind: FieldType::U64,
            visibility: FieldVisibility::Public,
            description: None,
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("description"));
    }
}
