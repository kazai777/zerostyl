//! AST transformation for zk-SNARK circuit generation
//!
//! This module transforms parsed Rust structs into an intermediate representation (IR)
//! suitable for generating halo2 zk-SNARK circuits. It validates type compatibility
//! and extracts metadata needed for circuit construction.

use crate::error::{CompilerError, Result};
use crate::parser::{ParsedContract, PrivateField};
use zerostyl_runtime::CircuitConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkField {
    pub name: String,
    pub field_type: ZkType,
    pub constraints: Vec<Constraint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZkType {
    U8,
    U16,
    U32,
    U64,
    U128,
    I64,
    Bool,
    Field,
    Bytes32,
    Array { element_type: Box<ZkType>, size: usize },
    Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constraint {
    RangeProof { min: u128, max: u128 },
    Comparison { operator: ComparisonOp, value: u64 },
    Commitment { hash_type: HashType },
    ArithmeticRelation { lhs_field: String, operator: ArithOp, rhs_fields: Vec<(String, ArithOp)> },
    MerkleProof { leaf_field: String, path_field: String, root_field: String, tree_depth: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonOp {
    GreaterThan,
    LessThan,
    Equal,
    NotEqual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashType {
    Pedersen,
    Poseidon,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CircuitIR {
    pub name: String,
    pub public_inputs: Vec<ZkField>,
    pub private_witnesses: Vec<ZkField>,
    pub inter_field_constraints: Vec<InterFieldConstraint>,
    pub circuit_config: CircuitConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterFieldConstraint {
    ArithmeticRelation {
        result_field: String,
        operation: ArithOp,
        operands: Vec<String>,
    },
    MerkleVerification {
        leaf: String,
        path: String,
        root: String,
    },
    CommitmentVerification {
        commitment: String,
        value: String,
        randomness: String,
        hash_type: HashType,
    },
}

pub fn transform_to_ir(parsed: ParsedContract) -> Result<CircuitIR> {
    validate_zk_types(&parsed.private_fields)?;

    let private_witnesses: Result<Vec<ZkField>> = parsed
        .private_fields
        .into_iter()
        .map(|field| {
            let field_type = parse_zk_type(&field.field_type)?;
            let constraints = default_constraints(&field_type);

            Ok(ZkField { name: field.name, field_type, constraints })
        })
        .collect();

    Ok(CircuitIR {
        name: parsed.contract_name,
        public_inputs: vec![],
        private_witnesses: private_witnesses?,
        inter_field_constraints: vec![],
        circuit_config: CircuitConfig::minimal(16)
            .map_err(|e| CompilerError::Other(format!("Failed to create circuit config: {}", e)))?,
    })
}

pub fn validate_zk_types(fields: &[PrivateField]) -> Result<()> {
    for field in fields {
        parse_zk_type(&field.field_type)?;
    }
    Ok(())
}

fn parse_zk_type(type_str: &str) -> Result<ZkType> {
    match type_str {
        "u8" => Ok(ZkType::U8),
        "u16" => Ok(ZkType::U16),
        "u32" => Ok(ZkType::U32),
        "u64" => Ok(ZkType::U64),
        "u128" => Ok(ZkType::U128),
        "i64" => Ok(ZkType::I64),
        "bool" => Ok(ZkType::Bool),
        "Field" => Ok(ZkType::Field),
        "[u8;32]" => Ok(ZkType::Bytes32),
        "Address" => Ok(ZkType::Address),
        _ => {
            if type_str.starts_with('[') && type_str.ends_with(']') {
                return Err(CompilerError::UnsupportedZkType(format!(
                    "Array type '{}' parsing not yet fully implemented. Currently only [u8;32] is supported.",
                    type_str
                )));
            }

            Err(CompilerError::UnsupportedZkType(format!(
                "Type '{}' is not supported for zk-SNARK circuits. Supported types: u8, u16, u32, u64, u128, i64, bool, Field, [u8;32], Address",
                type_str
            )))
        }
    }
}

fn default_constraints(zk_type: &ZkType) -> Vec<Constraint> {
    match zk_type {
        ZkType::U8 => vec![Constraint::RangeProof { min: 0, max: u8::MAX as u128 }],
        ZkType::U16 => vec![Constraint::RangeProof { min: 0, max: u16::MAX as u128 }],
        ZkType::U32 => vec![Constraint::RangeProof { min: 0, max: u32::MAX as u128 }],
        ZkType::U64 => vec![Constraint::RangeProof { min: 0, max: u64::MAX as u128 }],
        ZkType::U128 => vec![Constraint::RangeProof { min: 0, max: u128::MAX }],
        ZkType::I64 => vec![],
        ZkType::Bool => vec![Constraint::RangeProof { min: 0, max: 1 }],
        ZkType::Field => vec![],
        ZkType::Bytes32 => vec![],
        ZkType::Array { .. } => vec![],
        ZkType::Address => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_zk_type_u64() {
        let result = parse_zk_type("u64");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ZkType::U64);
    }

    #[test]
    fn test_parse_zk_type_u128() {
        let result = parse_zk_type("u128");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ZkType::U128);
    }

    #[test]
    fn test_parse_zk_type_bytes32() {
        let result = parse_zk_type("[u8;32]");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ZkType::Bytes32);
    }

    #[test]
    fn test_parse_zk_type_unsupported() {
        let result = parse_zk_type("String");
        assert!(result.is_err());
    }

    #[test]
    fn test_default_constraints_u64() {
        let constraints = default_constraints(&ZkType::U64);
        assert_eq!(constraints.len(), 1);
        if let Constraint::RangeProof { min, max } = constraints[0] {
            assert_eq!(min, 0);
            assert_eq!(max, u64::MAX as u128);
        } else {
            panic!("Expected RangeProof constraint");
        }
    }

    #[test]
    fn test_default_constraints_u128() {
        let constraints = default_constraints(&ZkType::U128);
        assert_eq!(constraints.len(), 1);
        if let Constraint::RangeProof { min, max } = constraints[0] {
            assert_eq!(min, 0);
            assert_eq!(max, u128::MAX);
        } else {
            panic!("Expected RangeProof constraint");
        }
    }

    #[test]
    fn test_default_constraints_bool() {
        let constraints = default_constraints(&ZkType::Bool);
        assert_eq!(constraints.len(), 1);
        if let Constraint::RangeProof { min, max } = constraints[0] {
            assert_eq!(min, 0);
            assert_eq!(max, 1);
        } else {
            panic!("Expected RangeProof constraint");
        }
    }

    #[test]
    fn test_all_zk_types_parseable() {
        let types = vec![
            ("u8", ZkType::U8),
            ("u16", ZkType::U16),
            ("u32", ZkType::U32),
            ("u64", ZkType::U64),
            ("u128", ZkType::U128),
            ("i64", ZkType::I64),
            ("bool", ZkType::Bool),
            ("Field", ZkType::Field),
            ("[u8;32]", ZkType::Bytes32),
            ("Address", ZkType::Address),
        ];

        for (type_str, expected) in types {
            let result = parse_zk_type(type_str).unwrap();
            assert_eq!(result, expected, "Failed for type: {}", type_str);
        }
    }
}
